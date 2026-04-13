from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import LoginAttempt, MFAChallenge
from authentication.serializers import (
    LoginAttemptSerializer,
    LoginRequestSerializer,
    MFAVerifySerializer,
    RegisterSerializer,
)
from authentication.services import create_mfa_challenge, is_soft_locked, verify_mfa_code
from notifications.services import notify_user
from risk.services.scoring import score_login_attempt
from security_log.services import log_security_event
from users.services import update_user_trust_profile


def _get_client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _find_user(identifier):
    return User.objects.filter(Q(username=identifier) | Q(email=identifier)).first()


class RegisterAPIView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.create_user(
            username=serializer.validated_data["username"],
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
        )

        log_security_event(
            event_type="register",
            severity="info",
            message="Создан новый пользователь",
            user=user,
            metadata={"username": user.username},
        )
        return Response({"message": "Регистрация успешна"}, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    def post(self, request):
        serializer = LoginRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = serializer.validated_data

        identifier = payload["identifier"].strip()
        ip = _get_client_ip(request)
        payload["ip"] = ip

        if is_soft_locked(identifier):
            attempt = LoginAttempt.objects.create(
                user=None,
                identifier=identifier,
                status="blocked",
                decision="block",
                risk_level="high",
                risk_score=1.0,
                factor_scores={},
                explanation=["Временная блокировка из-за большого числа неудачных попыток"],
                request_context=payload,
                ip_address=ip,
                failure_reason="soft_lock",
            )
            log_security_event(
                event_type="soft_lock",
                severity="critical",
                message="Превышен лимит неудачных попыток входа",
                metadata={"identifier": identifier, "ip": ip},
            )
            return Response(
                {
                    "message": "Вход временно ограничен. Попробуйте позже.",
                    "attempt_id": attempt.id,
                    "decision": "block",
                    "risk_level": "high",
                    "risk_score": 1.0,
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        user = _find_user(identifier)
        if not user or not check_password(payload["password"], user.password):
            LoginAttempt.objects.create(
                user=user,
                identifier=identifier,
                status="failed",
                decision="block",
                risk_level="high",
                risk_score=1.0,
                explanation=["Неверные учетные данные"],
                request_context=payload,
                ip_address=ip,
                failure_reason="invalid_credentials",
            )
            log_security_event(
                event_type="login_failed",
                severity="warning",
                message="Неуспешная попытка входа",
                user=user,
                metadata={"identifier": identifier, "ip": ip},
            )
            return Response(
                {"message": "Неверный логин/email или пароль"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        result = score_login_attempt(user, identifier, payload)

        attempt = LoginAttempt.objects.create(
            user=user,
            identifier=identifier,
            status="success" if result["decision"] == "allow" else "blocked" if result["decision"] == "block" else "pending_mfa",
            decision=result["decision"],
            risk_level=result["risk_level"],
            risk_score=result["risk_score"],
            factor_scores=result["factor_scores"],
            explanation=result["explanation"],
            request_context=payload,
            ip_address=ip,
            provider=payload.get("provider", ""),
            is_vpn_proxy=bool(payload.get("vpn", False)),
        )

        if result["decision"] == "allow":
            login(request, user)
            update_user_trust_profile(user, payload)
            log_security_event(
                event_type="login_success",
                severity="info",
                message="Успешный вход",
                user=user,
                metadata={"risk": result["risk_score"], "ip": ip},
            )
            return Response(
                {
                    "attempt_id": attempt.id,
                    **result,
                    "message": "Вход выполнен",
                }
            )

        if result["decision"] == "require_mfa":
            challenge, raw_code = create_mfa_challenge(user, attempt)
            notify_user(
                user,
                "Подозрительный вход",
                "Для входа потребовалось дополнительное подтверждение (MFA).",
            )
            log_security_event(
                event_type="mfa_required",
                severity="warning",
                message="Потребовалась дополнительная MFA проверка",
                user=user,
                metadata={"attempt_id": attempt.id, "risk": result["risk_score"]},
            )
            response = {
                "attempt_id": attempt.id,
                **result,
                "challenge_id": challenge.id,
                "message": "Требуется дополнительное подтверждение",
            }
            if settings.DEBUG:
                response["demo_mfa_code"] = raw_code
            return Response(response, status=status.HTTP_202_ACCEPTED)

        notify_user(
            user,
            "Опасная попытка входа",
            "Вход был заблокирован из-за высокого риска.",
        )
        log_security_event(
            event_type="login_blocked",
            severity="critical",
            message="Вход заблокирован из-за высокого риска",
            user=user,
            metadata={"attempt_id": attempt.id, "risk": result["risk_score"]},
        )
        return Response(
            {
                "attempt_id": attempt.id,
                **result,
                "message": "Вход заблокирован. Попробуйте позже или используйте другое устройство/сеть.",
            },
            status=status.HTTP_403_FORBIDDEN,
        )


class MFAVerifyAPIView(APIView):
    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        challenge = get_object_or_404(MFAChallenge, id=serializer.validated_data["challenge_id"])
        code = serializer.validated_data["code"]

        if not verify_mfa_code(challenge, code):
            log_security_event(
                event_type="mfa_failed",
                severity="warning",
                message="Неуспешная проверка MFA",
                user=challenge.user,
                metadata={"challenge_id": challenge.id},
            )
            return Response({"message": "Неверный или просроченный MFA код"}, status=status.HTTP_400_BAD_REQUEST)

        challenge.is_used = True
        challenge.save(update_fields=["is_used"])

        attempt = challenge.login_attempt
        attempt.status = "success_mfa"
        attempt.save(update_fields=["status"])

        login(request, challenge.user)
        update_user_trust_profile(challenge.user, attempt.request_context)

        log_security_event(
            event_type="mfa_success",
            severity="info",
            message="MFA подтверждение выполнено",
            user=challenge.user,
            metadata={"attempt_id": attempt.id},
        )
        return Response({"message": "MFA подтверждение успешно", "attempt_id": attempt.id})


class LoginAttemptDetailAPIView(APIView):
    def get(self, request, attempt_id):
        attempt = get_object_or_404(LoginAttempt, id=attempt_id)
        return Response(LoginAttemptSerializer(attempt).data)
