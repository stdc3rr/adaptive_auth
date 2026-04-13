import random
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone

from authentication.models import LoginAttempt, MFAChallenge


def is_soft_locked(identifier):
    limit = settings.ADAPTIVE_AUTH["MAX_FAILED_ATTEMPTS_PER_15_MIN"]
    window_start = timezone.now() - timedelta(minutes=15)
    fails = LoginAttempt.objects.filter(identifier=identifier, status="failed", created_at__gte=window_start).count()
    return fails >= limit


def create_mfa_challenge(user, login_attempt):
    raw_code = f"{random.randint(0, 999999):06d}"
    ttl_minutes = settings.ADAPTIVE_AUTH["MFA_CODE_TTL_MINUTES"]
    challenge = MFAChallenge.objects.create(
        user=user,
        login_attempt=login_attempt,
        code_hash=make_password(raw_code),
        expires_at=timezone.now() + timedelta(minutes=ttl_minutes),
    )
    return challenge, raw_code


def verify_mfa_code(challenge, code):
    if challenge.is_used:
        return False
    if challenge.expires_at < timezone.now():
        return False
    return check_password(code, challenge.code_hash)
