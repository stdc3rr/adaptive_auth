from django.contrib.auth.models import User
from django.db import models


class LoginAttempt(models.Model):
    """Хранит каждую попытку входа для истории, риска и ограничений."""

    STATUS_CHOICES = [
        ("success", "success"),
        ("success_mfa", "success_mfa"),
        ("pending_mfa", "pending_mfa"),
        ("failed", "failed"),
        ("blocked", "blocked"),
    ]

    DECISION_CHOICES = [
        ("allow", "allow"),
        ("require_mfa", "require_mfa"),
        ("block", "block"),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="login_attempts")
    identifier = models.CharField(max_length=150)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES)
    decision = models.CharField(max_length=16, choices=DECISION_CHOICES, default="allow")
    risk_level = models.CharField(max_length=16, blank=True)
    risk_score = models.FloatField(default=0.0)
    factor_scores = models.JSONField(default=dict, blank=True)
    explanation = models.JSONField(default=list, blank=True)
    request_context = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    provider = models.CharField(max_length=128, blank=True)
    is_vpn_proxy = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class MFAChallenge(models.Model):
    """Одноразовая MFA-проверка для входов со средним риском."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="mfa_challenges")
    login_attempt = models.ForeignKey(LoginAttempt, on_delete=models.CASCADE, related_name="mfa_challenges")
    code_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
