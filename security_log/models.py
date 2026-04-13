from django.contrib.auth.models import User
from django.db import models


class SecurityEvent(models.Model):
    """Аудит-событие для подозрительных или важных действий аутентификации."""

    SEVERITY_CHOICES = [
        ("info", "info"),
        ("warning", "warning"),
        ("critical", "critical"),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="security_events")
    event_type = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="info")
    message = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
