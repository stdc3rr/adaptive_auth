from django.contrib.auth.models import User
from django.db import models


class UserProfile(models.Model):
    """Хранит доверенный базовый контекст для адаптивной проверки."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    usual_country = models.CharField(max_length=64, blank=True)
    usual_city = models.CharField(max_length=64, blank=True)
    usual_timezone = models.CharField(max_length=64, blank=True)
    usual_language = models.CharField(max_length=64, blank=True)
    typical_login_hour = models.PositiveSmallIntegerField(null=True, blank=True)
    typical_login_weekday = models.PositiveSmallIntegerField(null=True, blank=True)
    last_provider = models.CharField(max_length=128, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile<{self.user.username}>"


class TrustedDevice(models.Model):
    """Простой список доверенных отпечатков браузера и устройства."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="trusted_devices")
    fingerprint_hash = models.CharField(max_length=128)
    user_agent = models.TextField(blank=True)
    platform = models.CharField(max_length=64, blank=True)
    timezone = models.CharField(max_length=64, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ("user", "fingerprint_hash")

    def __str__(self):
        return f"TrustedDevice<{self.user.username}>"
