from django.contrib.auth.models import User
from django.db import models


class UserNotification(models.Model):
    """Базовые пользовательские уведомления о подозрительной активности."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications")
    title = models.CharField(max_length=120)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
