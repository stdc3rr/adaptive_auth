from django.contrib.auth.models import User
from rest_framework import serializers

from authentication.models import LoginAttempt


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8, write_only=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Пользователь уже существует")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email уже используется")
        return value


class LoginRequestSerializer(serializers.Serializer):
    identifier = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    country = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    timezone = serializers.CharField(required=False, allow_blank=True)
    localHour = serializers.IntegerField(required=False)
    localWeekday = serializers.IntegerField(required=False)
    provider = serializers.CharField(required=False, allow_blank=True)
    vpn = serializers.BooleanField(required=False)
    ipReputation = serializers.FloatField(required=False)
    fingerprint = serializers.DictField(required=False)
    behavior = serializers.DictField(required=False)


class MFAVerifySerializer(serializers.Serializer):
    challenge_id = serializers.IntegerField()
    code = serializers.CharField(max_length=6)


class LoginAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginAttempt
        fields = [
            "id",
            "identifier",
            "status",
            "decision",
            "risk_level",
            "risk_score",
            "factor_scores",
            "explanation",
            "created_at",
        ]
