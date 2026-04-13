from django.utils import timezone
from users.models import TrustedDevice, UserProfile
from risk.services.scoring import build_fingerprint_signature


def update_user_trust_profile(user, context):
    """Обновляет доверенный профиль только после успешной аутентификации."""
    profile, _ = UserProfile.objects.get_or_create(user=user)

    profile.usual_country = context.get("country", profile.usual_country)
    profile.usual_city = context.get("city", profile.usual_city)
    profile.usual_timezone = context.get("timezone", profile.usual_timezone)

    fingerprint = context.get("fingerprint", {}) or {}
    profile.usual_language = fingerprint.get("language", profile.usual_language)

    local_hour = context.get("localHour")
    local_weekday = context.get("localWeekday")
    if local_hour is not None:
        profile.typical_login_hour = int(local_hour)
    if local_weekday is not None:
        profile.typical_login_weekday = int(local_weekday)

    provider = context.get("provider")
    if provider:
        profile.last_provider = provider

    profile.save()

    signature = build_fingerprint_signature(fingerprint)
    TrustedDevice.objects.update_or_create(
        user=user,
        fingerprint_hash=signature,
        defaults={
            "user_agent": fingerprint.get("userAgent", ""),
            "platform": fingerprint.get("platform", ""),
            "timezone": fingerprint.get("timezone", ""),
            "last_seen_at": timezone.now(),
            "is_active": True,
        },
    )
