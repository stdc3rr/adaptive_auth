import hashlib
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from authentication.models import LoginAttempt
from users.models import TrustedDevice, UserProfile


def clamp(value, min_value=0.0, max_value=1.0):
    return max(min_value, min(max_value, value))


def build_fingerprint_signature(fingerprint):
    keys = [
        "userAgent",
        "language",
        "timezone",
        "screenResolution",
        "platform",
        "deviceMemory",
        "hardwareConcurrency",
        "canvas",
        "webgl",
        "localStorage",
        "sessionStorage",
    ]
    raw = "|".join(str(fingerprint.get(k, "")) for k in keys)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _get_last_success(user):
    return (
        LoginAttempt.objects.filter(user=user, status__in=["success", "success_mfa"])
        .order_by("-created_at")
        .first()
    )


def _geo_anomaly(user_profile, context):
    mismatches = 0
    checks = 0
    for field, key in [("usual_country", "country"), ("usual_city", "city"), ("usual_timezone", "timezone")]:
        baseline = getattr(user_profile, field, "") if user_profile else ""
        current = context.get(key, "")
        if baseline and current:
            checks += 1
            if baseline.lower() != str(current).lower():
                mismatches += 1
    if checks == 0:
        return 0.5
    return clamp(mismatches / checks)


def _time_anomaly(user_profile, context, last_success):
    now = timezone.now()
    local_hour = int(context.get("localHour", now.hour))
    local_weekday = int(context.get("localWeekday", now.weekday()))

    score = 0.0
    parts = 0

    if user_profile and user_profile.typical_login_hour is not None:
        parts += 1
        hour_gap = abs(local_hour - user_profile.typical_login_hour)
        hour_gap = min(hour_gap, 24 - hour_gap)
        score += clamp(hour_gap / 12.0)

    if user_profile and user_profile.typical_login_weekday is not None:
        parts += 1
        score += 0.0 if local_weekday == user_profile.typical_login_weekday else 0.5

    if last_success:
        parts += 1
        delta = now - last_success.created_at
        if delta < timedelta(minutes=1):
            score += 0.7
        elif delta > timedelta(days=30):
            score += 0.6
        else:
            score += 0.1

    if parts == 0:
        return 0.4
    return clamp(score / parts)


def _fingerprint_similarity(user, fingerprint):
    signature = build_fingerprint_signature(fingerprint)
    known = TrustedDevice.objects.filter(user=user, is_active=True).values_list("fingerprint_hash", flat=True)
    if not known:
        return 0.35
    if signature in known:
        return 0.95

    # Приближенная оценка сходства, чтобы сохранить прозрачность логики без сложной математики.
    keys = ["userAgent", "timezone", "platform", "language", "screenResolution"]
    matches = 0
    checks = 0
    for device in TrustedDevice.objects.filter(user=user, is_active=True)[:5]:
        for key in keys:
            current = str(fingerprint.get(key, ""))
            baseline = ""
            if key == "userAgent":
                baseline = device.user_agent
            elif key == "timezone":
                baseline = device.timezone
            elif key == "platform":
                baseline = device.platform
            if baseline and current:
                checks += 1
                if baseline.lower() == current.lower():
                    matches += 1
    if checks == 0:
        return 0.45
    return clamp(matches / checks)


def _network_features(user, context):
    ip = context.get("ip", "")
    provider = context.get("provider", "")
    vpn = bool(context.get("vpn", False))
    reputation = float(context.get("ipReputation", 0.5))

    previous = LoginAttempt.objects.filter(user=user, status__in=["success", "success_mfa"]).values(
        "ip_address", "provider"
    )[:20]

    known_ips = {row["ip_address"] for row in previous if row["ip_address"]}
    known_providers = {row["provider"].lower() for row in previous if row["provider"]}

    x_ip = 0.1 if ip and ip in known_ips else 0.8
    x_prov = 0.1 if provider and provider.lower() in known_providers else 0.7
    x_vpn = 0.8 if vpn else 0.1
    x_rep = clamp(1 - reputation)

    return x_ip, x_prov, x_vpn, x_rep


def _session_features(context, identifier):
    behavior = context.get("behavior", {}) or {}
    tries_last_15 = LoginAttempt.objects.filter(
        identifier=identifier,
        created_at__gte=timezone.now() - timedelta(minutes=15),
    ).count()

    x_tries = clamp(tries_last_15 / 8.0)

    form_fill_ms = float(behavior.get("formFillMs", 4000) or 4000)
    x_speed = 0.8 if form_fill_ms < 1200 else 0.2 if form_fill_ms < 15000 else 0.55

    avg_delay_ms = float(behavior.get("avgKeyDelayMs", 200) or 200)
    if avg_delay_ms < 40:
        x_delay = 0.7
    elif avg_delay_ms > 800:
        x_delay = 0.6
    else:
        x_delay = 0.2

    repeat_count = LoginAttempt.objects.filter(
        identifier=identifier,
        created_at__gte=timezone.now() - timedelta(minutes=5),
    ).count()
    x_repeat = clamp(repeat_count / 5.0)

    return x_tries, x_speed, x_delay, x_repeat


def score_login_attempt(user, identifier, context):
    """
    Вычисляет адаптивный риск по явным формулам:
    1) X_gt = alpha * X_geo + (1 - alpha) * X_time
    2) X_dev = 1 - S_fp
    3) X_net = g1*x_ip + g2*x_prov + g3*x_vpn + g4*x_rep
    4) X_sess = d1*x_tries + d2*x_speed + d3*x_delay + d4*x_repeat
    5) R_ctx = w_gt*X_gt + w_dev*X_dev + w_net*X_net + w_sess*X_sess
    """
    cfg = settings.ADAPTIVE_AUTH
    user_profile = getattr(user, "profile", None)
    last_success = _get_last_success(user)

    x_geo = _geo_anomaly(user_profile, context)
    x_time = _time_anomaly(user_profile, context, last_success)
    alpha = cfg["ALPHA_GEO"]
    X_gt = alpha * x_geo + (1 - alpha) * x_time

    S_fp = _fingerprint_similarity(user, context.get("fingerprint", {}) or {})
    X_dev = 1 - S_fp

    x_ip, x_prov, x_vpn, x_rep = _network_features(user, context)
    g = cfg["GAMMA"]
    X_net = g["ip"] * x_ip + g["provider"] * x_prov + g["vpn"] * x_vpn + g["reputation"] * x_rep

    x_tries, x_speed, x_delay, x_repeat = _session_features(context, identifier)
    d = cfg["DELTA"]
    X_sess = d["tries"] * x_tries + d["speed"] * x_speed + d["delay"] * x_delay + d["repeat"] * x_repeat

    w = cfg["W"]
    R_ctx = w["gt"] * X_gt + w["dev"] * X_dev + w["net"] * X_net + w["sess"] * X_sess
    R_ctx = clamp(R_ctx)

    if R_ctx <= cfg["RISK_LOW_MAX"]:
        risk_level, decision = "low", "allow"
    elif R_ctx <= cfg["RISK_MEDIUM_MAX"]:
        risk_level, decision = "medium", "require_mfa"
    else:
        risk_level, decision = "high", "block"

    explanations = []
    if x_geo > 0.5:
        explanations.append("Новая геолокация относительно привычного профиля")
    if X_dev > 0.6:
        explanations.append("Новый или нестабильный fingerprint устройства")
    if x_vpn > 0.5:
        explanations.append("Обнаружен VPN/Proxy признак")
    if x_tries > 0.5:
        explanations.append("Слишком много попыток входа за короткое время")
    if not explanations:
        explanations.append("Контекст в пределах привычного поведения")

    return {
        "risk_score": round(R_ctx, 4),
        "risk_level": risk_level,
        "decision": decision,
        "factor_scores": {
            "spatio_temporal": round(X_gt, 4),
            "device_browser": round(X_dev, 4),
            "network": round(X_net, 4),
            "behavioral": round(X_sess, 4),
            "subscores": {
                "x_geo": round(x_geo, 4),
                "x_time": round(x_time, 4),
                "s_fp": round(S_fp, 4),
                "x_ip": round(x_ip, 4),
                "x_prov": round(x_prov, 4),
                "x_vpn": round(x_vpn, 4),
                "x_rep": round(x_rep, 4),
                "x_tries": round(x_tries, 4),
                "x_speed": round(x_speed, 4),
                "x_delay": round(x_delay, 4),
                "x_repeat": round(x_repeat, 4),
            },
        },
        "explanation": explanations,
    }
