from security_log.models import SecurityEvent


def log_security_event(event_type, severity, message, user=None, metadata=None):
    return SecurityEvent.objects.create(
        user=user,
        event_type=event_type,
        severity=severity,
        message=message,
        metadata=metadata or {},
    )
