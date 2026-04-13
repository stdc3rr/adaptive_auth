from notifications.models import UserNotification


def notify_user(user, title, message):
    """Базовая заглушка уведомлений: сохраняет сообщение в БД для страницы профиля."""
    if not user:
        return None
    return UserNotification.objects.create(user=user, title=title, message=message)
