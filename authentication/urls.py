from django.urls import path

from authentication.views import (
    LoginAPIView,
    LoginAttemptDetailAPIView,
    MFAVerifyAPIView,
    RegisterAPIView,
)

urlpatterns = [
    path("register/", RegisterAPIView.as_view(), name="api-register"),
    path("login/", LoginAPIView.as_view(), name="api-login"),
    path("verify-mfa/", MFAVerifyAPIView.as_view(), name="api-verify-mfa"),
    path("attempt/<int:attempt_id>/", LoginAttemptDetailAPIView.as_view(), name="api-attempt-detail"),
]
