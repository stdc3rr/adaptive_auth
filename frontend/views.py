from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView

from authentication.models import LoginAttempt
from notifications.models import UserNotification


class LoginPageView(TemplateView):
    template_name = "frontend/login.html"


class RegisterPageView(TemplateView):
    template_name = "frontend/register.html"


class ResultPageView(TemplateView):
    template_name = "frontend/result.html"


class ProfilePageView(LoginRequiredMixin, TemplateView):
    template_name = "frontend/profile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["notifications"] = UserNotification.objects.filter(user=self.request.user)[:10]
        context["recent_attempts"] = LoginAttempt.objects.filter(user=self.request.user)[:10]
        return context


class HistoryPageView(LoginRequiredMixin, TemplateView):
    template_name = "frontend/history.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["attempts"] = LoginAttempt.objects.filter(user=self.request.user)[:50]
        return context

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("login-page")
        return super().dispatch(request, *args, **kwargs)
