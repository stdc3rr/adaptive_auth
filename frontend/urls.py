from django.contrib.auth.views import LogoutView
from django.urls import path

from frontend.views import HistoryPageView, LoginPageView, ProfilePageView, RegisterPageView, ResultPageView

urlpatterns = [
    path("", LoginPageView.as_view(), name="login-page"),
    path("register/", RegisterPageView.as_view(), name="register-page"),
    path("result/", ResultPageView.as_view(), name="result-page"),
    path("profile/", ProfilePageView.as_view(), name="profile-page"),
    path("history/", HistoryPageView.as_view(), name="history-page"),
    path("logout/", LogoutView.as_view(next_page="login-page"), name="logout-page"),
]
