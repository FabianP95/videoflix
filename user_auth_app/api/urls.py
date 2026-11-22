from django.urls import path

from .views import (
    ActivateUserView,
    ConfirmPasswordView,
    CookieTokenRefreshView,
    LoginView,
    LogoutView,
    RegistrationView,
    ResetPasswordView,
)

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="registration"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("token/refresh/", CookieTokenRefreshView.as_view(), name="token_refresh"),
    path(
        "activate/<str:uidb64>/<str:token>/",
        ActivateUserView.as_view(),
        name="activate",
    ),
    path("password_reset/", ResetPasswordView.as_view(), name="password_reset"),
    path(
        "password_confirm/<str:uidb64>/<str:token>/",
        ConfirmPasswordView.as_view(),
        name="password_confirm",
    ),
]
