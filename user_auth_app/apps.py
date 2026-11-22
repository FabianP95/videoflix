from django.apps import AppConfig


class UserAuthAppConfig(AppConfig):
    name = "user_auth_app"

    def ready(self):
        from . import signals  # noqa: F401  # import for side effects (signal registration)
