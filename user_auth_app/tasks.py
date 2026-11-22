from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string


def send_activation_mail(uidb64, token, mail):
    activation_link = (
        f"{settings.FRONTEND_URL}/pages/auth/activate.html?uid={uidb64}&token={token}"
    )
    context = {
        "activation_link": activation_link,
        "user_name": mail.split("@")[0],
        "logo_url": f"{settings.FRONTEND_URL}/EmailTemplates_Backend/Logo.svg",
    }

    html_content = render_to_string("activation_email.html", context)
    text_content = f"Click the link to activate your account: {activation_link}"
    send_mail(
        "Confirm your email",
        text_content,
        settings.DEFAULT_FROM_EMAIL,
        [mail],
        html_message=html_content,
        fail_silently=False,
    )


def send_reset_password_mail(uidb64, token, mail):
    reset_link = f"{settings.FRONTEND_URL}/pages/auth/confirm_password.html?uid={uidb64}&token={token}"
    context = {
        "reset_link": reset_link,
        "user_name": mail.split("@")[0],
        "logo_url": f"{settings.FRONTEND_URL}/EmailTemplates_Backend/Logo.svg",
    }

    html_content = render_to_string("reset_password.html", context)
    text_content = f"Click the link to reset your password: {reset_link}"
    send_mail(
        "Reset your password",
        text_content,
        settings.DEFAULT_FROM_EMAIL,
        [mail],
        html_message=html_content,
        fail_silently=False,
    )
