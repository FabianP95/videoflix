import django.dispatch
import django_rq
from django.contrib.auth.tokens import default_token_generator
from django.db.models.signals import post_save
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import User
from .tasks import send_activation_mail, send_reset_password_mail

pre_password_reset = django.dispatch.Signal()


@django.dispatch.receiver(post_save, sender=User)
def user_post_saved(sender, instance, created, **kwargs):

    if created:
        id_bytes = force_bytes(instance.id)
        uidb64 = urlsafe_base64_encode(id_bytes)
        mail = instance.email
        token = default_token_generator.make_token(instance)
        django_rq.enqueue(send_activation_mail, uidb64, token, mail)


@django.dispatch.receiver(pre_password_reset, sender=User)
def user_pre_password_reset(sender, instance, **kwargs):
    id_bytes = force_bytes(instance.id)
    uidb64 = urlsafe_base64_encode(id_bytes)
    mail = instance.email
    token = default_token_generator.make_token(instance)
    django_rq.enqueue(send_reset_password_mail, uidb64, token, mail)
