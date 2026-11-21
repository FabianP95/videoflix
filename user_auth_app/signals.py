import django_rq
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import User


@receiver(post_save,sender=User)
def user_post_saved(sender, instance, created, **kwargs):
    queue = django_rq.get_queue("default", autocommit=True)
    print(sender)
    print(queue)
    queue.enqueue(print("hello"))
    