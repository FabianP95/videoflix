import os

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from .models import Video
from .tasks import convert_to_480p


@receiver(post_save, sender=Video)
def video_post_saved(sender, instance, created, **kwargs):
    if created:
        convert_to_480p(instance.video_file.path)


@receiver(post_delete, sender=Video)
def auto_delete_file_on_delete(sender, instance, **kwargs):

    if instance.video_file and os.path.isfile(instance.video_file.path):
        os.remove(instance.video_file.path)
