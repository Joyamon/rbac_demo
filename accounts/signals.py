from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import UserActivity
from django.dispatch import Signal


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    UserActivity.objects.create(user=user, activity_type='login')


# 自定义信号
user_edited = Signal()
user_deleted = Signal()
user_assigned_role = Signal()


@receiver(user_edited)
def log_user_edit(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'edit {instance}')


@receiver(user_deleted)
def log_user_delete(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'delete {instance}')
