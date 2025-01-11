from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import UserActivity
from django.dispatch import Signal


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    UserActivity.objects.create(user=user, activity_type='登录系统')


# 自定义信号
user_edited = Signal()
user_deleted = Signal()
user_assigned_role = Signal()
user_details = Signal()
add_permission = Signal()
del_permission = Signal()
add_role = Signal()
edit_role_signal = Signal()
del_role_signal = Signal()
assign_permission_signal = Signal()


@receiver(user_edited)
def log_user_edit(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'编辑 {instance}')


@receiver(user_deleted)
def log_user_delete(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'删除 {instance}')


@receiver(user_details)
def log_user_details(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'查看 {instance}')


@receiver(user_assigned_role)
def log_user_role_assignment(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'分配角色给 {instance}')


@receiver(add_role)
def log_add_role(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'添加角色 {instance}')


@receiver(add_permission)
def log_add_permission(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'添加权限 {instance}')


@receiver(del_permission)
def log_delete_permission(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'删除 {instance}权限')


@receiver(edit_role_signal)
def log_edit_role(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'编辑角色 {instance}')


@receiver(del_role_signal)
def log_delete_role(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'删除角色 {instance}')


@receiver(assign_permission_signal)
def log_assign_permission(sender, user, instance, **kwargs):
    UserActivity.objects.create(user=user, activity_type=f'分配权限给角色 {instance}')



