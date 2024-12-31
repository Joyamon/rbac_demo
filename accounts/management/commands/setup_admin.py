from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from accounts.models import CustomUser


class Command(BaseCommand):
    help = '创建默认管理员用户和权限'

    def handle(self, *args, **options):
        # 创建管理员组
        admin_group, created = Group.objects.get_or_create(name='Administrators')

        # 获取所有权限
        content_type = ContentType.objects.get_for_model(CustomUser)
        permissions = Permission.objects.filter(content_type=content_type)

        # 将所有权限添加到管理员组
        admin_group.permissions.add(*permissions)

        # 创建超级管理员用户（如果不存在）
        if not CustomUser.objects.filter(username='admin').exists():
            admin_user = CustomUser.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password='admin123'
            )
            admin_user.groups.add(admin_group)
            self.stdout.write(self.style.SUCCESS('成功创建管理员用户'))

        self.stdout.write(self.style.SUCCESS('成功设置权限'))

