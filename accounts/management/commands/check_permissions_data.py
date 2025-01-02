from django.core.management.base import BaseCommand
from accounts.models import Role, Permission
from django.db import connection


class Command(BaseCommand):
    help = '检查权限和角色数据的一致性'

    def handle(self, *args, **options):
        self.stdout.write('开始检查权限和角色数据...')

        # 检查 Role 表
        roles = Role.objects.all()
        self.stdout.write(f'发现 {roles.count()} 个角色')

        # 检查 Permission 表
        permissions = Permission.objects.all()
        self.stdout.write(f'发现 {permissions.count()} 个权限')

        # 检查 accounts_role_permissions 表
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM accounts_role_permissions")
            role_permissions_count = cursor.fetchone()[0]
            self.stdout.write(f'accounts_role_permissions 表中有 {role_permissions_count} 条记录')

            cursor.execute("""
                SELECT role_id, permission_id 
                FROM accounts_role_permissions 
                WHERE permission_id NOT IN (SELECT id FROM accounts_role_permissions)
            """)
            invalid_permissions = cursor.fetchall()

        if invalid_permissions:
            self.stdout.write(self.style.ERROR('发现无效的权限引用：'))
            for role_id, permission_id in invalid_permissions:
                self.stdout.write(self.style.ERROR(f'角色 ID: {role_id}, 无效的权限 ID: {permission_id}'))
        else:
            self.stdout.write(self.style.SUCCESS('未发现无效的权限引用'))

        self.stdout.write('数据检查完成')
