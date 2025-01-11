from django.core.management.base import BaseCommand
from accounts.models import Permission


class Command(BaseCommand):
    help = '创建默认权限'

    def handle(self, *args, **options):
        default_permissions = [
            # 用户列表
            {
                'name': '查看用户详情',
                'codename': 'view_user_detail',
                'description': '允许查看用户的详细信息'
            },
            {
                'name': '编辑用户',
                'codename': 'edit_user',
                'description': '允许编辑现有用户'
            },
            {
                'name': '删除用户',
                'codename': 'delete_user',
                'description': '允许删除用户'
            },
            {
                'name': '分配角色',
                'codename': 'assign_role',
                'description': '允许分配角色给用户'
            },
            # 权限管理页面
            {
                'name': '创建权限',
                'codename': 'add_permission',
                'description': '允许创建权限'
            },
            {
                'name': '删除权限',
                'codename': 'delete_permission',
                'description': '允许删除权限'
            },
            # 角色管理页面
            {
                'name': '创建角色',
                'codename': 'add_role',
                'description': '允许创建角色'
            },
            {
                'name': '编辑角色',
                'codename': 'edit_role',
                'description': '允许编辑角色'
            },
            {
                'name': '删除角色',
                'codename': 'delete_role',
                'description': '允许删除角色'
            },
            {
                'name': '分配权限',
                'codename': 'assign_permission',
                'description': '允许分配权限给角色'
            }
        ]

        for perm_data in default_permissions:
            Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults={
                    'name': perm_data['name'],
                    'description': perm_data['description']
                }
            )
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created permission "{perm_data["name"]}"')
            )
