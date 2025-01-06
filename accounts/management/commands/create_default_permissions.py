from django.core.management.base import BaseCommand
from accounts.models import Permission


class Command(BaseCommand):
    help = '创建默认权限'

    def handle(self, *args, **options):
        default_permissions = [
            {
                'name': '查看用户列表',
                'codename': 'view_user_list',
                'description': '允许查看系统中的用户列表'
            },
            {
                'name': '查看用户详情',
                'codename': 'view_user_detail',
                'description': '允许查看用户的详细信息'
            },
            {
                'name': '创建用户',
                'codename': 'create_user',
                'description': '允许创建新用户'
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
                'name': '管理角色',
                'codename': 'manage_roles',
                'description': '允许创建和管理角色'
            },
            {
                'name': '分配权限',
                'codename': 'assign_permissions',
                'description': '允许为角色分配权限'
            },
            {
                'name': '查看系统日志',
                'codename': 'view_system_logs',
                'description': '允许查看系统操作日志'
            },
            {
                'name': '系统设置',
                'codename': 'manage_settings',
                'description': '允许修改系统设置'
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
