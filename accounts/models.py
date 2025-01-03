from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission as DjangoPermission
import logging
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class CustomUser(AbstractUser):
    class Meta:
        permissions = [
            ("view_user_list", "Can view user list"),
            ("manage_roles", "Can manage roles"),
            ("manage_permissions", "Can manage permissions"),
        ]

    is_active = models.BooleanField(default=True)
    groups = models.ManyToManyField(
        Group,
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name='customuser_set',
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name='customuser_set',
        related_query_name='customuser',
    )

    # def has_user_management_permission(self):
    #     """检查用户是否有管理用户的权限"""
    #     return (
    #             self.is_superuser or
    #             self.is_staff or
    #             self.has_perm('accounts.view_customuser') or
    #             UserRole.objects.filter(
    #                 user=self,
    #                 role__permissions__codename='manage_roles'
    #             ).exists()
    #     )

    def has_role(self, role_name):
        """检查用户是否具有特定角色"""
        return self.user_roles.filter(role__name=role_name).exists()

    def has_permission(self, permission_codename):
        if self.is_superuser:
            return True

        if hasattr(self, 'all_permissions'):
            has_perm = permission_codename in self.all_permissions
            logger.debug(
                f"Cache hit - Permission check for user {self.username}: "
                f"{permission_codename} = {has_perm}"
            )
            return has_perm

        has_perm = self.user_roles.filter(
            role__permissions__codename=permission_codename
        ).exists()

        logger.debug(
            f"DB query - Permission check for user {self.username}: "
            f"{permission_codename} = {has_perm}"
        )

        return has_perm

    def get_all_permissions(self):
        if self.is_superuser:
            return Permission.objects.all()

        if hasattr(self, 'all_permissions'):
            return Permission.objects.filter(codename__in=self.all_permissions)

        return Permission.objects.filter(
            roles__userrole__user=self
        ).distinct()

    def has_user_management_permission(self):
        """检查用户是否有用户管理权限"""
        return (
                self.is_superuser or
                self.has_permission('user_manage') or
                self.has_permission('view_user')
        )

    def has_role_management_permission(self):
        """检查用户是否有角色管理权限"""
        return (
                self.is_superuser or
                self.has_permission('role_manage')
        )

    def has_permission_management_permission(self):
        """检查用户是否有权限管理权限"""
        return (
                self.is_superuser or
                self.has_permission('permission_manage')
        )

    def __str__(self):
        return self.username


class Permission(models.Model):
    name = models.CharField(max_length=255, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def clean(self):
        if not self.codename:
            raise ValidationError('权限代码不能为空')
        if not self.name:
            raise ValidationError('权限名称不能为空')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
        logger.info(f"Permission saved: {self.name} ({self.codename})")

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['codename']


#
class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, related_name='roles')

    def clean(self):
        if not self.name:
            raise ValidationError('角色名称不能为空')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
        logger.info(f"Role saved: {self.name}")

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class UserRole(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    def clean(self):
        # 检查是否已存在相同的用户-角色组合
        if UserRole.objects.filter(user=self.user, role=self.role).exists():
            raise ValidationError('该用户已被分配此角色')

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
        logger.info(
            f"UserRole assigned: {self.user.username} -> {self.role.name}"
        )

    class Meta:
        unique_together = ('user', 'role')
        ordering = ['user', 'role']

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
