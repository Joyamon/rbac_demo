from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission as DjangoPermission


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

    def has_user_management_permission(self):
        """检查用户是否有管理用户的权限"""
        return (
                self.is_superuser or
                self.is_staff or
                self.has_perm('accounts.view_customuser') or
                UserRole.objects.filter(
                    user=self,
                    role__permissions__codename='manage_roles'
                ).exists()
        )

    def __str__(self):
        return self.username


class Permission(models.Model):
    name = models.CharField(max_length=255, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


#
class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, related_name='roles')

    def __str__(self):
        return self.name


class UserRole(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'role')

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
