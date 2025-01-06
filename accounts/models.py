from django.contrib.auth.models import AbstractUser, Group, Permission as DjangoPermission
from django.db import models
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
        related_name='customuser_set',
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        DjangoPermission,
        verbose_name='user permissions',
        blank=True,
        related_name='customuser_set',
        related_query_name='customuser',
    )

    def has_perm(self, perm, obj=None):
        if self.is_superuser:
            return True

        if hasattr(self, 'all_permissions'):
            return perm in self.all_permissions

        return self.user_roles.filter(role__permissions__codename=perm).exists()

    def get_all_permissions(self):
        if self.is_superuser:
            return Permission.objects.all()

        if hasattr(self, 'all_permissions'):
            return Permission.objects.filter(codename__in=self.all_permissions)

        return Permission.objects.filter(roles__userrole__user=self).distinct()

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

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        logger.info(f"UserRole assigned: {self.user.username} -> {self.role.name}")

    class Meta:
        unique_together = ('user', 'role')
        ordering = ['user', 'role']

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
