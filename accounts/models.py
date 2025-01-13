from django.contrib.auth.models import AbstractUser, Group, Permission as DjangoPermission
from django.db import models
import logging
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    password_reset_token = models.CharField(max_length=100, null=True, blank=True)

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

    def has_permission(self, codename):
        """检查用户是否具有特定权限"""
        if self.is_superuser:
            return True

        # 获取用户所有角色的权限
        user_permissions = set()
        for user_role in self.user_roles.select_related('role').prefetch_related('role__permissions'):
            user_permissions.update(
                perm.codename for perm in user_role.role.permissions.all()
            )

        has_perm = codename in user_permissions
        logger.debug(
            f"User {self.username} permission check for {codename}: {has_perm}"
            f" (permissions: {user_permissions})"
        )
        return has_perm

    def get_all_permissions(self):
        """获取用户的所有权限"""
        if self.is_superuser:
            return Permission.objects.all()

        permissions = set()
        for user_role in self.user_roles.select_related('role').prefetch_related('role__permissions'):
            permissions.update(user_role.role.permissions.all())
        return permissions

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


class UserActivity(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.activity_type} at {self.timestamp}"


def document_upload_path(instance, filename):
    # 文件将被上传到 MEDIA_ROOT/documents/user_<id>/<filename>
    return f'documents/user_{instance.uploaded_by.id}/{filename}'


class Document(models.Model):
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to=document_upload_path)
    uploaded_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='uploaded_documents')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    def filename(self):
        return os.path.basename(self.file.name)

    def file_extension(self):
        name, extension = os.path.splitext(self.file.name)
        return extension
