import os

from django.conf import settings
from django.contrib.auth.models import AbstractUser, Group, Permission as DjangoPermission
from django.db import models
import logging
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True,verbose_name='邮箱')
    password_reset_token = models.CharField(max_length=100, null=True, blank=True,verbose_name='重置密码令牌')

    class Meta:
        verbose_name = '用户'
        verbose_name_plural = verbose_name
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
    name = models.CharField(max_length=255, unique=True,verbose_name='权限名称')
    codename = models.CharField(max_length=100, unique=True,verbose_name='权限代码')
    description = models.TextField(blank=True,verbose_name='权限描述')

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
        verbose_name = '权限'
        verbose_name_plural = verbose_name


class Role(models.Model):
    name = models.CharField(max_length=255, unique=True,verbose_name='角色名称')
    description = models.TextField(blank=True,verbose_name='角色描述')
    permissions = models.ManyToManyField(Permission, related_name='roles',verbose_name='权限')

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
        verbose_name = '角色'
        verbose_name_plural = verbose_name


class UserRole(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='user_roles',verbose_name='用户')
    role = models.ForeignKey(Role, on_delete=models.CASCADE,verbose_name='角色')

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        logger.info(f"UserRole assigned: {self.user.username} -> {self.role.name}")

    class Meta:
        unique_together = ('user', 'role')
        ordering = ['user', 'role']
        verbose_name = "用户角色"
        verbose_name_plural = verbose_name

    def __str__(self):
        return f"{self.user.username} - {self.role.name}"


class UserActivity(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE,verbose_name='用户')
    activity_type = models.CharField(max_length=255,verbose_name='活动类型')
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name='时间')

    def __str__(self):
        return f"{self.user.username} - {self.activity_type} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
        verbose_name = '用户活动'
        verbose_name_plural = verbose_name


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
        return extension.lower()

    def get_file_type(self):
        extension = self.file_extension().lower()
        if extension in ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml']:
            return 'text'
        elif extension in ['.docx']:
            return 'word'
        elif extension in ['.xlsx', '.xls']:
            return 'excel'
        else:
            return 'other'


def document_image_upload_path(instance, filename):
    # 图片将被上传到 MEDIA_ROOT/document_images/document_<id>/<filename>
    return f'document_images/document_{instance.document.id}/{filename}'


class DocumentImage(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to=document_image_upload_path)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Image for {self.document.title}"

    def get_image_url(self):
        return os.path.join(settings.MEDIA_URL, str(self.image))
