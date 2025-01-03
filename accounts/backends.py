from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models import CustomUser, Permission
import logging

logger = logging.getLogger(__name__)


class CustomAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(Q(username=username) | Q(email=username))
            if user.check_password(password):
                return user
            logger.warning(f"Password check failed for user: {username}")
            return None
        except CustomUser.DoesNotExist:
            logger.warning(f"User not found: {username}")
            return None
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None

    def get_user(self, user_id):
        try:
            return CustomUser.objects.select_related().prefetch_related(
                'user_roles__role__permissions'
            ).get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None

    def has_perm(self, user_obj, perm, obj=None):
        """
        检查用户是否具有特定权限
        :param user_obj: 用户对象
        :param perm: 权限字符串
        :param obj: 可选的相关对象
        """
        if not user_obj.is_active:
            logger.warning(f"Inactive user attempting to access: {user_obj.username}")
            return False

        if user_obj.is_superuser:
            return True

        try:
            # 处理 Django 内置权限格式 (app_label.codename)
            if '.' in perm:
                app_label, codename = perm.split('.')
                return user_obj.has_permission(codename)

            # 处理自定义权限格式
            return user_obj.has_permission(perm)

        except Exception as e:
            logger.error(
                f"Error checking permission '{perm}' for user {user_obj.username}: {str(e)}"
            )
            return False

