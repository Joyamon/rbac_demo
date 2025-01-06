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
        if not user_obj.is_active:
            return False
        return user_obj.has_perm(perm, obj)

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active:
            return set()
        return user_obj.get_all_permissions()
