from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)


class RBACMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if hasattr(request, 'user') and request.user.is_authenticated:
            # 预加载用户的角色和权限
            request.user.roles = [
                role.role for role in request.user.user_roles.select_related('role').all()
            ]
            request.user.all_permissions = set()
            for role in request.user.roles:
                request.user.all_permissions.update(
                    role.permissions.values_list('codename', flat=True)
                )

            logger.debug(
                f"User {request.user.username} loaded with roles: "
                f"{[role.name for role in request.user.roles]} and "
                f"permissions: {request.user.all_permissions}"
            )

# class RBACMiddleware(MiddlewareMixin):
#     def process_request(self, request):
#         if hasattr(request, 'user') and request.user.is_authenticated:
#             request.user.all_permissions = set(
#                 request.user.get_all_permissions().values_list('codename', flat=True)
#             )
#             logger.debug(
#                 f"User {request.user.username} loaded with permissions: "
#                 f"{request.user.all_permissions}"
#             )

