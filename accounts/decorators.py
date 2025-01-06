from django.contrib import messages
from django.shortcuts import redirect
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def user_management_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if request.user.has_user_management_permission():
            return view_func(request, *args, **kwargs)
        messages.error(request, '您没有访问用户管理的权限。如需权限，请联系管理员。')
        return redirect('home')

    return wrapped


# def permission_required(permission_codename):
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             if not request.user.is_authenticated:
#                 logger.warning(
#                     f"Unauthenticated user attempting to access view requiring "
#                     f"permission: {permission_codename}"
#                 )
#                 messages.error(request, '请先登录。')
#                 return redirect('login')
#
#             if not request.user.has_permission(permission_codename):
#                 logger.warning(
#                     f"User {request.user.username} denied access to view requiring "
#                     f"permission: {permission_codename}"
#                 )
#                 messages.error(request, '您没有权限执行此操作。')
#                 return redirect('home')
#
#             logger.debug(
#                 f"User {request.user.username} granted access to view requiring "
#                 f"permission: {permission_codename}"
#             )
#             return view_func(request, *args, **kwargs)
#
#         return _wrapped_view
#
#     return decorator


# def permission_required(permission_codename):
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             if not request.user.is_authenticated:
#                 messages.error(request, '请先登录。')
#                 return redirect('login')
#
#             if not request.user.has_perm(permission_codename):
#                 logger.warning(
#                     f"User {request.user.username} denied access to view requiring "
#                     f"permission: {permission_codename}"
#                 )
#                 messages.error(request, '您没有权限执行此操作。')
#                 return redirect('home')
#
#             return view_func(request, *args, **kwargs)
#         return _wrapped_view
#     return decorator

def permission_required(permission_codename):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                logger.warning(
                    f"Unauthenticated user attempting to access view requiring "
                    f"permission: {permission_codename}"
                )
                messages.error(request, '请先登录。')
                return redirect('login')

            if not request.user.has_perm(permission_codename):
                logger.warning(
                    f"User {request.user.username} denied access to view requiring "
                    f"permission: {permission_codename}"
                )
                messages.error(request, '您没有权限执行此操作。')
                return redirect('home')

            logger.info(
                f"User {request.user.username} granted access with permission: "
                f"{permission_codename}"
            )
            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator
