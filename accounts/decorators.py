from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.contrib import messages
from django.shortcuts import redirect
from functools import wraps


def user_management_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if request.user.has_user_management_permission():
            return view_func(request, *args, **kwargs)
        messages.error(request, '您没有访问用户管理的权限。如需权限，请联系管理员。')
        return redirect('home')

    return wrapped
