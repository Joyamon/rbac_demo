from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import PermissionDenied
from django.db.models import ProtectedError
from django.forms import forms
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Role, Permission, UserRole, CustomUser
from django.views.generic import ListView, DetailView, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse_lazy
from .forms import RoleForm, PermissionForm, CustomUserCreationForm, CustomAuthenticationForm, UserEditForm, \
    CustomPasswordChangeForm
import logging
from django.utils.decorators import method_decorator
from .decorators import user_management_required, permission_required
from django.db.models import Q

logger = logging.getLogger(__name__)


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                # 自动登录新注册的用户
                login(request, user)
                messages.success(request, '注册成功！欢迎加入我们。')
                return redirect('home')
            except Exception as e:
                logger.error(f'User registration failed: {str(e)}')
                messages.error(request, '注册过程中出现错误，请稍后重试。')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{error}')
    else:
        form = CustomUserCreationForm()

    return render(request, 'accounts/register.html', {'form': form})


# @login_required
# @permission_required('accounts.add_role', raise_exception=True)
# def manage_roles(request):
#     if request.method == 'POST':
#         form = RoleForm(request.POST)
#         if form.is_valid():
#             role = form.save()
#             messages.success(request, f'角色 {role.name} 创建成功！')
#             return redirect('manage_roles')
#         else:
#             messages.error(request, '创建角色失败，请检查输入。')
#     else:
#         form = RoleForm()
#
#     roles = Role.objects.all().order_by('name')
#     return render(request, 'accounts/manage_roles.html', {
#         'form': form,
#         'roles': roles
#     })


# @login_required
# @permission_required('accounts.delete_role', raise_exception=True)
# def delete_role(request, role_id):
#     role = get_object_or_404(Role, id=role_id)
#     try:
#         role.delete()
#         messages.success(request, f'角色 {role.name} 已成功删除。')
#     except ProtectedError:
#         messages.error(request, f'无法删除角色 {role.name}，因为它仍在使用中。')
#     return redirect('manage_roles')


@login_required
@permission_required('accounts.edit_role')
def edit_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    if request.method == 'POST':
        form = RoleForm(request.POST, instance=role)
        if form.is_valid():
            form.save()
            messages.success(request, '角色已更新。')
            return redirect('manage_roles')
    else:
        form = RoleForm(instance=role)
    return render(request, 'accounts/edit_role.html', {'form': form, 'role': role})


# @login_required
# def manage_permissions(request):
#     permissions = Permission.objects.all()
#     if request.method == 'POST':
#         form = PermissionForm(request.POST)
#         if form.is_valid():
#             form.save()
#             messages.success(request, '权限创建成功！')
#             return redirect('manage_permissions')
#     else:
#         form = PermissionForm()
#     return render(request, 'accounts/manage_permissions.html', {'permissions': permissions, 'form': form})


# @login_required
# def assign_role(request, user_id):
#     user = CustomUser.objects.get(id=user_id)
#     roles = Role.objects.all()
#     if request.method == 'POST':
#         role_id = request.POST.get('role')
#         role = Role.objects.get(id=role_id)
#         UserRole.objects.create(user=user, role=role)
#         messages.success(request, f'角色 {role.name} 已分配给用户 {user.username}')
#         return redirect('user_detail', user_id=user.id)
#     return render(request, 'accounts/assign_role.html', {'user': user, 'roles': roles})
#

# @login_required
# @permission_required('accounts.change_role', raise_exception=True)
# def assign_permission(request, role_id):
#     role = get_object_or_404(Role, id=role_id)
#     all_permissions = Permission.objects.all().select_related('content_type').order_by('content_type__app_label',
#                                                                                        'codename')
#
#     permission_groups = {}
#     for permission in all_permissions:
#         app_label = permission.content_type.app_label
#         if app_label not in permission_groups:
#             permission_groups[app_label] = []
#         permission_groups[app_label].append(permission)
#
#     if request.method == 'POST':
#         selected_permissions = request.POST.getlist('permissions')
#
#         try:
#             role.permissions.clear()
#             role.permissions.add(*selected_permissions)
#             messages.success(request, f'已成功更新角色 {role.name} 的权限。')
#             return redirect('manage_roles')
#         except Exception as e:
#             messages.error(request, f'更新权限时出错：{str(e)}')
#
#     current_permissions = set(role.permissions.values_list('id', flat=True))
#
#     context = {
#         'role': role,
#         'permission_groups': permission_groups,
#         'current_permissions': current_permissions,
#     }
#
#     return render(request, 'accounts/assign_permission.html', context)


def user_logout(request):
    logout(request)
    messages.success(request, '您已成功登出。')
    return redirect('login')


@login_required
def user_delete(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, f'用户 {user.username} 已被删除。')
        return redirect('user_list')
    return render(request, 'accounts/user_delete.html', {'user': user})


@method_decorator([login_required, user_management_required], name='dispatch')
class UserListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    model = CustomUser
    template_name = 'accounts/user_list.html'
    context_object_name = 'users'
    paginate_by = 10
    permission_required('accounts.user_list')

    def test_func(self):
        return self.request.user.is_staff

    def handle_no_permission(self):
        messages.error(self.request, "您没有权限访问此页面。")
        return super().handle_no_permission()


@method_decorator([login_required, user_management_required], name='dispatch')
class UserDetailView(LoginRequiredMixin, UserPassesTestMixin, DetailView):
    model = CustomUser
    pk = 'user_id'
    pk_url_kwarg = 'user_id'
    template_name = 'accounts/user_detail.html'
    context_object_name = 'user'
    permission_required('accounts.user_detail')

    def test_func(self):
        return self.request.user.is_staff or self.request.user == self.get_object()

    def handle_no_permission(self):
        messages.error(self.request, "您没有权限访问此页面。")
        return super().handle_no_permission()


@method_decorator([login_required, user_management_required], name='dispatch')
class UserEditView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = CustomUser
    pk = 'user_id'
    pk_url_kwarg = 'user_id'
    form_class = UserEditForm
    template_name = 'accounts/user_edit.html'
    context_object_name = 'user'
    permission_required('accounts.user_edit')

    def get_success_url(self):
        return reverse_lazy('user_detail', kwargs={'user_id': self.object.pk})

    def test_func(self):
        return self.request.user.is_staff or self.request.user == self.get_object()

    def handle_no_permission(self):
        messages.error(self.request, "您没有权限编辑此用户。")
        return super().handle_no_permission()

    def form_valid(self, form):
        messages.success(self.request, f"用户 {self.object.username} 的信息已成功更新。")
        return super().form_valid(form)


@login_required
def home(request):
    # 获取基础统计数据
    total_users = CustomUser.objects.count()
    total_roles = Role.objects.count()
    total_permissions = Permission.objects.count()

    # 定义快速操作卡片
    quick_actions = [
        {
            'title': '用户管理',
            'url': 'user_list',
            'icon_class': 'users',
            'bg_color': 'bg-blue-50',
            'text_color': 'text-blue-600',
            'hover_color': 'hover:bg-blue-100',
            'permission': 'accounts.view_customuser'
        },
        {
            'title': '角色管理',
            'url': 'manage_roles',
            'icon_class': 'user-group',
            'bg_color': 'bg-green-50',
            'text_color': 'text-green-600',
            'hover_color': 'hover:bg-green-100',
            'permission': 'accounts.view_role'
        },
        {
            'title': '权限管理',
            'url': 'manage_permissions',
            'icon_class': 'key',
            'bg_color': 'bg-purple-50',
            'text_color': 'text-purple-600',
            'hover_color': 'hover:bg-purple-100',
            'permission': 'accounts.view_permission'
        }
    ]

    # 过滤用户有权限访问的操作
    available_actions = [
        action for action in quick_actions
        if request.user.has_perm(action['permission'])
    ]

    # 获取最近活动
    recent_activities = [
        {
            'description': '新用户注册',
            'timestamp': '2024-01-01 10:00',
            'type': 'user'
        },
        {
            'description': '角色更新',
            'timestamp': '2024-01-01 09:30',
            'type': 'role'
        }
    ]

    context = {
        'total_users': total_users,
        'total_roles': total_roles,
        'total_permissions': total_permissions,
        'quick_actions': available_actions,
        'recent_activities': recent_activities,
    }

    return render(request, 'accounts/home.html', context)


def user_login(request):
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'欢迎回来，{user.username}！')

            return redirect('home')
        else:
            logger.warning(f"Failed login attempt for username: {form.data.get('username')}")
            messages.error(request, '登录失败。请检查您的用户名和密码。')
    else:
        form = CustomAuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def manage_roles(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, '角色创建成功。')
            return redirect('manage_roles')
    else:
        form = RoleForm()

    roles = Role.objects.all()
    return render(request, 'accounts/manage_roles.html', {'form': form, 'roles': roles})


@login_required
def delete_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    try:
        role.delete()
        messages.success(request, f'角色 {role.name} 已成功删除。')
    except ProtectedError:
        messages.error(request, f'无法删除角色 {role.name}，因为它仍在使用中。')
    return redirect('manage_roles')


@login_required
def manage_permissions(request):
    if request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, '权限创建成功。')
            return redirect('manage_permissions')
    else:
        form = PermissionForm()

    permissions = Permission.objects.all()
    return render(request, 'accounts/manage_permissions.html', {'form': form, 'permissions': permissions})


@login_required
def delete_permission(request, permission_id):
    permission = get_object_or_404(Permission, id=permission_id)
    try:
        permission.delete()
        messages.success(request, f'权限 "{permission.name}" 已成功删除。')
    except ProtectedError:
        messages.error(request, f'无法删除权限 "{permission.name}"，因为它正被使用。')
    return redirect('manage_permissions')


@login_required
def assign_permission(request, role_id):
    try:
        role = get_object_or_404(Role, id=role_id)

        # 获取所有权限并按类别分组
        permissions = Permission.objects.all().order_by('codename')

        # 将权限分组
        permission_groups = {
            '用户管理': permissions.filter(codename__startswith='user_'),
            '角色管理': permissions.filter(codename__startswith='role_'),
            '权限管理': permissions.filter(codename__startswith='permission_'),
            '系统管理': permissions.filter(Q(codename__startswith='system_') |
                                           Q(codename__startswith='manage_')),
        }

        # 其他权限
        used_permissions = set()
        for perms in permission_groups.values():
            used_permissions.update(perms.values_list('id', flat=True))

        permission_groups['其他'] = permissions.exclude(id__in=used_permissions)

        if request.method == 'POST':
            try:
                selected_permissions = request.POST.getlist('permissions')
                role.permissions.set(Permission.objects.filter(id__in=selected_permissions))
                messages.success(request, f'已成功更新角色 "{role.name}" 的权限。')
                logger.info(f'Updated permissions for role {role.name} (ID: {role.id})')
                return redirect('manage_roles')
            except Exception as e:
                logger.error(f'Error updating permissions for role {role.id}: {str(e)}')
                messages.error(request, f'更新权限时出错：{str(e)}')

        current_permissions = set(role.permissions.values_list('id', flat=True))

        context = {
            'role': role,
            'permission_groups': permission_groups,
            'current_permissions': current_permissions,
        }

        return render(request, 'accounts/assign_permission.html', context)

    except Exception as e:
        logger.error(f'Error in assign_permission view: {str(e)}')
        messages.error(request, '加载权限时出错，请稍后重试。')
        return redirect('manage_roles')


@login_required
def assign_role(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    roles = Role.objects.all()

    if request.method == 'POST':
        selected_roles = request.POST.getlist('roles')
        UserRole.objects.filter(user=user).delete()
        for role_id in selected_roles:
            UserRole.objects.create(user=user, role_id=role_id)
        messages.success(request, f'已成功更新用户 "{user.username}" 的角色。')
        return redirect('user_list')

    current_roles = user.user_roles.all().values_list('role_id', flat=True)
    context = {
        'user': user,
        'roles': roles,
        'current_roles': current_roles,
    }
    return render(request, 'accounts/assign_role.html', context)


def has_permission(user, permission_codename):
    return UserRole.objects.filter(
        user=user,
        role__permissions__codename=permission_codename
    ).exists()


@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # 更新会话，避免用户被登出
            messages.success(request, '您的密码已成功更新！')
            return redirect('profile')
        else:
            messages.error(request, '请更正下面的错误。')
    else:
        form = CustomPasswordChangeForm(request.user)
    return render(request, 'accounts/change_password.html', {
        'form': form
    })


def profile(request):
    return render(request, 'accounts/profile.html')
