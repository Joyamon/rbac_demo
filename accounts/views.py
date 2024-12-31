from django.db.models import ProtectedError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib import messages
from .models import Role, Permission, UserRole, RolePermission, CustomUser
from django.views.generic import ListView, DetailView, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse_lazy
from .forms import RoleForm, PermissionForm, CustomUserCreationForm, CustomAuthenticationForm, UserEditForm
import logging
from django.utils.decorators import method_decorator
from .decorators import user_management_required

logger = logging.getLogger(__name__)


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, '注册成功！')
            return redirect('home')  # 假设你有一个名为'home'的URL模式
    else:
        form = CustomUserCreationForm()
    return render(request, 'accounts/register.html', {'form': form})


@login_required
@permission_required('accounts.add_role', raise_exception=True)
def manage_roles(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            role = form.save()
            messages.success(request, f'角色 {role.name} 创建成功！')
            return redirect('manage_roles')
        else:
            messages.error(request, '创建角色失败，请检查输入。')
    else:
        form = RoleForm()

    roles = Role.objects.all().order_by('name')
    return render(request, 'accounts/manage_roles.html', {
        'form': form,
        'roles': roles
    })


@login_required
@permission_required('accounts.delete_role', raise_exception=True)
def delete_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    try:
        role.delete()
        messages.success(request, f'角色 {role.name} 已成功删除。')
    except ProtectedError:
        messages.error(request, f'无法删除角色 {role.name}，因为它仍在使用中。')
    return redirect('manage_roles')


@login_required
@permission_required('accounts.edit_role', raise_exception=True)
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


@login_required
def manage_permissions(request):
    permissions = Permission.objects.all()
    if request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, '权限创建成功！')
            return redirect('manage_permissions')
    else:
        form = PermissionForm()
    return render(request, 'accounts/manage_permissions.html', {'permissions': permissions, 'form': form})


@login_required
def assign_role(request, user_id):
    user = CustomUser.objects.get(id=user_id)
    roles = Role.objects.all()
    if request.method == 'POST':
        role_id = request.POST.get('role')
        role = Role.objects.get(id=role_id)
        UserRole.objects.create(user=user, role=role)
        messages.success(request, f'角色 {role.name} 已分配给用户 {user.username}')
        return redirect('user_detail', user_id=user.id)
    return render(request, 'accounts/assign_role.html', {'user': user, 'roles': roles})


@login_required
def assign_permission(request, role_id):
    role = Role.objects.get(id=role_id)
    permissions = Permission.objects.all()
    if request.method == 'POST':
        permission_id = request.POST.get('permission')
        permission = Permission.objects.get(id=permission_id)
        RolePermission.objects.create(role=role, permission=permission)
        messages.success(request, f'权限 {permission.name} 已分配给角色 {role.name}')
        return redirect('role_detail', role_id=role.id)
    return render(request, 'accounts/assign_permission.html', {'role': role, 'permissions': permissions})


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
    context_object_name = 'users'

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
    context_object_name = 'users'

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
