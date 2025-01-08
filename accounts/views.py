import time

from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import ProtectedError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Role, Permission, UserRole, CustomUser, UserActivity
from .forms import RoleForm, PermissionForm, CustomUserCreationForm, CustomAuthenticationForm, UserEditForm, \
    CustomPasswordChangeForm, UserRoleForm
import logging
from .decorators import permission_required
from django.db.models import Q

from .signals import user_edited, user_deleted

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


def user_logout(request):
    logout(request)
    messages.success(request, '您已成功登出。')
    return redirect('login')


@login_required
@permission_required('delete_user')
def user_delete(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, f'用户 {user.username} 已被删除。')
        user_deleted.send(sender=UserActivity, user=request.user, instance=user)  # 发送信号,删除用户
        return redirect('user_list')
    return render(request, 'accounts/user_delete.html', {'user': user})


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
    list_data = []
    for activity in UserActivity.objects.all().order_by('-timestamp'):
        list_data.append({
            'description': activity.activity_type,
            'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M'),
            'user': activity.user.username if activity.user else '系统',
            'type': activity.activity_type
        })

    # 获取最近活动
    recent_activities = list_data

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
@permission_required('accounts.manage_roles')
def manage_roles(request):
    if request.method == 'POST':
        form = RoleForm(request.POST)
        if form.is_valid():
            role = form.save()
            messages.success(request, f'角色 "{role.name}" 创建成功。')
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
# @permission_required('accounts.manage_permissions')
def manage_permissions(request):
    if request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            permission = form.save()
            messages.success(request, f'权限 "{permission.name}" 创建成功。')
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
            # 'home权限': permissions.filter(codename__startswith='home_'),
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


@login_required
def assign_permissions_to_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    if request.method == 'POST':
        selected_permissions = request.POST.getlist('permissions')
        role.permissions.set(selected_permissions)
        messages.success(request, f'已成功更新角色 "{role.name}" 的权限。')
        return redirect('manage_roles')

    all_permissions = Permission.objects.all()
    role_permissions = role.permissions.all()
    return render(request, 'accounts/assign_permissions_to_role.html', {
        'role': role,
        'all_permissions': all_permissions,
        'role_permissions': role_permissions
    })


@login_required
def assign_role_to_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    can_manage_roles = has_permission(request.user, 'manage_roles')
    if request.method == 'POST':
        form = UserRoleForm(request.POST, user=user)
        # 检查用户是否有角色
        if user.user_roles.exists():
            messages.info(request,
                          f'"{user.username}"已分配了"{UserRole.objects.get(user_id=user_id).role.name}"角色')
            return redirect('user_list')
        else:
            if form.is_valid():
                user_role = form.save()
                messages.success(request, f'已成功将角色 "{user_role.role.name}" 分配给用户 "{user.username}"。')
                return redirect('user_list')
    else:
        form = UserRoleForm(user=user)

    user_roles = user.user_roles.all()
    return render(request, 'accounts/assign_role_to_user.html', {
        'form': form,
        'user': user,
        'user_roles': user_roles,
        'can_manage_roles': can_manage_roles
    })


@login_required
def user_list(request):
    users = CustomUser.objects.all().order_by('username')
    page = request.GET.get('page', 1)
    per_page = request.GET.get('per_page', 10)

    paginator = Paginator(users, per_page)

    try:
        users = paginator.page(page)
    except PageNotAnInteger:
        users = paginator.page(1)
    except EmptyPage:
        users = paginator.page(paginator.num_pages)
        # 计算要显示的页码范围
    index = users.number - 1
    max_index = len(paginator.page_range)
    start_index = index - 2 if index >= 2 else 0
    end_index = index + 3 if index <= max_index - 3 else max_index
    page_range = list(paginator.page_range)[start_index:end_index]

    # 计算当前页的用户范围
    start_user = (users.number - 1) * paginator.per_page + 1
    end_user = start_user + len(users) - 1

    # 检查用户是否具有编辑和删除权限和分配权限
    can_detail = request.user.has_permission('view_user_detail')
    can_edit = request.user.has_permission('edit_user')
    can_delete = request.user.has_permission('delete_user')
    can_assign = request.user.has_permission('assign_role')

    context = {
        'users': users,
        'page_range': page_range,
        'total_users': paginator.count,
        'start_user': start_user,
        'end_user': end_user,
        'per_page': int(per_page),
        'can_edit': can_edit,
        'can_delete': can_delete,
        'can_assign': can_assign,
        'can_detail': can_detail,
    }

    logger.debug(
        f"User {request.user.username} accessing user list with "
        f"edit_permission: {can_edit}, delete_permission: {can_delete}"
    )

    return render(request, 'accounts/user_list.html', context)


@login_required
def user_detail(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user_roles = user.user_roles.all()
    user_permissions = user.get_all_permissions()
    return render(request, 'accounts/user_detail.html', {
        'user': user,
        'user_roles': user_roles,
        'user_permissions': user_permissions
    })


@login_required
def user_edit(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            user_edited.send(sender=UserActivity, user=request.user, instance=user)  # 发送信号,记录用户编辑操作
            messages.success(request, '用户信息已更新。')
            return redirect('user_list')
    else:
        form = UserEditForm(instance=user)
        return render(request, 'accounts/user_edit.html', {'form': form})
