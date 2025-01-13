import os
from django.conf import settings
from django.core.mail import send_mail
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import ProtectedError
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.utils.crypto import get_random_string
from .models import Role, Permission, UserRole, CustomUser, UserActivity, Document, DocumentImage
from .forms import RoleForm, PermissionForm, CustomUserCreationForm, CustomAuthenticationForm, UserEditForm, \
    CustomPasswordChangeForm, UserRoleForm, DocumentForm, DocumentEditForm
import logging
from .decorators import permission_required
from django.db.models import Q
from .forms import ForgotPasswordForm, ResetPasswordForm
from .signals import user_edited, user_deleted, user_assigned_role, add_role, user_details, add_permission, \
    del_permission, edit_role_signal, del_role_signal, assign_permission_signal
from docx import Document as DocxDocument
import pandas as pd
import io
from PIL import Image
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
            edit_role_signal.send(sender=UserActivity, user=request.user, instance=role)
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
    # available_actions = [
    #     action for action in quick_actions
    #     if request.user.has_perm(action['permission'])
    # ]
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
        'quick_actions': quick_actions,
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
            role = form.save()
            messages.success(request, f'角色 "{role.name}" 创建成功。')
            add_role.send(sender=UserActivity, user=request.user, instance=role)  # 发送信号,添加角色
            return redirect('manage_roles')
    else:
        form = RoleForm()

    roles = Role.objects.all()
    can_add_role = request.user.has_permission('add_role')
    can_edit_role = request.user.has_permission('edit_role')
    can_delete_role = request.user.has_permission('delete_role')
    can_assign_permission = request.user.has_permission('assign_permission')
    return render(request, 'accounts/manage_roles.html',
                  {'form': form,
                   'roles': roles,
                   'can_add_role': can_add_role,
                   'can_edit_role': can_edit_role,
                   'can_delete_role': can_delete_role,
                   'can_assign_permission': can_assign_permission
                   })


@login_required
def delete_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    try:
        role.delete()
        del_role_signal.send(sender=UserActivity, user=request.user, instance=role)
        messages.success(request, f'角色 {role.name} 已成功删除。')
    except ProtectedError:
        messages.error(request, f'无法删除角色 {role.name}，因为它仍在使用中。')
    return redirect('manage_roles')


@login_required
def manage_permissions(request):
    if request.method == 'POST':
        form = PermissionForm(request.POST)
        if form.is_valid():
            permission = form.save()
            messages.success(request, f'权限 "{permission.name}" 创建成功。')
            add_permission.send(sender=UserActivity, user=request.user, instance=permission)
            return redirect('manage_permissions')
    else:
        form = PermissionForm()

    permissions = Permission.objects.all()
    can_add_permission = request.user.has_permission('add_permission')
    can_delete_permission = request.user.has_permission('delete_permission')
    return render(request, 'accounts/manage_permissions.html', {'form': form,
                                                                'permissions': permissions,
                                                                'can_add_permission': can_add_permission,
                                                                'can_delete_permission': can_delete_permission})


@login_required
def delete_permission(request, permission_id):
    permission = get_object_or_404(Permission, id=permission_id)
    try:
        permission.delete()
        messages.success(request, f'权限 "{permission.name}" 已成功删除。')
        del_permission.send(sender=UserActivity, user=request.user, instance=permission)
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


@login_required
def profile(request, user_id):
    # 通过user_id获取用户的角色列表
    user = get_object_or_404(CustomUser, id=user_id)
    roles = UserRole.objects.filter(user_id=user_id).values_list('role__name', flat=True)
    print(roles)
    # 通过user_id获取用户的权限
    permissions = UserRole.objects.filter(user_id=user_id).values_list('role__permissions__name', flat=True)

    return render(request, 'accounts/profile.html', {'roles': roles, 'permissions': permissions, 'user': user})


def assign_permissions_to_role(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    if request.method == 'POST':
        selected_permissions = request.POST.getlist('permissions')
        role.permissions.set(selected_permissions)
        assign_permission_signal.send(sender=UserActivity, user=request.user, instance=role)
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
    user_ = get_object_or_404(CustomUser, id=user_id)
    role_list = set(UserRole.objects.all())  # 全部角色
    assign_role = set(UserRole.objects.filter(user_id=user_id))  # 用户已分配的角色
    is_subset = assign_role.issubset(role_list)
    can_manage_roles = has_permission(request.user, 'manage_roles')
    form = UserRoleForm(request.POST, user=user_)
    if request.method == 'POST':
        if form.is_valid():
            user_role = form.save()
            messages.success(request, f'已成功将角色 "{user_role.role.name}" 分配给用户 "{user_.username}"。')
            user_assigned_role.send(sender=UserActivity, user=request.user, instance=user_)  # 发送信号,记录用户授权
            return redirect('assign_role_to_user', user_id=user_.id)
        if is_subset:
            messages.info(request, f'用户 "{user_.username}" 已经拥有该角色。')
            return redirect('user_list')
    else:
        form = UserRoleForm(user=user_)
    user_roles = user_.user_roles.all()
    return render(request, 'accounts/assign_role_to_user.html', {
        'form': form,
        'user_': user_,
        'user_roles': user_roles,
        'can_manage_roles': can_manage_roles
    })


@login_required
def unassign_role_from_user(request, user_id, role_id):
    user = get_object_or_404(CustomUser, id=user_id)
    role = get_object_or_404(Role, id=role_id)
    user_role = get_object_or_404(UserRole, user=user, role=role)

    if request.method == 'POST':
        user_role.delete()
        messages.success(request, f'已成功取消用户 "{user.username}" 的角色 "{role.name}"。')
        return redirect('assign_role_to_user', user_id=user.id)

    return redirect('assign_role_to_user', user_id=user.id)


@login_required
def user_list(request):
    users = CustomUser.objects.all().order_by('username')
    page = request.GET.get('page', 1)
    per_page = request.GET.get('per_page', 5)

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
    user_sigle = get_object_or_404(CustomUser, id=user_id)
    user_roles = user_sigle.user_roles.all()
    user_permissions = user_sigle.get_all_permissions()
    user_details.send(sender=UserActivity, user=request.user, instance=user_sigle)
    return render(request, 'accounts/user_detail.html', {
        'user_sigle': user_sigle,
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


# @login_required
# def view_system_logs(request):
#     log_entries = []
#     path = os.path.join(settings.BASE_DIR, r'log/debug.log')
#     with open(path, 'r', encoding='utf-8') as log_file:
#         log_entries = log_file.readlines()
#     log_entries.reverse()  # 最新的日志在前面
#
#     # page = request.GET.get('page', 1)
#     # per_page = request.GET.get('per_page', 1)
#     #
#     # paginator = Paginator(logs, per_page)
#     #
#     # try:
#     #     logs = paginator.page(page)
#     # except PageNotAnInteger:
#     #     logs = paginator.page(1)
#     # except EmptyPage:
#     #     logs = paginator.page(paginator.num_pages)
#     #     # 计算要显示的页码范围
#     # index = logs.number - 1
#     # max_index = len(paginator.page_range)
#     # start_index = index - 2 if index >= 2 else 0
#     # end_index = index + 3 if index <= max_index - 3 else max_index
#     # page_range = list(paginator.page_range)[start_index:end_index]
#     #
#     # start_logs = (logs.number - 1) * paginator.per_page + 1
#     # end_logs = start_logs + len(logs) - 1
#
#     paginator = Paginator(log_entries, 5)  # 每页显示10条日志
#     page_number = request.GET.get('page')
#     page_obj = paginator.get_page(page_number)
#
#     context = {
#         "page_obj": page_obj
#
#     }
#     return render(request, 'accounts/system_logs.html', context)

@login_required
def view_system_logs(request):
    log_file_path = os.path.join(settings.BASE_DIR, r'log/debug.log')
    matching_entries = []
    try:
        with open(log_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        entry_buffer = []
        for line in lines:
            # 假设每个日志条目以某种方式开始，例如时间戳或特定的日志级别
            if line.startswith('ERROR') or line.startswith('INFO') or line.startswith('DEBUG'):
                # 如果缓冲区中有内容，检查它是否包含关键字
                if entry_buffer:
                    matching_entries.append(''.join(entry_buffer))
                # 开始新的日志条目
                entry_buffer = [line]
            else:
                # 否则，将行附加到当前日志条目
                entry_buffer.append(line)
        # 检查最后一个缓冲区是否包含关键字
        if entry_buffer:
            matching_entries.append(''.join(entry_buffer))

    except FileNotFoundError:
        return HttpResponse("Log file not found.", status=404)
    paginator = Paginator(matching_entries, 5)  # 每页显示10条日志
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        "page_obj": page_obj

    }
    return render(request, 'accounts/system_logs.html', context)


def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                # 生成重置令牌
                token = get_random_string(length=32)
                user.password_reset_token = token
                user.save()

                # 构建重置链接
                reset_url = request.build_absolute_uri(
                    reverse('reset_password', kwargs={'token': token})
                )

                # 发送重置邮件
                send_mail(
                    '重置您的密码',
                    f'请点击以下链接重置您的密码：\n\n{reset_url}\n\n如果您没有请求重置密码，请忽略此邮件。',
                    '1210777805@qq.com',
                    [email],
                    fail_silently=False,
                )

                messages.success(request, '重置链接已发送到您的邮箱，请查收。')
                logger.info(f"Password reset link sent to {email}")
                return redirect('login')
            except CustomUser.DoesNotExist:
                messages.error(request, '该邮箱未注册。')
                logger.warning(f"Password reset attempted for non-existent email: {email}")
    else:
        form = ForgotPasswordForm()

    return render(request, 'accounts/forgot_password.html', {'form': form})


def reset_password(request, token):
    try:
        user = CustomUser.objects.get(password_reset_token=token)
        if request.method == 'POST':
            form = ResetPasswordForm(request.POST)
            if form.is_valid():
                user.set_password(form.cleaned_data['password'])
                user.password_reset_token = None
                user.save()
                messages.success(request, '密码重置成功，请使用新密码登录。')
                logger.info(f"Password reset successful for user {user.username}")
                return redirect('login')
        else:
            form = ResetPasswordForm()
        return render(request, 'accounts/reset_password.html', {'form': form})
    except CustomUser.DoesNotExist:
        messages.error(request, '无效的重置链接。')
        logger.warning(f"Invalid password reset token used: {token}")
        return redirect('login')


@login_required
@permission_required('view_document')
def document_list(request):
    documents = Document.objects.all()
    return render(request, 'accounts/document_list.html', {'documents': documents})


@login_required
@permission_required('upload_document')
def upload_document(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.uploaded_by = request.user
            document.save()
            return redirect('document_list')
    else:
        form = DocumentForm()
    return render(request, 'accounts/upload_document.html', {'form': form})


@login_required
def document_list(request):
    documents = Document.objects.all()
    return render(request, 'accounts/document_list.html', {'documents': documents})


@login_required
@permission_required('view_document')
def document_list(request):
    documents = Document.objects.all()
    return render(request, 'accounts/document_list.html', {'documents': documents})


@login_required
@permission_required('upload_document')
def upload_document(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            document = form.save(commit=False)
            document.uploaded_by = request.user
            document.save()
            return redirect('document_list')
    else:
        form = DocumentForm()
    return render(request, 'accounts/upload_document.html', {'form': form})


@login_required
@permission_required('view_document')
def view_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    return render(request, 'accounts/view_document.html', {'document': document})


@login_required
@permission_required('edit_document')
def edit_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    if request.method == 'POST':
        form = DocumentEditForm(request.POST, instance=document)
        if form.is_valid():
            form.save()
            return redirect('document_list')
    else:
        form = DocumentEditForm(instance=document)
    return render(request, 'accounts/edit_document.html', {'form': form, 'document': document})


@login_required
@permission_required('download_document')
def download_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    file_path = os.path.join(settings.MEDIA_ROOT, str(document.file))
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/vnd.ms-excel")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response
    raise Http404


@login_required
@permission_required('view_document')
def view_document_content(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    file_path = os.path.join(settings.MEDIA_ROOT, str(document.file))

    if os.path.exists(file_path):
        file_type = document.get_file_type()

        if file_type == 'text':
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

            language = {
                '.py': 'python',
                '.js': 'javascript',
                '.html': 'html',
                '.css': 'css',
                '.json': 'json',
                '.xml': 'xml'
            }.get(document.file_extension().lower(), 'plaintext')

            context = {
                'document': document,
                'content': content,
                'language': language,
            }
            return render(request, 'accounts/view_document_content.html', context)

        elif file_type == 'word':
            doc = DocxDocument(file_path)
            content = []
            images = []
            for i, para in enumerate(doc.paragraphs):
                content.append(para.text)
                for run in para.runs:
                    if run._element.findall('.//w:drawing', namespaces={
                        'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}):
                        for inline in run._element.findall('.//wp:inline', namespaces={
                            'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'}):
                            blip = inline.find('.//a:blip', namespaces={
                                'a': 'http://schemas.openxmlformats.org/drawingml/2006/main'})
                            if blip is not None:
                                img_id = blip.get(
                                    '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed')
                                img_part = doc.part.related_parts[img_id]
                                image = Image.open(io.BytesIO(img_part.blob))
                                img_filename = f'document_{document.id}_image_{i}.png'
                                img_path = os.path.join(settings.MEDIA_ROOT, 'document_images', str(document.id),
                                                        img_filename)
                                os.makedirs(os.path.dirname(img_path), exist_ok=True)
                                image.save(img_path)
                                doc_image = DocumentImage.objects.create(document=document,
                                                                         image=f'document_images/{document.id}/{img_filename}')
                                images.append(doc_image)
                        content.append(f'[Image {len(images)}]')
            context = {
                'document': document,
                'content': '\n'.join(content),
                'images': images,
            }
            return render(request, 'accounts/view_word_content.html', context)

        elif file_type == 'excel':
            df = pd.read_excel(file_path)
            html_table = df.to_html(classes='table table-striped table-bordered', index=False)
            context = {
                'document': document,
                'html_table': html_table,
            }
            return render(request, 'accounts/view_excel_content.html', context)

        else:
            return redirect('view_document', document_id=document_id)
    else:
        return HttpResponse("文件不存在", status=404)


