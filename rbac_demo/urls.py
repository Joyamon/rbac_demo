"""
URL configuration for rbac_demo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from accounts import views as account_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path('', account_views.home, name='home'),  # 新增的首页 URL
    path('accounts/login/', account_views.user_login, name='login'),
    path('accounts/logout/', account_views.user_logout, name='logout'),
    path('accounts/', include('django.contrib.auth.urls')),
    path('accounts/register/', account_views.register, name='register'),
    path('accounts/manage-roles/', account_views.manage_roles, name='manage_roles'),
    path('accounts/roles/<int:role_id>/delete/', account_views.delete_role, name='delete_role'),
    path('accounts/roles/<int:role_id>/edit/', account_views.edit_role, name='edit_role'),
    path('accounts/manage-permissions/', account_views.manage_permissions, name='manage_permissions'),
    path('accounts/roles/<int:role_id>/assign-permissions/', account_views.assign_permissions_to_role,
         name='assign_permissions_to_role'),
    path('accounts/users/<int:user_id>/assign-role/', account_views.assign_role_to_user, name='assign_role_to_user'),
    path('accounts/users/<int:user_id>/unassign-role/<int:role_id>/', account_views.unassign_role_from_user,
         name='unassign_role_from_user'),
    path('accounts/users/', account_views.user_list, name='user_list'),
    path('accounts/users/<int:user_id>/', account_views.user_detail, name='user_detail'),
    path('accounts/users/<int:user_id>/edit/', account_views.user_edit, name='user_edit'),
    path('accounts/permission/<int:permission_id>/delete/', account_views.delete_permission, name='delete_permission'),
    path('accounts/assign-permission/<int:role_id>/', account_views.assign_permission, name='assign_permission'),
    path('accounts/users/<int:user_id>/delete/', account_views.user_delete, name='user_delete'),
    path('accounts/users/change-password/', account_views.change_password, name='change_password'),
    path('accounts/users/profile/<int:user_id>', account_views.profile, name='profile'),
    path('accounts/users/system-logs/', account_views.view_system_logs, name='view_system_logs'),
    path('forgot-password/', account_views.forgot_password, name='forgot_password'),
    path('reset-password/<str:token>/', account_views.reset_password, name='reset_password'),
    # 文档相关
    path('documents/', account_views.document_list, name='document_list'),
    path('documents/upload/', account_views.upload_document, name='upload_document'),
    path('documents/<int:document_id>/', account_views.view_document, name='view_document'),
    path('documents/<int:document_id>/edit/', account_views.edit_document, name='edit_document'),
    path('documents/<int:document_id>/download/', account_views.download_document, name='download_document'),
    path('documents/<int:document_id>/content/', account_views.view_document_content, name='view_document_content'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
