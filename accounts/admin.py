from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import Group
from accounts.models import CustomUser, Permission, Role, UserRole, UserActivity


# Register your models here.

class AdminCustomUser(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_staff', 'is_active', 'is_superuser', 'date_joined')
    search_fields = ('username', 'email')
    list_filter = ('is_staff', 'is_active', 'is_superuser')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions')
    readonly_fields = ('password',)
    fieldsets = (
        (None, {'fields': ('username', 'password','email','is_active', 'is_superuser',)}),
    )
    list_per_page = 10


class AdminPermission(admin.ModelAdmin):
    list_display = ('codename', 'name', 'description')
    search_fields = ('codename', 'name')
    list_filter = ('description',)
    ordering = ('codename',)
    fieldsets = (
        (None, {'fields': ('codename', 'name', 'description')}),
    )
    list_per_page = 10


class AdminRole(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name', 'description')
    ordering = ('name',)
    fieldsets = (
        (None, {'fields': ('name', 'description')}),
    )
    list_per_page = 10


class AdminUserRole(admin.ModelAdmin):
    list_display = ('user', 'role')
    search_fields = ('user__username', 'role__name')
    ordering = ('user__username',)
    fieldsets = (
        (None, {'fields': ('user', 'role')}),
    )
    list_per_page = 10


class AdminUserActivity(admin.ModelAdmin):
    list_display = ('user', 'activity_type', 'timestamp')
    search_fields = ('user__username', 'activity_type')
    ordering = ('-timestamp',)
    fieldsets = (
        (None, {'fields': ('user', 'activity_type', 'timestamp')}),
    )
    readonly_fields = ('user', 'activity_type', 'timestamp')
    list_per_page = 10


admin.site.register(CustomUser, AdminCustomUser)
admin.site.register(Permission, AdminPermission)
admin.site.register(Role, AdminRole)
admin.site.register(UserRole, AdminUserRole)
admin.site.register(UserActivity, AdminUserActivity)
# 取消注册默认的Group模型
admin.site.unregister(Group)

admin.site.site_title = settings.SITE_TITLE
admin.site.site_header = settings.SITE_TITLE
admin.site.index_title = settings.SITE_TITLE