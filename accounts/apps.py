from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"
    verbose_name = "用户管理"
    verbose_name_plural = verbose_name
    icon = '<i class="el-icon-user"></i>'
    order = 1

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verbose_name = self.verbose_name_plural

    def ready(self):
        import accounts.signals
