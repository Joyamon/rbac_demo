from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser, Role, Permission
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model, authenticate

User = get_user_model()


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = UserCreationForm.Meta.fields + ('email',)


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label=_("用户"), max_length=254)
    password = forms.CharField(label=_("密码"), widget=forms.PasswordInput)

    error_messages = {
        'invalid_login': _(
            "请输入正确的用户名和密码。注意两者都区分大小写。"
        ),
        'inactive': _("此账号已被禁用。"),
    }

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                try:
                    user = User.objects.get(username=username)
                    if not user.check_password(password):
                        raise forms.ValidationError(
                            self.error_messages['invalid_login'],
                            code='invalid_login',
                        )
                    if not user.is_active:
                        raise forms.ValidationError(
                            self.error_messages['inactive'],
                            code='inactive',
                        )
                except User.DoesNotExist:
                    raise forms.ValidationError(
                        self.error_messages['invalid_login'],
                        code='invalid_login',
                    )
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data


class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['name', 'description']


class PermissionForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['name', 'codename']


class UserEditForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'is_active']
