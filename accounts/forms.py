from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from .models import CustomUser, Role, Permission, UserRole, Document
from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model, authenticate

User = get_user_model()


class UserEditForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'is_active']


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        label=_('电子邮箱'),
        max_length=254,
        widget=forms.EmailInput(attrs={'class': 'form-input', 'placeholder': '请输入电子邮箱'})
    )

    class Meta(UserCreationForm.Meta):
        model = CustomUser
        fields = ('username', 'email')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-input',
            'placeholder': '请输入用户名'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-input',
            'placeholder': '请输入密码'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-input',
            'placeholder': '请确认密码'
        })

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError(_('该邮箱已被注册。'))
        return email


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        label=_('用户名'),
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': '请输入用户名',
            'autocomplete': 'username'
        })
    )
    password = forms.CharField(
        label=_('密码'),
        widget=forms.PasswordInput(attrs={
            'class': 'form-input',
            'placeholder': '请输入密码',
            'autocomplete': 'current-password'
        })
    )

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


class CustomPasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label=_("当前密码"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'current-password',
            'class': 'form-input',
            'placeholder': '请输入当前密码'
        }),
    )
    new_password1 = forms.CharField(
        label=_("新密码"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'new-password',
            'class': 'form-input',
            'placeholder': '请输入新密码'
        }),
    )
    new_password2 = forms.CharField(
        label=_("确认新密码"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            'autocomplete': 'new-password',
            'class': 'form-input',
            'placeholder': '请再次输入新密码'
        }),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages['password_mismatch'] = _("两次输入的新密码不匹配。")
        self.error_messages['password_incorrect'] = _("您的旧密码输入不正确。请重新输入。")


class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = ['name', 'description']


class PermissionForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['name', 'codename', 'description']


class UserRoleForm(forms.ModelForm):
    class Meta:
        model = UserRole
        fields = ['role']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        if self.user and role:
            if UserRole.objects.filter(user=self.user, role=role).exists():
                raise forms.ValidationError('该用户已被分配此角色')
        return cleaned_data

    def save(self, commit=True):
        user_role = super().save(commit=False)
        user_role.user = self.user
        if commit:
            user_role.save()
        return user_role


from django import forms


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
                'placeholder': '请输入您的注册邮箱'
            }
        )
    )


class ResetPasswordForm(forms.Form):
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
                'placeholder': '请输入新密码'
            }
        )
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
                'placeholder': '请确认新密码'
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError('两次输入的密码不一致')
        return cleaned_data


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'file']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
                'placeholder': '请输入文档标题'
            }),
            'file': forms.FileInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
            }),
        }


class DocumentEditForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm',
                'placeholder': '请输入文档标题'
            }),
        }
