"""
CipherVault Forms
=================
Django forms for authentication, file upload, and key management.
"""

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm


class LoginForm(forms.Form):
    """User login form."""
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Username',
            'autocomplete': 'username',
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password',
            'autocomplete': 'current-password',
        })
    )


class RegisterForm(UserCreationForm):
    """User registration form."""
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email',
        })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in self.fields:
            self.fields[field_name].widget.attrs['class'] = 'form-control'
            if field_name == 'username':
                self.fields[field_name].widget.attrs['placeholder'] = 'Username'
            elif field_name == 'password1':
                self.fields[field_name].widget.attrs['placeholder'] = 'Password'
            elif field_name == 'password2':
                self.fields[field_name].widget.attrs['placeholder'] = 'Confirm Password'


class FileTransferForm(forms.Form):
    """Form for uploading and sending a file."""
    receiver = forms.ModelChoiceField(
        queryset=User.objects.none(),
        widget=forms.Select(attrs={
            'class': 'form-select',
        }),
        help_text="Select the recipient",
    )
    file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '*/*',
        }),
        help_text="Select the file to transfer securely",
    )

    def __init__(self, *args, current_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if current_user:
            self.fields['receiver'].queryset = User.objects.exclude(
                pk=current_user.pk
            ).filter(is_active=True)


class APIKeyForm(forms.Form):
    """Form for API key generation."""
    confirm = forms.BooleanField(
        required=True,
        label="I understand this will replace my existing API key",
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
        })
    )
