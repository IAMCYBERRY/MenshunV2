from django import forms
from .models import VaultEntry, CredentialType


class VaultEntryForm(forms.ModelForm):
    """
    Form for creating and editing vault entries
    """
    
    class Meta:
        model = VaultEntry
        fields = ['name', 'username', 'password', 'credential_type', 'url', 'notes']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., Gmail Account, SSH Server',
                'required': True
            }),
            'username': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Username or email'
            }),
            'password': forms.PasswordInput(attrs={
                'class': 'form-input',
                'placeholder': 'Enter password',
                'required': True
            }),
            'credential_type': forms.Select(attrs={
                'class': 'form-input',
                'required': True
            }),
            'url': forms.URLInput(attrs={
                'class': 'form-input',
                'placeholder': 'https://example.com'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-input',
                'rows': 3,
                'placeholder': 'Additional notes or instructions...'
            })
        }
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show non-deleted credential types
        self.fields['credential_type'].queryset = CredentialType.objects.filter(is_deleted=False)
        
        # Make credential_type have an empty option
        self.fields['credential_type'].empty_label = "Select Type"
        
    def clean_name(self):
        """Validate entry name"""
        name = self.cleaned_data.get('name')
        if len(name.strip()) < 3:
            raise forms.ValidationError('Entry name must be at least 3 characters long.')
        return name.strip()
        
    def clean_password(self):
        """Validate password strength"""
        password = self.cleaned_data.get('password')
        if len(password) < 8:
            raise forms.ValidationError('Password must be at least 8 characters long.')
        return password


class CredentialTypeForm(forms.ModelForm):
    """
    Form for creating and editing credential types
    """
    
    class Meta:
        model = CredentialType
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'e.g., Database, SSH Key, API Token',
                'required': True
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-input',
                'rows': 3,
                'placeholder': 'Describe when to use this credential type...'
            })
        }
        
    def clean_name(self):
        """Validate credential type name"""
        name = self.cleaned_data.get('name')
        if len(name.strip()) < 2:
            raise forms.ValidationError('Credential type name must be at least 2 characters long.')
        return name.strip()