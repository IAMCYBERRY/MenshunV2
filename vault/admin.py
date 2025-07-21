from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import CustomUser, CredentialType, VaultEntry, VaultAccessLog


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """Admin interface for CustomUser"""
    list_display = ('username', 'email', 'first_name', 'last_name', 'source', 'is_staff', 'is_active', 'date_joined')
    list_filter = ('source', 'is_staff', 'is_active', 'is_superuser', 'groups')
    search_fields = ('username', 'first_name', 'last_name', 'email', 'aad_object_id')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions')
    
    fieldsets = UserAdmin.fieldsets + (
        ('Entra Integration', {
            'fields': ('source', 'aad_object_id'),
        }),
        ('Audit Info', {
            'fields': ('created_at', 'updated_at', 'is_deleted', 'deleted_at'),
            'classes': ('collapse',),
        }),
    )
    
    readonly_fields = ('created_at', 'updated_at', 'deleted_at', 'date_joined', 'last_login')
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            return qs.filter(is_deleted=False)
        return qs


@admin.register(CredentialType)
class CredentialTypeAdmin(admin.ModelAdmin):
    """Admin interface for CredentialType"""
    list_display = ('name', 'description', 'vault_entries_count', 'created_at', 'is_deleted')
    list_filter = ('is_deleted', 'created_at')
    search_fields = ('name', 'description')
    ordering = ('name',)
    readonly_fields = ('created_at', 'updated_at', 'deleted_at')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description'),
        }),
        ('Audit Info', {
            'fields': ('created_at', 'updated_at', 'is_deleted', 'deleted_at'),
            'classes': ('collapse',),
        }),
    )
    
    def vault_entries_count(self, obj):
        return obj.vault_entries.filter(is_deleted=False).count()
    vault_entries_count.short_description = 'Active Entries'
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            return qs.filter(is_deleted=False)
        return qs


@admin.register(VaultEntry)
class VaultEntryAdmin(admin.ModelAdmin):
    """Admin interface for VaultEntry"""
    list_display = ('name', 'username', 'credential_type', 'owner', 'last_accessed', 'access_count', 'is_deleted')
    list_filter = ('credential_type', 'is_deleted', 'created_at', 'last_accessed')
    search_fields = ('name', 'username', 'owner__username', 'owner__email')
    ordering = ('-updated_at',)
    readonly_fields = (
        'created_at', 'updated_at', 'deleted_at', 'created_by', 'updated_by', 
        'deleted_by', 'last_accessed', 'access_count', 'password_display'
    )
    raw_id_fields = ('owner', 'created_by', 'updated_by', 'deleted_by')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'username', 'password', 'password_display', 'credential_type', 'owner'),
        }),
        ('Additional Info', {
            'fields': ('url', 'notes'),
        }),
        ('Access Tracking', {
            'fields': ('last_accessed', 'access_count'),
            'classes': ('collapse',),
        }),
        ('Audit Info', {
            'fields': (
                'created_at', 'updated_at', 'created_by', 'updated_by',
                'is_deleted', 'deleted_at', 'deleted_by'
            ),
            'classes': ('collapse',),
        }),
    )
    
    def password_display(self, obj):
        """Display masked password"""
        if obj.password:
            return format_html('<span style="font-family: monospace;">{"*" * len(obj.password)}</span>')
        return '-'
    password_display.short_description = 'Password (masked)'
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if not request.user.is_superuser:
            # Non-superusers can only see non-deleted entries they own or have group access to
            user_groups = request.user.groups.all()
            vault_admin = user_groups.filter(name='Vault Admin').exists()
            vault_editor = user_groups.filter(name='Vault Editor').exists()
            
            if vault_admin or vault_editor:
                return qs.filter(is_deleted=False)
            else:
                return qs.filter(owner=request.user, is_deleted=False)
        return qs
    
    def has_change_permission(self, request, obj=None):
        """Check if user can change the vault entry"""
        if not obj:
            return True
            
        if request.user.is_superuser:
            return True
            
        user_groups = request.user.groups.all()
        vault_admin = user_groups.filter(name='Vault Admin').exists()
        vault_editor = user_groups.filter(name='Vault Editor').exists()
        
        if vault_admin or vault_editor:
            return True
            
        return obj.owner == request.user
    
    def has_delete_permission(self, request, obj=None):
        """Check if user can delete the vault entry"""
        if not obj:
            return True
            
        if request.user.is_superuser:
            return True
            
        user_groups = request.user.groups.all()
        vault_admin = user_groups.filter(name='Vault Admin').exists()
        
        if vault_admin:
            return True
            
        return obj.owner == request.user
    
    def save_model(self, request, obj, form, change):
        """Set audit fields on save"""
        if not change:  # Creating new object
            obj.created_by = request.user
            obj.owner = obj.owner or request.user
        else:  # Updating existing object
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(VaultAccessLog)
class VaultAccessLogAdmin(admin.ModelAdmin):
    """Admin interface for VaultAccessLog"""
    list_display = ('vault_entry', 'accessed_by', 'access_type', 'timestamp', 'ip_address')
    list_filter = ('access_type', 'timestamp')
    search_fields = ('vault_entry__name', 'accessed_by__username', 'ip_address')
    ordering = ('-timestamp',)
    readonly_fields = ('vault_entry', 'accessed_by', 'access_type', 'timestamp', 'ip_address', 'user_agent')
    
    def has_add_permission(self, request):
        """Disable manual addition of access logs"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Make access logs read-only"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete access logs"""
        return request.user.is_superuser
