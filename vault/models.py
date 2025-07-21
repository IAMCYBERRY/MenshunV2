from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.utils import timezone
import json


class CustomUser(AbstractUser):
    """
    Extended User model for Microsoft Entra integration
    """
    source = models.CharField(max_length=50, default='local')
    aad_object_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)

    def soft_delete(self):
        """Soft delete the user"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.is_active = False
        self.save()

    def restore(self):
        """Restore a soft deleted user"""
        self.is_deleted = False
        self.deleted_at = None
        self.is_active = True
        self.save()

    class Meta:
        db_table = 'vault_customuser'


class CredentialType(models.Model):
    """
    Different types of credentials (e.g., Database, Server, API Key, etc.)
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)

    def soft_delete(self):
        """Soft delete the credential type"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    def restore(self):
        """Restore a soft deleted credential type"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'vault_credentialtype'
        ordering = ['name']


class VaultEntry(models.Model):
    """
    Stored credentials with metadata
    """
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=512)  # Will be encrypted in production
    credential_type = models.ForeignKey(
        CredentialType, 
        on_delete=models.PROTECT,
        related_name='vault_entries'
    )
    owner = models.ForeignKey(
        'CustomUser', 
        on_delete=models.CASCADE, 
        related_name='vault_entries'
    )
    url = models.URLField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_vault_entries'
    )
    updated_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='updated_vault_entries'
    )
    
    # Soft delete fields
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)
    deleted_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='deleted_vault_entries'
    )

    # Access tracking
    last_accessed = models.DateTimeField(blank=True, null=True)
    access_count = models.PositiveIntegerField(default=0)
    
    # Admin account tagging
    is_admin_account = models.BooleanField(default=False)
    admin_account_type = models.CharField(max_length=50, blank=True, null=True)  # e.g., 'Entra_admin', 'Proxmox_admin'
    source_integration = models.CharField(max_length=50, blank=True, null=True)  # e.g., 'Entra', 'Proxmox'
    tags = models.JSONField(default=list, blank=True)  # Additional flexible tagging

    def soft_delete(self, user=None):
        """Soft delete the vault entry"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        if user:
            self.deleted_by = user
        self.save()

    def restore(self):
        """Restore a soft deleted vault entry"""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save()

    def record_access(self, user=None):
        """Record access to the vault entry"""
        self.last_accessed = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed', 'access_count'])
        
        # Create access log entry
        VaultAccessLog.objects.create(
            vault_entry=self,
            accessed_by=user,
            access_type='VIEW'
        )
    
    @classmethod
    def create_admin_account(cls, username, password, admin_type, integration_source, 
                           display_name=None, created_by=None, notes=None):
        """
        Create a vault entry for an admin account with proper tagging
        
        Args:
            username: The admin account username/email
            password: The admin account password
            admin_type: Type of admin account (e.g., 'Entra_admin', 'Proxmox_admin')
            integration_source: Source integration (e.g., 'Entra', 'Proxmox')
            display_name: Friendly name for the vault entry
            created_by: User who created this entry
            notes: Additional notes
        """
        from .models import CredentialType
        
        # Get or create the admin credential type
        admin_cred_type, created = CredentialType.objects.get_or_create(
            name='Admin Account',
            defaults={
                'description': 'Administrative user accounts for various systems'
            }
        )
        
        # Create the vault entry
        vault_entry = cls.objects.create(
            name=display_name or f"{admin_type}: {username}",
            username=username,
            password=password,
            credential_type=admin_cred_type,
            owner=created_by or cls._get_system_user(),
            created_by=created_by,
            notes=notes or f"Auto-generated {admin_type} account",
            is_admin_account=True,
            admin_account_type=admin_type,
            source_integration=integration_source,
            tags=[admin_type, integration_source, 'auto-generated']
        )
        
        return vault_entry
    
    @classmethod
    def _get_system_user(cls):
        """Get or create a system user for automated operations"""
        from .models import CustomUser
        system_user, created = CustomUser.objects.get_or_create(
            username='system',
            defaults={
                'first_name': 'System',
                'last_name': 'Account',
                'email': 'system@menshun.local',
                'is_active': False,
                'source': 'system'
            }
        )
        return system_user

    def __str__(self):
        return f"{self.name} ({self.credential_type.name})"

    class Meta:
        db_table = 'vault_vaultentry'
        ordering = ['-updated_at']
        verbose_name_plural = 'Vault entries'


class SystemAuditLog(models.Model):
    """
    Comprehensive audit log for all system events
    """
    # Categories of audit events
    CATEGORY_CHOICES = [
        ('AUTH', 'Authentication'),
        ('USER', 'User Management'),
        ('VAULT', 'Vault Entry'),
        ('CRED_TYPE', 'Credential Type'),
        ('PERMISSION', 'Permission'),
        ('SYSTEM', 'System'),
        ('SECURITY', 'Security'),
    ]
    
    # Action types
    ACTION_CHOICES = [
        # Authentication actions
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('TOKEN_REFRESH', 'Token Refresh'),
        ('SESSION_EXPIRED', 'Session Expired'),
        
        # User management actions
        ('USER_CREATE', 'User Created'),
        ('USER_UPDATE', 'User Updated'),
        ('USER_DELETE', 'User Deleted'),
        ('USER_ACTIVATE', 'User Activated'),
        ('USER_DEACTIVATE', 'User Deactivated'),
        ('USER_GROUP_ADD', 'User Added to Group'),
        ('USER_GROUP_REMOVE', 'User Removed from Group'),
        ('PASSWORD_CHANGE', 'Password Changed'),
        ('PASSWORD_RESET', 'Password Reset'),
        
        # Vault entry actions
        ('VAULT_CREATE', 'Vault Entry Created'),
        ('VAULT_VIEW', 'Vault Entry Viewed'),
        ('VAULT_UPDATE', 'Vault Entry Updated'),
        ('VAULT_DELETE', 'Vault Entry Deleted'),
        ('VAULT_RESTORE', 'Vault Entry Restored'),
        ('VAULT_PASSWORD_VIEW', 'Vault Entry Password Viewed'),
        ('VAULT_EXPORT', 'Vault Entry Exported'),
        
        # Credential type actions
        ('CRED_TYPE_CREATE', 'Credential Type Created'),
        ('CRED_TYPE_UPDATE', 'Credential Type Updated'),
        ('CRED_TYPE_DELETE', 'Credential Type Deleted'),
        
        # Permission actions
        ('PERMISSION_GRANT', 'Permission Granted'),
        ('PERMISSION_REVOKE', 'Permission Revoked'),
        ('GROUP_CREATE', 'Group Created'),
        ('GROUP_UPDATE', 'Group Updated'),
        ('GROUP_DELETE', 'Group Deleted'),
        
        # System actions
        ('SYSTEM_CONFIG', 'System Configuration Changed'),
        ('BACKUP_CREATE', 'Backup Created'),
        ('BACKUP_RESTORE', 'Backup Restored'),
        
        # Security actions
        ('FAILED_ACCESS', 'Failed Access Attempt'),
        ('SUSPICIOUS_ACTIVITY', 'Suspicious Activity Detected'),
        ('SECURITY_VIOLATION', 'Security Policy Violation'),
        ('API_KEY_CREATE', 'API Key Created'),
        ('API_KEY_REVOKE', 'API Key Revoked'),
    ]
    
    # Severity levels
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    # Core audit fields
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # User information
    user = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    username = models.CharField(max_length=255, blank=True, null=True)  # Store username even if user is deleted
    
    # Session and request information
    session_id = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    
    # Event details
    description = models.TextField()  # Human-readable description
    details = models.JSONField(blank=True, null=True)  # Structured event data
    
    # Resource information (what was affected)
    resource_type = models.CharField(max_length=50, blank=True, null=True)  # e.g., 'VaultEntry', 'User'
    resource_id = models.CharField(max_length=50, blank=True, null=True)   # ID of affected resource
    resource_name = models.CharField(max_length=255, blank=True, null=True) # Name of affected resource
    
    # Security context
    success = models.BooleanField(default=True)  # Whether the action succeeded
    risk_score = models.IntegerField(default=0)  # Risk assessment score (0-100)
    
    def __str__(self):
        user_info = self.username or 'Anonymous'
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {user_info}: {self.get_action_display()}"
    
    @classmethod
    def log(cls, category, action, user=None, description=None, details=None, 
            resource_type=None, resource_id=None, resource_name=None,
            severity='MEDIUM', success=True, ip_address=None, user_agent=None,
            session_id=None, risk_score=0):
        """
        Convenience method to create audit log entries
        """
        return cls.objects.create(
            category=category,
            action=action,
            user=user,
            username=user.username if user else None,
            description=description or f"{action.replace('_', ' ').title()}",
            details=details,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            resource_name=resource_name,
            severity=severity,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            risk_score=risk_score,
        )
    
    class Meta:
        db_table = 'vault_systemauditlog'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['category', 'action']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['success']),
            models.Index(fields=['severity']),
        ]


class VaultAccessLog(models.Model):
    """
    Audit log for vault entry access (kept for backward compatibility)
    """
    ACCESS_TYPES = [
        ('VIEW', 'View'),
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
    ]

    vault_entry = models.ForeignKey(
        VaultEntry,
        on_delete=models.CASCADE,
        related_name='access_logs'
    )
    accessed_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='vault_access_logs'
    )
    access_type = models.CharField(max_length=10, choices=ACCESS_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.accessed_by} {self.access_type} {self.vault_entry.name} at {self.timestamp}"

    class Meta:
        db_table = 'vault_vaultaccesslog'
        ordering = ['-timestamp']


# ===============================
# Integration Models
# ===============================

class IntegrationConfig(models.Model):
    """
    Configuration settings for external integrations
    """
    INTEGRATION_TYPES = [
        ('ENTRA', 'Microsoft Entra ID'),
        ('PROXMOX', 'Proxmox VE'),
        ('AWS', 'Amazon Web Services'),
        ('AZURE', 'Microsoft Azure'),
        ('GOOGLE', 'Google Cloud Platform'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    integration_type = models.CharField(max_length=20, choices=INTEGRATION_TYPES)
    is_enabled = models.BooleanField(default=False)
    configuration = models.JSONField(default=dict)  # Encrypted configuration data
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_integration_type_display()})"
    
    def get_config_value(self, key: str, default=None):
        """Get a configuration value safely"""
        return self.configuration.get(key, default)
    
    def set_config_value(self, key: str, value):
        """Set a configuration value"""
        self.configuration[key] = value
        self.save()
    
    class Meta:
        db_table = 'vault_integrationconfig'
        ordering = ['name']


class EntraUser(models.Model):
    """
    Cached information about Entra ID users
    """
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('DISABLED', 'Disabled'),
        ('DELETED', 'Deleted'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    entra_user_id = models.CharField(max_length=255, unique=True)  # Object ID from Entra
    user_principal_name = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    email = models.EmailField(blank=True, null=True)
    job_title = models.CharField(max_length=255, blank=True, null=True)
    department = models.CharField(max_length=255, blank=True, null=True)
    account_enabled = models.BooleanField(default=True)
    created_datetime = models.DateTimeField(blank=True, null=True)
    last_sign_in = models.DateTimeField(blank=True, null=True)
    
    # Internal tracking
    local_user = models.OneToOneField('CustomUser', on_delete=models.SET_NULL, null=True, blank=True, related_name='entra_profile')
    sync_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    last_sync = models.DateTimeField(auto_now=True)
    sync_metadata = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.display_name} ({self.user_principal_name})"
    
    def sync_with_local_user(self):
        """Create or update corresponding local user"""
        if not self.local_user:
            # Create new local user
            self.local_user = CustomUser.objects.create(
                username=self.user_principal_name,
                email=self.email or '',
                first_name=self.display_name.split(' ')[0] if ' ' in self.display_name else self.display_name,
                last_name=' '.join(self.display_name.split(' ')[1:]) if ' ' in self.display_name else '',
                source='entra',
                aad_object_id=self.entra_user_id,
                is_active=self.account_enabled
            )
            self.save()
        else:
            # Update existing user
            self.local_user.email = self.email or ''
            self.local_user.is_active = self.account_enabled
            self.local_user.save()
    
    class Meta:
        db_table = 'vault_entrauser'
        ordering = ['display_name']


class EntraRole(models.Model):
    """
    Cached information about Entra ID directory roles
    """
    entra_role_id = models.CharField(max_length=255, unique=True)
    role_template_id = models.CharField(max_length=255, blank=True, null=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    is_built_in = models.BooleanField(default=True)
    is_enabled = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_sync = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.display_name
    
    class Meta:
        db_table = 'vault_entrarole'
        ordering = ['display_name']


class EntraRoleAssignment(models.Model):
    """
    Track role assignments in Entra ID
    """
    ASSIGNMENT_TYPES = [
        ('PERMANENT', 'Permanent'),
        ('ELIGIBLE', 'Eligible (PIM)'),
        ('ACTIVE', 'Active (PIM)'),
    ]
    
    user = models.ForeignKey(EntraUser, on_delete=models.CASCADE, related_name='role_assignments')
    role = models.ForeignKey(EntraRole, on_delete=models.CASCADE, related_name='user_assignments')
    assignment_type = models.CharField(max_length=20, choices=ASSIGNMENT_TYPES)
    
    # Assignment details
    assigned_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, related_name='entra_assignments_made')
    assignment_reason = models.TextField(blank=True, null=True)
    start_datetime = models.DateTimeField(blank=True, null=True)
    end_datetime = models.DateTimeField(blank=True, null=True)
    
    # PIM specific fields
    pim_request_id = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.display_name} -> {self.role.display_name} ({self.assignment_type})"
    
    def is_expired(self):
        """Check if assignment is expired"""
        if self.end_datetime:
            return timezone.now() > self.end_datetime
        return False
    
    class Meta:
        db_table = 'vault_entraroleassignment'
        unique_together = ['user', 'role', 'assignment_type']
        ordering = ['-created_at']


class EntraServicePrincipal(models.Model):
    """
    Track service principals and applications in Entra ID
    """
    APPLICATION_TYPES = [
        ('WEB', 'Web Application'),
        ('SPA', 'Single Page Application'),
        ('NATIVE', 'Native Application'),
        ('API', 'API Application'),
    ]
    
    entra_app_id = models.CharField(max_length=255, unique=True)  # Application ID
    entra_object_id = models.CharField(max_length=255, unique=True)  # Service Principal Object ID
    display_name = models.CharField(max_length=255)
    app_display_name = models.CharField(max_length=255)
    application_type = models.CharField(max_length=20, choices=APPLICATION_TYPES)
    
    # Application details
    home_page_url = models.URLField(blank=True, null=True)
    sign_in_audience = models.CharField(max_length=100, blank=True, null=True)
    service_principal_type = models.CharField(max_length=50, blank=True, null=True)
    
    # Permissions
    app_roles = models.JSONField(default=list)
    api_permissions = models.JSONField(default=list)
    delegated_permissions = models.JSONField(default=list)
    
    # Internal tracking
    created_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True, related_name='created_service_principals')
    is_managed = models.BooleanField(default=True)  # Whether this was created through Menshun
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_sync = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.display_name} ({self.entra_app_id})"
    
    class Meta:
        db_table = 'vault_entraserviceprincipal'
        ordering = ['display_name']


class IntegrationTask(models.Model):
    """
    Track long-running integration tasks
    """
    TASK_TYPES = [
        ('USER_SYNC', 'User Synchronization'),
        ('ROLE_SYNC', 'Role Synchronization'),
        ('USER_CREATE', 'User Creation'),
        ('ROLE_ASSIGN', 'Role Assignment'),
        ('ROLE_REMOVE', 'Role Removal'),
        ('ACCOUNT_DISABLE', 'Account Disable'),
        ('ACCOUNT_ENABLE', 'Account Enable'),
        ('SP_CREATE', 'Service Principal Creation'),
        ('API_PERMISSION', 'API Permission Assignment'),
    ]
    
    STATUSES = [
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    task_id = models.CharField(max_length=100, unique=True)
    task_type = models.CharField(max_length=20, choices=TASK_TYPES)
    integration_type = models.CharField(max_length=20, choices=IntegrationConfig.INTEGRATION_TYPES)
    status = models.CharField(max_length=20, choices=STATUSES, default='PENDING')
    
    # Task details
    initiated_by = models.ForeignKey('CustomUser', on_delete=models.SET_NULL, null=True)
    target_resource = models.CharField(max_length=255, blank=True, null=True)  # User ID, Role ID, etc.
    task_parameters = models.JSONField(default=dict)
    
    # Results
    result_data = models.JSONField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    
    # Timing
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.task_type} - {self.status} ({self.task_id})"
    
    def mark_started(self):
        """Mark task as started"""
        self.status = 'IN_PROGRESS'
        self.started_at = timezone.now()
        self.save()
    
    def mark_completed(self, result_data=None):
        """Mark task as completed"""
        self.status = 'COMPLETED'
        self.completed_at = timezone.now()
        if result_data:
            self.result_data = result_data
        self.save()
    
    def mark_failed(self, error_message):
        """Mark task as failed"""
        self.status = 'FAILED'
        self.completed_at = timezone.now()
        self.error_message = error_message
        self.save()
    
    class Meta:
        db_table = 'vault_integrationtask'
        ordering = ['-created_at']
