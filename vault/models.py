from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.utils import timezone


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
