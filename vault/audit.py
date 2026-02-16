"""
Audit logging utilities for Menshun PAM system
"""
import logging
import asyncio
from typing import Optional, Dict, Any
from django.http import HttpRequest
from .models import SystemAuditLog
from .sentinel_integration import get_sentinel_service

logger = logging.getLogger(__name__)


def get_client_ip(request: HttpRequest) -> Optional[str]:
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def get_user_agent(request: HttpRequest) -> str:
    """Extract user agent from request"""
    return request.META.get('HTTP_USER_AGENT', '')[:1000]  # Limit length


def get_session_id(request: HttpRequest) -> Optional[str]:
    """Extract session ID from request"""
    return request.session.session_key if hasattr(request, 'session') else None


def run_sentinel_async(coro):
    """Helper to run async Sentinel logging in sync context"""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an event loop, create a task
            asyncio.create_task(coro)
        else:
            # If no event loop is running, run the coroutine
            loop.run_until_complete(coro)
    except Exception as e:
        logger.warning(f"Failed to send event to Sentinel: {e}")
        # Don't let Sentinel failures break the main audit logging


class AuditLogger:
    """
    Centralized audit logging utility
    """
    
    @staticmethod
    def log_auth_success(user, request: HttpRequest = None, details: Dict[str, Any] = None):
        """Log successful authentication"""
        audit_log = SystemAuditLog.log(
            category='AUTH',
            action='LOGIN_SUCCESS',
            user=user,
            description=f"User {user.username} logged in successfully",
            details=details or {},
            severity='LOW',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
        
        # Send to Sentinel
        sentinel_service = get_sentinel_service()
        if sentinel_service.is_enabled():
            run_sentinel_async(
                sentinel_service.send_authentication_event(
                    user=user,
                    request=request,
                    success=True,
                    details=details
                )
            )
        
        return audit_log
    
    @staticmethod
    def log_auth_failure(username: str, request: HttpRequest = None, reason: str = None, details: Dict[str, Any] = None):
        """Log failed authentication attempt"""
        risk_score = 30  # Failed login attempts have moderate risk
        log = SystemAuditLog.objects.create(
            category='AUTH',
            action='LOGIN_FAILED',
            user=None,  # No user object for failed login
            username=username,  # Store username directly
            description=f"Failed login attempt for user {username}" + (f": {reason}" if reason else ""),
            details=details or {},
            severity='MEDIUM',
            success=False,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
            risk_score=risk_score,
        )
        
        # Send to Sentinel
        sentinel_service = get_sentinel_service()
        if sentinel_service.is_enabled():
            # Create a temporary user object for Sentinel
            class TempUser:
                email = username
                username = username
            
            run_sentinel_async(
                sentinel_service.send_authentication_event(
                    user=TempUser(),
                    request=request,
                    success=False,
                    details={**(details or {}), 'reason': reason}
                )
            )
        
        return log
    
    @staticmethod
    def log_logout(user, request: HttpRequest = None):
        """Log user logout"""
        return SystemAuditLog.log(
            category='AUTH',
            action='LOGOUT',
            user=user,
            description=f"User {user.username} logged out",
            severity='LOW',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_user_create(admin_user, created_user, request: HttpRequest = None, details: Dict[str, Any] = None):
        """Log user creation"""
        return SystemAuditLog.log(
            category='USER',
            action='USER_CREATE',
            user=admin_user,
            description=f"User {created_user.username} created by {admin_user.username}",
            details=details or {},
            resource_type='User',
            resource_id=created_user.id,
            resource_name=created_user.username,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_user_update(admin_user, updated_user, request: HttpRequest = None, changes: Dict[str, Any] = None):
        """Log user updates"""
        return SystemAuditLog.log(
            category='USER',
            action='USER_UPDATE',
            user=admin_user,
            description=f"User {updated_user.username} updated by {admin_user.username}",
            details={'changes': changes} if changes else {},
            resource_type='User',
            resource_id=updated_user.id,
            resource_name=updated_user.username,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_user_delete(admin_user, deleted_user, request: HttpRequest = None):
        """Log user deletion"""
        return SystemAuditLog.log(
            category='USER',
            action='USER_DELETE',
            user=admin_user,
            description=f"User {deleted_user.username} deleted by {admin_user.username}",
            resource_type='User',
            resource_id=deleted_user.id,
            resource_name=deleted_user.username,
            severity='HIGH',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_group_change(admin_user, target_user, action: str, group_name: str, request: HttpRequest = None):
        """Log group membership changes"""
        action_type = 'USER_GROUP_ADD' if action == 'add' else 'USER_GROUP_REMOVE'
        description = f"User {target_user.username} {'added to' if action == 'add' else 'removed from'} group {group_name} by {admin_user.username}"
        
        return SystemAuditLog.log(
            category='USER',
            action=action_type,
            user=admin_user,
            description=description,
            details={'group': group_name, 'action': action},
            resource_type='User',
            resource_id=target_user.id,
            resource_name=target_user.username,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_vault_create(user, vault_entry, request: HttpRequest = None):
        """Log vault entry creation"""
        audit_log = SystemAuditLog.log(
            category='VAULT',
            action='VAULT_CREATE',
            user=user,
            description=f"Vault entry '{vault_entry.name}' created by {user.username}",
            details={'credential_type': vault_entry.credential_type.name},
            resource_type='VaultEntry',
            resource_id=vault_entry.id,
            resource_name=vault_entry.name,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
        
        # Send to Sentinel
        sentinel_service = get_sentinel_service()
        if sentinel_service.is_enabled():
            run_sentinel_async(
                sentinel_service.send_vault_access_event(
                    user=user,
                    action='CREATE',
                    vault_entry=vault_entry,
                    request=request,
                    details={'credential_type': vault_entry.credential_type.name}
                )
            )
        
        return audit_log
    
    @staticmethod
    def log_vault_view(user, vault_entry, request: HttpRequest = None):
        """Log vault entry view"""
        return SystemAuditLog.log(
            category='VAULT',
            action='VAULT_VIEW',
            user=user,
            description=f"Vault entry '{vault_entry.name}' viewed by {user.username}",
            resource_type='VaultEntry',
            resource_id=vault_entry.id,
            resource_name=vault_entry.name,
            severity='LOW',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_vault_password_view(user, vault_entry, request: HttpRequest = None):
        """Log vault entry password view (high security event)"""
        return SystemAuditLog.log(
            category='VAULT',
            action='VAULT_PASSWORD_VIEW',
            user=user,
            description=f"Password for vault entry '{vault_entry.name}' viewed by {user.username}",
            resource_type='VaultEntry',
            resource_id=vault_entry.id,
            resource_name=vault_entry.name,
            severity='HIGH',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
            risk_score=20,  # Password access has inherent risk
        )
    
    @staticmethod
    def log_vault_update(user, vault_entry, request: HttpRequest = None, changes: Dict[str, Any] = None):
        """Log vault entry update"""
        return SystemAuditLog.log(
            category='VAULT',
            action='VAULT_UPDATE',
            user=user,
            description=f"Vault entry '{vault_entry.name}' updated by {user.username}",
            details={'changes': changes} if changes else {},
            resource_type='VaultEntry',
            resource_id=vault_entry.id,
            resource_name=vault_entry.name,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_vault_delete(user, vault_entry, request: HttpRequest = None):
        """Log vault entry deletion"""
        return SystemAuditLog.log(
            category='VAULT',
            action='VAULT_DELETE',
            user=user,
            description=f"Vault entry '{vault_entry.name}' deleted by {user.username}",
            resource_type='VaultEntry',
            resource_id=vault_entry.id,
            resource_name=vault_entry.name,
            severity='HIGH',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_credential_type_create(user, cred_type, request: HttpRequest = None):
        """Log credential type creation"""
        return SystemAuditLog.log(
            category='CRED_TYPE',
            action='CRED_TYPE_CREATE',
            user=user,
            description=f"Credential type '{cred_type.name}' created by {user.username}",
            resource_type='CredentialType',
            resource_id=cred_type.id,
            resource_name=cred_type.name,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_credential_type_update(user, cred_type, request: HttpRequest = None, changes: Dict[str, Any] = None):
        """Log credential type update"""
        return SystemAuditLog.log(
            category='CRED_TYPE',
            action='CRED_TYPE_UPDATE',
            user=user,
            description=f"Credential type '{cred_type.name}' updated by {user.username}",
            details={'changes': changes} if changes else {},
            resource_type='CredentialType',
            resource_id=cred_type.id,
            resource_name=cred_type.name,
            severity='MEDIUM',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_credential_type_delete(user, cred_type, request: HttpRequest = None):
        """Log credential type deletion"""
        return SystemAuditLog.log(
            category='CRED_TYPE',
            action='CRED_TYPE_DELETE',
            user=user,
            description=f"Credential type '{cred_type.name}' deleted by {user.username}",
            resource_type='CredentialType',
            resource_id=cred_type.id,
            resource_name=cred_type.name,
            severity='HIGH',
            success=True,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
        )
    
    @staticmethod
    def log_security_event(category: str, action: str, user=None, description: str = None, 
                          request: HttpRequest = None, severity: str = 'HIGH', 
                          success: bool = False, risk_score: int = 50, details: Dict[str, Any] = None):
        """Log security-related events"""
        return SystemAuditLog.log(
            category='SECURITY',
            action=action,
            user=user,
            description=description,
            details=details or {},
            severity=severity,
            success=success,
            ip_address=get_client_ip(request) if request else None,
            user_agent=get_user_agent(request) if request else None,
            session_id=get_session_id(request) if request else None,
            risk_score=risk_score,
        )