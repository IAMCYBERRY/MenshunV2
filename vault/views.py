from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_http_methods
from django.db import models, transaction
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
import json
import logging

from .models import VaultEntry, CredentialType, VaultAccessLog, SystemAuditLog, EntraUser, EntraRole, EntraRoleAssignment, ServiceAccount, ServicePrincipal, ServicePrincipalSecret
from .audit import AuditLogger, run_sentinel_async
from .sentinel_integration import get_sentinel_service
from .forms import VaultEntryForm, CredentialTypeForm
from .serializers import (
    VaultEntryListSerializer, VaultEntryDetailSerializer,
    CredentialTypeSerializer, VaultAccessLogSerializer
)
from .permissions import VaultPermission, CredentialTypePermission

logger = logging.getLogger(__name__)


class VaultEntryViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing vault entries with role-based access control
    """
    permission_classes = [IsAuthenticated, VaultPermission]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['credential_type', 'owner']
    search_fields = ['name', 'username', 'notes']
    ordering_fields = ['name', 'created_at', 'updated_at', 'last_accessed']
    ordering = ['-updated_at']
    
    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = VaultEntry.objects.filter(is_deleted=False).select_related(
            'credential_type', 'owner', 'created_by', 'updated_by'
        )
        
        if self.request.user.is_superuser:
            return queryset
        
        user_groups = self.request.user.groups.values_list('name', flat=True)
        
        if 'Vault Admin' in user_groups or 'Vault Editor' in user_groups:
            # Admin and Editor can see all entries
            return queryset
        elif 'Vault Viewer' in user_groups:
            # Viewer can only see their own entries
            return queryset.filter(owner=self.request.user)
        else:
            # No access
            return queryset.none()
    
    def get_serializer_class(self):
        """Use different serializers for list and detail views"""
        if self.action == 'list':
            return VaultEntryListSerializer
        return VaultEntryDetailSerializer
    
    def perform_create(self, serializer):
        """Set the owner and created_by when creating a vault entry"""
        serializer.save(
            owner=self.request.user,
            created_by=self.request.user
        )
    
    def perform_update(self, serializer):
        """Set the updated_by when updating a vault entry"""
        serializer.save(updated_by=self.request.user)
    
    def retrieve(self, request, *args, **kwargs):
        """Override retrieve to log access"""
        instance = self.get_object()
        
        # Record access
        instance.record_access(request.user)
        
        # Log the access with IP and user agent (legacy format)
        VaultAccessLog.objects.create(
            vault_entry=instance,
            accessed_by=request.user,
            access_type='VIEW',
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log with new comprehensive audit system
        AuditLogger.log_vault_view(
            user=request.user,
            vault_entry=instance,
            request=request
        )
        
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def password(self, request, pk=None):
        """Endpoint to get just the password (with additional logging)"""
        vault_entry = self.get_object()
        
        # Record access specifically for password retrieval (legacy format)
        VaultAccessLog.objects.create(
            vault_entry=vault_entry,
            accessed_by=request.user,
            access_type='VIEW',
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log password access with high security attention
        AuditLogger.log_vault_password_view(
            user=request.user,
            vault_entry=vault_entry,
            request=request
        )
        
        return Response({'password': vault_entry.password})
    
    @action(detail=True, methods=['get'])
    def access_logs(self, request, pk=None):
        """Get access logs for a specific vault entry"""
        vault_entry = self.get_object()
        logs = vault_entry.access_logs.all()[:50]  # Last 50 access logs
        serializer = VaultAccessLogSerializer(logs, many=True)
        return Response(serializer.data)
    
    def get_client_ip(self, request):
        """Get the client IP address from the request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class CredentialTypeViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing credential types
    """
    serializer_class = CredentialTypeSerializer
    permission_classes = [IsAuthenticated, CredentialTypePermission]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    
    def get_queryset(self):
        """Filter out deleted credential types"""
        return CredentialType.objects.filter(is_deleted=False)


@login_required
@ensure_csrf_cookie
def dashboard_view(request):
    """
    Unified dashboard view with both user dashboard and admin console access
    """
    user = request.user
    user_groups = user.groups.values_list('name', flat=True)
    
    # Determine what vault entries the user can see
    if user.is_superuser or 'Vault Admin' in user_groups or 'Vault Editor' in user_groups:
        vault_entries = VaultEntry.objects.filter(is_deleted=False).select_related(
            'credential_type', 'owner'
        )
        can_edit = True
    elif 'Vault Viewer' in user_groups:
        vault_entries = VaultEntry.objects.filter(
            owner=user, is_deleted=False
        ).select_related('credential_type', 'owner')
        can_edit = False
    else:
        vault_entries = VaultEntry.objects.none()
        can_edit = False
    
    # Pagination
    paginator = Paginator(vault_entries, 12)  # Show more items per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get credential types for the form
    credential_types = CredentialType.objects.filter(is_deleted=False)
    
    # Recent activity (last 15 access logs for the user)
    recent_activity = VaultAccessLog.objects.filter(
        accessed_by=user
    ).select_related('vault_entry')[:15]
    
    context = {
        'user': user,
        'user_groups': user_groups,
        'page_obj': page_obj,
        'credential_types': credential_types,
        'recent_activity': recent_activity,
        'can_edit': can_edit,
        'total_entries': vault_entries.count() if vault_entries else 0,
    }
    
    return render(request, 'vault/menshun_dashboard.html', context)


@login_required
def vault_entries_view(request):
    """
    Dedicated vault entries management view
    """
    user = request.user
    user_groups = user.groups.values_list('name', flat=True)
    
    # Same permission logic as dashboard
    if user.is_superuser or 'Vault Admin' in user_groups or 'Vault Editor' in user_groups:
        vault_entries = VaultEntry.objects.filter(is_deleted=False).select_related(
            'credential_type', 'owner'
        )
        can_edit = True
    elif 'Vault Viewer' in user_groups:
        vault_entries = VaultEntry.objects.filter(
            owner=user, is_deleted=False
        ).select_related('credential_type', 'owner')
        can_edit = False
    else:
        vault_entries = VaultEntry.objects.none()
        can_edit = False
    
    # Apply filters
    search = request.GET.get('search', '')
    credential_type = request.GET.get('credential_type', '')
    
    if search:
        vault_entries = vault_entries.filter(
            name__icontains=search
        )
    
    if credential_type:
        vault_entries = vault_entries.filter(
            credential_type__name=credential_type
        )
    
    # Pagination
    paginator = Paginator(vault_entries, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get credential types for filters
    credential_types = CredentialType.objects.filter(is_deleted=False)
    
    context = {
        'user': user,
        'user_groups': user_groups,
        'page_obj': page_obj,
        'credential_types': credential_types,
        'can_edit': can_edit,
        'total_entries': vault_entries.count() if vault_entries else 0,
        'search': search,
        'selected_credential_type': credential_type,
    }
    
    return render(request, 'vault/vault_entries.html', context)


@login_required
def credential_types_view(request):
    """
    Credential types management view
    """
    user = request.user
    user_groups = user.groups.values_list('name', flat=True)
    
    # Only admins can manage credential types
    can_manage = user.is_superuser or 'Vault Admin' in user_groups
    
    credential_types = CredentialType.objects.filter(is_deleted=False)
    
    context = {
        'user': user,
        'user_groups': user_groups,
        'credential_types': credential_types,
        'can_manage': can_manage,
    }
    
    return render(request, 'vault/credential_types.html', context)


@login_required
def user_management_view(request):
    """
    User management view for admins
    """
    user = request.user
    
    # Only staff and superusers can access
    if not (user.is_staff or user.is_superuser):
        return render(request, '403.html', status=403)
    
    from .models import CustomUser
    users = CustomUser.objects.filter(is_deleted=False).select_related().prefetch_related('groups')
    
    context = {
        'user': user,
        'users': users,
    }
    
    return render(request, 'vault/user_management.html', context)


@login_required
def audit_logs_view(request):
    """
    Audit logs view for admins
    """
    user = request.user
    
    # Only staff and superusers can access
    if not (user.is_staff or user.is_superuser):
        return render(request, '403.html', status=403)
    
    logs = VaultAccessLog.objects.all().select_related(
        'vault_entry', 'accessed_by'
    )[:100]  # Last 100 logs
    
    context = {
        'user': user,
        'logs': logs,
    }
    
    return render(request, 'vault/audit_logs.html', context)


@login_required
def api_docs_view(request):
    """
    API documentation view
    """
    context = {
        'user': request.user,
    }
    
    return render(request, 'vault/api_docs.html', context)


@login_required
@require_http_methods(["POST"])
def create_vault_entry(request):
    """
    AJAX endpoint for creating new vault entries
    """
    try:
        # Check permissions
        user_groups = request.user.groups.values_list('name', flat=True)
        if not (request.user.is_superuser or 'Vault Admin' in user_groups or 'Vault Editor' in user_groups):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to create vault entries.'
            }, status=403)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        # Create form with the data
        form = VaultEntryForm(data)
        
        if form.is_valid():
            # Create the vault entry
            vault_entry = form.save(commit=False)
            vault_entry.owner = request.user
            vault_entry.created_by = request.user
            vault_entry.save()
            
            # Log the creation (legacy format)
            VaultAccessLog.objects.create(
                vault_entry=vault_entry,
                accessed_by=request.user,
                access_type='CREATE',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log with comprehensive audit system
            AuditLogger.log_vault_create(
                user=request.user,
                vault_entry=vault_entry,
                request=request
            )
            
            # Return success response
            return JsonResponse({
                'success': True,
                'message': f'Vault entry "{vault_entry.name}" created successfully!',
                'entry_id': vault_entry.id
            })
        else:
            # Return form errors
            return JsonResponse({
                'success': False,
                'errors': form.errors
            }, status=400)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error creating vault entry: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def update_vault_entry(request, entry_id):
    """
    AJAX endpoint for updating vault entries
    """
    try:
        # Get the vault entry
        vault_entry = get_object_or_404(VaultEntry, id=entry_id, is_deleted=False)
        
        # Check permissions
        user_groups = request.user.groups.values_list('name', flat=True)
        if not (request.user.is_superuser or 'Vault Admin' in user_groups or 'Vault Editor' in user_groups):
            # Viewers can only edit their own entries (if allowed)
            if vault_entry.owner != request.user:
                return JsonResponse({
                    'success': False,
                    'error': 'You do not have permission to edit this vault entry.'
                }, status=403)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        # Create form with the data and existing instance
        form = VaultEntryForm(data, instance=vault_entry)
        
        if form.is_valid():
            # Capture changes for audit
            original_name = vault_entry.name
            changes = {}
            for field, value in data.items():
                if hasattr(vault_entry, field) and getattr(vault_entry, field) != value:
                    changes[field] = {'old': getattr(vault_entry, field), 'new': value}
            
            # Update the vault entry
            vault_entry = form.save(commit=False)
            vault_entry.updated_by = request.user
            vault_entry.save()
            
            # Log the update (legacy format)
            VaultAccessLog.objects.create(
                vault_entry=vault_entry,
                accessed_by=request.user,
                access_type='UPDATE',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Log with comprehensive audit system
            AuditLogger.log_vault_update(
                user=request.user,
                vault_entry=vault_entry,
                request=request,
                changes=changes
            )
            
            # Return success response
            return JsonResponse({
                'success': True,
                'message': f'Vault entry "{vault_entry.name}" updated successfully!'
            })
        else:
            # Return form errors
            return JsonResponse({
                'success': False,
                'errors': form.errors
            }, status=400)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error updating vault entry: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def get_vault_entry(request, entry_id):
    """
    AJAX endpoint for getting vault entry data for editing
    """
    logger.info(f"get_vault_entry called for entry_id: {entry_id} by user: {request.user.username}")
    try:
        # Get the vault entry
        vault_entry = get_object_or_404(VaultEntry, id=entry_id, is_deleted=False)
        
        # Check permissions
        user_groups = request.user.groups.values_list('name', flat=True)
        if not (request.user.is_superuser or 'Vault Admin' in user_groups or 'Vault Editor' in user_groups):
            # Viewers can only see their own entries
            if vault_entry.owner != request.user and 'Vault Viewer' not in user_groups:
                return JsonResponse({
                    'success': False,
                    'error': 'You do not have permission to view this vault entry.'
                }, status=403)
        
        # Log vault entry view (for audit)
        vault_entry.record_access(request.user)
        
        # Log with both legacy and new audit systems
        VaultAccessLog.objects.create(
            vault_entry=vault_entry,
            accessed_by=request.user,
            access_type='VIEW',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log with comprehensive audit system
        AuditLogger.log_vault_view(
            user=request.user,
            vault_entry=vault_entry,
            request=request
        )
        
        # Since password is included, also log password view
        AuditLogger.log_vault_password_view(
            user=request.user,
            vault_entry=vault_entry,
            request=request
        )
        
        # Return entry data
        return JsonResponse({
            'success': True,
            'data': {
                'id': vault_entry.id,
                'name': vault_entry.name,
                'username': vault_entry.username,
                'password': vault_entry.password,
                'credential_type': vault_entry.credential_type.id,
                'url': vault_entry.url or '',
                'notes': vault_entry.notes or ''
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting vault entry: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def delete_vault_entry(request, entry_id):
    """
    AJAX endpoint for soft deleting vault entries
    """
    try:
        # Get the vault entry
        vault_entry = get_object_or_404(VaultEntry, id=entry_id, is_deleted=False)
        
        # Check permissions - only admins can delete
        user_groups = request.user.groups.values_list('name', flat=True)
        if not (request.user.is_superuser or 'Vault Admin' in user_groups):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to delete vault entries.'
            }, status=403)
        
        # Capture entry name before deletion
        entry_name = vault_entry.name
        
        # Soft delete the entry
        vault_entry.soft_delete(user=request.user)
        
        # Log the deletion (legacy format)
        VaultAccessLog.objects.create(
            vault_entry=vault_entry,
            accessed_by=request.user,
            access_type='DELETE',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Log with comprehensive audit system
        AuditLogger.log_vault_delete(
            user=request.user,
            vault_entry=vault_entry,
            request=request
        )
        
        # Return success response
        return JsonResponse({
            'success': True,
            'message': f'Vault entry "{entry_name}" deleted successfully!'
        })
        
    except Exception as e:
        logger.error(f"Error deleting vault entry: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


def get_client_ip(request):
    """Get the client IP address from the request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required
@require_http_methods(["GET"])
def get_users(request):
    """
    AJAX endpoint for getting all users for management
    """
    try:
        # Check permissions - only staff and superusers can access
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to view users.'
            }, status=403)
        
        from .models import CustomUser
        from django.contrib.auth.models import Group
        
        users = CustomUser.objects.filter(is_deleted=False).prefetch_related('groups')
        
        users_data = []
        for user in users:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_active': user.is_active,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'source': user.source,
                'groups': [group.name for group in user.groups.all()],
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
            })
        
        # Get all available groups
        groups = Group.objects.all()
        groups_data = [{'id': group.id, 'name': group.name} for group in groups]
        
        return JsonResponse({
            'success': True,
            'users': users_data,
            'groups': groups_data
        })
        
    except Exception as e:
        logger.error(f"Error getting users: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def create_user(request):
    """
    AJAX endpoint for creating new users
    """
    try:
        # Check permissions - only staff and superusers can create users
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to create users.'
            }, status=403)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        from .models import CustomUser
        from django.contrib.auth.models import Group
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'error': f'{field.title()} is required.'
                }, status=400)
        
        # Check if username already exists
        if CustomUser.objects.filter(username=data['username']).exists():
            return JsonResponse({
                'success': False,
                'error': 'Username already exists.'
            }, status=400)
        
        # Check if email already exists
        if CustomUser.objects.filter(email=data['email']).exists():
            return JsonResponse({
                'success': False,
                'error': 'Email already exists.'
            }, status=400)
        
        # Create the user
        user = CustomUser.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
            is_active=data.get('is_active', True),
            is_staff=data.get('is_staff', False),
            is_superuser=data.get('is_superuser', False),
            source='local'
        )
        
        # Add user to groups
        assigned_groups = []
        if data.get('groups'):
            groups = Group.objects.filter(id__in=data['groups'])
            user.groups.set(groups)
            assigned_groups = [group.name for group in groups]
        
        # Log user creation
        AuditLogger.log_user_create(
            admin_user=request.user,
            created_user=user,
            request=request,
            details={
                'assigned_groups': assigned_groups,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'is_active': user.is_active
            }
        )
        
        return JsonResponse({
            'success': True,
            'message': f'User "{user.username}" created successfully!',
            'user_id': user.id
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def update_user(request, user_id):
    """
    AJAX endpoint for updating users
    """
    try:
        # Check permissions - only staff and superusers can update users
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to update users.'
            }, status=403)
        
        from .models import CustomUser
        from django.contrib.auth.models import Group
        
        # Get the user
        user = get_object_or_404(CustomUser, id=user_id, is_deleted=False)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        # Track changes for audit
        changes = {}
        if user.first_name != data.get('first_name', user.first_name):
            changes['first_name'] = {'old': user.first_name, 'new': data.get('first_name', user.first_name)}
        if user.last_name != data.get('last_name', user.last_name):
            changes['last_name'] = {'old': user.last_name, 'new': data.get('last_name', user.last_name)}
        if user.email != data.get('email', user.email):
            changes['email'] = {'old': user.email, 'new': data.get('email', user.email)}
        if user.is_active != data.get('is_active', user.is_active):
            changes['is_active'] = {'old': user.is_active, 'new': data.get('is_active', user.is_active)}
        if user.is_staff != data.get('is_staff', user.is_staff):
            changes['is_staff'] = {'old': user.is_staff, 'new': data.get('is_staff', user.is_staff)}
        if user.is_superuser != data.get('is_superuser', user.is_superuser):
            changes['is_superuser'] = {'old': user.is_superuser, 'new': data.get('is_superuser', user.is_superuser)}
        
        # Update user fields
        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.email = data.get('email', user.email)
        user.is_active = data.get('is_active', user.is_active)
        user.is_staff = data.get('is_staff', user.is_staff)
        user.is_superuser = data.get('is_superuser', user.is_superuser)
        
        # Update password if provided
        if data.get('password'):
            user.set_password(data['password'])
            changes['password'] = {'old': '***', 'new': '*** (changed)'}
        
        user.save()
        
        # Update groups and track changes
        old_groups = set(user.groups.values_list('name', flat=True))
        if 'groups' in data:
            groups = Group.objects.filter(id__in=data['groups'])
            user.groups.set(groups)
            new_groups = set(user.groups.values_list('name', flat=True))
            
            if old_groups != new_groups:
                changes['groups'] = {
                    'old': list(old_groups),
                    'new': list(new_groups),
                    'added': list(new_groups - old_groups),
                    'removed': list(old_groups - new_groups)
                }
        
        # Log user update
        AuditLogger.log_user_update(
            admin_user=request.user,
            updated_user=user,
            request=request,
            changes=changes
        )
        
        return JsonResponse({
            'success': True,
            'message': f'User "{user.username}" updated successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def delete_user(request, user_id):
    """
    AJAX endpoint for soft deleting users
    """
    try:
        # Check permissions - only superusers can delete users
        if not request.user.is_superuser:
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to delete users.'
            }, status=403)
        
        from .models import CustomUser
        
        # Get the user
        user = get_object_or_404(CustomUser, id=user_id, is_deleted=False)
        
        # Prevent deleting self
        if user.id == request.user.id:
            return JsonResponse({
                'success': False,
                'error': 'You cannot delete your own account.'
            }, status=400)
        
        # Capture username before deletion
        username = user.username
        
        # Soft delete the user
        user.soft_delete()
        
        # Log user deletion
        AuditLogger.log_user_delete(
            admin_user=request.user,
            deleted_user=user,
            request=request
        )
        
        return JsonResponse({
            'success': True,
            'message': f'User "{username}" deleted successfully!'
        })
        
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def get_audit_logs(request):
    """
    AJAX endpoint for getting comprehensive audit logs
    """
    try:
        # Check permissions - only staff and superusers can access
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to view audit logs.'
            }, status=403)
        
        # Get query parameters for filtering
        limit = int(request.GET.get('limit', 50))  # Default to 50 logs
        offset = int(request.GET.get('offset', 0))
        user_filter = request.GET.get('user', '')
        category_filter = request.GET.get('category', '')
        action_filter = request.GET.get('action', '')
        severity_filter = request.GET.get('severity', '')
        success_filter = request.GET.get('success', '')
        
        # Build queryset - use new comprehensive audit log
        logs = SystemAuditLog.objects.all().select_related('user')
        
        # Apply filters
        if user_filter:
            logs = logs.filter(username__icontains=user_filter)
        
        if category_filter:
            logs = logs.filter(category=category_filter)
        
        if action_filter:
            logs = logs.filter(action__icontains=action_filter)
        
        if severity_filter:
            logs = logs.filter(severity=severity_filter)
            
        if success_filter:
            success_bool = success_filter.lower() == 'true'
            logs = logs.filter(success=success_bool)
        
        # Get total count before pagination
        total_count = logs.count()
        
        # Apply pagination
        logs = logs.order_by('-timestamp')[offset:offset + limit]
        
        logs_data = []
        for log in logs:
            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'category': log.get_category_display(),
                'action': log.get_action_display(),
                'severity': log.get_severity_display(),
                'description': log.description,
                'success': log.success,
                'user': {
                    'id': log.user.id if log.user else None,
                    'username': log.username,
                    'first_name': log.user.first_name if log.user else '',
                    'last_name': log.user.last_name if log.user else '',
                } if log.username else None,
                'resource': {
                    'type': log.resource_type,
                    'id': log.resource_id,
                    'name': log.resource_name,
                } if log.resource_type else None,
                'ip_address': log.ip_address,
                'risk_score': log.risk_score,
                'details': log.details,
            })
        
        # Get summary statistics
        categories = SystemAuditLog.objects.values('category').annotate(
            count=models.Count('id')
        ).order_by('-count')[:5]
        
        severity_stats = SystemAuditLog.objects.values('severity').annotate(
            count=models.Count('id')
        )
        
        return JsonResponse({
            'success': True,
            'logs': logs_data,
            'total_count': total_count,
            'has_more': (offset + limit) < total_count,
            'stats': {
                'top_categories': list(categories),
                'severity_distribution': list(severity_stats),
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def get_credential_types(request):
    """
    AJAX endpoint for getting all credential types for management
    """
    try:
        # Check permissions - only staff and superusers can access
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to view credential types.'
            }, status=403)
        
        credential_types = CredentialType.objects.filter(is_deleted=False).order_by('name')
        
        types_data = []
        for cred_type in credential_types:
            # Count how many vault entries use this type
            entry_count = VaultEntry.objects.filter(
                credential_type=cred_type, 
                is_deleted=False
            ).count()
            
            types_data.append({
                'id': cred_type.id,
                'name': cred_type.name,
                'description': cred_type.description or '',
                'icon': 'key',  # Default icon
                'color': '#0ea5e9',  # Default color (electric blue)
                'entry_count': entry_count,
                'created_at': cred_type.created_at.isoformat() if cred_type.created_at else None,
            })
        
        return JsonResponse({
            'success': True,
            'credential_types': types_data
        })
        
    except Exception as e:
        logger.error(f"Error getting credential types: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def create_credential_type(request):
    """
    AJAX endpoint for creating new credential types
    """
    try:
        # Check permissions - only staff and superusers can create credential types
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to create credential types.'
            }, status=403)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['name']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'error': f'{field.title()} is required.'
                }, status=400)
        
        # Check if name already exists
        if CredentialType.objects.filter(name=data['name'], is_deleted=False).exists():
            return JsonResponse({
                'success': False,
                'error': 'A credential type with this name already exists.'
            }, status=400)
        
        # Create the credential type
        cred_type = CredentialType.objects.create(
            name=data['name'],
            description=data.get('description', ''),
        )
        
        # Log credential type creation
        AuditLogger.log_credential_type_create(
            user=request.user,
            cred_type=cred_type,
            request=request
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Credential type "{cred_type.name}" created successfully!',
            'credential_type_id': cred_type.id
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error creating credential type: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def update_credential_type(request, type_id):
    """
    AJAX endpoint for updating credential types
    """
    try:
        # Check permissions - only staff and superusers can update credential types
        if not (request.user.is_staff or request.user.is_superuser):
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to update credential types.'
            }, status=403)
        
        # Get the credential type
        cred_type = get_object_or_404(CredentialType, id=type_id, is_deleted=False)
        
        # Parse JSON data
        data = json.loads(request.body)
        
        # Track changes for audit
        changes = {}
        if cred_type.name != data.get('name', cred_type.name):
            changes['name'] = {'old': cred_type.name, 'new': data.get('name', cred_type.name)}
        if cred_type.description != data.get('description', cred_type.description):
            changes['description'] = {'old': cred_type.description, 'new': data.get('description', cred_type.description)}
        
        # Update credential type fields
        cred_type.name = data.get('name', cred_type.name)
        cred_type.description = data.get('description', cred_type.description)
        
        cred_type.save()
        
        # Log credential type update
        AuditLogger.log_credential_type_update(
            user=request.user,
            cred_type=cred_type,
            request=request,
            changes=changes
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Credential type "{cred_type.name}" updated successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        }, status=400)
    except Exception as e:
        logger.error(f"Error updating credential type: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def delete_credential_type(request, type_id):
    """
    AJAX endpoint for soft deleting credential types
    """
    try:
        # Check permissions - only superusers can delete credential types
        if not request.user.is_superuser:
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to delete credential types.'
            }, status=403)
        
        # Get the credential type
        cred_type = get_object_or_404(CredentialType, id=type_id, is_deleted=False)
        
        # Check if there are vault entries using this type
        entry_count = VaultEntry.objects.filter(
            credential_type=cred_type, 
            is_deleted=False
        ).count()
        
        if entry_count > 0:
            return JsonResponse({
                'success': False,
                'error': f'Cannot delete credential type "{cred_type.name}" because it is used by {entry_count} vault entries.'
            }, status=400)
        
        # Capture name before deletion
        cred_type_name = cred_type.name
        
        # Soft delete the credential type
        cred_type.soft_delete()
        
        # Log credential type deletion
        AuditLogger.log_credential_type_delete(
            user=request.user,
            cred_type=cred_type,
            request=request
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Credential type "{cred_type_name}" deleted successfully!'
        })
        
    except Exception as e:
        logger.error(f"Error deleting credential type: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'An unexpected error occurred.'
        }, status=500)


# ===============================
# Integration AJAX Endpoints
# ===============================

@login_required
@require_http_methods(["GET"])
def integration_overview(request):
    """Get integration overview statistics"""
    try:
        # Import here to avoid circular imports
        from .models import IntegrationConfig, EntraUser, IntegrationTask
        
        # Calculate statistics
        total_configs = IntegrationConfig.objects.count()
        active_integrations = IntegrationConfig.objects.filter(is_enabled=True).count()
        total_entra_users = EntraUser.objects.count()
        pending_tasks = IntegrationTask.objects.filter(status='PENDING').count()
        
        # Get last sync time
        last_sync = None
        latest_task = IntegrationTask.objects.filter(status='COMPLETED').order_by('-completed_at').first()
        if latest_task:
            last_sync = latest_task.completed_at.strftime('%Y-%m-%d %H:%M')
        
        # Check integration statuses
        entra_config = IntegrationConfig.objects.filter(integration_type='ENTRA', is_enabled=True).first()
        proxmox_config = IntegrationConfig.objects.filter(integration_type='PROXMOX', is_enabled=True).first()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_users': total_entra_users,
                'active_integrations': active_integrations,
                'last_sync': last_sync or 'Never',
                'pending_tasks': pending_tasks
            },
            'status': {
                'entra': {
                    'state': 'connected' if entra_config else 'unknown'
                },
                'proxmox': {
                    'state': 'connected' if proxmox_config else 'unknown'
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting integration overview: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load integration overview.'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def admin_overview(request):
    """Get admin overview statistics (for compatibility)"""
    try:
        from .models import CustomUser, VaultEntry, CredentialType, SystemAuditLog
        
        # Calculate statistics
        total_users = CustomUser.objects.filter(is_deleted=False).count()
        total_entries = VaultEntry.objects.filter(is_deleted=False).count()
        total_credential_types = CredentialType.objects.filter(is_deleted=False).count()
        recent_activity_count = SystemAuditLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        stats = [
            {'label': 'Total Users', 'value': total_users},
            {'label': 'Vault Entries', 'value': total_entries},
            {'label': 'Credential Types', 'value': total_credential_types},
            {'label': 'Recent Activity', 'value': recent_activity_count},
        ]
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting admin overview: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load admin overview.'
        }, status=500)


@login_required
@require_http_methods(["GET", "POST"])
def entra_config(request):
    """Handle Entra configuration get/save"""
    try:
        from .models import IntegrationConfig
        
        if request.method == 'GET':
            # Get current Entra configuration
            try:
                config = IntegrationConfig.objects.get(integration_type='ENTRA')
                config_data = {
                    'tenant_id': config.get_config_value('tenant_id', ''),
                    'client_id': config.get_config_value('client_id', ''),
                    'auto_sync': config.get_config_value('auto_sync', False),
                    # Don't return client_secret for security
                }
                return JsonResponse({
                    'success': True,
                    'config': config_data
                })
            except IntegrationConfig.DoesNotExist:
                return JsonResponse({
                    'success': True,
                    'config': {
                        'tenant_id': '',
                        'client_id': '',
                        'auto_sync': False
                    }
                })
        
        elif request.method == 'POST':
            # Save Entra configuration
            try:
                data = json.loads(request.body)
            except json.JSONDecodeError:
                return JsonResponse({
                    'success': False,
                    'error': 'Invalid JSON data.'
                }, status=400)
            
            # Get or create Entra configuration
            config, created = IntegrationConfig.objects.get_or_create(
                integration_type='ENTRA',
                defaults={
                    'name': 'Microsoft Entra ID',
                    'created_by': request.user
                }
            )
            
            # Update configuration
            config.set_config_value('tenant_id', data.get('tenant_id', ''))
            config.set_config_value('client_id', data.get('client_id', ''))
            config.set_config_value('auto_sync', data.get('auto_sync', False))
            
            # Only update client_secret if provided
            if data.get('client_secret'):
                config.set_config_value('client_secret', data.get('client_secret'))
            
            # Enable integration if all required fields are provided
            if all([data.get('tenant_id'), data.get('client_id')]):
                config.is_enabled = True
            
            config.save()
            
            # Log the configuration change
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='CONFIG_UPDATE',
                user=request.user,
                description=f"Entra ID configuration {'created' if created else 'updated'}",
                request=request,
                severity='MEDIUM',
                success=True
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Entra configuration saved successfully!'
            })
            
    except Exception as e:
        logger.error(f"Error handling Entra config: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to handle Entra configuration.'
        }, status=500)


@login_required
@require_POST
def entra_test(request):
    """Test Entra ID connection"""
    try:
        from .models import IntegrationConfig
        from .entra_integration import EntraIntegrationService
        
        # Get Entra configuration
        try:
            config = IntegrationConfig.objects.get(integration_type='ENTRA', is_enabled=True)
        except IntegrationConfig.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Test connection using the integration service
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not properly configured.'
            }, status=400)
        
        # Test the connection
        result = service.test_connection()
        
        # Log the test attempt
        AuditLogger.log_security_event(
            category='INTEGRATION',
            action='CONNECTION_TEST',
            user=request.user,
            description=f"Entra ID connection test: {'successful' if result['success'] else 'failed'}",
            request=request,
            severity='LOW' if result['success'] else 'MEDIUM',
            success=result['success']
        )
        
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error testing Entra connection: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f'Connection test failed: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def entra_activity(request):
    """Get recent Entra integration activities"""
    try:
        from datetime import timedelta
        from django.utils import timezone
        
        # Get recent Entra-related audit logs
        recent_logs = SystemAuditLog.objects.filter(
            category='INTEGRATION',
            timestamp__gte=timezone.now() - timedelta(days=7)
        ).order_by('-timestamp')[:10]
        
        activities = []
        for log in recent_logs:
            activities.append({
                'description': log.description,
                'user': log.username or 'System',
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M'),
                'status': 'SUCCESS' if log.success else 'FAILED'
            })
        
        return JsonResponse({
            'success': True,
            'activities': activities
        })
        
    except Exception as e:
        logger.error(f"Error getting Entra activity: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load Entra activity.'
        }, status=500)


@login_required
@require_POST
def entra_user_search(request):
    """Search for Entra users"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Get search term from request
        try:
            data = json.loads(request.body)
            search_term = data.get('search', '').strip()
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid request data.'
            }, status=400)
        
        if len(search_term) < 3:
            return JsonResponse({
                'success': False,
                'error': 'Search term must be at least 3 characters.'
            }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Search for users
        result = service.user_manager.search_users(search_term)
        
        if result['success']:
            # Log the search
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='USER_SEARCH',
                user=request.user,
                description=f"Searched for Entra users: '{search_term}' - Found {len(result['users'])} users",
                request=request,
                severity='LOW',
                success=True
            )
            
            return JsonResponse({
                'success': True,
                'users': result['users']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Search failed')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error searching Entra users: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to search users.'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def entra_user_details(request, user_id):
    """Get detailed information about an Entra user"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user details including manager
        result = service.user_manager.get_user_with_manager(user_id)
        
        if result['success']:
            # Log the access
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='USER_VIEW',
                user=request.user,
                description=f"Viewed Entra user details: {result['user']['userPrincipalName']}",
                request=request,
                severity='LOW',
                success=True
            )
            
            return JsonResponse({
                'success': True,
                'user': result['user']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to get user details')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error getting Entra user details: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get user details.'
        }, status=500)


@login_required
@require_POST
def entra_create_admin(request):
    """Create an admin account based on existing user"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Get admin user data from request
        try:
            admin_data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid request data.'
            }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Create the admin user
        try:
            result = service.user_manager.create_user(admin_data)
        except Exception as e:
            logger.error(f"Error in user_manager.create_user: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to create user: {str(e)}'
            }, status=500)
        
        if result['success']:
            # Create vault entry for the new admin account
            vault_entry_created = False
            try:
                from .models import VaultEntry
                
                vault_entry = VaultEntry.create_admin_account(
                    username=admin_data['userPrincipalName'],
                    password=result.get('password'),
                    admin_type='Entra_admin',
                    integration_source='Entra',
                    display_name=f"Entra Admin: {admin_data['displayName']}",
                    created_by=request.user,
                    notes=f"Auto-created during admin account creation on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                vault_entry_created = True
            except Exception as e:
                logger.warning(f"Failed to create vault entry for {admin_data['userPrincipalName']}: {e}")
                # Continue execution - don't fail the admin creation if vault creation fails
            
            # Log the creation
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ADMIN_CREATE',
                user=request.user,
                description=f"Created admin account: {admin_data['userPrincipalName']} based on user {admin_data.get('sourceUserId', 'unknown')}" + (
                    " with vault entry" if vault_entry_created else ""
                ),
                request=request,
                severity='HIGH',
                success=True,
                details={
                    'target_user': admin_data['userPrincipalName'], 
                    'source_user_id': admin_data.get('sourceUserId'),
                    'vault_entry_created': vault_entry_created
                }
            )
            
            # Create integration task for tracking
            from .models import IntegrationTask
            import uuid
            IntegrationTask.objects.create(
                task_id=str(uuid.uuid4()),
                integration_type='ENTRA',
                task_type='USER_CREATE',
                status='COMPLETED',
                initiated_by=request.user,
                target_resource=admin_data['userPrincipalName'],
                task_parameters=admin_data,
                result_data={'user_id': result.get('user_id'), 'upn': admin_data['userPrincipalName']},
                started_at=timezone.now(),
                completed_at=timezone.now()
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Admin account created successfully' + (
                    ' with vault entry' if vault_entry_created else ''
                ),
                'user_id': result.get('user_id'),
                'password': result.get('password'),
                'vault_entry_created': vault_entry_created
            })
        else:
            # Log the failure
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ADMIN_CREATE',
                user=request.user,
                description=f"Failed to create admin account: {admin_data['userPrincipalName']} - {result.get('error', 'Unknown error')}",
                request=request,
                severity='HIGH',
                success=False
            )
            
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to create admin account')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error creating admin account: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to create admin account.'
        }, status=500)


@login_required
def entra_user_roles(request, user_id):
    """Get current role assignments for a user"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user roles from Entra
        try:
            result = service.role_manager.get_user_role_assignments(user_id)
        except Exception as e:
            logger.error(f"Error getting user roles: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to get user roles: {str(e)}'
            }, status=500)
        
        if result['success']:
            return JsonResponse({
                'success': True,
                'roles': result['roles']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to get user roles')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error getting user roles: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get user roles.'
        }, status=500)


@login_required
def entra_available_roles(request):
    """Get available directory roles for assignment"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get available roles from Entra
        try:
            result = service.role_manager.get_directory_roles()
        except Exception as e:
            logger.error(f"Error getting directory roles: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to get directory roles: {str(e)}'
            }, status=500)
        
        if result['success']:
            return JsonResponse({
                'success': True,
                'roles': result['roles']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to get directory roles')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error getting directory roles: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get directory roles.'
        }, status=500)


@login_required
def entra_assign_role(request):
    """Assign a directory role to a user"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Get role assignment data from request
        try:
            assignment_data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid request data.'
            }, status=400)
        
        required_fields = ['user_id', 'role_id', 'assignment_type', 'justification']
        for field in required_fields:
            if field not in assignment_data:
                return JsonResponse({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Assign the role
        try:
            result = service.role_manager.assign_role(
                user_id=assignment_data['user_id'],
                role_id=assignment_data['role_id'],
                assignment_type=assignment_data['assignment_type'],
                justification=assignment_data['justification'],
                duration_hours=assignment_data.get('duration_hours'),
                assigned_by=request.user
            )
        except Exception as e:
            logger.error(f"Error assigning role: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to assign role: {str(e)}'
            }, status=500)
        
        if result['success']:
            # Log the assignment
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ROLE_ASSIGN',
                user=request.user,
                description=f"Assigned role {assignment_data['role_id']} to user {assignment_data['user_id']} ({assignment_data['assignment_type']})",
                request=request,
                severity='HIGH',
                success=True,
                details=assignment_data
            )
            
            # Create integration task for tracking
            from .models import IntegrationTask
            import uuid
            IntegrationTask.objects.create(
                task_id=str(uuid.uuid4()),
                integration_type='ENTRA',
                task_type='ROLE_ASSIGN',
                status='COMPLETED',
                initiated_by=request.user,
                target_resource=f"{assignment_data['user_id']}:{assignment_data['role_id']}",
                task_parameters=assignment_data,
                result_data=result.get('assignment', {}),
                started_at=timezone.now(),
                completed_at=timezone.now()
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Role assigned successfully',
                'assignment': result.get('assignment')
            })
        else:
            # Log the failure
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ROLE_ASSIGN',
                user=request.user,
                description=f"Failed to assign role {assignment_data['role_id']} to user {assignment_data['user_id']} - {result.get('error', 'Unknown error')}",
                request=request,
                severity='HIGH',
                success=False,
                details=assignment_data
            )
            
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to assign role')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error assigning role: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to assign role.'
        }, status=500)


@login_required
def entra_remove_role(request):
    """Remove a directory role from a user"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Get role removal data from request
        try:
            removal_data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid request data.'
            }, status=400)
        
        required_fields = ['user_id', 'role_id']
        for field in required_fields:
            if field not in removal_data:
                return JsonResponse({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Remove the role
        try:
            result = service.role_manager.remove_role_assignment(
                user_id=removal_data['user_id'],
                role_id=removal_data['role_id'],
                removed_by=request.user
            )
        except Exception as e:
            logger.error(f"Error removing role: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to remove role: {str(e)}'
            }, status=500)
        
        if result['success']:
            # Log the removal
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ROLE_REMOVE',
                user=request.user,
                description=f"Removed role {removal_data['role_id']} from user {removal_data['user_id']}",
                request=request,
                severity='HIGH',
                success=True,
                details=removal_data
            )
            
            # Create integration task for tracking
            from .models import IntegrationTask
            import uuid
            IntegrationTask.objects.create(
                task_id=str(uuid.uuid4()),
                integration_type='ENTRA',
                task_type='ROLE_REMOVE',
                status='COMPLETED',
                initiated_by=request.user,
                target_resource=f"{removal_data['user_id']}:{removal_data['role_id']}",
                task_parameters=removal_data,
                result_data=result.get('removal', {}),
                started_at=timezone.now(),
                completed_at=timezone.now()
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Role removed successfully'
            })
        else:
            # Log the failure
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='ROLE_REMOVE',
                user=request.user,
                description=f"Failed to remove role {removal_data['role_id']} from user {removal_data['user_id']} - {result.get('error', 'Unknown error')}",
                request=request,
                severity='HIGH',
                success=False,
                details=removal_data
            )
            
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to remove role')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error removing role: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to remove role.'
        }, status=500)


@login_required
def entra_role_members(request, role_id):
    """Get members of a specific directory role"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get role members from Entra
        try:
            result = service.role_manager.get_role_members(role_id)
        except Exception as e:
            logger.error(f"Error getting role members: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to get role members: {str(e)}'
            }, status=500)
        
        if result['success']:
            return JsonResponse({
                'success': True,
                'members': result['members']
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Failed to get role members')
            }, status=400)
            
    except Exception as e:
        logger.error(f"Error getting role members: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get role members.'
        }, status=500)


@login_required
def cloud_admins(request):
    """Get all cloud admin accounts created within the platform"""
    try:
        from django.db import models
        from .models import SystemAuditLog
        
        # Get all admin account creation events from audit logs
        # Try multiple possible action values that might be used for admin creation
        admin_creation_logs = SystemAuditLog.objects.filter(
            models.Q(action='ADMIN_CREATE') | 
            models.Q(action='USER_CREATE') |
            models.Q(action='CREATE_ADMIN') |
            models.Q(description__icontains='admin account') |
            models.Q(description__icontains='Created admin'),
            success=True
        ).order_by('-timestamp')
        
        logger.info(f"Found {admin_creation_logs.count()} admin creation logs")
        for log in admin_creation_logs:
            logger.info(f"Log {log.id}: action={log.action}, category={log.category}, details={log.details}")
        
        admins = []
        processed_accounts = set()  # To avoid duplicates
        
        for log in admin_creation_logs:
            try:
                details = log.details or {}
                
                # Extract platform - if not in details, infer from category or action
                platform = details.get('platform', 'unknown').lower()
                if platform == 'unknown' and log.category == 'SECURITY' and 'admin account' in (log.description or ''):
                    platform = 'entra'  # Assume Entra for security admin creation
                
                # Extract user identifier from details or description
                user_identifier = (
                    details.get('user_principal_name') or 
                    details.get('username') or 
                    details.get('display_name') or 
                    details.get('target_user')
                )
                
                # If no identifier in details, try to extract from description
                if not user_identifier and log.description:
                    desc = log.description
                    # Look for email pattern in description like "Wright_Drea@domain.com"
                    import re
                    email_match = re.search(r'([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+)', desc)
                    if email_match:
                        user_identifier = email_match.group(1)
                    else:
                        # Look for pattern like "Created admin account: USERNAME"
                        name_match = re.search(r'admin account:\s*([^\s]+)', desc)
                        if name_match:
                            user_identifier = name_match.group(1)
                
                if not user_identifier:
                    user_identifier = f"admin_{log.id}"  # Fallback identifier
                
                account_key = f"{platform}_{user_identifier}"
                
                if account_key in processed_accounts:
                    continue
                
                processed_accounts.add(account_key)
                
                # Determine account status (placeholder - would need to check actual platform status)
                enabled = True  # Default assumption, would need API calls to verify
                
                # Create display name from user_identifier if not available
                display_name = details.get('display_name')
                if not display_name and user_identifier:
                    # Convert "Wright_Drea@domain.com" to "Wright Drea"
                    if '@' in user_identifier:
                        name_part = user_identifier.split('@')[0]
                        display_name = name_part.replace('_', ' ').replace('.', ' ')
                    else:
                        display_name = user_identifier.replace('_', ' ')
                
                # Check for associated vault entry
                vault_entry = None
                has_vault_entry = False
                try:
                    from .models import VaultEntry
                    vault_entry = VaultEntry.objects.filter(
                        username=user_identifier,
                        is_admin_account=True,
                        source_integration__iexact=platform
                    ).first()
                    has_vault_entry = vault_entry is not None
                except Exception as e:
                    logger.warning(f"Error checking vault entry for {user_identifier}: {e}")
                
                admin_data = {
                    'id': f"{platform}_{log.id}",
                    'platform': platform,
                    'display_name': display_name or user_identifier,
                    'user_principal_name': user_identifier if '@' in str(user_identifier) else details.get('mail'),
                    'mail': details.get('mail', user_identifier if '@' in str(user_identifier) else None),
                    'enabled': enabled,
                    'created_at': log.timestamp.isoformat(),
                    'last_activity': None,  # Would need to track this separately
                    'created_by': log.user.username if log.user else 'System',
                    'has_vault_entry': has_vault_entry,
                    'vault_entry_id': vault_entry.id if vault_entry else None
                }
                
                admins.append(admin_data)
                
            except Exception as e:
                logger.warning(f"Error processing admin log {log.id}: {e}")
                continue
        
        # Calculate statistics
        stats = {
            'total_admins': len(admins),
            'entra_admins': len([a for a in admins if a['platform'] == 'entra']),
            'proxmox_admins': len([a for a in admins if a['platform'] == 'proxmox']),
            'active_this_month': len(admins)  # Simplified - all are "active"
        }
        
        # Transform for frontend compatibility
        accounts = []
        for admin in admins:
            accounts.append({
                'username': admin.get('user_principal_name', admin.get('display_name', 'Unknown')),
                'account_name': admin.get('display_name', admin.get('user_principal_name', 'Unknown')),
                'platform': admin['platform'].title(),
                'status': 'enabled' if admin.get('enabled', True) else 'disabled',
                'created_date': admin['created_at'][:10],  # Just the date part
                'created_by': admin.get('created_by', 'System'),
                'has_vault_entry': admin.get('has_vault_entry', False),
                'vault_entry_id': admin.get('vault_entry_id')
            })
        
        # Calculate vault entry statistics
        with_vault = len([a for a in accounts if a['has_vault_entry']])
        without_vault = len(accounts) - with_vault
        
        # Transform accounts to match the expected format for the global modal
        transformed_admins = []
        for account in accounts:
            transformed_admins.append({
                'username': account['username'],
                'display_name': account['account_name'],
                'platform': account['platform'],
                'has_vault_entry': account['has_vault_entry'],
                'vault_entry_id': account['vault_entry_id']
            })
        
        return JsonResponse({
            'success': True,
            'stats': stats,
            'accounts': accounts,
            'total_count': len(accounts),
            # Add fields expected by the global modal
            'total_admins': len(accounts),
            'with_vault_entries': with_vault,
            'without_vault_entries': without_vault,
            'admins': transformed_admins
        })
        
    except Exception as e:
        logger.error(f"Error in cloud_admins view: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load admin accounts'
        })

@login_required
def create_test_admin_logs(request):
    """Create test admin account audit logs for testing Cloud Admins functionality"""
    if not request.user.is_staff:
        return JsonResponse({'success': False, 'error': 'Not authorized'})
    
    try:
        from .models import SystemAuditLog
        from django.utils import timezone
        import json
        
        # Create test admin logs
        test_admins = [
            {
                'platform': 'entra',
                'display_name': 'John Admin',
                'user_principal_name': 'john.admin@company.com',
                'mail': 'john.admin@company.com'
            },
            {
                'platform': 'entra', 
                'display_name': 'Sarah Manager',
                'user_principal_name': 'sarah.manager@company.com',
                'mail': 'sarah.manager@company.com'
            },
            {
                'platform': 'proxmox',
                'display_name': 'proxmox-admin-01',
                'username': 'proxmox-admin-01'
            }
        ]
        
        created_count = 0
        for admin_data in test_admins:
            # Check if already exists
            existing = SystemAuditLog.objects.filter(
                action='ADMIN_CREATE',
                success=True,
                details__user_principal_name=admin_data.get('user_principal_name'),
                details__username=admin_data.get('username')
            ).exists()
            
            if not existing:
                SystemAuditLog.objects.create(
                    user=request.user,
                    action='ADMIN_CREATE',
                    resource_type='admin_account',
                    resource_id=admin_data.get('user_principal_name', admin_data.get('username')),
                    success=True,
                    details=admin_data,
                    timestamp=timezone.now()
                )
                created_count += 1
        
        return JsonResponse({
            'success': True,
            'message': f'Created {created_count} test admin logs',
            'created_count': created_count
        })
        
    except Exception as e:
        logger.error(f"Error creating test admin logs: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
def admin_details(request, username):
    """Get detailed admin account information from Entra ID"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user details from Entra
        try:
            # Get basic user info
            user = service.user_manager.get_user_by_email(username)
            if not user:
                return JsonResponse({
                    'success': False,
                    'error': f'User not found: {username}'
                })
            
            # Get role assignments
            try:
                roles_data = service.role_manager.get_user_roles(user.get('id', ''))
                roles = roles_data.get('roles', []) if roles_data.get('success') else []
            except Exception as e:
                logger.warning(f"Failed to get roles for {username}: {e}")
                roles = []
            
            # Get group memberships
            try:
                groups_data = service.user_manager.get_user_groups(user.get('id', ''))
                groups = groups_data.get('groups', []) if groups_data.get('success') else []
            except Exception as e:
                logger.warning(f"Failed to get groups for {username}: {e}")
                groups = []
            
            # Combine all data
            admin_details = {
                'success': True,
                'user': user,
                'roles': roles,
                'groups': groups,
                'last_updated': timezone.now().isoformat()
            }
            
            return JsonResponse(admin_details)
            
        except Exception as e:
            logger.error(f"Error fetching Entra data for {username}: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to fetch admin details: {str(e)}'
            }, status=500)
        
    except Exception as e:
        logger.error(f"Error in admin_details view: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to load admin details'
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def reset_admin_password(request, username):
    """Reset an admin account password in Entra ID"""
    try:
        from .entra_integration import EntraIntegrationService
        from .models import SystemAuditLog
        import json
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user ID first
        user_data = service.user_manager.get_user_by_email(username)
        if not user_data:
            return JsonResponse({
                'success': False,
                'error': f'User not found: {username}'
            })
        
        user_id = user_data.get('id')
        if not user_id:
            return JsonResponse({
                'success': False,
                'error': 'Could not retrieve user ID'
            })
        
        # Reset password
        result = service.user_manager.reset_user_password(user_id)
        
        if result.get('success'):
            # Create or update vault entry for this admin account
            vault_entry_created = False
            try:
                from .models import VaultEntry
                
                # Check if vault entry already exists for this admin account
                existing_vault_entry = VaultEntry.objects.filter(
                    username=username,
                    is_admin_account=True,
                    admin_account_type='Entra_admin'
                ).first()
                
                if existing_vault_entry:
                    # Update existing vault entry with new password
                    existing_vault_entry.password = result.get('password')
                    existing_vault_entry.updated_by = request.user
                    existing_vault_entry.notes = f"Password reset on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    existing_vault_entry.save()
                    vault_entry_created = True
                else:
                    # Create new vault entry
                    display_name = user.get('displayName', username.split('@')[0])
                    vault_entry = VaultEntry.create_admin_account(
                        username=username,
                        password=result.get('password'),
                        admin_type='Entra_admin',
                        integration_source='Entra',
                        display_name=f"Entra Admin: {display_name}",
                        created_by=request.user,
                        notes=f"Created during password reset on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    vault_entry_created = True
                    
            except Exception as e:
                logger.warning(f"Failed to create/update vault entry for {username}: {e}")
                # Continue execution - don't fail the password reset if vault creation fails
            
            # Log the activity
            SystemAuditLog.objects.create(
                user=request.user,
                category='Security',
                action='PASSWORD_RESET',
                resource=f"Admin Account: {username}",
                description=f"Password reset for admin account {username}" + (
                    " and vault entry created/updated" if vault_entry_created else ""
                ),
                details={
                    'user_id': user_id, 
                    'username': username,
                    'vault_entry_created': vault_entry_created
                },
                severity='Medium',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                risk_score=30
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Password reset successfully' + (
                    ' and vault entry created/updated' if vault_entry_created else ''
                ),
                'new_password': result.get('password'),
                'force_change': True,
                'vault_entry_created': vault_entry_created
            })
        else:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Password reset failed')
            }, status=500)
        
    except Exception as e:
        logger.error(f"Error in reset_admin_password view: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to reset password'
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def toggle_admin_account(request, username):
    """Enable or disable an admin account in Entra ID"""
    try:
        from .entra_integration import EntraIntegrationService
        from .models import SystemAuditLog
        import json
        
        # Parse request data
        try:
            data = json.loads(request.body)
            enable = data.get('enable', False)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user ID first
        user_data = service.user_manager.get_user_by_email(username)
        if not user_data:
            return JsonResponse({
                'success': False,
                'error': f'User not found: {username}'
            })
        
        user_id = user_data.get('id')
        if not user_id:
            return JsonResponse({
                'success': False,
                'error': 'Could not retrieve user ID'
            })
        
        # Enable or disable user
        if enable:
            success = service.user_manager.enable_user(user_id)
            action = 'ACCOUNT_ENABLED'
            action_text = 'enabled'
        else:
            success = service.user_manager.disable_user(user_id)
            action = 'ACCOUNT_DISABLED'
            action_text = 'disabled'
        
        if success:
            # Log the activity
            SystemAuditLog.objects.create(
                user=request.user,
                category='Security',
                action=action,
                resource=f"Admin Account: {username}",
                description=f"Admin account {username} {action_text}",
                details={'user_id': user_id, 'username': username, 'enabled': enable},
                severity='High' if not enable else 'Medium',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                risk_score=50 if not enable else 25
            )
            
            return JsonResponse({
                'success': True,
                'message': f'Account {action_text} successfully',
                'enabled': enable
            })
        else:
            return JsonResponse({
                'success': False,
                'error': f'Failed to {action_text} account'
            }, status=500)
        
    except Exception as e:
        logger.error(f"Error in toggle_admin_account view: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to update account status'
        }, status=500)


@login_required
@csrf_exempt
@require_http_methods(["POST"])
def update_admin_account(request, username):
    """Update admin account details in Entra ID"""
    try:
        from .entra_integration import EntraIntegrationService
        from .models import SystemAuditLog
        import json
        
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
        
        # Check if Entra is configured
        service = EntraIntegrationService()
        if not service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra integration is not configured.'
            }, status=400)
        
        # Get user ID first
        user_data = service.user_manager.get_user_by_email(username)
        if not user_data:
            return JsonResponse({
                'success': False,
                'error': f'User not found: {username}'
            })
        
        user_id = user_data.get('id')
        if not user_id:
            return JsonResponse({
                'success': False,
                'error': 'Could not retrieve user ID'
            })
        
        # Prepare update data (only allow certain fields)
        allowed_fields = ['displayName', 'jobTitle', 'department', 'officeLocation', 'businessPhones']
        update_data = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
        
        if not update_data:
            return JsonResponse({
                'success': False,
                'error': 'No valid fields to update'
            }, status=400)
        
        # Update user
        success = service.user_manager.update_user(user_id, update_data)
        
        if success:
            # Log the activity
            SystemAuditLog.objects.create(
                user=request.user,
                category='Security',
                action='ACCOUNT_UPDATED',
                resource=f"Admin Account: {username}",
                description=f"Updated admin account {username}",
                details={'user_id': user_id, 'username': username, 'updated_fields': list(update_data.keys())},
                severity='Medium',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                risk_score=20
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Account updated successfully',
                'updated_fields': list(update_data.keys())
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Failed to update account'
            }, status=500)
        
    except Exception as e:
        logger.error(f"Error in update_admin_account view: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to update account'
        }, status=500)


@login_required
def pam_dashboard_view(request):
    """
    PAM (Privileged Account Management) Dashboard
    """
    user = request.user
    user_groups = user.groups.values_list('name', flat=True)
    
    # Check if user has admin permissions
    is_admin = user.is_superuser or 'Vault Admin' in user_groups
    
    if not is_admin:
        messages.error(request, 'You do not have permission to access the PAM Dashboard.')
        return redirect('vault:dashboard')
    
    # Get admin account metrics
    admin_vault_entries = VaultEntry.objects.filter(
        is_admin_account=True,
        is_deleted=False
    ).select_related('credential_type', 'owner')
    
    # Admin Account Overview metrics
    total_admin_accounts = admin_vault_entries.count()
    active_admin_accounts = admin_vault_entries.filter(owner__is_active=True).count()
    inactive_admin_accounts = total_admin_accounts - active_admin_accounts
    
    # Recent admin activity (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_admin_activity = SystemAuditLog.objects.filter(
        timestamp__gte=thirty_days_ago,
        category='USER',
        action__in=['USER_CREATE', 'USER_UPDATE', 'PASSWORD_RESET', 'USER_ACTIVATE', 'USER_DEACTIVATE']
    ).count()
    
    # Risk metrics - accounts with old passwords (over 90 days)
    ninety_days_ago = timezone.now() - timedelta(days=90)
    high_risk_accounts = admin_vault_entries.filter(updated_at__lt=ninety_days_ago).count()
    
    # Credential Management metrics
    vault_compliance = {
        'total_entries': total_admin_accounts,
        'with_vault_entry': admin_vault_entries.count(),
        'compliance_rate': round((admin_vault_entries.count() / max(total_admin_accounts, 1)) * 100, 1)
    }
    
    # Password age analysis
    password_age_breakdown = {
        'recent': admin_vault_entries.filter(updated_at__gte=timezone.now() - timedelta(days=30)).count(),
        'moderate': admin_vault_entries.filter(
            updated_at__gte=timezone.now() - timedelta(days=90),
            updated_at__lt=timezone.now() - timedelta(days=30)
        ).count(),
        'old': admin_vault_entries.filter(updated_at__lt=ninety_days_ago).count()
    }
    
    # Role & Permission Management metrics
    if EntraUser.objects.exists():
        total_entra_users = EntraUser.objects.filter(sync_status='ACTIVE').count()
        users_with_roles = EntraRoleAssignment.objects.filter(
            is_active=True
        ).values('user').distinct().count()
        
        # PIM metrics
        permanent_assignments = EntraRoleAssignment.objects.filter(
            assignment_type='PERMANENT',
            is_active=True
        ).count()
        eligible_assignments = EntraRoleAssignment.objects.filter(
            assignment_type='ELIGIBLE',
            is_active=True
        ).count()
        active_pim_assignments = EntraRoleAssignment.objects.filter(
            assignment_type='ACTIVE',
            is_active=True
        ).count()
        
        # MFA metrics (placeholder - would need actual MFA data)
        mfa_enabled_accounts = total_entra_users  # Assume all have MFA for now
        mfa_compliance_rate = 100.0 if total_entra_users > 0 else 0.0
    else:
        total_entra_users = 0
        users_with_roles = 0
        permanent_assignments = 0
        eligible_assignments = 0
        active_pim_assignments = 0
        mfa_enabled_accounts = 0
        mfa_compliance_rate = 0.0
    
    context = {
        'user': user,
        'is_admin': is_admin,
        'page_title': 'PAM Dashboard',
        
        # Admin Account Overview
        'admin_overview': {
            'total_accounts': total_admin_accounts,
            'active_accounts': active_admin_accounts,
            'inactive_accounts': inactive_admin_accounts,
            'recent_activity': recent_admin_activity,
            'high_risk_accounts': high_risk_accounts,
            'risk_percentage': round((high_risk_accounts / max(total_admin_accounts, 1)) * 100, 1)
        },
        
        # Credential Management
        'credential_management': {
            'vault_compliance': vault_compliance,
            'password_age': password_age_breakdown,
            'total_credentials': total_admin_accounts,
            'managed_credentials': admin_vault_entries.count()
        },
        
        # Role & Permission Management
        'role_management': {
            'total_users': total_entra_users,
            'users_with_roles': users_with_roles,
            'permanent_assignments': permanent_assignments,
            'eligible_assignments': eligible_assignments,
            'active_pim_assignments': active_pim_assignments,
            'mfa_enabled': mfa_enabled_accounts,
            'mfa_compliance_rate': mfa_compliance_rate
        },
        
        # Recent admin entries for quick access
        'recent_admin_entries': admin_vault_entries.order_by('-updated_at')[:5]
    }
    
    return render(request, 'vault/pam_dashboard.html', context)


@login_required
def service_identities_view(request):
    """Service Identities dashboard view"""
    
    # Get all service accounts
    service_accounts = ServiceAccount.objects.select_related(
        'manager', 'owner', 'vault_entry', 'created_by'
    ).prefetch_related('service_principals')
    
    # Debug: Log the service accounts and their managers
    logger.info(f"Service Identities View - Found {service_accounts.count()} service accounts:")
    for sa in service_accounts[:3]:  # Log first 3 for debugging
        manager_name = sa.manager.display_name if sa.manager else "No manager"
        logger.info(f"  {sa.employee_id}: {sa.service_name} (Manager: {manager_name})")
    
    # Get all service principals
    service_principals = ServicePrincipal.objects.select_related(
        'owner', 'service_account', 'vault_entry', 'created_by'
    ).prefetch_related('secrets')
    
    # Get all secrets
    secrets = ServicePrincipalSecret.objects.select_related(
        'service_principal', 'vault_entry', 'created_by'
    )
    
    # Calculate metrics
    total_service_accounts = service_accounts.count()
    active_service_accounts = service_accounts.filter(status='ACTIVE').count()
    
    total_service_principals = service_principals.count()
    active_service_principals = service_principals.filter(status='ACTIVE').count()
    
    total_secrets = secrets.count()
    expiring_secrets = sum(1 for secret in secrets if secret.is_expiring_soon())
    expired_secrets = sum(1 for secret in secrets if secret.is_expired())
    
    # Service accounts needing rotation
    accounts_needing_rotation = sum(1 for account in service_accounts if account.needs_password_rotation())
    
    # Context for template
    context = {
        'service_accounts': service_accounts,
        'service_principals': service_principals,
        'secrets': secrets,
        
        # Metrics
        'metrics': {
            'total_service_accounts': total_service_accounts,
            'active_service_accounts': active_service_accounts,
            'total_service_principals': total_service_principals,
            'active_service_principals': active_service_principals,
            'total_secrets': total_secrets,
            'expiring_secrets': expiring_secrets,
            'expired_secrets': expired_secrets,
            'accounts_needing_rotation': accounts_needing_rotation,
        }
    }
    
    return render(request, 'vault/service_identities.html', context)


@login_required
@require_http_methods(['GET'])
def get_next_employee_id(request):
    """Get the next available employee ID for Service Accounts"""
    try:
        next_id = ServiceAccount.generate_employee_id()
        return JsonResponse({
            'success': True,
            'employee_id': next_id
        })
    except Exception as e:
        logger.error(f"Error generating employee ID: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
@require_http_methods(['GET'])
def get_default_domain(request):
    """Get the default domain for auto-completion in User Principal Name field"""
    try:
        from .entra_integration import EntraIntegrationService
        
        # Try to get domain from existing service accounts or users
        domain = None
        
        # First, try to get domain from existing service accounts
        service_accounts = ServiceAccount.objects.filter(
            user_principal_name__isnull=False
        ).exclude(user_principal_name='').first()
        
        if service_accounts and '@' in service_accounts.user_principal_name:
            domain = service_accounts.user_principal_name.split('@')[1]
        else:
            # Try to get domain from Entra integration by searching for any user
            entra_service = EntraIntegrationService()
            if entra_service.is_configured():
                # Search for users and extract domain from the first result
                try:
                    users_result = entra_service.user_manager.search_users('a')  # Generic search
                    if users_result.get('success') and users_result.get('users'):
                        first_user = users_result['users'][0]
                        upn = first_user.get('userPrincipalName', '')
                        if '@' in upn:
                            domain = upn.split('@')[1]
                except Exception:
                    pass
        
        if domain:
            return JsonResponse({
                'success': True,
                'domain': domain
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Could not determine default domain'
            })
            
    except Exception as e:
        logger.error(f"Error getting default domain: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
@require_http_methods(['POST'])
def create_service_account(request):
    """Create a new Service Account"""
    try:
        # Get form data
        service_name = request.POST.get('service_name')
        user_principal_name = request.POST.get('user_principal_name')
        display_name = request.POST.get('display_name')
        description = request.POST.get('description')
        account_type = request.POST.get('account_type')
        department = request.POST.get('department')
        manager_id = request.POST.get('manager_id')
        
        # Log the form data for debugging
        logger.info(f"Create Service Account - Form data received:")
        logger.info(f"  service_name: {service_name}")
        logger.info(f"  user_principal_name: {user_principal_name}")
        logger.info(f"  display_name: {display_name}")
        logger.info(f"  manager_id: {manager_id}")
        
        # Validate required fields
        if not all([service_name, user_principal_name, display_name, description, account_type, manager_id]):
            logger.error(f"Missing required fields: service_name={bool(service_name)}, user_principal_name={bool(user_principal_name)}, display_name={bool(display_name)}, description={bool(description)}, account_type={bool(account_type)}, manager_id={bool(manager_id)}")
            return JsonResponse({
                'success': False,
                'error': 'All required fields must be filled'
            })
        
        # Get manager from Entra ID and ensure local record exists
        manager = None
        
        try:
            from .entra_integration import EntraIntegrationService
            entra_service = EntraIntegrationService()
            
            # Check if Entra is configured
            if not entra_service.is_configured():
                return JsonResponse({
                    'success': False,
                    'error': 'Entra ID integration is not configured'
                })
            
            logger.info(f"Looking up manager with ID: {manager_id}")
            
            # Get user details from Entra ID
            user_info = entra_service.user_manager.get_user_by_id(manager_id)
            
            if not user_info:
                logger.error(f"Manager with ID {manager_id} not found in Entra ID")
                return JsonResponse({
                    'success': False,
                    'error': f'Manager with ID {manager_id} not found in Entra ID'
                })
            
            logger.info(f"Found manager in Entra: {user_info.get('displayName', 'Unknown')}")
            
            # Create or update local EntraUser record
            manager, created = EntraUser.objects.get_or_create(
                entra_user_id=manager_id,
                defaults={
                    'user_principal_name': user_info.get('userPrincipalName', ''),
                    'display_name': user_info.get('displayName', ''),
                    'email': user_info.get('mail', user_info.get('userPrincipalName', '')),
                    'job_title': user_info.get('jobTitle', ''),
                    'department': user_info.get('department', ''),
                    'account_enabled': user_info.get('accountEnabled', True)
                }
            )
            
            # Update existing record if needed
            if not created:
                manager.display_name = user_info.get('displayName', manager.display_name)
                manager.email = user_info.get('mail', manager.email)
                manager.job_title = user_info.get('jobTitle', manager.job_title)
                manager.department = user_info.get('department', manager.department)
                manager.account_enabled = user_info.get('accountEnabled', manager.account_enabled)
                manager.save()
            
            logger.info(f"Manager {'created' if created else 'updated'} locally: {manager.display_name}")
                
        except Exception as e:
            logger.error(f"Error finding manager: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f'Error finding manager: {str(e)}'
            })
        
        # Generate employee ID
        employee_id = ServiceAccount.generate_employee_id()
        
        # Generate secure password for the service account
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(24))
        
        # Create Service Account in Entra ID first
        entra_user_data = {
            'displayName': display_name,
            'userPrincipalName': user_principal_name,
            'mail': user_principal_name,  # Set email to UPN as well
            'mailNickname': user_principal_name.split('@')[0],
            'accountEnabled': True,
            'passwordProfile': {
                'password': password,
                'forceChangePasswordNextSignIn': False
            },
            'jobTitle': 'Service Account',
            'department': department or 'Automation',
            'employeeId': employee_id,
            'usageLocation': 'US',  # Required for license assignment
            'userType': 'Member'
        }
        
        # Create user in Entra ID
        entra_creation_result = entra_service.user_manager.create_user(entra_user_data)
        
        if not entra_creation_result.get('success'):
            logger.error(f"Failed to create service account in Entra ID: {entra_creation_result.get('error')}")
            return JsonResponse({
                'success': False,
                'error': f"Failed to create service account in Entra ID: {entra_creation_result.get('error', 'Unknown error')}"
            })
        
        entra_user_id = entra_creation_result.get('user', {}).get('id')
        
        # Create local Service Account record
        service_account = ServiceAccount.objects.create(
            employee_id=employee_id,
            service_name=service_name,
            user_principal_name=user_principal_name,
            display_name=display_name,
            description=description,
            account_type=account_type,
            department=department,
            manager=manager,
            owner=request.user,
            job_title='Service Account',
            employee_type='Automation',
            status='ACTIVE',  # Mark as active since it was created in Entra ID
            entra_user_id=entra_user_id,  # Store the Entra ID
            created_by=request.user
        )
        
        # Create vault entry for the service account
        credential_type, _ = CredentialType.objects.get_or_create(
            name='Service Account',
            defaults={'description': 'Service account credentials'}
        )
        
        vault_entry = VaultEntry.objects.create(
            name=f"Service Account - {service_name}",
            username=user_principal_name,
            password=password,  # In production, this should be encrypted
            credential_type=credential_type,
            owner=request.user,
            notes=f"Auto-generated password for service account {employee_id}",
            created_by=request.user,
            updated_by=request.user
        )
        
        # Link vault entry to service account and update status
        service_account.vault_entry = vault_entry
        service_account.password_last_set = timezone.now()
        service_account.schedule_password_rotation()
        service_account.status = 'ACTIVE'  # Update status from PENDING to ACTIVE
        service_account.save()
        
        # Log the creation
        AuditLogger.log_security_event(
            category='USER',
            action='SERVICE_ACCOUNT_CREATED',
            user=request.user,
            description=f"Service account '{service_name}' created with Employee ID {employee_id}",
            request=request,
            severity='MEDIUM',
            success=True,
            risk_score=20,
            details={
                'employee_id': employee_id,
                'service_name': service_name,
                'user_principal_name': user_principal_name,
                'entra_user_id': entra_user_id,
                'manager': manager.display_name,
                'created_in_entra': True,
                'department': department
            }
        )
        
        # Send to Sentinel
        sentinel_service = get_sentinel_service()
        if sentinel_service.is_enabled():
            run_sentinel_async(
                sentinel_service.send_service_identity_event(
                    user=request.user,
                    action='CREATE',
                    identity_type='SERVICE_ACCOUNT',
                    identity_id=employee_id,
                    request=request,
                    details={
                        'service_name': service_name,
                        'user_principal_name': user_principal_name,
                        'manager': manager.display_name,
                        'department': department
                    }
                )
            )
        
        return JsonResponse({
            'success': True,
            'service_account': {
                'id': service_account.id,
                'employee_id': service_account.employee_id,
                'service_name': service_account.service_name
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating service account: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
@require_http_methods(['GET'])
def search_managers(request):
    """Search for managers in Entra ID for Service Account creation"""
    try:
        search_term = request.GET.get('q', '').strip()
        
        if len(search_term) < 2:
            return JsonResponse({
                'success': True,
                'users': []
            })
        
        # Use Entra Integration Service to search for users
        from .entra_integration import EntraIntegrationService
        
        entra_service = EntraIntegrationService()
        
        # Check if Entra is configured
        if not entra_service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra ID integration is not configured. Please configure it first.'
            })
        
        # Search users in Entra ID
        search_result = entra_service.user_manager.search_users(search_term)
        
        if not search_result.get('success'):
            logger.error(f"Entra user search failed: {search_result.get('error')}")
            return JsonResponse({
                'success': False,
                'error': f"Search failed: {search_result.get('error', 'Unknown error')}"
            })
        
        users_data = []
        entra_users = search_result.get('users', [])
        
        for user in entra_users:
            users_data.append({
                'id': user.get('id'),  # Use actual Entra ID
                'type': 'entra',
                'display_name': user.get('displayName', ''),
                'user_principal_name': user.get('userPrincipalName', ''),
                'email': user.get('mail', user.get('userPrincipalName', '')),
                'job_title': user.get('jobTitle', ''),
                'department': user.get('department', ''),
                'source': 'Entra ID'
            })
        
        return JsonResponse({
            'success': True,
            'users': users_data[:10]  # Limit to 10 results
        })
        
    except Exception as e:
        logger.error(f"Error searching managers: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"Search failed: {str(e)}"
        })


@login_required
@require_http_methods(["GET"])
def search_service_accounts(request):
    """Search for Service Accounts to link to Service Principals"""
    try:
        search_term = request.GET.get('q', '').strip()
        
        if len(search_term) < 2:
            return JsonResponse({
                'success': True,
                'accounts': []
            })
        
        # Search Service Accounts
        from .models import ServiceAccount
        
        accounts = ServiceAccount.objects.filter(
            Q(service_name__icontains=search_term) |
            Q(employee_id__icontains=search_term) |
            Q(description__icontains=search_term)
        )[:10]  # Limit to 10 results
        
        accounts_data = []
        for account in accounts:
            accounts_data.append({
                'id': account.id,
                'employee_id': account.employee_id,
                'service_name': account.service_name,
                'description': account.description or '',
                'display_name': f"{account.service_name} ({account.employee_id})"
            })
        
        return JsonResponse({
            'success': True,
            'accounts': accounts_data
        })
        
    except Exception as e:
        logger.error(f"Error searching service accounts: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"Search failed: {str(e)}"
        })


@login_required
@csrf_exempt
@require_POST
def create_service_principal(request):
    """Create a new Service Principal with Entra ID integration"""
    try:
        # Parse JSON data
        if hasattr(request, '_body'):
            body = request._body
        else:
            body = request.body
        
        data = json.loads(body)
        
        # Validate required fields
        required_fields = ['application_name', 'owner_id']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'error': f'{field.replace("_", " ").title()} is required.'
                })
        
        application_name = data.get('application_name').strip()
        application_type = data.get('application_type', 'web')  # Default to 'web'
        description = data.get('description', '').strip()
        home_page_url = data.get('home_page_url', '').strip()
        redirect_uris = data.get('redirect_uris', [])
        service_account_id = data.get('service_account_id')
        owner_id = data.get('owner_id')
        secret_expiration_months = int(data.get('secret_expiration_months', 6))  # Default to 6 months
        
        # Validate application type if provided
        valid_types = ['web', 'spa', 'mobile', 'daemon']
        if application_type and application_type not in valid_types:
            return JsonResponse({
                'success': False,
                'error': f'Invalid application type. Must be one of: {", ".join(valid_types)}.'
            })
        
        # Validate Service Account if provided
        service_account = None
        if service_account_id:
            try:
                from .models import ServiceAccount
                service_account = ServiceAccount.objects.get(id=service_account_id)
            except ServiceAccount.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Selected Service Account not found.'
                })
        
        # Create Service Principal in Entra ID first
        from .entra_integration import EntraIntegrationService
        
        entra_service = EntraIntegrationService()
        
        # Check if Entra is configured
        if not entra_service.is_configured():
            return JsonResponse({
                'success': False,
                'error': 'Entra ID integration is not configured. Please configure it first.'
            })
        
        # Prepare app registration data
        app_data = {
            'displayName': application_name,
            'signInAudience': 'AzureADMyOrg',  # Single tenant
            'requiredResourceAccess': []
        }
        
        # Add platform-specific configurations based on application type
        if application_type == 'web':
            if redirect_uris or home_page_url:
                app_data['web'] = {}
                if redirect_uris:
                    app_data['web']['redirectUris'] = redirect_uris
                if home_page_url:
                    app_data['web']['homePageUrl'] = home_page_url
        elif application_type == 'spa':
            if redirect_uris:
                app_data['spa'] = {
                    'redirectUris': redirect_uris
                }
        elif application_type == 'mobile':
            if redirect_uris:
                app_data['publicClient'] = {
                    'redirectUris': redirect_uris
                }
        # daemon type doesn't need redirect URIs
        
        # Create app registration in Entra ID
        app_creation_result = entra_service.application_manager.create_application(app_data)
        
        if not app_creation_result.get('success'):
            logger.error(f"Entra app creation failed: {app_creation_result.get('error')}")
            return JsonResponse({
                'success': False,
                'error': f"Failed to create application in Entra ID: {app_creation_result.get('error', 'Unknown error')}"
            })
        
        app_info = app_creation_result.get('application', {})
        app_id = app_info.get('appId')  # Client ID
        object_id = app_info.get('id')  # Object ID
        
        # Create Service Principal for the app
        sp_creation_result = entra_service.application_manager.create_service_principal(app_id)
        
        if not sp_creation_result.get('success'):
            logger.error(f"Service Principal creation failed: {sp_creation_result.get('error')}")
            # Try to clean up the app registration
            try:
                entra_service.application_manager.delete_application(object_id)
            except:
                pass
            return JsonResponse({
                'success': False,
                'error': f"Failed to create Service Principal: {sp_creation_result.get('error', 'Unknown error')}"
            })
        
        sp_info = sp_creation_result.get('service_principal', {})
        
        # Add owner to the application
        owner_result = entra_service.application_manager.add_application_owner(object_id, owner_id)
        
        if not owner_result.get('success'):
            logger.warning(f"Failed to add owner to application: {owner_result.get('error')}")
            # Continue anyway as the app is created, just log the warning
        
        # Generate client secret
        secret_creation_result = entra_service.application_manager.create_application_secret(
            object_id, 
            f"{application_name} Secret",
            secret_expiration_months
        )
        
        if not secret_creation_result.get('success'):
            logger.error(f"Secret creation failed: {secret_creation_result.get('error')}")
            # Clean up created resources
            try:
                entra_service.application_manager.delete_application(object_id)
            except:
                pass
            return JsonResponse({
                'success': False,
                'error': f"Failed to create client secret: {secret_creation_result.get('error', 'Unknown error')}"
            })
        
        secret_info = secret_creation_result.get('secret', {})
        client_secret_value = secret_info.get('secretText')
        secret_key_id = secret_info.get('keyId')
        
        # Create local ServicePrincipal record
        from .models import ServicePrincipal, ServicePrincipalSecret
        
        try:
            with transaction.atomic():
                # Map application type to model choices
                type_mapping = {
                    'web': 'WEB',
                    'spa': 'SPA',
                    'mobile': 'NATIVE',
                    'daemon': 'DAEMON'
                }
                
                # Create Service Principal
                service_principal = ServicePrincipal.objects.create(
                application_name=application_name,
                application_type=type_mapping.get(application_type, 'WEB'),
                description=description,
                home_page_url=home_page_url,
                redirect_uris=redirect_uris,
                service_account=service_account,
                client_id=app_id,
                entra_app_id=app_id,  # Application ID
                entra_object_id=object_id,  # Service Principal Object ID
                tenant_id=entra_service.tenant_id,
                owner=request.user,
                owner_entra_id=owner_id,
                created_by=request.user
                )
                
                # Create Service Principal Secret record
                from dateutil import parser
                expires_at_str = secret_info.get('endDateTime')
                expires_at = parser.parse(expires_at_str) if expires_at_str else None
                
                secret = ServicePrincipalSecret.objects.create(
                service_principal=service_principal,
                secret_id=secret_key_id,
                display_name=f"{application_name} Secret",
                description=f"Client secret for {application_name}",
                secret_value=client_secret_value,  # This should be encrypted in production
                created_date=timezone.now(),
                expires_at=expires_at
                )
                
                # Vault the credentials
                from .models import VaultEntry, CredentialType
                
                # Get or create Service Principal credential type
                sp_credential_type, _ = CredentialType.objects.get_or_create(
                name='Service Principal',
                defaults={
                    'description': 'Service Principal credentials for app registrations'
                }
                )
                
                # Create vault entry for Service Principal
                vault_entry = VaultEntry.objects.create(
                    name=f"SP - {application_name}",
                    username=app_id,  # Client ID as username
                    password=client_secret_value,  # Client Secret as password
                    credential_type=sp_credential_type,
                    owner=request.user,
                    url=f"https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/Overview/appId/{app_id}",
                    notes=f"Service Principal for {application_name}\n\nDescription: {description}\n\nClient ID: {app_id}\nObject ID: {object_id}\nTenant ID: {entra_service.tenant_id}\nApplication Type: {application_type}",
                    created_by=request.user,
                    updated_by=request.user
                )
                
                # Link vault entry to Service Principal and update status
                service_principal.vault_entry = vault_entry
                service_principal.status = 'ACTIVE'  # Update status from PENDING to ACTIVE
                service_principal.save()
        
        except Exception as e:
            # Local creation failed, clean up Entra resources
            logger.error(f"Failed to create Service Principal locally: {str(e)}")
            
            # Try to clean up the Entra resources
            try:
                logger.info(f"Attempting to clean up Entra resources for {application_name}")
                entra_service.application_manager.delete_application(object_id)
                logger.info(f"Successfully deleted orphaned application {object_id}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up Entra application {object_id}: {cleanup_error}")
                # Return error with cleanup warning
                return JsonResponse({
                    'success': False,
                    'error': f"Failed to create Service Principal locally: {str(e)}. WARNING: Application was created in Entra ID but could not be removed. Please manually delete app with Object ID: {object_id}"
                })
            
            # Return the original error
            return JsonResponse({
                'success': False,
                'error': f"Failed to create Service Principal: {str(e)}"
            })
        
        # Log the creation
        AuditLogger.log_security_event(
            category='SERVICE_IDENTITY',
            action='SERVICE_PRINCIPAL_CREATE',
            user=request.user,
            description=f"Created Service Principal: {application_name} ({app_id})",
            request=request,
            severity='MEDIUM',
            success=True,
            details={
                'application_name': application_name,
                'application_type': application_type,
                'client_id': app_id,
                'service_account_id': service_account_id if service_account else None
            }
        )
        
        # Send to Sentinel
        sentinel_service = get_sentinel_service()
        if sentinel_service.is_enabled():
            run_sentinel_async(
                sentinel_service.send_service_identity_event(
                    user=request.user,
                    action='CREATE',
                    identity_type='SERVICE_PRINCIPAL',
                    identity_id=app_id,
                    request=request,
                    details={
                        'application_name': application_name,
                        'application_type': application_type,
                        'client_id': app_id,
                        'object_id': object_id,
                        'tenant_id': entra_service.tenant_id
                    }
                )
            )
        
        return JsonResponse({
            'success': True,
            'message': f'Service Principal "{application_name}" created successfully!',
            'service_principal': {
                'id': service_principal.id,
                'application_name': application_name,
                'client_id': app_id,
                'application_type': application_type
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data.'
        })
    except Exception as e:
        logger.error(f"Error creating Service Principal: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"Failed to create Service Principal: {str(e)}"
        })


# Sentinel Integration Views
@login_required
@require_http_methods(['GET', 'POST'])
def sentinel_config(request):
    """Manage Sentinel integration configuration"""
    try:
        if request.method == 'GET':
            # Get current Sentinel configuration
            from .models import SentinelIntegration
            config = SentinelIntegration.objects.filter(enabled=True).first()
            
            return JsonResponse({
                'success': True,
                'config': {
                    'enabled': config.enabled if config else False,
                    'workspace_id': config.workspace_id if config else '',
                    'data_collection_endpoint': config.data_collection_endpoint if config else '',
                    'data_collection_rule_id': config.data_collection_rule_id if config else '',
                    'stream_name': config.stream_name if config else 'Custom-MenshunPAM_CL',
                    'connector_type': config.connector_type if config else 'LOG_ANALYTICS',
                    'batch_size': config.batch_size if config else 10,
                    'batch_timeout': config.batch_timeout if config else 30,
                    'send_auth_events': config.send_auth_events if config else True,
                    'send_vault_events': config.send_vault_events if config else True,
                    'send_service_identity_events': config.send_service_identity_events if config else True,
                    'send_privileged_access_events': config.send_privileged_access_events if config else True,
                    'last_event_count': config.last_event_count if config else 0,
                    'last_success': config.last_success.isoformat() if config and config.last_success else None,
                    'last_error': config.last_error if config else None,
                } if config else {
                    'enabled': False,
                    'workspace_id': '',
                    'data_collection_endpoint': '',
                    'data_collection_rule_id': '',
                    'stream_name': 'Custom-MenshunPAM_CL',
                    'connector_type': 'LOG_ANALYTICS',
                    'batch_size': 10,
                    'batch_timeout': 30,
                    'send_auth_events': True,
                    'send_vault_events': True,
                    'send_service_identity_events': True,
                    'send_privileged_access_events': True,
                    'last_event_count': 0,
                    'last_success': None,
                    'last_error': None,
                }
            })
            
        elif request.method == 'POST':
            # Update Sentinel configuration
            data = json.loads(request.body)
            
            from .models import SentinelIntegration
            
            # Get or create configuration
            config, created = SentinelIntegration.objects.get_or_create(
                defaults={
                    'enabled': data.get('enabled', False),
                    'workspace_id': data.get('workspace_id', ''),
                    'data_collection_endpoint': data.get('data_collection_endpoint', ''),
                    'data_collection_rule_id': data.get('data_collection_rule_id', ''),
                    'stream_name': data.get('stream_name', 'Custom-MenshunPAM_CL'),
                    'connector_type': data.get('connector_type', 'LOG_ANALYTICS'),
                    'batch_size': data.get('batch_size', 10),
                    'batch_timeout': data.get('batch_timeout', 30),
                    'send_auth_events': data.get('send_auth_events', True),
                    'send_vault_events': data.get('send_vault_events', True),
                    'send_service_identity_events': data.get('send_service_identity_events', True),
                    'send_privileged_access_events': data.get('send_privileged_access_events', True),
                    'created_by': request.user,
                    'updated_by': request.user,
                }
            )
            
            if not created:
                # Update existing configuration
                config.enabled = data.get('enabled', config.enabled)
                config.workspace_id = data.get('workspace_id', config.workspace_id)
                config.data_collection_endpoint = data.get('data_collection_endpoint', config.data_collection_endpoint)
                config.data_collection_rule_id = data.get('data_collection_rule_id', config.data_collection_rule_id)
                config.stream_name = data.get('stream_name', config.stream_name)
                config.connector_type = data.get('connector_type', config.connector_type)
                config.batch_size = data.get('batch_size', config.batch_size)
                config.batch_timeout = data.get('batch_timeout', config.batch_timeout)
                config.send_auth_events = data.get('send_auth_events', config.send_auth_events)
                config.send_vault_events = data.get('send_vault_events', config.send_vault_events)
                config.send_service_identity_events = data.get('send_service_identity_events', config.send_service_identity_events)
                config.send_privileged_access_events = data.get('send_privileged_access_events', config.send_privileged_access_events)
                config.updated_by = request.user
                config.save()
            
            # Log configuration change
            AuditLogger.log_security_event(
                category='INTEGRATION',
                action='SENTINEL_CONFIG_UPDATE',
                user=request.user,
                description=f"Sentinel integration configuration {'enabled' if config.enabled else 'disabled'}",
                request=request,
                severity='HIGH',
                success=True,
                details={
                    'enabled': config.enabled,
                    'connector_type': config.connector_type,
                    'created': created
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Sentinel configuration updated successfully',
                'created': created
            })
            
    except Exception as e:
        logger.error(f"Error managing Sentinel configuration: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@login_required
@require_http_methods(['POST'])
def sentinel_test(request):
    """Test Sentinel integration by sending a test event"""
    try:
        sentinel_service = get_sentinel_service()
        
        if not sentinel_service.is_enabled():
            return JsonResponse({
                'success': False,
                'error': 'Sentinel integration is not enabled or configured'
            })
        
        # Send a test event
        run_sentinel_async(
            sentinel_service.send_authentication_event(
                user=request.user,
                request=request,
                success=True,
                details={
                    'test_event': True,
                    'message': 'This is a test event from Menshun PAM'
                }
            )
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Test event sent successfully to Sentinel'
        })
        
    except Exception as e:
        logger.error(f"Error testing Sentinel integration: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        })
