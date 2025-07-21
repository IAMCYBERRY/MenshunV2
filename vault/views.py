from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.core.paginator import Paginator
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_http_methods
from django.db import models
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
import json
import logging

from .models import VaultEntry, CredentialType, VaultAccessLog, SystemAuditLog
from .audit import AuditLogger
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
