from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .authentication import (
    CustomTokenObtainPairView, logout_view, 
    microsoft_login, microsoft_callback
)
from .views import (
    VaultEntryViewSet, CredentialTypeViewSet, dashboard_view,
    vault_entries_view, credential_types_view, user_management_view,
    audit_logs_view, api_docs_view, create_vault_entry, update_vault_entry,
    get_vault_entry, delete_vault_entry, get_users, create_user, update_user, delete_user,
    get_audit_logs, get_credential_types, create_credential_type, update_credential_type, delete_credential_type
)

# Create a router for DRF ViewSets
router = DefaultRouter()
router.register(r'vault-entries', VaultEntryViewSet, basename='vaultentry')
router.register(r'credential-types', CredentialTypeViewSet, basename='credentialtype')

app_name = 'vault'

urlpatterns = [
    # Authentication endpoints
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', logout_view, name='logout'),
    
    # Microsoft Entra authentication
    path('auth/microsoft/login/', microsoft_login, name='microsoft_login'),
    path('auth/microsoft/callback/', microsoft_callback, name='microsoft_callback'),
    
    # API endpoints
    path('api/', include(router.urls)),
    
    # Main application views
    path('', dashboard_view, name='home'),  # Default home view
    path('dashboard/', dashboard_view, name='dashboard'),
    path('vault/', vault_entries_view, name='vault_entries'),
    path('credentials/', credential_types_view, name='credential_types'),
    
    # Admin views
    path('users/', user_management_view, name='user_management'),
    path('audit/', audit_logs_view, name='audit_logs'),
    path('docs/', api_docs_view, name='api_docs'),
    
    # AJAX endpoints for vault entry management
    path('ajax/vault-entry/create/', create_vault_entry, name='ajax_create_vault_entry'),
    path('ajax/vault-entry/<int:entry_id>/update/', update_vault_entry, name='ajax_update_vault_entry'),
    path('ajax/vault-entry/<int:entry_id>/get/', get_vault_entry, name='ajax_get_vault_entry'),
    path('ajax/vault-entry/<int:entry_id>/delete/', delete_vault_entry, name='ajax_delete_vault_entry'),
    
    # AJAX endpoints for user management
    path('ajax/users/', get_users, name='ajax_get_users'),
    path('ajax/user/create/', create_user, name='ajax_create_user'),
    path('ajax/user/<int:user_id>/update/', update_user, name='ajax_update_user'),
    path('ajax/user/<int:user_id>/delete/', delete_user, name='ajax_delete_user'),
    
    # AJAX endpoints for audit logs
    path('ajax/audit-logs/', get_audit_logs, name='ajax_get_audit_logs'),
    
    # AJAX endpoints for credential type management
    path('ajax/credential-types/', get_credential_types, name='ajax_get_credential_types'),
    path('ajax/credential-type/create/', create_credential_type, name='ajax_create_credential_type'),
    path('ajax/credential-type/<int:type_id>/update/', update_credential_type, name='ajax_update_credential_type'),
    path('ajax/credential-type/<int:type_id>/delete/', delete_credential_type, name='ajax_delete_credential_type'),
]