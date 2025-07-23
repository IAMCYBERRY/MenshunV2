from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .authentication import (
    CustomTokenObtainPairView, logout_view, 
    microsoft_login, microsoft_callback
)
from .views import (
    VaultEntryViewSet, CredentialTypeViewSet, dashboard_view, pam_dashboard_view,
    vault_entries_view, credential_types_view, user_management_view,
    audit_logs_view, api_docs_view, create_vault_entry, update_vault_entry,
    get_vault_entry, delete_vault_entry, get_users, create_user, update_user, delete_user,
    get_audit_logs, get_credential_types, create_credential_type, update_credential_type, delete_credential_type,
    # Integration endpoints
    integration_overview, entra_config, entra_test, entra_activity, admin_overview,
    entra_user_search, entra_user_details, entra_create_admin,
    # Role management endpoints
    entra_user_roles, entra_available_roles, entra_assign_role, entra_remove_role, entra_role_members,
    # Cloud admin management
    cloud_admins, create_test_admin_logs, admin_details, reset_admin_password, toggle_admin_account, update_admin_account,
    # Service Identity management
    service_identities_view, get_next_employee_id, create_service_account, search_managers,
    search_service_accounts, create_service_principal,
    # Sentinel Integration
    sentinel_config, sentinel_test
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
    path('pam-dashboard/', pam_dashboard_view, name='pam_dashboard'),
    path('vault/', vault_entries_view, name='vault_entries'),
    path('credentials/', credential_types_view, name='credential_types'),
    path('service-identities/', service_identities_view, name='service_identities'),
    
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
    
    # AJAX endpoints for integrations
    path('ajax/integration-overview/', integration_overview, name='ajax_integration_overview'),
    path('ajax/admin-overview/', admin_overview, name='ajax_admin_overview'),
    path('ajax/entra-config/', entra_config, name='ajax_entra_config'),
    path('ajax/entra-test/', entra_test, name='ajax_entra_test'),
    path('ajax/entra-activity/', entra_activity, name='ajax_entra_activity'),
    path('ajax/entra-user-search/', entra_user_search, name='ajax_entra_user_search'),
    path('ajax/entra-user-details/<str:user_id>/', entra_user_details, name='ajax_entra_user_details'),
    path('ajax/entra-create-admin/', entra_create_admin, name='ajax_entra_create_admin'),
    
    # Role management endpoints
    path('ajax/entra-user-roles/<str:user_id>/', entra_user_roles, name='ajax_entra_user_roles'),
    path('ajax/entra-available-roles/', entra_available_roles, name='ajax_entra_available_roles'),
    path('ajax/entra-assign-role/', entra_assign_role, name='ajax_entra_assign_role'),
    path('ajax/entra-remove-role/', entra_remove_role, name='ajax_entra_remove_role'),
    path('ajax/entra-role-members/<str:role_id>/', entra_role_members, name='ajax_entra_role_members'),
    path('ajax/cloud-admins/', cloud_admins, name='ajax_cloud_admins'),
    path('ajax/create-test-admin-logs/', create_test_admin_logs, name='ajax_create_test_admin_logs'),
    path('ajax/admin-details/<str:username>/', admin_details, name='ajax_admin_details'),
    path('ajax/admin-reset-password/<str:username>/', reset_admin_password, name='ajax_reset_admin_password'),
    path('ajax/admin-toggle-account/<str:username>/', toggle_admin_account, name='ajax_toggle_admin_account'),
    path('ajax/admin-update-account/<str:username>/', update_admin_account, name='ajax_update_admin_account'),
    
    # Service Identity AJAX endpoints
    path('ajax/get-next-employee-id/', get_next_employee_id, name='ajax_get_next_employee_id'),
    path('ajax/create-service-account/', create_service_account, name='ajax_create_service_account'),
    path('ajax/search-managers/', search_managers, name='ajax_search_managers'),
    path('ajax/search-service-accounts/', search_service_accounts, name='ajax_search_service_accounts'),
    path('ajax/create-service-principal/', create_service_principal, name='ajax_create_service_principal'),
    
    # Sentinel Integration AJAX endpoints
    path('ajax/sentinel-config/', sentinel_config, name='ajax_sentinel_config'),
    path('ajax/sentinel-test/', sentinel_test, name='ajax_sentinel_test'),
]