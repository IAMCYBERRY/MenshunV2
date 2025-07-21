import pytest
from django.test import TestCase
from django.contrib.auth.models import Group
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import json

from .models import CustomUser, CredentialType, VaultEntry
from .test_models import CustomUserFactory, CredentialTypeFactory, VaultEntryFactory


@pytest.mark.django_db
class TestAuthentication:
    """Test authentication endpoints"""
    
    def setup_method(self):
        self.client = APIClient()
    
    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        user = CustomUserFactory()
        user.set_password('testpassword123')
        user.save()
        
        url = reverse('vault:token_obtain_pair')
        data = {
            'username': user.username,
            'password': 'testpassword123'
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
        assert 'refresh' in response.data
        assert 'user' in response.data
        assert response.data['user']['username'] == user.username
    
    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        url = reverse('vault:token_obtain_pair')
        data = {
            'username': 'nonexistent',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_token_refresh(self):
        """Test token refresh"""
        user = CustomUserFactory()
        refresh = RefreshToken.for_user(user)
        
        url = reverse('vault:token_refresh')
        data = {'refresh': str(refresh)}
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data
    
    def test_logout(self):
        """Test logout endpoint"""
        user = CustomUserFactory()
        refresh = RefreshToken.for_user(user)
        
        url = reverse('vault:logout')
        data = {'refresh_token': str(refresh)}
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'message' in response.data


@pytest.mark.django_db
class TestVaultEntryAPI:
    """Test VaultEntry API endpoints"""
    
    def setup_method(self):
        self.client = APIClient()
        
        # Create groups
        self.vault_admin_group = Group.objects.create(name='Vault Admin')
        self.vault_editor_group = Group.objects.create(name='Vault Editor')
        self.vault_viewer_group = Group.objects.create(name='Vault Viewer')
        
        # Create users with different roles
        self.admin_user = CustomUserFactory()
        self.admin_user.groups.add(self.vault_admin_group)
        
        self.editor_user = CustomUserFactory()
        self.editor_user.groups.add(self.vault_editor_group)
        
        self.viewer_user = CustomUserFactory()
        self.viewer_user.groups.add(self.vault_viewer_group)
        
        self.regular_user = CustomUserFactory()  # No groups
        
        # Create test data
        self.credential_type = CredentialTypeFactory()
        self.vault_entry = VaultEntryFactory(
            owner=self.admin_user,
            credential_type=self.credential_type
        )
    
    def authenticate_user(self, user):
        """Helper to authenticate a user"""
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    
    def test_list_vault_entries_as_admin(self):
        """Test listing vault entries as admin"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1
        
        # Admin should see password length but not actual password in list view
        entry_data = response.data['results'][0]
        assert 'password_length' in entry_data
        assert 'password' not in entry_data
    
    def test_list_vault_entries_as_viewer(self):
        """Test listing vault entries as viewer (should only see own entries)"""
        # Create an entry owned by the viewer
        viewer_entry = VaultEntryFactory(
            owner=self.viewer_user,
            credential_type=self.credential_type
        )
        
        self.authenticate_user(self.viewer_user)
        
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        # Should only see their own entry, not the admin's entry
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['id'] == viewer_entry.id
    
    def test_list_vault_entries_unauthorized(self):
        """Test listing vault entries without authentication"""
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_list_vault_entries_no_groups(self):
        """Test listing vault entries with user that has no vault groups"""
        self.authenticate_user(self.regular_user)
        
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_retrieve_vault_entry_as_admin(self):
        """Test retrieving a specific vault entry as admin"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-detail', kwargs={'pk': self.vault_entry.pk})
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        # Detail view should include password for authorized users
        assert 'password' in response.data
        assert response.data['name'] == self.vault_entry.name
    
    def test_create_vault_entry_as_editor(self):
        """Test creating a vault entry as editor"""
        self.authenticate_user(self.editor_user)
        
        url = reverse('vault:vaultentry-list')
        data = {
            'name': 'New Test Entry',
            'username': 'testuser',
            'password': 'securepassword123',
            'credential_type_id': self.credential_type.id,
            'url': 'https://example.com',
            'notes': 'Test notes'
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'New Test Entry'
        assert response.data['owner']['id'] == self.editor_user.id
        
        # Verify entry was created in database
        entry = VaultEntry.objects.get(pk=response.data['id'])
        assert entry.owner == self.editor_user
        assert entry.created_by == self.editor_user
    
    def test_create_vault_entry_as_viewer(self):
        """Test creating a vault entry as viewer (should be forbidden)"""
        self.authenticate_user(self.viewer_user)
        
        url = reverse('vault:vaultentry-list')
        data = {
            'name': 'New Test Entry',
            'username': 'testuser',
            'password': 'securepassword123',
            'credential_type_id': self.credential_type.id
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_update_vault_entry_as_editor(self):
        """Test updating a vault entry as editor"""
        self.authenticate_user(self.editor_user)
        
        url = reverse('vault:vaultentry-detail', kwargs={'pk': self.vault_entry.pk})
        data = {
            'name': 'Updated Entry Name',
            'username': self.vault_entry.username,
            'password': self.vault_entry.password,
            'credential_type_id': self.credential_type.id
        }
        
        response = self.client.put(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'Updated Entry Name'
        
        # Verify update in database
        self.vault_entry.refresh_from_db()
        assert self.vault_entry.name == 'Updated Entry Name'
        assert self.vault_entry.updated_by == self.editor_user
    
    def test_delete_vault_entry_as_admin(self):
        """Test deleting a vault entry as admin"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-detail', kwargs={'pk': self.vault_entry.pk})
        response = self.client.delete(url)
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify entry was deleted
        with pytest.raises(VaultEntry.DoesNotExist):
            VaultEntry.objects.get(pk=self.vault_entry.pk)
    
    def test_delete_vault_entry_as_editor(self):
        """Test deleting a vault entry as editor (should be forbidden for others' entries)"""
        self.authenticate_user(self.editor_user)
        
        url = reverse('vault:vaultentry-detail', kwargs={'pk': self.vault_entry.pk})
        response = self.client.delete(url)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_password_endpoint(self):
        """Test the password-specific endpoint"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-password', kwargs={'pk': self.vault_entry.pk})
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'password' in response.data
        assert response.data['password'] == self.vault_entry.password
    
    def test_access_logs_endpoint(self):
        """Test the access logs endpoint"""
        # Record some access
        self.vault_entry.record_access(self.admin_user)
        
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-access-logs', kwargs={'pk': self.vault_entry.pk})
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data) >= 1
        assert response.data[0]['access_type'] == 'VIEW'
    
    def test_filtering_by_credential_type(self):
        """Test filtering vault entries by credential type"""
        other_type = CredentialTypeFactory(name='Other Type')
        other_entry = VaultEntryFactory(
            owner=self.admin_user,
            credential_type=other_type
        )
        
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url, {'credential_type': self.credential_type.id})
        
        assert response.status_code == status.HTTP_200_OK
        # Should only return entries with the specified credential type
        for entry in response.data['results']:
            assert entry['credential_type']['id'] == self.credential_type.id
    
    def test_searching_vault_entries(self):
        """Test searching vault entries"""
        searchable_entry = VaultEntryFactory(
            owner=self.admin_user,
            name='Searchable Entry',
            credential_type=self.credential_type
        )
        
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:vaultentry-list')
        response = self.client.get(url, {'search': 'Searchable'})
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1
        assert any(entry['name'] == 'Searchable Entry' for entry in response.data['results'])


@pytest.mark.django_db
class TestCredentialTypeAPI:
    """Test CredentialType API endpoints"""
    
    def setup_method(self):
        self.client = APIClient()
        
        # Create groups
        self.vault_admin_group = Group.objects.create(name='Vault Admin')
        self.vault_viewer_group = Group.objects.create(name='Vault Viewer')
        
        # Create users
        self.admin_user = CustomUserFactory()
        self.admin_user.groups.add(self.vault_admin_group)
        
        self.viewer_user = CustomUserFactory()
        self.viewer_user.groups.add(self.vault_viewer_group)
        
        self.credential_type = CredentialTypeFactory()
    
    def authenticate_user(self, user):
        """Helper to authenticate a user"""
        refresh = RefreshToken.for_user(user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
    
    def test_list_credential_types(self):
        """Test listing credential types"""
        self.authenticate_user(self.viewer_user)
        
        url = reverse('vault:credentialtype-list')
        response = self.client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1
    
    def test_create_credential_type_as_admin(self):
        """Test creating credential type as admin"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:credentialtype-list')
        data = {
            'name': 'New Credential Type',
            'description': 'Test description'
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'New Credential Type'
    
    def test_create_credential_type_as_viewer(self):
        """Test creating credential type as viewer (should be forbidden)"""
        self.authenticate_user(self.viewer_user)
        
        url = reverse('vault:credentialtype-list')
        data = {
            'name': 'New Credential Type',
            'description': 'Test description'
        }
        
        response = self.client.post(url, data)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_update_credential_type_as_admin(self):
        """Test updating credential type as admin"""
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:credentialtype-detail', kwargs={'pk': self.credential_type.pk})
        data = {
            'name': 'Updated Type Name',
            'description': self.credential_type.description
        }
        
        response = self.client.put(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'Updated Type Name'
    
    def test_delete_credential_type_as_admin(self):
        """Test deleting credential type as admin"""
        deletable_type = CredentialTypeFactory()
        
        self.authenticate_user(self.admin_user)
        
        url = reverse('vault:credentialtype-detail', kwargs={'pk': deletable_type.pk})
        response = self.client.delete(url)
        
        assert response.status_code == status.HTTP_204_NO_CONTENT