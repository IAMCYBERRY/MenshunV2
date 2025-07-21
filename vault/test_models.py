import pytest
from django.test import TestCase
from django.contrib.auth.models import Group
from django.utils import timezone
from factory import django, Faker, SubFactory
from .models import CustomUser, CredentialType, VaultEntry, VaultAccessLog


class CustomUserFactory(django.DjangoModelFactory):
    """Factory for creating test users"""
    class Meta:
        model = CustomUser
    
    username = Faker('user_name')
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    source = 'local'
    is_active = True


class CredentialTypeFactory(django.DjangoModelFactory):
    """Factory for creating test credential types"""
    class Meta:
        model = CredentialType
    
    name = Faker('word')
    description = Faker('text', max_nb_chars=200)


class VaultEntryFactory(django.DjangoModelFactory):
    """Factory for creating test vault entries"""
    class Meta:
        model = VaultEntry
    
    name = Faker('catch_phrase')
    username = Faker('user_name')
    password = Faker('password', length=12, special_chars=True, digits=True, upper_case=True, lower_case=True)
    credential_type = SubFactory(CredentialTypeFactory)
    owner = SubFactory(CustomUserFactory)
    url = Faker('url')
    notes = Faker('text', max_nb_chars=500)


@pytest.mark.django_db
class TestCustomUser:
    """Test cases for CustomUser model"""
    
    def test_create_user(self):
        """Test creating a user"""
        user = CustomUserFactory()
        assert user.pk is not None
        assert user.source == 'local'
        assert user.is_active is True
        assert user.is_deleted is False
    
    def test_soft_delete_user(self):
        """Test soft deleting a user"""
        user = CustomUserFactory()
        assert user.is_deleted is False
        assert user.deleted_at is None
        assert user.is_active is True
        
        user.soft_delete()
        
        assert user.is_deleted is True
        assert user.deleted_at is not None
        assert user.is_active is False
    
    def test_restore_user(self):
        """Test restoring a soft deleted user"""
        user = CustomUserFactory()
        user.soft_delete()
        
        assert user.is_deleted is True
        assert user.is_active is False
        
        user.restore()
        
        assert user.is_deleted is False
        assert user.deleted_at is None
        assert user.is_active is True
    
    def test_entra_user_creation(self):
        """Test creating an Entra user"""
        user = CustomUserFactory(
            source='entra',
            aad_object_id='12345-67890-abcdef'
        )
        
        assert user.source == 'entra'
        assert user.aad_object_id == '12345-67890-abcdef'


@pytest.mark.django_db
class TestCredentialType:
    """Test cases for CredentialType model"""
    
    def test_create_credential_type(self):
        """Test creating a credential type"""
        cred_type = CredentialTypeFactory(name="Database")
        assert cred_type.pk is not None
        assert cred_type.name == "Database"
        assert cred_type.is_deleted is False
    
    def test_credential_type_str(self):
        """Test string representation"""
        cred_type = CredentialTypeFactory(name="API Key")
        assert str(cred_type) == "API Key"
    
    def test_soft_delete_credential_type(self):
        """Test soft deleting a credential type"""
        cred_type = CredentialTypeFactory()
        assert cred_type.is_deleted is False
        
        cred_type.soft_delete()
        
        assert cred_type.is_deleted is True
        assert cred_type.deleted_at is not None
    
    def test_restore_credential_type(self):
        """Test restoring a soft deleted credential type"""
        cred_type = CredentialTypeFactory()
        cred_type.soft_delete()
        
        cred_type.restore()
        
        assert cred_type.is_deleted is False
        assert cred_type.deleted_at is None


@pytest.mark.django_db
class TestVaultEntry:
    """Test cases for VaultEntry model"""
    
    def test_create_vault_entry(self):
        """Test creating a vault entry"""
        entry = VaultEntryFactory()
        assert entry.pk is not None
        assert entry.is_deleted is False
        assert entry.access_count == 0
        assert entry.last_accessed is None
    
    def test_vault_entry_str(self):
        """Test string representation"""
        cred_type = CredentialTypeFactory(name="Database")
        entry = VaultEntryFactory(name="Production DB", credential_type=cred_type)
        assert str(entry) == "Production DB (Database)"
    
    def test_soft_delete_vault_entry(self):
        """Test soft deleting a vault entry"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        assert entry.is_deleted is False
        assert entry.deleted_at is None
        assert entry.deleted_by is None
        
        entry.soft_delete(user)
        
        assert entry.is_deleted is True
        assert entry.deleted_at is not None
        assert entry.deleted_by == user
    
    def test_restore_vault_entry(self):
        """Test restoring a soft deleted vault entry"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        entry.soft_delete(user)
        
        entry.restore()
        
        assert entry.is_deleted is False
        assert entry.deleted_at is None
        assert entry.deleted_by is None
    
    def test_record_access(self):
        """Test recording access to a vault entry"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        assert entry.access_count == 0
        assert entry.last_accessed is None
        
        entry.record_access(user)
        
        assert entry.access_count == 1
        assert entry.last_accessed is not None
        
        # Check that access log was created
        access_log = VaultAccessLog.objects.get(vault_entry=entry, accessed_by=user)
        assert access_log.access_type == 'VIEW'
    
    def test_multiple_access_records(self):
        """Test multiple access records"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        # Record multiple accesses
        entry.record_access(user)
        entry.record_access(user)
        entry.record_access(user)
        
        assert entry.access_count == 3
        assert VaultAccessLog.objects.filter(vault_entry=entry, accessed_by=user).count() == 3


@pytest.mark.django_db
class TestVaultAccessLog:
    """Test cases for VaultAccessLog model"""
    
    def test_create_access_log(self):
        """Test creating an access log"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        log = VaultAccessLog.objects.create(
            vault_entry=entry,
            accessed_by=user,
            access_type='VIEW',
            ip_address='192.168.1.1',
            user_agent='Test Browser'
        )
        
        assert log.pk is not None
        assert log.vault_entry == entry
        assert log.accessed_by == user
        assert log.access_type == 'VIEW'
        assert log.ip_address == '192.168.1.1'
    
    def test_access_log_str(self):
        """Test string representation"""
        user = CustomUserFactory(username='testuser')
        entry = VaultEntryFactory(name='Test Entry')
        
        log = VaultAccessLog.objects.create(
            vault_entry=entry,
            accessed_by=user,
            access_type='VIEW'
        )
        
        assert 'testuser VIEW Test Entry' in str(log)
    
    def test_access_log_ordering(self):
        """Test that access logs are ordered by timestamp descending"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        # Create logs with slight time differences
        log1 = VaultAccessLog.objects.create(
            vault_entry=entry,
            accessed_by=user,
            access_type='VIEW'
        )
        
        log2 = VaultAccessLog.objects.create(
            vault_entry=entry,
            accessed_by=user,
            access_type='UPDATE'
        )
        
        logs = VaultAccessLog.objects.all()
        assert logs[0] == log2  # Most recent first
        assert logs[1] == log1


@pytest.mark.django_db
class TestModelRelationships:
    """Test model relationships and cascading"""
    
    def test_vault_entry_owner_cascade(self):
        """Test that vault entries are deleted when owner is deleted"""
        user = CustomUserFactory()
        entry = VaultEntryFactory(owner=user)
        
        assert VaultEntry.objects.filter(owner=user).count() == 1
        
        user.delete()
        
        assert VaultEntry.objects.filter(pk=entry.pk).count() == 0
    
    def test_credential_type_protection(self):
        """Test that credential types are protected from deletion when in use"""
        cred_type = CredentialTypeFactory()
        entry = VaultEntryFactory(credential_type=cred_type)
        
        with pytest.raises(Exception):  # Should raise ProtectedError
            cred_type.delete()
    
    def test_access_log_cascade(self):
        """Test that access logs are deleted when vault entry is deleted"""
        user = CustomUserFactory()
        entry = VaultEntryFactory()
        
        log = VaultAccessLog.objects.create(
            vault_entry=entry,
            accessed_by=user,
            access_type='VIEW'
        )
        
        assert VaultAccessLog.objects.filter(vault_entry=entry).count() == 1
        
        entry.delete()
        
        assert VaultAccessLog.objects.filter(pk=log.pk).count() == 0