from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from vault.models import VaultEntry, CredentialType


class Command(BaseCommand):
    help = 'Set up default groups and permissions for Menshen PAM'

    def handle(self, *args, **options):
        # Create groups
        vault_admin_group, created = Group.objects.get_or_create(name='Vault Admin')
        vault_editor_group, created = Group.objects.get_or_create(name='Vault Editor')
        vault_viewer_group, created = Group.objects.get_or_create(name='Vault Viewer')
        
        # Get content types
        vault_entry_ct = ContentType.objects.get_for_model(VaultEntry)
        credential_type_ct = ContentType.objects.get_for_model(CredentialType)
        
        # Vault Admin permissions (full access)
        admin_permissions = [
            # VaultEntry permissions
            Permission.objects.get_or_create(
                codename='view_vaultentry',
                name='Can view vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='add_vaultentry',
                name='Can add vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='change_vaultentry',
                name='Can change vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='delete_vaultentry',
                name='Can delete vault entry',
                content_type=vault_entry_ct
            )[0],
            # CredentialType permissions
            Permission.objects.get_or_create(
                codename='view_credentialtype',
                name='Can view credential type',
                content_type=credential_type_ct
            )[0],
            Permission.objects.get_or_create(
                codename='add_credentialtype',
                name='Can add credential type',
                content_type=credential_type_ct
            )[0],
            Permission.objects.get_or_create(
                codename='change_credentialtype',
                name='Can change credential type',
                content_type=credential_type_ct
            )[0],
            Permission.objects.get_or_create(
                codename='delete_credentialtype',
                name='Can delete credential type',
                content_type=credential_type_ct
            )[0],
        ]
        
        # Vault Editor permissions (CRUD but limited delete)
        editor_permissions = [
            Permission.objects.get_or_create(
                codename='view_vaultentry',
                name='Can view vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='add_vaultentry',
                name='Can add vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='change_vaultentry',
                name='Can change vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='view_credentialtype',
                name='Can view credential type',
                content_type=credential_type_ct
            )[0],
        ]
        
        # Vault Viewer permissions (read-only)
        viewer_permissions = [
            Permission.objects.get_or_create(
                codename='view_vaultentry',
                name='Can view vault entry',
                content_type=vault_entry_ct
            )[0],
            Permission.objects.get_or_create(
                codename='view_credentialtype',
                name='Can view credential type',
                content_type=credential_type_ct
            )[0],
        ]
        
        # Assign permissions to groups
        vault_admin_group.permissions.set(admin_permissions)
        vault_editor_group.permissions.set(editor_permissions)
        vault_viewer_group.permissions.set(viewer_permissions)
        
        self.stdout.write(
            self.style.SUCCESS('Successfully created groups and permissions:')
        )
        self.stdout.write(f'  - Vault Admin: {len(admin_permissions)} permissions')
        self.stdout.write(f'  - Vault Editor: {len(editor_permissions)} permissions')
        self.stdout.write(f'  - Vault Viewer: {len(viewer_permissions)} permissions')