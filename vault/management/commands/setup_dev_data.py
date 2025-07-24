from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from vault.models import CredentialType, VaultEntry

User = get_user_model()


class Command(BaseCommand):
    help = 'Set up development data including users, groups, and sample vault entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset all data before creating (WARNING: This deletes all existing data)',
        )

    def handle(self, *args, **options):
        if options['reset']:
            self.stdout.write(self.style.WARNING('Resetting all data...'))
            self.reset_data()

        with transaction.atomic():
            self.create_groups()
            self.create_users()
            self.create_credential_types()
            self.create_sample_vault_entries()

        self.stdout.write(
            self.style.SUCCESS('Successfully set up development data!')
        )

    def reset_data(self):
        """Reset all data - use with caution!"""
        User.objects.filter(is_superuser=False).delete()
        VaultEntry.objects.all().delete()
        CredentialType.objects.all().delete()
        Group.objects.all().delete()
        self.stdout.write('All data reset.')

    def create_groups(self):
        """Create user groups with permissions"""
        from vault.management.commands.setup_groups import Command as SetupGroupsCommand
        
        setup_groups = SetupGroupsCommand()
        setup_groups.handle()
        self.stdout.write('✓ Groups and permissions created')

    def create_users(self):
        """Create development test users"""
        users_data = [
            {
                'username': 'admin',
                'password': 'admin123',
                'email': 'admin@menshun.local',
                'first_name': 'Admin',
                'last_name': 'User',
                'is_superuser': True,
                'is_staff': True
            },
            {
                'username': 'vault_admin',
                'password': 'admin123',
                'email': 'vault.admin@menshun.local',
                'first_name': 'Vault',
                'last_name': 'Admin',
                'group': 'Vault Admin'
            },
            {
                'username': 'vault_editor',
                'password': 'editor123',
                'email': 'vault.editor@menshun.local',
                'first_name': 'Vault',
                'last_name': 'Editor',
                'group': 'Vault Editor'
            },
            {
                'username': 'vault_viewer',
                'password': 'viewer123',
                'email': 'vault.viewer@menshun.local',
                'first_name': 'Vault',
                'last_name': 'Viewer',
                'group': 'Vault Viewer'
            },
        ]

        for user_data in users_data:
            user, created = User.objects.get_or_create(
                username=user_data['username'],
                defaults={
                    'email': user_data['email'],
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name'],
                    'is_superuser': user_data.get('is_superuser', False),
                    'is_staff': user_data.get('is_staff', False),
                }
            )
            
            if created:
                user.set_password(user_data['password'])
                user.save()
                self.stdout.write(f'  Created user: {user.username}')
            else:
                self.stdout.write(f'  User exists: {user.username}')
            
            # Add to group if specified
            if 'group' in user_data:
                try:
                    group = Group.objects.get(name=user_data['group'])
                    user.groups.add(group)
                    if created:
                        self.stdout.write(f'    Added to group: {group.name}')
                except Group.DoesNotExist:
                    self.stdout.write(
                        self.style.ERROR(f'    Group {user_data["group"]} does not exist')
                    )

        self.stdout.write('✓ Development users created')

    def create_credential_types(self):
        """Create sample credential types"""
        from vault.management.commands.setup_sample_data import Command as SetupSampleDataCommand
        
        setup_sample_data = SetupSampleDataCommand()
        setup_sample_data.handle()
        self.stdout.write('✓ Credential types created')

    def create_sample_vault_entries(self):
        """Create sample vault entries for testing"""
        if not CredentialType.objects.exists():
            self.stdout.write(self.style.WARNING('No credential types found, skipping vault entries'))
            return

        # Get credential types
        db_type = CredentialType.objects.filter(name='Database').first()
        server_type = CredentialType.objects.filter(name='Server').first()
        api_type = CredentialType.objects.filter(name='API Key').first()

        # Get admin user for ownership
        admin_user = User.objects.filter(username='admin').first()

        if not admin_user:
            self.stdout.write(self.style.WARNING('Admin user not found, skipping vault entries'))
            return

        sample_entries = []
        
        if db_type:
            sample_entries.append({
                'name': 'Production Database',
                'username': 'db_admin',
                'password': 'secure_db_password_123',
                'url': 'postgresql://prod-db.company.com:5432/maindb',
                'notes': 'Main production PostgreSQL database - handle with care',
                'credential_type': db_type,
                'owner': admin_user,
                'created_by': admin_user,
                'updated_by': admin_user,
            })

        if server_type:
            sample_entries.append({
                'name': 'Web Server SSH',
                'username': 'ubuntu',
                'password': 'ssh_key_stored_separately',
                'url': 'ssh://web-prod-01.company.com:22',
                'notes': 'SSH access to production web server - use SSH key authentication when possible',
                'credential_type': server_type,
                'owner': admin_user,
                'created_by': admin_user,
                'updated_by': admin_user,
            })

        if api_type:
            sample_entries.append({
                'name': 'Stripe API Key',
                'username': 'api_user',
                'password': 'sk_live_abcdef123456789',
                'url': 'https://api.stripe.com',
                'notes': 'Payment processing API credentials - rotate monthly',
                'credential_type': api_type,
                'owner': admin_user,
                'created_by': admin_user,
                'updated_by': admin_user,
            })

        created_count = 0
        for entry_data in sample_entries:
            entry, created = VaultEntry.objects.get_or_create(
                name=entry_data['name'],
                owner=entry_data['owner'],
                defaults={
                    'username': entry_data['username'],
                    'password': entry_data['password'],
                    'url': entry_data['url'],
                    'notes': entry_data['notes'],
                    'credential_type': entry_data['credential_type'],
                    'created_by': entry_data['created_by'],
                    'updated_by': entry_data['updated_by'],
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f'  Created vault entry: {entry.name}')
            else:
                self.stdout.write(f'  Vault entry exists: {entry.name}')

        self.stdout.write(f'✓ Created {created_count} sample vault entries')