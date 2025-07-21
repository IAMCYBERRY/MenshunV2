from django.core.management.base import BaseCommand
from vault.models import CredentialType


class Command(BaseCommand):
    help = 'Set up sample credential types for Menshen PAM'

    def handle(self, *args, **options):
        # Create sample credential types
        credential_types = [
            {
                'name': 'Database',
                'description': 'Database server credentials (MySQL, PostgreSQL, etc.)'
            },
            {
                'name': 'Server',
                'description': 'Server and system access credentials'
            },
            {
                'name': 'API Key',
                'description': 'API keys and tokens for external services'
            },
            {
                'name': 'Cloud Service',
                'description': 'Cloud platform credentials (AWS, Azure, GCP)'
            },
            {
                'name': 'Application',
                'description': 'Application-specific credentials and service accounts'
            },
            {
                'name': 'Network Device',
                'description': 'Network equipment credentials (routers, switches, firewalls)'
            },
        ]
        
        created_count = 0
        for ct_data in credential_types:
            credential_type, created = CredentialType.objects.get_or_create(
                name=ct_data['name'],
                defaults={'description': ct_data['description']}
            )
            if created:
                created_count += 1
                self.stdout.write(f'Created credential type: {credential_type.name}')
            else:
                self.stdout.write(f'Credential type already exists: {credential_type.name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully set up {created_count} new credential types')
        )