import secrets

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = (
        'Creates a single superuser (username "admin") if no superuser exists yet. '
        'Idempotent — safe to run on every deploy. Prints the generated password '
        'once; use that account to log in and create everyone else.'
    )

    def handle(self, *args, **options):
        User = get_user_model()

        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write('A superuser already exists — skipping.')
            return

        password = secrets.token_urlsafe(16)
        User.objects.create_superuser(
            username='admin', email='admin@menshun.local', password=password
        )

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(self.style.SUCCESS('Initial superuser created — SAVE THIS PASSWORD NOW:'))
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(f'  Username: admin')
        self.stdout.write(f'  Password: {password}')
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write('Log in and create individual accounts for everyone else.')
        self.stdout.write('')
