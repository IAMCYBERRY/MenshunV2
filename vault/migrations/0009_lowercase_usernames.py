"""
Migration 0009: Normalize existing usernames to lowercase.

Usernames are now case-insensitive (CustomUser.save() lowercases on write,
CustomUserManager.get_by_natural_key() looks up case-insensitively). This
migration brings any pre-existing rows in line. If two existing accounts
already differ only by case (e.g. "Admin" and "admin"), lowercasing one
would collide with the other — those are left untouched and need manual
resolution, since merging them isn't a decision a migration can make safely.
"""
from django.db import migrations


def lowercase_usernames(apps, schema_editor):
    CustomUser = apps.get_model('vault', 'CustomUser')
    for user in CustomUser.objects.all().order_by('id'):
        lowered = user.username.lower()
        if lowered == user.username:
            continue
        if CustomUser.objects.filter(username=lowered).exclude(pk=user.pk).exists():
            continue
        user.username = lowered
        user.save(update_fields=['username'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0008_encrypt_vault_passwords"),
    ]

    operations = [
        migrations.RunPython(lowercase_usernames, reverse_code=noop),
    ]
