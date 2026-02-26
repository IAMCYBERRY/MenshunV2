"""
Migration 0008: Encrypt VaultEntry passwords at rest.

Phase 1 — Schema change:
    Alters vault_vaultentry.password from VARCHAR(512) to TEXT.
    PostgreSQL supports this cast without data loss.

Phase 2 — Data migration:
    Re-encrypts every existing plaintext password using Fernet
    (FIELD_ENCRYPTION_KEY from settings).  If FIELD_ENCRYPTION_KEY is not
    set the data step is skipped (development convenience only — the key
    MUST be set before the app starts).
"""
import vault.fields
from django.db import migrations


def encrypt_existing_passwords(apps, schema_editor):
    """
    Read each VaultEntry's plaintext password directly via SQL and write back
    a Fernet-encrypted token.  We use raw SQL so that the historical model
    (which has no EncryptedCharField logic) does not interfere.
    """
    from cryptography.fernet import Fernet
    from django.conf import settings

    key = settings.FIELD_ENCRYPTION_KEY
    if not key:
        # Skip in CI / dev environments where the key is not yet configured.
        return

    if isinstance(key, str):
        key = key.encode()
    f = Fernet(key)

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, password FROM vault_vaultentry "
            "WHERE password IS NOT NULL AND password <> ''"
        )
        rows = cursor.fetchall()

    with schema_editor.connection.cursor() as cursor:
        for entry_id, plaintext in rows:
            if plaintext:
                encrypted = f.encrypt(plaintext.encode()).decode()
                cursor.execute(
                    "UPDATE vault_vaultentry SET password = %s WHERE id = %s",
                    [encrypted, entry_id],
                )


def noop(apps, schema_editor):
    """Reverse migration: we cannot reverse encryption (no key guarantee)."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0007_sentinelintegration_sentinelevent"),
    ]

    operations = [
        # Step 1: Change column type VARCHAR(512) → TEXT
        migrations.AlterField(
            model_name="vaultentry",
            name="password",
            field=vault.fields.EncryptedCharField(),
        ),
        # Step 2: Encrypt all existing rows
        migrations.RunPython(encrypt_existing_passwords, reverse_code=noop),
    ]
