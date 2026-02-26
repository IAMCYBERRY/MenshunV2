from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken
import logging

logger = logging.getLogger(__name__)


class EncryptedCharField(models.TextField):
    """
    A field that transparently encrypts/decrypts its value using Fernet
    symmetric encryption (AES-128-CBC + HMAC-SHA256).

    Stores data as a TextField (text) in the database, containing
    base64url-encoded Fernet tokens.

    Requires FIELD_ENCRYPTION_KEY in settings — a URL-safe base64-encoded
    32-byte key. Generate with:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """

    def _get_fernet(self):
        key = settings.FIELD_ENCRYPTION_KEY
        if not key:
            raise ValueError(
                "FIELD_ENCRYPTION_KEY is not configured. "
                "Set it in your environment before starting the application."
            )
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)

    def from_db_value(self, value, expression, connection):
        if value is None or value == "":
            return value
        return self._decrypt(value)

    def to_python(self, value):
        # Deserialization path — value is already plaintext string
        if value is None:
            return value
        return value

    def get_prep_value(self, value):
        # Called when writing to the database — always encrypt
        if value is None or value == "":
            return value
        return self._encrypt(value)

    def _encrypt(self, value):
        f = self._get_fernet()
        if isinstance(value, str):
            value = value.encode()
        return f.encrypt(value).decode()

    def _decrypt(self, value):
        try:
            f = self._get_fernet()
            if isinstance(value, str):
                value = value.encode()
            return f.decrypt(value).decode()
        except InvalidToken:
            # Value is not a valid Fernet token — treat as plaintext.
            # This occurs during the data migration window before existing
            # rows have been re-encrypted.
            return value.decode() if isinstance(value, bytes) else value
        except Exception as e:
            logger.error("EncryptedCharField decryption failed: %s", e)
            return value.decode() if isinstance(value, bytes) else value
