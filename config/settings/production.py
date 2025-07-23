"""
Production settings for Menshun PAM
Inherits from base settings and overrides for production environment
"""

from menshen.settings.base import *
import logging.config
import os

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Allowed hosts - should be set via environment variable
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
if not ALLOWED_HOSTS or ALLOWED_HOSTS == ['']:
    raise ValueError("ALLOWED_HOSTS must be set in production")

# Security Settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'true').lower() == 'true'
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Session and Cookie Security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 28800  # 8 hours

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_TRUSTED_ORIGINS = [f"https://{host}" for host in ALLOWED_HOSTS if host != 'localhost']

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "'unsafe-eval'", "https://unpkg.com")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", "https://fonts.googleapis.com")
CSP_FONT_SRC = ("'self'", "https://fonts.gstatic.com")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_CONNECT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)

# Database Connection Pooling
DATABASES['default'].update({
    'CONN_MAX_AGE': 60,
    'OPTIONS': {
        'MAX_CONNS': 20,
        'sslmode': 'prefer',
    }
})

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            },
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
        },
        'KEY_PREFIX': 'menshun',
        'VERSION': 1,
        'TIMEOUT': 300,  # 5 minutes default timeout
    }
}

# Static files configuration
STATIC_ROOT = '/app/staticfiles'
STATIC_URL = '/static/'

# Media files configuration
MEDIA_ROOT = '/app/media'
MEDIA_URL = '/media/'

# Email Configuration
if os.environ.get('EMAIL_HOST'):
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_HOST = os.environ.get('EMAIL_HOST')
    EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
    EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'true').lower() == 'true'
    EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'noreply@menshun.local')
    SERVER_EMAIL = DEFAULT_FROM_EMAIL
else:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Logging Configuration
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'standard': {
            'format': '{asctime} [{levelname}] {name}: {message}',
            'style': '{',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'json': {
            'format': '{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
        'file': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/django.log',
            'maxBytes': 50 * 1024 * 1024,  # 50 MB
            'backupCount': 5,
            'formatter': 'json',
        },
        'security_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/security.log',
            'maxBytes': 50 * 1024 * 1024,  # 50 MB
            'backupCount': 10,
            'formatter': 'json',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'django.security': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'vault': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'vault.audit': {
            'handlers': ['security_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'vault.sentinel_integration': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
    },
    'root': {
        'level': LOG_LEVEL,
        'handlers': ['console', 'file'],
    },
}

# Sentry Configuration (Optional)
SENTRY_DSN = os.environ.get('SENTRY_DSN')
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.redis import RedisIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(transaction_style='url'),
            CeleryIntegration(),
            RedisIntegration(),
        ],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment='production',
    )

# Performance Settings
DATA_UPLOAD_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100 MB

# Gunicorn Settings (passed via environment)
GUNICORN_WORKERS = int(os.environ.get('GUNICORN_WORKERS', 4))
GUNICORN_THREADS = int(os.environ.get('GUNICORN_THREADS', 2))
GUNICORN_MAX_REQUESTS = int(os.environ.get('GUNICORN_MAX_REQUESTS', 1000))
GUNICORN_MAX_REQUESTS_JITTER = int(os.environ.get('GUNICORN_MAX_REQUESTS_JITTER', 100))

# Health Check Configuration
HEALTH_CHECK = {
    'DISK_USAGE_MAX': 90,  # Percent
    'MEMORY_MIN': 100,     # MB
}

# Additional Production Middleware
MIDDLEWARE.insert(1, 'django.middleware.cache.UpdateCacheMiddleware')
MIDDLEWARE.append('django.middleware.cache.FetchFromCacheMiddleware')

# Admin Configuration
ADMIN_URL = os.environ.get('ADMIN_URL', 'admin/')
if not ADMIN_URL.endswith('/'):
    ADMIN_URL += '/'

# Update URL configuration for custom admin URL
if ADMIN_URL != 'admin/':
    # This would need to be handled in URLs
    pass

# Disable Django Debug Toolbar in production
if 'debug_toolbar' in INSTALLED_APPS:
    INSTALLED_APPS.remove('debug_toolbar')

# Remove debug middleware if present
MIDDLEWARE = [m for m in MIDDLEWARE if 'debug_toolbar' not in m]

# Production-specific apps
INSTALLED_APPS += [
    'django_celery_beat',  # For scheduled tasks
]

# Celery Production Settings
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000

# Microsoft Sentinel Production Settings
SENTINEL_ENABLED = os.environ.get('SENTINEL_ENABLED', 'false').lower() == 'true'
if SENTINEL_ENABLED:
    # Ensure all required Sentinel settings are present
    required_sentinel_vars = [
        'SENTINEL_WORKSPACE_ID',
        'SENTINEL_DATA_COLLECTION_ENDPOINT',
        'SENTINEL_DATA_COLLECTION_RULE_ID',
    ]
    
    missing_vars = [var for var in required_sentinel_vars if not os.environ.get(var)]
    if missing_vars:
        raise ValueError(f"Sentinel is enabled but missing required environment variables: {', '.join(missing_vars)}")

# Backup Configuration
BACKUP_ROOT = '/opt/menshun/backups'
BACKUP_RETENTION_DAYS = int(os.environ.get('BACKUP_RETENTION_DAYS', 30))

# Monitoring Configuration
MONITORING_ENABLED = os.environ.get('MONITORING_ENABLED', 'true').lower() == 'true'

# Feature Flags
FEATURE_FLAGS = {
    'ENABLE_API_THROTTLING': True,
    'ENABLE_ADVANCED_AUDIT': True,
    'ENABLE_SENTINEL_INTEGRATION': SENTINEL_ENABLED,
    'ENABLE_SERVICE_IDENTITIES': True,
    'ENABLE_ENTRA_INTEGRATION': bool(os.environ.get('AZURE_TENANT_ID')),
}

# Custom Settings Validation
def validate_production_settings():
    """Validate critical production settings"""
    errors = []
    
    if DEBUG:
        errors.append("DEBUG must be False in production")
    
    if not SECRET_KEY or SECRET_KEY == 'django-insecure-development-key-change-in-production':
        errors.append("SECRET_KEY must be set to a secure value in production")
    
    if not ALLOWED_HOSTS:
        errors.append("ALLOWED_HOSTS must be configured in production")
    
    if not DATABASE_PASSWORD:
        errors.append("DATABASE_PASSWORD must be set in production")
    
    if errors:
        raise ValueError("Production settings validation failed:\n" + "\n".join(f"- {error}" for error in errors))

# Run validation
try:
    validate_production_settings()
except Exception as e:
    import sys
    print(f"Production settings validation failed: {e}", file=sys.stderr)
    if not os.environ.get('SKIP_SETTINGS_VALIDATION'):
        sys.exit(1)