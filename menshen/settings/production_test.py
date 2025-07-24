"""
Production Test settings for Menshun PAM
Based on production settings but without SSL requirements for testing
"""

from menshen.settings.production import *

# Override SSL settings for testing
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Allow all hosts for testing (should be restricted in real production)
ALLOWED_HOSTS = ['*']

# Simplified logging for testing
LOGGING['handlers']['console']['level'] = 'DEBUG'
LOGGING['loggers']['django']['level'] = 'DEBUG'

# Disable some security features for easier testing
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False

print("🧪 Using production test settings - SSL disabled for testing")