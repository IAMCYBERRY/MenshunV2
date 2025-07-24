#!/bin/bash

echo "Creating production .env file..."

# Generate secure secret key
SECRET_KEY=$(openssl rand -base64 50 | tr -d "=+/" | cut -c1-50)
DB_PASSWORD=$(openssl rand -base64 30 | tr -d "=+/" | cut -c1-25)

# Get server IP
SERVER_IP=$(hostname -I | cut -d' ' -f1 2>/dev/null || echo "10.0.0.71")

cat > .env << EOF
# Menshun PAM - Production Environment Configuration
# Generated on $(date)

# =================================
# Basic Django Configuration
# =================================
DEBUG=False
SECRET_KEY=$SECRET_KEY
ALLOWED_HOSTS=localhost,127.0.0.1,$SERVER_IP

# =================================
# Database Configuration
# =================================
DATABASE_NAME=menshen_db
DATABASE_USER=postgres
DATABASE_PASSWORD=$DB_PASSWORD
DATABASE_HOST=db
DATABASE_PORT=5432

# =================================
# Redis Configuration
# =================================
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# =================================
# Security Settings (SSL disabled for testing)
# =================================
SECURE_SSL_REDIRECT=False
SECURE_HSTS_SECONDS=0
SESSION_COOKIE_SECURE=False
CSRF_COOKIE_SECURE=False

# =================================
# Microsoft Entra ID Configuration (Optional)
# =================================
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_REDIRECT_URI=

# Entra Group Mappings
MENSHEN_VAULT_ADMIN_GROUP=Menshen_Vault_Admin
MENSHEN_VAULT_EDITOR_GROUP=Menshen_Vault_Editor
MENSHEN_VAULT_VIEWER_GROUP=Menshen_Vault_Viewer

# =================================
# Microsoft Sentinel Integration (Optional)
# =================================
SENTINEL_ENABLED=false
SENTINEL_WORKSPACE_ID=
SENTINEL_DATA_COLLECTION_ENDPOINT=
SENTINEL_DATA_COLLECTION_RULE_ID=
SENTINEL_STREAM_NAME=Custom-MenshunPAM_CL

# =================================
# Email Configuration (Optional)
# =================================
EMAIL_HOST=
EMAIL_PORT=587
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
EMAIL_USE_TLS=true
DEFAULT_FROM_EMAIL=noreply@menshun.local

# =================================
# Performance Configuration
# =================================
GUNICORN_WORKERS=4
GUNICORN_THREADS=2
GUNICORN_MAX_REQUESTS=1000
GUNICORN_MAX_REQUESTS_JITTER=100

# =================================
# Logging Configuration
# =================================
LOG_LEVEL=INFO
SENTRY_DSN=
EOF

chmod 600 .env

echo "✅ .env file created successfully!"
echo "🔑 Generated secure secret key and database password"
echo "🌐 Configured for server IP: $SERVER_IP"
echo ""
echo "📝 You can edit .env to customize settings if needed"
echo "🚀 Run: make -f Makefile.simple deploy"