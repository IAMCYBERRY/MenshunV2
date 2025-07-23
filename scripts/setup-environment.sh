#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Generate secure random string
generate_secret() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-50
}

# Get server IP
get_server_ip() {
    # Try different methods to get the server IP
    local ip=""
    
    # Method 1: hostname -I (most reliable on Linux)
    if command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | cut -d' ' -f1)
    fi
    
    # Method 2: ip route (if hostname -I fails)
    if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
        ip=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')
    fi
    
    # Method 3: ifconfig (fallback)
    if [ -z "$ip" ] && command -v ifconfig >/dev/null 2>&1; then
        ip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -1)
    fi
    
    # Default fallback
    if [ -z "$ip" ]; then
        ip="localhost"
    fi
    
    echo "$ip"
}

print_section "Environment Configuration Setup"

# Check if .env.production already exists
if [ -f .env.production ]; then
    print_warning "Production environment file already exists"
    read -p "Do you want to recreate it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Keeping existing .env.production file"
        exit 0
    fi
fi

print_status "Creating production environment configuration..."

# Get server information
SERVER_IP=$(get_server_ip)
HOSTNAME=$(hostname)

print_status "Detected server IP: $SERVER_IP"
print_status "Detected hostname: $HOSTNAME"

# Interactive configuration
echo ""
print_section "Basic Configuration"

# Domain/Hostname configuration
echo "Enter your domain name (or press Enter to use IP: $SERVER_IP):"
read -r DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then
    DOMAIN_NAME="$SERVER_IP"
fi

# Secret key generation
print_status "Generating secure Django secret key..."
SECRET_KEY=$(generate_secret)

# Database configuration
echo ""
print_section "Database Configuration"
echo "Database name (default: menshen_db):"
read -r DB_NAME
DB_NAME=${DB_NAME:-menshen_db}

echo "Database user (default: postgres):"
read -r DB_USER
DB_USER=${DB_USER:-postgres}

echo "Database password (will be generated if empty):"
read -rs DB_PASSWORD
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(generate_secret)
    echo "Generated secure database password"
fi

# Azure/Entra ID configuration
echo ""
print_section "Microsoft Entra ID Integration"
echo "Configure Microsoft Entra ID integration? (y/N):"
read -r CONFIGURE_ENTRA
if [[ $CONFIGURE_ENTRA =~ ^[Yy]$ ]]; then
    echo "Azure Tenant ID:"
    read -r AZURE_TENANT_ID
    
    echo "Azure Client ID (Application ID):"
    read -r AZURE_CLIENT_ID
    
    echo "Azure Client Secret:"
    read -rs AZURE_CLIENT_SECRET
    
    echo "Vault Admin Group (default: Menshen_Vault_Admin):"
    read -r VAULT_ADMIN_GROUP
    VAULT_ADMIN_GROUP=${VAULT_ADMIN_GROUP:-Menshen_Vault_Admin}
    
    echo "Vault Editor Group (default: Menshen_Vault_Editor):"
    read -r VAULT_EDITOR_GROUP
    VAULT_EDITOR_GROUP=${VAULT_EDITOR_GROUP:-Menshen_Vault_Editor}
    
    echo "Vault Viewer Group (default: Menshen_Vault_Viewer):"
    read -r VAULT_VIEWER_GROUP
    VAULT_VIEWER_GROUP=${VAULT_VIEWER_GROUP:-Menshen_Vault_Viewer}
fi

# Microsoft Sentinel configuration
echo ""
print_section "Microsoft Sentinel Integration"
echo "Configure Microsoft Sentinel integration? (y/N):"
read -r CONFIGURE_SENTINEL
if [[ $CONFIGURE_SENTINEL =~ ^[Yy]$ ]]; then
    echo "Sentinel Workspace ID:"
    read -r SENTINEL_WORKSPACE_ID
    
    echo "Data Collection Endpoint URL:"
    read -r SENTINEL_ENDPOINT
    
    echo "Data Collection Rule ID:"
    read -r SENTINEL_DCR_ID
    
    echo "Stream Name (default: Custom-MenshunPAM_CL):"
    read -r SENTINEL_STREAM
    SENTINEL_STREAM=${SENTINEL_STREAM:-Custom-MenshunPAM_CL}
    
    SENTINEL_ENABLED="true"
else
    SENTINEL_ENABLED="false"
fi

# Email configuration
echo ""
print_section "Email Configuration (Optional)"
echo "Configure email settings? (y/N):"
read -r CONFIGURE_EMAIL
if [[ $CONFIGURE_EMAIL =~ ^[Yy]$ ]]; then
    echo "SMTP Host:"
    read -r EMAIL_HOST
    
    echo "SMTP Port (default: 587):"
    read -r EMAIL_PORT
    EMAIL_PORT=${EMAIL_PORT:-587}
    
    echo "SMTP Username:"
    read -r EMAIL_USER
    
    echo "SMTP Password:"
    read -rs EMAIL_PASSWORD
    
    echo "Default From Email:"
    read -r FROM_EMAIL
fi

# Performance settings
echo ""
print_section "Performance Configuration"
echo "Gunicorn workers (default: 4):"
read -r GUNICORN_WORKERS
GUNICORN_WORKERS=${GUNICORN_WORKERS:-4}

echo "Gunicorn threads per worker (default: 2):"
read -r GUNICORN_THREADS
GUNICORN_THREADS=${GUNICORN_THREADS:-2}

# Create .env.production file
print_status "Creating .env.production file..."

cat > .env.production << EOF
# Menshun PAM - Production Environment Configuration
# Generated on $(date)

# =================================
# Basic Django Configuration
# =================================
DEBUG=False
SECRET_KEY=$SECRET_KEY
ALLOWED_HOSTS=$DOMAIN_NAME,localhost,127.0.0.1

# =================================
# Database Configuration
# =================================
DATABASE_NAME=$DB_NAME
DATABASE_USER=$DB_USER
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
# Security Settings
# =================================
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true

# =================================
# Microsoft Entra ID Configuration
# =================================
EOF

if [[ $CONFIGURE_ENTRA =~ ^[Yy]$ ]]; then
    cat >> .env.production << EOF
AZURE_TENANT_ID=$AZURE_TENANT_ID
AZURE_CLIENT_ID=$AZURE_CLIENT_ID
AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET
AZURE_REDIRECT_URI=https://$DOMAIN_NAME/auth/microsoft/callback/

# Entra Group Mappings
MENSHEN_VAULT_ADMIN_GROUP=$VAULT_ADMIN_GROUP
MENSHEN_VAULT_EDITOR_GROUP=$VAULT_EDITOR_GROUP
MENSHEN_VAULT_VIEWER_GROUP=$VAULT_VIEWER_GROUP
EOF
else
    cat >> .env.production << EOF
AZURE_TENANT_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_REDIRECT_URI=

# Entra Group Mappings
MENSHEN_VAULT_ADMIN_GROUP=Menshen_Vault_Admin
MENSHEN_VAULT_EDITOR_GROUP=Menshen_Vault_Editor
MENSHEN_VAULT_VIEWER_GROUP=Menshen_Vault_Viewer
EOF
fi

cat >> .env.production << EOF

# =================================
# Microsoft Sentinel Integration
# =================================
SENTINEL_ENABLED=$SENTINEL_ENABLED
EOF

if [[ $CONFIGURE_SENTINEL =~ ^[Yy]$ ]]; then
    cat >> .env.production << EOF
SENTINEL_WORKSPACE_ID=$SENTINEL_WORKSPACE_ID
SENTINEL_DATA_COLLECTION_ENDPOINT=$SENTINEL_ENDPOINT
SENTINEL_DATA_COLLECTION_RULE_ID=$SENTINEL_DCR_ID
SENTINEL_STREAM_NAME=$SENTINEL_STREAM
SENTINEL_CONNECTOR_TYPE=LOG_ANALYTICS
SENTINEL_BATCH_SIZE=10
SENTINEL_BATCH_TIMEOUT=30
SENTINEL_SEND_AUTH_EVENTS=true
SENTINEL_SEND_VAULT_EVENTS=true
SENTINEL_SEND_SERVICE_IDENTITY_EVENTS=true
SENTINEL_SEND_PRIVILEGED_ACCESS_EVENTS=true
EOF
else
    cat >> .env.production << EOF
SENTINEL_WORKSPACE_ID=
SENTINEL_DATA_COLLECTION_ENDPOINT=
SENTINEL_DATA_COLLECTION_RULE_ID=
SENTINEL_STREAM_NAME=Custom-MenshunPAM_CL
SENTINEL_CONNECTOR_TYPE=LOG_ANALYTICS
SENTINEL_BATCH_SIZE=10
SENTINEL_BATCH_TIMEOUT=30
SENTINEL_SEND_AUTH_EVENTS=true
SENTINEL_SEND_VAULT_EVENTS=true
SENTINEL_SEND_SERVICE_IDENTITY_EVENTS=true
SENTINEL_SEND_PRIVILEGED_ACCESS_EVENTS=true
EOF
fi

cat >> .env.production << EOF

# =================================
# Email Configuration
# =================================
EOF

if [[ $CONFIGURE_EMAIL =~ ^[Yy]$ ]]; then
    cat >> .env.production << EOF
EMAIL_HOST=$EMAIL_HOST
EMAIL_PORT=$EMAIL_PORT
EMAIL_HOST_USER=$EMAIL_USER
EMAIL_HOST_PASSWORD=$EMAIL_PASSWORD
EMAIL_USE_TLS=true
DEFAULT_FROM_EMAIL=$FROM_EMAIL
EOF
else
    cat >> .env.production << EOF
EMAIL_HOST=
EMAIL_PORT=587
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
EMAIL_USE_TLS=true
DEFAULT_FROM_EMAIL=noreply@menshun.local
EOF
fi

cat >> .env.production << EOF

# =================================
# Performance Configuration
# =================================
GUNICORN_WORKERS=$GUNICORN_WORKERS
GUNICORN_THREADS=$GUNICORN_THREADS
GUNICORN_MAX_REQUESTS=1000
GUNICORN_MAX_REQUESTS_JITTER=100

# =================================
# Logging Configuration
# =================================
LOG_LEVEL=INFO
SENTRY_DSN=

# =================================
# Backup Configuration
# =================================
BACKUP_RETENTION_DAYS=30

# =================================
# Monitoring Configuration
# =================================
MONITORING_ENABLED=true

# =================================
# Feature Flags
# =================================
ENABLE_API_THROTTLING=true
ENABLE_ADVANCED_AUDIT=true
ENABLE_SERVICE_IDENTITIES=true
EOF

# Set secure permissions
chmod 600 .env.production

print_status "✅ Production environment configuration created successfully!"

# Create additional configuration files
print_status "Creating additional configuration files..."

# Create Redis configuration
mkdir -p config/redis
cat > config/redis/redis.conf << EOF
# Redis production configuration for Menshun PAM

# Network
bind 0.0.0.0
port 6379
timeout 300
tcp-keepalive 60

# Memory
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes

# Security
requirepass $DB_PASSWORD

# Logging
loglevel notice
syslog-enabled yes
syslog-ident redis

# Performance
tcp-backlog 511
databases 16
EOF

print_status "✅ Environment setup completed!"
echo ""
print_section "Configuration Summary"
echo "Domain: $DOMAIN_NAME"
echo "Database: $DB_NAME"
echo "Entra ID: $([ -n "$AZURE_TENANT_ID" ] && echo "Configured" || echo "Not configured")"
echo "Sentinel: $([ "$SENTINEL_ENABLED" = "true" ] && echo "Enabled" || echo "Disabled")"
echo "Email: $([ -n "$EMAIL_HOST" ] && echo "Configured" || echo "Not configured")"
echo ""
print_warning "Important: Keep your .env.production file secure and never commit it to version control!"
print_status "Next step: Run 'make deploy' to deploy the application"