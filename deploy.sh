#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

cd "$(dirname "$0")"

# --- Pre-flight checks ---
if ! command -v docker &>/dev/null; then
    error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker info &>/dev/null; then
    error "Docker daemon is not running (or current user lacks permission)."
    exit 1
fi

if ! docker compose version &>/dev/null; then
    error "Docker Compose (v2 plugin) is not available."
    exit 1
fi

# --- Generate .env if missing ---
if [ ! -f .env ]; then
    info "No .env found — generating from template..."
    cp .env.deploy.template .env

    generate_secret() {
        python3 -c "import secrets; print(secrets.token_urlsafe(50))" 2>/dev/null \
            || openssl rand -base64 50 | tr -d '\n/+=' | head -c 50
    }

    # Fernet key = 32 random bytes in URL-safe base64 (required by field encryption)
    generate_fernet_key() {
        python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
            || openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'
    }

    SECRET_KEY=$(generate_secret)
    DB_PASSWORD=$(generate_secret)
    ENCRYPTION_KEY=$(generate_fernet_key)

    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|__GENERATED_SECRET_KEY__|${SECRET_KEY}|" .env
        sed -i '' "s|__GENERATED_DB_PASSWORD__|${DB_PASSWORD}|" .env
        sed -i '' "s|__GENERATED_ENCRYPTION_KEY__|${ENCRYPTION_KEY}|" .env
    else
        sed -i "s|__GENERATED_SECRET_KEY__|${SECRET_KEY}|" .env
        sed -i "s|__GENERATED_DB_PASSWORD__|${DB_PASSWORD}|" .env
        sed -i "s|__GENERATED_ENCRYPTION_KEY__|${ENCRYPTION_KEY}|" .env
    fi

    info ".env created with random secrets."
    warn "IMPORTANT: Back up FIELD_ENCRYPTION_KEY from .env — losing it makes vault passwords unrecoverable."
else
    info "Using existing .env file."
fi

# --- Build and start ---
info "Building and starting containers..."
docker compose -f docker-compose.deploy.yml up --build -d

# --- Health check polling ---
info "Waiting for application to become healthy (up to 120s)..."
elapsed=0
interval=5
timeout=120

while [ $elapsed -lt $timeout ]; do
    if curl -sf http://localhost/health/ &>/dev/null; then
        echo ""
        info "Application is healthy!"
        break
    fi
    printf "."
    sleep $interval
    elapsed=$((elapsed + interval))
done

if [ $elapsed -ge $timeout ]; then
    echo ""
    warn "Health check timed out after ${timeout}s. The app may still be starting."
    warn "Check logs: docker compose -f docker-compose.deploy.yml logs web"
fi

# --- Done ---
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Menshun PAM is deployed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  Web:   ${BLUE}http://localhost/${NC}"
echo -e "  Admin: ${BLUE}http://localhost/admin/${NC}"
echo ""
echo -e "  Create a superuser:"
echo -e "  ${YELLOW}docker compose -f docker-compose.deploy.yml exec web python manage.py createsuperuser${NC}"
echo ""
echo -e "  View logs:"
echo -e "  ${YELLOW}docker compose -f docker-compose.deploy.yml logs -f${NC}"
echo ""
