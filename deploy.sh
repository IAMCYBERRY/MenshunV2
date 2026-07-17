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

if ! command -v openssl &>/dev/null; then
    error "openssl is not installed (needed to generate the SSL certificate)."
    exit 1
fi

# --- Detect the host others will actually connect to ---
# `hostname -I` / local interfaces only ever see a cloud VM's *private* IP —
# Azure (and AWS/GCP) NAT the public IP, so it's invisible from inside the VM.
# Without this, ALLOWED_HOSTS and the SSL cert end up built for an address
# nobody connects through, and Django rejects every request with 400 DisallowedHost.
detect_public_host() {
    local ip=""

    # Explicit override always wins (e.g. a real domain name)
    if [ -n "${PUBLIC_HOST:-}" ]; then
        echo "$PUBLIC_HOST"
        return
    fi

    # Azure Instance Metadata Service — instant, no internet egress needed
    ip=$(curl -s -m 2 -H "Metadata:true" \
        "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2021-02-01&format=text" 2>/dev/null || true)

    # Generic public-IP lookup (works on any host with outbound internet)
    if [ -z "$ip" ]; then
        ip=$(curl -s -m 3 https://api.ipify.org 2>/dev/null || true)
    fi

    # Private/local IP fallback (on-prem VMs, air-gapped hosts, local testing)
    if [ -z "$ip" ] && command -v hostname &>/dev/null; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [ -z "$ip" ] && command -v ip &>/dev/null; then
        ip=$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')
    fi

    echo "${ip:-localhost}"
}

PUBLIC_HOST=$(detect_public_host)
info "Detected reachable host: $PUBLIC_HOST"
if [ "$PUBLIC_HOST" = "localhost" ]; then
    warn "Could not auto-detect a public IP. If this VM has one, re-run with: PUBLIC_HOST=<ip-or-domain> ./deploy.sh"
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
        sed -i '' "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=${PUBLIC_HOST},localhost,127.0.0.1|" .env
    else
        sed -i "s|__GENERATED_SECRET_KEY__|${SECRET_KEY}|" .env
        sed -i "s|__GENERATED_DB_PASSWORD__|${DB_PASSWORD}|" .env
        sed -i "s|__GENERATED_ENCRYPTION_KEY__|${ENCRYPTION_KEY}|" .env
        sed -i "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=${PUBLIC_HOST},localhost,127.0.0.1|" .env
    fi

    info ".env created with random secrets. ALLOWED_HOSTS set to: ${PUBLIC_HOST},localhost,127.0.0.1"
    warn "IMPORTANT: Back up FIELD_ENCRYPTION_KEY from .env — losing it makes vault passwords unrecoverable."
else
    info "Using existing .env file."

    # Self-heal ALLOWED_HOSTS if the detected host isn't already covered
    # (e.g. an Azure VM without a Static Public IP gets a new one on every restart)
    CURRENT_HOSTS=$(grep "^ALLOWED_HOSTS=" .env | cut -d'=' -f2-)
    if [[ ",${CURRENT_HOSTS}," != *",${PUBLIC_HOST},"* ]]; then
        NEW_HOSTS="${PUBLIC_HOST},${CURRENT_HOSTS}"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=${NEW_HOSTS}|" .env
        else
            sed -i "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=${NEW_HOSTS}|" .env
        fi
        info "Added ${PUBLIC_HOST} to ALLOWED_HOSTS in .env"
    fi
fi

# --- Generate self-signed SSL cert if missing or the host has changed ---
SSL_DIR="./config/nginx/ssl"
PREVIOUS_HOST=$(cat "$SSL_DIR/.host" 2>/dev/null || true)

if [ ! -f "$SSL_DIR/menshun.crt" ] || [ ! -f "$SSL_DIR/menshun.key" ] || [ "$PREVIOUS_HOST" != "$PUBLIC_HOST" ]; then
    info "Generating a self-signed SSL certificate for $PUBLIC_HOST..."
    mkdir -p "$SSL_DIR"

    if [[ $PUBLIC_HOST =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="IP.1 = $PUBLIC_HOST"
    else
        SAN="DNS.1 = $PUBLIC_HOST"
    fi

    TMPCONF=$(mktemp)
    cat > "$TMPCONF" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $PUBLIC_HOST

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$SAN
EOF

    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -keyout "$SSL_DIR/menshun.key" \
        -out    "$SSL_DIR/menshun.crt" \
        -config "$TMPCONF" \
        -extensions v3_req
    rm -f "$TMPCONF"
    chmod 600 "$SSL_DIR/menshun.key"
    echo "$PUBLIC_HOST" > "$SSL_DIR/.host"

    info "Self-signed certificate created for $PUBLIC_HOST."
    warn "Browsers will show a security warning for self-signed certs — this is expected."
else
    info "Using existing SSL certificate (already valid for $PUBLIC_HOST)."
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
    if curl -skf https://localhost/health/ &>/dev/null; then
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
echo -e "  Web:   ${BLUE}https://${PUBLIC_HOST}/${NC} (self-signed cert — browser warning expected)"
echo -e "  Admin: ${BLUE}https://${PUBLIC_HOST}/admin/${NC}"
echo ""
if [ "$PUBLIC_HOST" != "localhost" ]; then
    echo -e "  ${YELLOW}On Azure: make sure the VM's Network Security Group allows inbound${NC}"
    echo -e "  ${YELLOW}TCP 80 and 443, or nothing above will be reachable from outside the VM.${NC}"
    echo ""
fi
echo -e "  Create a superuser:"
echo -e "  ${YELLOW}docker compose -f docker-compose.deploy.yml exec web python manage.py createsuperuser${NC}"
echo ""
echo -e "  View logs:"
echo -e "  ${YELLOW}docker compose -f docker-compose.deploy.yml logs -f${NC}"
echo ""
