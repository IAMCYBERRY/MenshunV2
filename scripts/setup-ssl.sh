#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_section() { echo -e "${BLUE}=== $1 ===${NC}"; }

print_section "SSL Certificate Setup"

# SSL directory must match the docker-compose volume mount:
#   ${HOME}/opt/menshun/ssl:/etc/nginx/ssl:ro
SSL_DIR="${HOME}/opt/menshun/ssl"
mkdir -p "$SSL_DIR"

# Resolve domain: prefer .env ALLOWED_HOSTS, then server IP
if [ -f .env ]; then
    DOMAIN=$(grep "^ALLOWED_HOSTS=" .env | cut -d'=' -f2 | cut -d',' -f1)
fi
if [ -z "$DOMAIN" ]; then
    DOMAIN=$(hostname -I 2>/dev/null | cut -d' ' -f1)
fi
if [ -z "$DOMAIN" ]; then
    DOMAIN="localhost"
fi

print_status "Setting up SSL for: $DOMAIN"

# Determine whether the domain is an IP address
if [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP=true
else
    IS_IP=false
fi

# Choose certificate method (non-interactive when IP; menu for real domains)
if [ "$IS_IP" = true ]; then
    SSL_CHOICE=2
    print_status "IP address detected — generating self-signed certificate automatically."
else
    echo ""
    echo "Choose SSL certificate method:"
    echo "  1) Let's Encrypt (recommended for public domains)"
    echo "  2) Self-signed certificate (development / internal use)"
    echo "  3) Use existing certificate files"
    read -p "Enter choice (1-3) [default: 2]: " SSL_CHOICE
    SSL_CHOICE=${SSL_CHOICE:-2}
fi

case "$SSL_CHOICE" in
    1)
        print_section "Setting up Let's Encrypt Certificate"

        if command -v apt-get >/dev/null 2>&1; then
            print_status "Installing certbot..."
            sudo apt-get update -qq
            sudo apt-get install -y certbot python3-certbot-nginx
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y epel-release
            sudo yum install -y certbot python3-certbot-nginx
        else
            print_error "Cannot install certbot automatically. Please install manually."
            exit 1
        fi

        sudo systemctl stop nginx 2>/dev/null || true

        print_status "Requesting Let's Encrypt certificate for $DOMAIN..."
        sudo certbot certonly --standalone \
            --non-interactive \
            --agree-tos \
            --email "admin@$DOMAIN" \
            --domains "$DOMAIN"

        cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/menshun.crt"
        cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$SSL_DIR/menshun.key"

        # Auto-renewal cron
        echo "0 12 * * * /usr/bin/certbot renew --quiet --deploy-hook 'docker compose -f $(pwd)/docker-compose.prod.yml restart nginx'" \
            | sudo tee /etc/cron.d/menshun-certbot > /dev/null

        print_status "✅ Let's Encrypt certificate installed."
        ;;

    2)
        print_section "Generating Self-Signed Certificate"

        # Build SAN config
        TMPCONF=$(mktemp)
        cat > "$TMPCONF" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $DOMAIN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF
        if [ "$IS_IP" = true ]; then
            echo "IP.1 = $DOMAIN" >> "$TMPCONF"
        else
            echo "DNS.1 = $DOMAIN" >> "$TMPCONF"
        fi

        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
            -keyout "$SSL_DIR/menshun.key" \
            -out    "$SSL_DIR/menshun.crt" \
            -config "$TMPCONF" \
            -extensions v3_req

        rm -f "$TMPCONF"

        print_status "✅ Self-signed certificate created."
        print_warning "Browsers will show a security warning — expected for self-signed certs."
        ;;

    3)
        print_section "Using Existing Certificate Files"

        echo "Path to certificate file (.crt or .pem):"
        read -r CERT_FILE
        echo "Path to private key file (.key):"
        read -r KEY_FILE

        [ -f "$CERT_FILE" ] || { print_error "Certificate not found: $CERT_FILE"; exit 1; }
        [ -f "$KEY_FILE"  ] || { print_error "Private key not found: $KEY_FILE";  exit 1; }

        cp "$CERT_FILE" "$SSL_DIR/menshun.crt"
        cp "$KEY_FILE"  "$SSL_DIR/menshun.key"

        print_status "✅ Existing certificate installed."
        ;;

    *)
        print_error "Invalid choice."
        exit 1
        ;;
esac

# Lock down the private key
chmod 644 "$SSL_DIR/menshun.crt"
chmod 600 "$SSL_DIR/menshun.key"

# Verify
if openssl x509 -in "$SSL_DIR/menshun.crt" -noout 2>/dev/null; then
    EXPIRY=$(openssl x509 -in "$SSL_DIR/menshun.crt" -noout -enddate 2>/dev/null | cut -d= -f2)
    print_status "Certificate valid until: $EXPIRY"
else
    print_error "Certificate verification failed."
    exit 1
fi

print_section "SSL Setup Complete"
echo "Certificate : $SSL_DIR/menshun.crt"
echo "Private key : $SSL_DIR/menshun.key"
print_status "Run 'make deploy' or restart nginx to apply."
