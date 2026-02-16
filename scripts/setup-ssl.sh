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

print_section "SSL Certificate Setup"

# Create SSL directory
sudo mkdir -p /opt/menshun/ssl
SSL_DIR="/opt/menshun/ssl"

# Get domain from environment or ask user
if [ -f .env.production ]; then
    DOMAIN=$(grep ALLOWED_HOSTS .env.production | cut -d'=' -f2 | cut -d',' -f1)
else
    echo "Enter your domain name (or IP address):"
    read -r DOMAIN
fi

print_status "Setting up SSL for domain: $DOMAIN"

# Check if domain is an IP address
if [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_IP=true
    print_warning "IP address detected. Will create self-signed certificate."
else
    IS_IP=false
    echo "Choose SSL certificate method:"
    echo "1) Let's Encrypt (recommended for public domains)"
    echo "2) Self-signed certificate"
    echo "3) Use existing certificate files"
    read -p "Enter choice (1-3): " SSL_CHOICE
fi

case ${SSL_CHOICE:-2} in
    1)
        print_section "Setting up Let's Encrypt Certificate"
        
        # Install certbot
        if command -v apt-get >/dev/null 2>&1; then
            print_status "Installing certbot (Ubuntu/Debian)..."
            sudo apt-get update
            sudo apt-get install -y certbot python3-certbot-nginx
        elif command -v yum >/dev/null 2>&1; then
            print_status "Installing certbot (CentOS/RHEL)..."
            sudo yum install -y epel-release
            sudo yum install -y certbot python3-certbot-nginx
        else
            print_error "Cannot install certbot automatically. Please install manually."
            exit 1
        fi
        
        # Stop nginx if running
        sudo systemctl stop nginx || true
        
        # Request certificate
        print_status "Requesting Let's Encrypt certificate..."
        sudo certbot certonly --standalone \
            --non-interactive \
            --agree-tos \
            --email admin@$DOMAIN \
            --domains $DOMAIN
        
        # Copy certificates to Menshun SSL directory
        sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem $SSL_DIR/menshun.crt
        sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem $SSL_DIR/menshun.key
        
        # Set permissions
        sudo chown root:root $SSL_DIR/menshun.*
        sudo chmod 644 $SSL_DIR/menshun.crt
        sudo chmod 600 $SSL_DIR/menshun.key
        
        # Create renewal cron job
        echo "0 12 * * * /usr/bin/certbot renew --quiet --deploy-hook 'systemctl reload nginx'" | sudo crontab -
        
        print_status "✅ Let's Encrypt certificate installed successfully!"
        ;;
        
    2)
        print_section "Creating Self-Signed Certificate"
        
        # Generate self-signed certificate
        print_status "Generating self-signed SSL certificate..."
        
        # Create OpenSSL config for SAN
        cat > /tmp/ssl.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
OU = IT Department
CN = $DOMAIN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
EOF

        if [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "IP.1 = $DOMAIN" >> /tmp/ssl.conf
        fi
        
        # Generate private key and certificate
        sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -keyout $SSL_DIR/menshun.key \
            -out $SSL_DIR/menshun.crt \
            -config /tmp/ssl.conf \
            -extensions v3_req
        
        # Set permissions
        sudo chown root:root $SSL_DIR/menshun.*
        sudo chmod 644 $SSL_DIR/menshun.crt
        sudo chmod 600 $SSL_DIR/menshun.key
        
        # Clean up
        rm /tmp/ssl.conf
        
        print_status "✅ Self-signed certificate created successfully!"
        print_warning "⚠️  Browsers will show security warnings for self-signed certificates."
        ;;
        
    3)
        print_section "Using Existing Certificate Files"
        
        echo "Enter path to certificate file (.crt or .pem):"
        read -r CERT_FILE
        
        echo "Enter path to private key file (.key):"
        read -r KEY_FILE
        
        if [ ! -f "$CERT_FILE" ]; then
            print_error "Certificate file not found: $CERT_FILE"
            exit 1
        fi
        
        if [ ! -f "$KEY_FILE" ]; then
            print_error "Private key file not found: $KEY_FILE"
            exit 1
        fi
        
        # Copy files
        sudo cp "$CERT_FILE" $SSL_DIR/menshun.crt
        sudo cp "$KEY_FILE" $SSL_DIR/menshun.key
        
        # Set permissions
        sudo chown root:root $SSL_DIR/menshun.*
        sudo chmod 644 $SSL_DIR/menshun.crt
        sudo chmod 600 $SSL_DIR/menshun.key
        
        print_status "✅ Existing certificates installed successfully!"
        ;;
        
    *)
        print_error "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Verify certificate
print_status "Verifying SSL certificate..."
if sudo openssl x509 -in $SSL_DIR/menshun.crt -text -noout >/dev/null 2>&1; then
    print_status "✅ Certificate verification successful!"
    
    # Show certificate info
    print_section "Certificate Information"
    sudo openssl x509 -in $SSL_DIR/menshun.crt -text -noout | grep -A 2 "Subject:"
    sudo openssl x509 -in $SSL_DIR/menshun.crt -text -noout | grep -A 1 "Not After"
else
    print_error "❌ Certificate verification failed!"
    exit 1
fi

# Create DH parameters for additional security
print_status "Generating Diffie-Hellman parameters (this may take a while)..."
sudo openssl dhparam -out $SSL_DIR/dhparam.pem 2048
sudo chmod 644 $SSL_DIR/dhparam.pem

# Update Nginx configuration to use DH parameters
if [ -f config/nginx/sites-available/menshun.conf ]; then
    if ! grep -q "ssl_dhparam" config/nginx/sites-available/menshun.conf; then
        sed -i '/ssl_session_tickets off;/a\    ssl_dhparam /etc/nginx/ssl/dhparam.pem;' config/nginx/sites-available/menshun.conf
    fi
fi

print_status "✅ SSL setup completed successfully!"

# Create certificate renewal script (for self-signed)
if [ "${SSL_CHOICE:-2}" = "2" ]; then
    sudo tee $SSL_DIR/renew-cert.sh << 'EOF' >/dev/null
#!/bin/bash
# Self-signed certificate renewal script
# Run this script annually to renew the self-signed certificate

SSL_DIR="/opt/menshun/ssl"
DOMAIN="$1"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Backup old certificate
cp $SSL_DIR/menshun.crt $SSL_DIR/menshun.crt.backup
cp $SSL_DIR/menshun.key $SSL_DIR/menshun.key.backup

# Generate new certificate
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -keyout $SSL_DIR/menshun.key \
    -out $SSL_DIR/menshun.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=IT Department/CN=$DOMAIN"

# Set permissions
chown root:root $SSL_DIR/menshun.*
chmod 644 $SSL_DIR/menshun.crt
chmod 600 $SSL_DIR/menshun.key

# Reload nginx
systemctl reload nginx

echo "Certificate renewed successfully!"
EOF
    
    sudo chmod +x $SSL_DIR/renew-cert.sh
    print_status "Created certificate renewal script: $SSL_DIR/renew-cert.sh"
fi

print_section "SSL Setup Summary"
echo "SSL Directory: $SSL_DIR"
echo "Certificate: $SSL_DIR/menshun.crt"
echo "Private Key: $SSL_DIR/menshun.key"
echo "DH Parameters: $SSL_DIR/dhparam.pem"

if [ "${SSL_CHOICE:-2}" = "1" ]; then
    echo "Type: Let's Encrypt (auto-renewal configured)"
elif [ "${SSL_CHOICE:-2}" = "2" ]; then
    echo "Type: Self-signed (expires in 1 year)"
    echo "Renewal script: $SSL_DIR/renew-cert.sh"
else
    echo "Type: Existing certificate"
fi

echo ""
print_status "SSL configuration is ready for Nginx!"