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

print_section "Nginx Setup"

# Check if Nginx is already installed
if command -v nginx >/dev/null 2>&1; then
    print_status "Nginx is already installed: $(nginx -v 2>&1)"
else
    print_status "Installing Nginx..."
    
    # Detect OS and install Nginx
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
    
    case $OS in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y nginx
            ;;
        centos|rhel|rocky|alma)
            sudo yum install -y nginx
            ;;
        *)
            print_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
fi

# Stop nginx if running (we'll start it with systemd later)
sudo systemctl stop nginx || true

# Create Nginx directories
print_status "Creating Nginx directory structure..."
sudo mkdir -p /etc/nginx/{sites-available,sites-enabled}
sudo mkdir -p /var/www/menshun/errors
sudo mkdir -p /opt/menshun/logs/nginx

# Remove default Nginx configuration
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# Copy our Nginx configuration
print_status "Installing Nginx configuration..."

# Main nginx.conf
if [ -f config/nginx/nginx.conf ]; then
    sudo cp config/nginx/nginx.conf /etc/nginx/nginx.conf
else
    print_error "Nginx main configuration not found at config/nginx/nginx.conf"
    exit 1
fi

# Site configuration
if [ -f config/nginx/sites-available/menshun.conf ]; then
    sudo cp config/nginx/sites-available/menshun.conf /etc/nginx/sites-available/menshun.conf
    sudo ln -sf /etc/nginx/sites-available/menshun.conf /etc/nginx/sites-enabled/menshun.conf
else
    print_error "Menshun site configuration not found at config/nginx/sites-available/menshun.conf"
    exit 1
fi

# Create custom error pages
print_status "Creating custom error pages..."

cat > /tmp/50x.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Service Temporarily Unavailable</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px;
            background: #0f172a;
            color: #fff;
        }
        .error-container {
            max-width: 500px;
            margin: 0 auto;
            background: rgba(30, 41, 59, 0.6);
            padding: 40px;
            border-radius: 12px;
            border: 1px solid rgba(71, 85, 105, 0.3);
        }
        h1 { color: #0ea5e9; font-size: 24px; margin-bottom: 20px; }
        p { color: #cbd5e1; line-height: 1.6; }
        .status-code { font-size: 48px; font-weight: bold; color: #ef4444; }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="status-code">503</div>
        <h1>Menshun PAM Temporarily Unavailable</h1>
        <p>The service is temporarily unavailable due to maintenance or high load.</p>
        <p>Please try again in a few moments.</p>
    </div>
</body>
</html>
EOF

sudo cp /tmp/50x.html /var/www/menshun/errors/50x.html
sudo chown -R www-data:www-data /var/www/menshun
rm /tmp/50x.html

# Set proper permissions
print_status "Setting Nginx permissions..."
# Check if nginx user exists, if not create it
if ! id nginx >/dev/null 2>&1; then
    print_warning "Nginx user doesn't exist, creating it..."
    sudo useradd -r -s /bin/false nginx
fi
sudo chown -R nginx:nginx /opt/menshun/logs/nginx
sudo chmod 755 /opt/menshun/logs/nginx

# Test Nginx configuration
print_status "Testing Nginx configuration..."
if sudo nginx -t; then
    print_status "✅ Nginx configuration test passed"
else
    print_error "❌ Nginx configuration test failed"
    exit 1
fi

# Create Nginx systemd override for better integration
print_status "Creating Nginx systemd override..."
sudo mkdir -p /etc/systemd/system/nginx.service.d

cat > /tmp/menshun-override.conf << EOF
[Unit]
# Ensure Nginx starts after Docker
After=docker.service

[Service]
# Reload configuration without dropping connections
ExecReload=/bin/kill -s HUP \$MAINPID
ExecReload=/bin/sleep 0.1

# Better restart policy
Restart=always
RestartSec=5

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/log/nginx /var/lib/nginx /opt/menshun/logs/nginx
EOF

sudo cp /tmp/menshun-override.conf /etc/systemd/system/nginx.service.d/menshun-override.conf
rm /tmp/menshun-override.conf

# Enable Nginx service
print_status "Enabling Nginx service..."
sudo systemctl daemon-reload
sudo systemctl enable nginx

# Create Nginx log rotation override
print_status "Configuring Nginx log rotation..."
cat > /tmp/nginx-logrotate << EOF
/opt/menshun/logs/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 nginx nginx
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 \$(cat /var/run/nginx.pid)
        fi
    endscript
}
EOF

sudo cp /tmp/nginx-logrotate /etc/logrotate.d/nginx-menshun
rm /tmp/nginx-logrotate

# Create Nginx monitoring script
print_status "Creating Nginx monitoring script..."
cat > /opt/menshun/scripts/nginx-monitor.sh << 'EOF'
#!/bin/bash
# Nginx monitoring script for Menshun PAM

# Check if Nginx is running
if ! systemctl is-active --quiet nginx; then
    echo "$(date): Nginx is not running, attempting to start..." >> /opt/menshun/logs/nginx-monitor.log
    systemctl start nginx
    exit 1
fi

# Check if Nginx is responding
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost/health/ | grep -q "200\|301\|302"; then
    echo "$(date): Nginx health check failed, reloading configuration..." >> /opt/menshun/logs/nginx-monitor.log
    systemctl reload nginx
    exit 1
fi

# Check Nginx error log for critical errors
if tail -n 100 /opt/menshun/logs/nginx/error.log | grep -q "\[emerg\]\|\[alert\]\|\[crit\]"; then
    echo "$(date): Critical errors detected in Nginx log" >> /opt/menshun/logs/nginx-monitor.log
    exit 1
fi

echo "$(date): Nginx monitoring check passed" >> /opt/menshun/logs/nginx-monitor.log
EOF

chmod +x /opt/menshun/scripts/nginx-monitor.sh
# Ensure nginx user exists before setting ownership
if id nginx >/dev/null 2>&1; then
    sudo chown nginx:nginx /opt/menshun/scripts/nginx-monitor.sh
else
    print_warning "Nginx user not found, keeping default ownership"
fi

print_status "✅ Nginx setup completed successfully!"

print_section "Nginx Configuration Summary"
echo "Main Config: /etc/nginx/nginx.conf"
echo "Site Config: /etc/nginx/sites-available/menshun.conf"
echo "Error Pages: /var/www/menshun/errors/"
echo "Logs: /opt/menshun/logs/nginx/"
echo "Monitor Script: /opt/menshun/scripts/nginx-monitor.sh"

print_section "Next Steps"
echo "1. Configure SSL certificates: ./scripts/setup-ssl.sh"
echo "2. Start Nginx: sudo systemctl start nginx"
echo "3. Check status: sudo systemctl status nginx"

print_warning "⚠️  Nginx is configured but not started. SSL setup is required first."