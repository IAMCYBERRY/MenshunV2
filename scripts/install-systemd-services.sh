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

print_section "Installing Systemd Services"

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

# Get the current user who ran sudo
REAL_USER=${SUDO_USER:-$USER}
MENSHUN_DIR="/opt/menshun"
APP_DIR=$(pwd)

print_status "Installing systemd services for user: $REAL_USER"
print_status "Application directory: $APP_DIR"

# Create systemd service for Menshun web application
print_status "Creating menshun-web.service..."

cat > /etc/systemd/system/menshun-web.service << EOF
[Unit]
Description=Menshun PAM Web Application
Documentation=https://github.com/your-org/menshun-pam
After=docker.service
Requires=docker.service
PartOf=menshun.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=$REAL_USER
Group=docker
WorkingDirectory=$APP_DIR


# Start command
ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d

# Stop command
ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down

# Reload command
ExecReload=/usr/bin/docker compose -f docker-compose.prod.yml restart

# Restart policy
Restart=no
TimeoutStartSec=300
TimeoutStopSec=120

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR $MENSHUN_DIR

[Install]
WantedBy=multi-user.target
Also=menshun-backup.timer
EOF

# Create systemd service for Menshun monitoring
print_status "Creating menshun-monitor.service..."

cat > /etc/systemd/system/menshun-monitor.service << EOF
[Unit]
Description=Menshun PAM Health Monitor
After=menshun-web.service
Requires=menshun-web.service

[Service]
Type=simple
User=$REAL_USER
Group=docker
WorkingDirectory=$APP_DIR

# Monitor script
ExecStart=/bin/bash $APP_DIR/scripts/monitor.sh

# Restart policy
Restart=always
RestartSec=60

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadOnlyPaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for automatic backups
print_status "Creating menshun-backup.service and timer..."

cat > /etc/systemd/system/menshun-backup.service << EOF
[Unit]
Description=Menshun PAM Backup Service
Documentation=https://github.com/your-org/menshun-pam

[Service]
Type=oneshot
User=$REAL_USER
Group=docker
WorkingDirectory=$APP_DIR

# Backup command
ExecStart=/bin/bash $APP_DIR/scripts/backup.sh

# Environment
Environment=BACKUP_RETENTION_DAYS=30

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR $MENSHUN_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=menshun-backup
EOF

cat > /etc/systemd/system/menshun-backup.timer << EOF
[Unit]
Description=Menshun PAM Backup Timer
Requires=menshun-backup.service

[Timer]
# Run backup daily at 2 AM
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
EOF

# Create systemd target for managing all Menshun services
print_status "Creating menshun.target..."

cat > /etc/systemd/system/menshun.target << EOF
[Unit]
Description=Menshun PAM System
Documentation=https://github.com/your-org/menshun-pam
Wants=menshun-web.service menshun-monitor.service
After=network.target docker.service

[Install]
WantedBy=multi-user.target
EOF

# Create log rotation configuration
print_status "Creating log rotation configuration..."

cat > /etc/logrotate.d/menshun << EOF
# Menshun PAM log rotation
$MENSHUN_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $REAL_USER $REAL_USER
    postrotate
        # Send SIGUSR1 to Gunicorn to reopen log files
        /usr/bin/docker compose -f $APP_DIR/docker-compose.prod.yml kill -s USR1 web 2>/dev/null || true
    endscript
}

# Nginx logs (if managed by systemd)
/opt/menshun/logs/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 nginx nginx
    postrotate
        systemctl reload nginx 2>/dev/null || true
    endscript
}
EOF

# Create tmpfiles configuration for log directory
print_status "Creating tmpfiles configuration..."

cat > /etc/tmpfiles.d/menshun.conf << EOF
# Menshun PAM tmpfiles configuration
d $MENSHUN_DIR/logs 0755 $REAL_USER $REAL_USER -
d $MENSHUN_DIR/logs/nginx 0755 nginx nginx -
d $MENSHUN_DIR/backups 0755 $REAL_USER $REAL_USER -
d $MENSHUN_DIR/data 0755 $REAL_USER $REAL_USER -
d $MENSHUN_DIR/ssl 0755 root root -
EOF

# Reload systemd daemon
print_status "Reloading systemd daemon..."
systemctl daemon-reload

# Enable services
print_status "Enabling Menshun services..."
systemctl enable menshun.target
systemctl enable menshun-web.service
systemctl enable menshun-monitor.service
systemctl enable menshun-backup.timer

# Reset any previous failed state and restart
print_status "Resetting and starting menshun-web.service..."
systemctl reset-failed menshun-web.service 2>/dev/null || true
systemctl restart menshun-web.service || true

print_status "✅ Systemd services installed and enabled successfully!"

print_section "Service Management Commands"
echo "Start Menshun:     sudo systemctl start menshun.target"
echo "Stop Menshun:      sudo systemctl stop menshun.target"
echo "Restart Menshun:   sudo systemctl restart menshun-web.service"
echo "Check Status:      sudo systemctl status menshun.target"
echo "View Logs:         sudo journalctl -u menshun-web.service -f"
echo "Backup Now:        sudo systemctl start menshun-backup.service"
echo "Check Backup Timer: sudo systemctl status menshun-backup.timer"

print_section "Service Status"
systemctl is-enabled menshun.target && echo "✅ menshun.target: enabled" || echo "❌ menshun.target: disabled"
systemctl is-enabled menshun-web.service && echo "✅ menshun-web.service: enabled" || echo "❌ menshun-web.service: disabled"
systemctl is-enabled menshun-monitor.service && echo "✅ menshun-monitor.service: enabled" || echo "❌ menshun-monitor.service: disabled"
systemctl is-enabled menshun-backup.timer && echo "✅ menshun-backup.timer: enabled" || echo "❌ menshun-backup.timer: disabled"

print_status "🎉 Systemd service installation completed!"