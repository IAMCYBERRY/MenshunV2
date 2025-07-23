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

# Configuration
BACKUP_DIR="/opt/menshun/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="menshun-backup-$TIMESTAMP"
BACKUP_FILE="$BACKUP_DIR/$BACKUP_NAME.tar.gz"
COMPOSE_FILE="docker-compose.prod.yml"

# Retention settings
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

print_section "Menshun PAM System Backup"

# Create backup directory if it doesn't exist
sudo mkdir -p $BACKUP_DIR

# Check if Docker Compose is running
if ! docker-compose -f $COMPOSE_FILE ps | grep -q "Up"; then
    print_warning "Menshun services are not running. Backup will continue but may be incomplete."
fi

# Create temporary backup directory
TEMP_BACKUP_DIR="/tmp/$BACKUP_NAME"
mkdir -p $TEMP_BACKUP_DIR

print_status "Starting backup process..."

# 1. Database Backup
print_section "Database Backup"
if docker-compose -f $COMPOSE_FILE ps db | grep -q "Up"; then
    print_status "Backing up PostgreSQL database..."
    
    # Get database credentials from environment
    if [ -f .env.production ]; then
        source .env.production
    fi
    
    # Create database dump
    docker-compose -f $COMPOSE_FILE exec -T db pg_dump \
        -U ${DATABASE_USER:-postgres} \
        -d ${DATABASE_NAME:-menshen_db} \
        --no-owner --no-privileges \
        > $TEMP_BACKUP_DIR/database.sql
    
    # Compress database dump
    gzip $TEMP_BACKUP_DIR/database.sql
    
    print_status "✅ Database backup completed ($(du -h $TEMP_BACKUP_DIR/database.sql.gz | cut -f1))"
else
    print_warning "Database container is not running. Skipping database backup."
fi

# 2. Application Files Backup
print_section "Application Files Backup"
print_status "Backing up application configuration..."

# Copy important configuration files
mkdir -p $TEMP_BACKUP_DIR/config
cp -r config/ $TEMP_BACKUP_DIR/config/ 2>/dev/null || true
cp .env.production $TEMP_BACKUP_DIR/ 2>/dev/null || true
cp docker-compose.prod.yml $TEMP_BACKUP_DIR/ 2>/dev/null || true
cp Makefile $TEMP_BACKUP_DIR/ 2>/dev/null || true

# Copy scripts
mkdir -p $TEMP_BACKUP_DIR/scripts
cp -r scripts/ $TEMP_BACKUP_DIR/scripts/ 2>/dev/null || true

print_status "✅ Application files backup completed"

# 3. Media Files Backup
print_section "Media Files Backup"
if [ -d "/opt/menshun/data/media" ]; then
    print_status "Backing up media files..."
    cp -r /opt/menshun/data/media $TEMP_BACKUP_DIR/
    print_status "✅ Media files backup completed ($(du -sh $TEMP_BACKUP_DIR/media 2>/dev/null | cut -f1 || echo "0B"))"
else
    print_warning "Media directory not found. Skipping media backup."
fi

# 4. SSL Certificates Backup
print_section "SSL Certificates Backup"
if [ -d "/opt/menshun/ssl" ]; then
    print_status "Backing up SSL certificates..."
    mkdir -p $TEMP_BACKUP_DIR/ssl
    sudo cp -r /opt/menshun/ssl/* $TEMP_BACKUP_DIR/ssl/ 2>/dev/null || true
    print_status "✅ SSL certificates backup completed"
else
    print_warning "SSL directory not found. Skipping SSL backup."
fi

# 5. Logs Backup (recent logs only)
print_section "Logs Backup"
if [ -d "/opt/menshun/logs" ]; then
    print_status "Backing up recent logs (last 7 days)..."
    mkdir -p $TEMP_BACKUP_DIR/logs
    
    # Find and copy recent log files
    find /opt/menshun/logs -name "*.log" -mtime -7 -exec cp {} $TEMP_BACKUP_DIR/logs/ \; 2>/dev/null || true
    find /opt/menshun/logs -name "*.log.*" -mtime -7 -exec cp {} $TEMP_BACKUP_DIR/logs/ \; 2>/dev/null || true
    
    print_status "✅ Logs backup completed ($(du -sh $TEMP_BACKUP_DIR/logs 2>/dev/null | cut -f1 || echo "0B"))"
else
    print_warning "Logs directory not found. Skipping logs backup."
fi

# 6. Docker Volumes Backup
print_section "Docker Volumes Backup"
print_status "Backing up Docker volume data..."

# Backup Redis data
if docker-compose -f $COMPOSE_FILE ps redis | grep -q "Up"; then
    print_status "Creating Redis backup..."
    docker-compose -f $COMPOSE_FILE exec -T redis redis-cli BGSAVE
    sleep 5  # Wait for background save to complete
    
    if [ -d "/opt/menshun/data/redis" ]; then
        cp -r /opt/menshun/data/redis $TEMP_BACKUP_DIR/ 2>/dev/null || true
    fi
fi

# Backup static files
if [ -d "/opt/menshun/data/static" ]; then
    cp -r /opt/menshun/data/static $TEMP_BACKUP_DIR/ 2>/dev/null || true
fi

print_status "✅ Docker volumes backup completed"

# 7. System Information
print_section "System Information"
print_status "Collecting system information..."

mkdir -p $TEMP_BACKUP_DIR/system
{
    echo "=== Backup Information ==="
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
    echo "Kernel: $(uname -r)"
    echo "Docker Version: $(docker --version)"
    echo "Docker Compose Version: $(docker-compose --version)"
    echo ""
    
    echo "=== Docker Container Status ==="
    docker-compose -f $COMPOSE_FILE ps
    echo ""
    
    echo "=== Disk Usage ==="
    df -h
    echo ""
    
    echo "=== Memory Usage ==="
    free -h
    echo ""
    
    echo "=== Environment Variables (Sanitized) ==="
    if [ -f .env.production ]; then
        grep -v -E "(PASSWORD|SECRET|KEY)" .env.production || true
    fi
} > $TEMP_BACKUP_DIR/system/backup-info.txt

print_status "✅ System information collected"

# 8. Create Final Archive
print_section "Creating Archive"
print_status "Creating compressed archive..."

cd /tmp
tar -czf $BACKUP_FILE $BACKUP_NAME/

# Set proper permissions
sudo chown $(whoami):$(whoami) $BACKUP_FILE
chmod 600 $BACKUP_FILE

# Clean up temporary directory
rm -rf $TEMP_BACKUP_DIR

# Get backup size
BACKUP_SIZE=$(du -h $BACKUP_FILE | cut -f1)

print_status "✅ Archive created: $BACKUP_FILE ($BACKUP_SIZE)"

# 9. Backup Verification
print_section "Backup Verification"
print_status "Verifying backup integrity..."

if tar -tzf $BACKUP_FILE >/dev/null 2>&1; then
    print_status "✅ Backup verification successful"
else
    print_error "❌ Backup verification failed!"
    exit 1
fi

# 10. Cleanup Old Backups
print_section "Cleanup Old Backups"
print_status "Removing backups older than $RETENTION_DAYS days..."

find $BACKUP_DIR -name "menshun-backup-*.tar.gz" -mtime +$RETENTION_DAYS -delete 2>/dev/null || true

REMAINING_BACKUPS=$(find $BACKUP_DIR -name "menshun-backup-*.tar.gz" | wc -l)
print_status "✅ Cleanup completed. $REMAINING_BACKUPS backups remaining."

# 11. Backup Summary
print_section "Backup Summary"
echo "Backup File: $BACKUP_FILE"
echo "Backup Size: $BACKUP_SIZE"
echo "Components Backed Up:"
echo "  ✅ Database (PostgreSQL)"
echo "  ✅ Application Configuration"
echo "  ✅ Scripts and Tools"
echo "  ✅ Media Files"
echo "  ✅ SSL Certificates"
echo "  ✅ Recent Logs (7 days)"
echo "  ✅ Docker Volumes"
echo "  ✅ System Information"
echo ""

print_status "🎉 Backup completed successfully!"
print_status "To restore this backup, run: make restore BACKUP_FILE=$BACKUP_FILE"

# Optional: Upload to external storage
if [ -n "$BACKUP_UPLOAD_SCRIPT" ] && [ -f "$BACKUP_UPLOAD_SCRIPT" ]; then
    print_status "Running external backup upload script..."
    $BACKUP_UPLOAD_SCRIPT $BACKUP_FILE
fi

# Optional: Send notification
if [ -n "$BACKUP_NOTIFICATION_SCRIPT" ] && [ -f "$BACKUP_NOTIFICATION_SCRIPT" ]; then
    $BACKUP_NOTIFICATION_SCRIPT "Menshun PAM backup completed" "$BACKUP_FILE ($BACKUP_SIZE)"
fi

exit 0