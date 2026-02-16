#!/bin/bash
# Database-only backup script for Menshun PAM

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

# Configuration
BACKUP_DIR="/opt/menshun/backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/db-backup-$TIMESTAMP.sql.gz"
COMPOSE_FILE="docker-compose.prod.yml"

print_status "Starting database backup..."

# Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# Check if database container is running
if ! docker-compose -f $COMPOSE_FILE ps db | grep -q "Up"; then
    print_error "Database container is not running"
    exit 1
fi

# Get database credentials from environment
if [ -f .env.production ]; then
    source .env.production
fi

print_status "Creating database dump..."

# Create database dump
docker-compose -f $COMPOSE_FILE exec -T db pg_dump \
    -U ${DATABASE_USER:-postgres} \
    -d ${DATABASE_NAME:-menshen_db} \
    --no-owner --no-privileges \
    --clean --create | gzip > $BACKUP_FILE

# Check if backup was successful
if [ $? -eq 0 ] && [ -f $BACKUP_FILE ]; then
    BACKUP_SIZE=$(du -h $BACKUP_FILE | cut -f1)
    print_status "✅ Database backup completed: $BACKUP_FILE ($BACKUP_SIZE)"
    
    # Test backup integrity
    if zcat $BACKUP_FILE | head -20 | grep -q "PostgreSQL database dump"; then
        print_status "✅ Backup verification successful"
    else
        print_error "❌ Backup verification failed"
        exit 1
    fi
else
    print_error "❌ Database backup failed"
    exit 1
fi

# Cleanup old database backups (keep last 7 days)
find $BACKUP_DIR -name "db-backup-*.sql.gz" -mtime +7 -delete 2>/dev/null

print_status "Database backup completed successfully!"
echo "To restore: make db-restore DB_BACKUP_FILE=$BACKUP_FILE"