#!/bin/bash
# Database restore script for Menshun PAM

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

# Check if backup file is provided
if [ -z "$1" ]; then
    print_error "Usage: $0 <backup-file.sql.gz>"
    print_error "Example: $0 /opt/menshun/backups/db-backup-20231201-120000.sql.gz"
    exit 1
fi

BACKUP_FILE="$1"
COMPOSE_FILE="docker-compose.prod.yml"

# Check if backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    print_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

print_status "Starting database restore from: $BACKUP_FILE"

# Check if database container is running
if ! docker-compose -f $COMPOSE_FILE ps db | grep -q "Up"; then
    print_error "Database container is not running. Starting database service..."
    docker-compose -f $COMPOSE_FILE up -d db
    sleep 10
fi

# Get database credentials from environment
if [ -f .env.production ]; then
    source .env.production
fi

# Verify backup file integrity
print_status "Verifying backup file..."
if zcat $BACKUP_FILE | head -20 | grep -q "PostgreSQL database dump"; then
    print_status "✅ Backup file verification successful"
else
    print_error "❌ Backup file appears to be corrupted"
    exit 1
fi

# Warning about data loss
print_warning "⚠️  WARNING: This will replace all existing data in the database!"
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^yes$ ]]; then
    print_status "Database restore cancelled"
    exit 0
fi

# Stop web application to prevent connections during restore
print_status "Stopping web application..."
docker-compose -f $COMPOSE_FILE stop web celery celery-beat

# Create a backup of current database before restore
CURRENT_BACKUP="/tmp/pre-restore-backup-$(date +%Y%m%d-%H%M%S).sql.gz"
print_status "Creating backup of current database..."
docker-compose -f $COMPOSE_FILE exec -T db pg_dump \
    -U ${DATABASE_USER:-postgres} \
    -d ${DATABASE_NAME:-menshen_db} \
    --no-owner --no-privileges | gzip > $CURRENT_BACKUP

print_status "Current database backed up to: $CURRENT_BACKUP"

# Restore database
print_status "Restoring database..."
zcat $BACKUP_FILE | docker-compose -f $COMPOSE_FILE exec -T db psql \
    -U ${DATABASE_USER:-postgres} \
    -d ${DATABASE_NAME:-menshen_db}

if [ $? -eq 0 ]; then
    print_status "✅ Database restore completed successfully"
    
    # Start services back up
    print_status "Starting services..."
    docker-compose -f $COMPOSE_FILE up -d
    
    # Wait for services to be ready
    sleep 15
    
    # Run health check
    print_status "Running health check..."
    if curl -s --max-time 10 http://localhost:8000/health/ >/dev/null; then
        print_status "✅ Application is responding after restore"
    else
        print_warning "⚠️  Application may need more time to start up"
    fi
    
    print_status "🎉 Database restore completed successfully!"
    print_status "Pre-restore backup saved at: $CURRENT_BACKUP"
    
else
    print_error "❌ Database restore failed"
    
    print_status "Attempting to restore previous database..."
    zcat $CURRENT_BACKUP | docker-compose -f $COMPOSE_FILE exec -T db psql \
        -U ${DATABASE_USER:-postgres} \
        -d ${DATABASE_NAME:-menshen_db}
    
    print_status "Starting services..."
    docker-compose -f $COMPOSE_FILE up -d
    
    exit 1
fi