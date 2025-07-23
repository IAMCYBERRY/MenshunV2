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

# Wait for database to be ready
print_status "Waiting for database to be ready..."
while ! pg_isready -h $DATABASE_HOST -p $DATABASE_PORT -U $DATABASE_USER; do
    print_warning "Database is unavailable - sleeping"
    sleep 1
done
print_status "Database is ready!"

# Wait for Redis to be ready
print_status "Waiting for Redis to be ready..."
while ! python -c "import redis; r=redis.Redis(host='$REDIS_HOST', port=$REDIS_PORT, socket_connect_timeout=1); r.ping()" > /dev/null 2>&1; do
    print_warning "Redis is unavailable - sleeping"
    sleep 1
done
print_status "Redis is ready!"

# Run database migrations
print_status "Running database migrations..."
python manage.py migrate --noinput

# Create cache table if it doesn't exist
print_status "Creating cache table..."
python manage.py createcachetable || true

# Collect static files
print_status "Collecting static files..."
python manage.py collectstatic --noinput --clear

# Create default superuser if it doesn't exist (only in development)
if [ "$DEBUG" = "True" ]; then
    print_status "Creating default superuser (development only)..."
    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
    print('Created default superuser: admin/admin123')
"
fi

# Validate deployment settings
print_status "Validating deployment settings..."
python manage.py check --deploy

# Create log directory if it doesn't exist
mkdir -p /app/logs

# Set log file permissions (make sure menshun user can write)
touch /app/logs/gunicorn-access.log /app/logs/gunicorn-error.log 2>/dev/null || true
chmod 644 /app/logs/gunicorn-*.log 2>/dev/null || true

print_status "Starting application..."

# Execute the main command
exec "$@"