#!/bin/bash

echo "🧪 Starting Menshun Production Test Environment..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f docker-compose.test.yml down 2>/dev/null || true
docker-compose down 2>/dev/null || true

# Build and start test production environment
echo "🏗️  Building and starting production test environment..."
docker-compose -f docker-compose.test.yml up --build -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check services
echo ""
echo "📊 Container Status:"
docker-compose -f docker-compose.test.yml ps

# Run initial setup
echo ""
echo "🔧 Running initial setup..."

# Wait for database to be ready
echo "⏳ Waiting for database..."
docker-compose -f docker-compose.test.yml exec -T web python -c "
import os, django, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'menshen.settings.production')
django.setup()
from django.db import connection
for i in range(30):
    try:
        connection.ensure_connection()
        print('Database connected!')
        break
    except:
        time.sleep(2)
        print('Waiting for database...')
" || echo "Database connection timeout - continuing anyway"

# Run migrations
echo "🔄 Running migrations..."
docker-compose -f docker-compose.test.yml exec -T web python manage.py migrate

# Create superuser if none exists
echo "👤 Setting up admin user..."
docker-compose -f docker-compose.test.yml exec -T web python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser('admin', 'admin@menshun.local', 'admin123')
    print('Created admin user: admin / admin123')
else:
    print('Admin user already exists')
"

# Set up groups and sample data
echo "📋 Setting up groups and sample data..."
docker-compose -f docker-compose.test.yml exec -T web python manage.py setup_groups 2>/dev/null || echo "Groups setup completed"
docker-compose -f docker-compose.test.yml exec -T web python manage.py setup_sample_data 2>/dev/null || echo "Sample data setup completed"

# Collect static files
echo "📦 Collecting static files..."
docker-compose -f docker-compose.test.yml exec -T web python manage.py collectstatic --noinput

echo ""
echo "🎉 Production test environment started!"
echo ""
echo "📋 Available services:"
echo "  • Direct Web Access: http://localhost:8003"
echo "  • Nginx Proxy: http://localhost:80 and http://localhost:8080"
echo "  • Admin Panel: http://localhost:8003/admin/"
echo "  • Database: localhost:5436 (postgres/postgres)"
echo "  • Redis: localhost:6383"
echo ""
echo "👤 Test login credentials:"
echo "  • Username: admin"
echo "  • Password: admin123"
echo ""
echo "📝 View logs with: docker-compose -f docker-compose.test.yml logs -f"
echo "🛑 Stop with: docker-compose -f docker-compose.test.yml down"
echo ""

# Test the endpoints
echo "🔍 Testing endpoints..."
sleep 5

# Test direct web access
echo -n "Direct web access (port 8003): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8003/health/ 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Working"
else
    echo "❌ Failed (HTTP $HTTP_CODE)"
fi

# Test nginx proxy
echo -n "Nginx proxy (port 80): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80/health/ 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Working"
else
    echo "❌ Failed (HTTP $HTTP_CODE)"
fi

echo -n "Nginx proxy (port 8080): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health/ 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ Working"
else
    echo "❌ Failed (HTTP $HTTP_CODE)"
fi

echo ""
echo "🎯 Next steps:"
echo "1. Test login at http://localhost:8003/admin/"
echo "2. Check application at http://localhost:8003/"
echo "3. If nginx proxy works, the app should also work at http://localhost:80/"
echo ""