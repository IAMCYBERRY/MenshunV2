#!/bin/bash
set -e

echo "🚀 Starting Menshun Development Environment Setup..."

# Wait for database to be ready
echo "⏳ Waiting for database..."
python manage.py wait_for_db 2>/dev/null || {
    echo "📡 Checking database connection..."
    while ! python -c "
import os
import django
from django.conf import settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'menshen.settings.base')
django.setup()
from django.db import connection
connection.ensure_connection()
print('Database connected!')
" 2>/dev/null; do
        echo "⏳ Database not ready, waiting 2 seconds..."
        sleep 2
    done
}

# Run migrations
echo "🔄 Running database migrations..."
python manage.py migrate --noinput

# Check if we need to set up development data
SETUP_DATA=$(python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
print('setup' if User.objects.count() == 0 else 'skip')
" 2>/dev/null || echo "setup")

if [ "$SETUP_DATA" = "setup" ]; then
    echo "🎯 Setting up development data..."
    python manage.py setup_dev_data
else
    echo "✅ Development data already exists"
fi

# Collect static files (for consistency)
echo "📦 Collecting static files..."
python manage.py collectstatic --noinput --clear > /dev/null 2>&1 || echo "⚠️  Static files collection failed (non-critical)"

echo "🎉 Development environment ready!"
echo ""
echo "📋 Available test users:"
echo "  • admin / admin123 (Superuser)"
echo "  • vault_admin / admin123 (Vault Admin)"
echo "  • vault_editor / editor123 (Vault Editor)"  
echo "  • vault_viewer / viewer123 (Vault Viewer)"
echo ""
echo "🌐 Access the application at: http://localhost:8001"
echo ""

# Execute the main command
exec "$@"