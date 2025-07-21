#!/bin/bash

# Menshen PAM Smart Startup Script
# This script automatically detects port conflicts and configures Docker Compose accordingly

set -e

echo "🚀 Starting Menshen PAM with automatic port detection..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if Docker and Docker Compose are available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is required but not installed."
    exit 1
fi

# Run the port checker and configuration generator
echo "🔍 Checking for port conflicts..."
python3 scripts/check_ports.py

# Check if ports were changed (exit code 1 means ports were changed)
if [ $? -eq 1 ]; then
    echo ""
    echo "⚠️  Some default ports were in use and have been changed."
    echo "📝 The docker-compose.yml and .env files have been updated accordingly."
    echo ""
fi

# Ask user if they want to proceed
read -p "🐳 Start Docker Compose services? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔄 Starting Docker Compose services..."
    
    # Build and start services
    docker-compose up --build -d
    
    # Wait for services to be ready
    echo "⏳ Waiting for services to start..."
    sleep 10
    
    # Check service health
    echo "🏥 Checking service health..."
    
    # Get the web port from docker-compose.yml
    WEB_PORT=$(grep -A 1 'web:' docker-compose.yml | grep 'ports:' -A 1 | grep -o '[0-9]*:8000' | cut -d':' -f1)
    if [ -z "$WEB_PORT" ]; then
        WEB_PORT=8000
    fi
    
    # Wait for web service to be ready
    echo "🌐 Waiting for web service on port $WEB_PORT..."
    for i in {1..30}; do
        if curl -s "http://localhost:$WEB_PORT" > /dev/null; then
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""
    
    # Initialize the database if this is the first run
    echo "🔧 Initializing database (if needed)..."
    docker-compose exec -T web python manage.py migrate --noinput
    
    # Check if superuser exists, if not run setup
    if ! docker-compose exec -T web python manage.py shell -c "from vault.models import CustomUser; exit(0 if CustomUser.objects.filter(is_superuser=True).exists() else 1)" 2>/dev/null; then
        echo "👤 Setting up initial data and users..."
        docker-compose exec -T web python setup.py
    else
        echo "✅ Database already initialized"
    fi
    
    echo ""
    echo "🎉 Menshen PAM is now running!"
    echo ""
    echo "🌐 Access your application:"
    echo "   Dashboard:    http://localhost:$WEB_PORT"
    echo "   Admin Panel:  http://localhost:$WEB_PORT/admin"
    echo "   API Browser:  http://localhost:$WEB_PORT/api"
    echo ""
    echo "👥 Default users:"
    echo "   Superuser:    admin / admin123"
    echo "   Vault Admin:  vault_admin / admin123"
    echo "   Vault Editor: vault_editor / editor123"
    echo "   Vault Viewer: vault_viewer / viewer123"
    echo ""
    echo "🛑 To stop services: docker-compose down"
    echo "📋 To view logs: docker-compose logs -f"
    
else
    echo "❌ Startup cancelled by user"
    exit 0
fi