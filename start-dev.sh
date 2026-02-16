#!/bin/bash

echo "🔧 Starting Menshun Development Environment..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down

# Build and start development environment
echo "🏗️  Building and starting development environment..."
docker-compose up --build -d

# Wait a moment for services to start
sleep 3

# Show status
echo ""
echo "📊 Container Status:"
docker-compose ps

echo ""
echo "🎉 Development environment started!"
echo ""
echo "📋 Available services:"
echo "  • Web Application: http://localhost:8001"
echo "  • Database: localhost:5435 (postgres/postgres)"
echo "  • Redis: localhost:6382"
echo ""
echo "📝 View logs with: docker-compose logs -f"
echo "🛑 Stop with: docker-compose down"
echo ""