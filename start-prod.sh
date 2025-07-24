#!/bin/bash

echo "🚀 Starting Menshun Production Environment..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check for .env file
if [ ! -f .env ]; then
    echo "❌ .env file not found. Please create it with production settings."
    echo "See docker-compose.prod.yml for required environment variables."
    exit 1
fi

# Load environment variables
export $(cat .env | grep -v ^# | xargs)

# Validate required environment variables
REQUIRED_VARS=("SECRET_KEY" "DATABASE_PASSWORD")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ Required environment variable $var is not set in .env file"
        exit 1
    fi
done

# Create required directories
echo "📁 Creating required directories..."
mkdir -p "$HOME/opt/menshun/data/postgres"
mkdir -p "$HOME/opt/menshun/data/redis" 
mkdir -p "$HOME/opt/menshun/data/static"
mkdir -p "$HOME/opt/menshun/data/media"
mkdir -p "$HOME/opt/menshun/logs"
mkdir -p "$HOME/opt/menshun/backups/postgres"
mkdir -p "$HOME/opt/menshun/ssl"

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose -f docker-compose.prod.yml down

# Build and start production environment
echo "🏗️  Building and starting production environment..."
docker-compose -f docker-compose.prod.yml up --build -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Show status
echo ""
echo "📊 Container Status:"
docker-compose -f docker-compose.prod.yml ps

echo ""
echo "🎉 Production environment started!"
echo ""
echo "📋 Available services:"
echo "  • Web Application: https://localhost (or your configured domain)"
echo "  • Database: localhost:5436"
echo "  • Redis: localhost:6383"
echo ""
echo "📝 View logs with: docker-compose -f docker-compose.prod.yml logs -f"
echo "🛑 Stop with: docker-compose -f docker-compose.prod.yml down"
echo ""