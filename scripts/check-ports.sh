#!/bin/bash

echo "=== Checking Port Usage ==="
echo ""

check_port() {
    local port=$1
    local service=$2
    echo -n "Port $port ($service): "
    
    if command -v lsof >/dev/null 2>&1; then
        # Use lsof if available
        local result=$(sudo lsof -i :$port 2>/dev/null | grep LISTEN | head -1)
        if [ -n "$result" ]; then
            echo "IN USE"
            echo "  Process: $(echo $result | awk '{print $1}')"
            echo "  PID: $(echo $result | awk '{print $2}')"
        else
            echo "FREE"
        fi
    elif command -v ss >/dev/null 2>&1; then
        # Use ss as fallback
        local result=$(sudo ss -tlnp | grep ":$port " 2>/dev/null | head -1)
        if [ -n "$result" ]; then
            echo "IN USE"
            echo "  Details: $result"
        else
            echo "FREE"
        fi
    else
        # Use netstat as last resort
        local result=$(sudo netstat -tlnp 2>/dev/null | grep ":$port " | head -1)
        if [ -n "$result" ]; then
            echo "IN USE"
            echo "  Details: $result"
        else
            echo "FREE"
        fi
    fi
}

echo "Checking Menshun-related ports..."
echo ""
check_port 80 "HTTP/Nginx"
check_port 443 "HTTPS/Nginx"
check_port 5432 "PostgreSQL"
check_port 5435 "PostgreSQL Dev"
check_port 5436 "PostgreSQL Prod"
check_port 6379 "Redis"
check_port 6382 "Redis Dev"
check_port 6383 "Redis Prod"
check_port 8000 "Django"
check_port 8001 "Django Dev"
check_port 8003 "Django Test"

echo ""
echo "=== Docker Containers ==="
docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"

echo ""
echo "=== Recommendations ==="
echo "If Menshun is already running:"
echo "  - Use 'docker-compose -f docker-compose.prod.yml down' to stop it"
echo "  - Or use 'make stop' if using the Makefile"
echo ""
echo "If other services are using the ports:"
echo "  - Stop conflicting services"
echo "  - Or modify docker-compose.prod.yml to use different ports"