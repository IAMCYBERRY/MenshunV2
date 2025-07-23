#!/bin/bash
# System monitoring script for Menshun PAM

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo -e "${BLUE}=== Menshun PAM System Monitor ===${NC}"
echo ""

# System Resources
echo -e "${BLUE}System Resources:${NC}"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory: $(free -h | awk 'NR==2{printf "%.1f%% (%s/%s)", $3*100/$2, $3, $2}')"
echo "Disk: $(df -h / | awk 'NR==2{printf "%s/%s (%s)", $3, $2, $5}')"
echo ""

# Docker Status
echo -e "${BLUE}Docker Containers:${NC}"
if command -v docker-compose >/dev/null 2>&1; then
    if [ -f docker-compose.prod.yml ]; then
        docker-compose -f docker-compose.prod.yml ps
    else
        echo "Production compose file not found"
    fi
else
    echo "Docker Compose not available"
fi

echo ""

# Network Connectivity
echo -e "${BLUE}Network Status:${NC}"
if curl -s --max-time 5 http://localhost:8000/health/ >/dev/null; then
    print_status "Web application: Responding"
else
    print_error "Web application: Not responding"
fi

# Service Status
echo ""
echo -e "${BLUE}System Services:${NC}"
services=("nginx" "docker" "menshun-web")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        print_status "$service: Active"
    else
        print_warning "$service: Inactive or not found"
    fi
done