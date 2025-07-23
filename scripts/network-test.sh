#!/bin/bash
# Network connectivity test for Menshun PAM

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo -e "${BLUE}=== Network Connectivity Test ===${NC}"
echo ""

# Test internal services
echo -e "${BLUE}Internal Services:${NC}"

# Test web application
if curl -s --max-time 5 http://localhost:8000/health/ >/dev/null; then
    print_status "Web application (port 8000): Accessible"
else
    print_error "Web application (port 8000): Not accessible"
fi

# Test Nginx
if curl -s --max-time 5 http://localhost/ >/dev/null; then
    print_status "Nginx (port 80): Accessible"
else
    print_error "Nginx (port 80): Not accessible"
fi

# Test HTTPS
if curl -s --max-time 5 -k https://localhost/ >/dev/null; then
    print_status "HTTPS (port 443): Accessible"
else
    print_error "HTTPS (port 443): Not accessible"
fi

echo ""
echo -e "${BLUE}External Connectivity:${NC}"

# Test external services
sites=("google.com" "github.com" "registry-1.docker.io")
for site in "${sites[@]}"; do
    if curl -s --max-time 5 https://$site >/dev/null; then
        print_status "$site: Reachable"
    else
        print_error "$site: Not reachable"
    fi
done

echo ""
echo -e "${BLUE}DNS Resolution:${NC}"

# Test DNS resolution
if nslookup google.com >/dev/null 2>&1; then
    print_status "DNS resolution: Working"
else
    print_error "DNS resolution: Failed"
fi

echo ""
echo -e "${BLUE}Port Status:${NC}"

# Check listening ports
ports=("80:HTTP" "443:HTTPS" "8000:Django" "5432:PostgreSQL" "6379:Redis")
for port_info in "${ports[@]}"; do
    port=$(echo $port_info | cut -d: -f1)
    service=$(echo $port_info | cut -d: -f2)
    
    if ss -tlnp | grep -q ":$port "; then
        print_status "$service (port $port): Listening"
    else
        print_warning "$service (port $port): Not listening"
    fi
done