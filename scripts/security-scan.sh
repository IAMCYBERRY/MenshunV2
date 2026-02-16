#!/bin/bash
# Basic security scan for Menshun PAM deployment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

echo -e "${BLUE}=== Menshun PAM Security Scan ===${NC}"
echo ""

# Check environment file permissions
if [ -f .env.production ]; then
    PERM=$(stat -c "%a" .env.production 2>/dev/null || stat -f "%A" .env.production 2>/dev/null)
    if [ "$PERM" = "600" ]; then
        print_status "Environment file permissions: Secure (600)"
    else
        print_error "Environment file permissions: Insecure ($PERM) - should be 600"
    fi
else
    print_warning "Environment file not found"
fi

# Check for debug mode
if [ -f .env.production ] && grep -q "DEBUG=False" .env.production; then
    print_status "Debug mode: Disabled"
else
    print_error "Debug mode: Enabled or not set"
fi

# Check SSL certificates
if [ -f /opt/menshun/ssl/menshun.crt ]; then
    if openssl x509 -in /opt/menshun/ssl/menshun.crt -noout -checkend 2592000 >/dev/null 2>&1; then
        print_status "SSL certificate: Valid (expires in >30 days)"
    else
        print_warning "SSL certificate: Expires within 30 days"
    fi
else
    print_warning "SSL certificate: Not found"
fi

# Check for exposed ports
echo ""
echo -e "${BLUE}Network Security:${NC}"
if ss -tlnp | grep -q ":5432.*0.0.0.0"; then
    print_error "PostgreSQL exposed on all interfaces"
else
    print_status "PostgreSQL: Not exposed externally"
fi

if ss -tlnp | grep -q ":6379.*0.0.0.0"; then
    print_error "Redis exposed on all interfaces"
else
    print_status "Redis: Not exposed externally"
fi

# Check Docker security
echo ""
echo -e "${BLUE}Container Security:${NC}"
if docker info --format '{{.SecurityOptions}}' | grep -q "name=userns"; then
    print_status "Docker user namespaces: Enabled"
else
    print_warning "Docker user namespaces: Not enabled"
fi

# Check log permissions
if [ -d /opt/menshun/logs ]; then
    LOG_PERM=$(stat -c "%a" /opt/menshun/logs 2>/dev/null || stat -f "%A" /opt/menshun/logs 2>/dev/null)
    if [ "$LOG_PERM" = "755" ] || [ "$LOG_PERM" = "750" ]; then
        print_status "Log directory permissions: Secure"
    else
        print_warning "Log directory permissions: Check manually"
    fi
fi

echo ""
echo -e "${BLUE}Security scan completed${NC}"