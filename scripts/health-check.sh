#!/bin/bash
# Comprehensive health check for Menshun PAM

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

print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

OVERALL_HEALTH=0

check_status() {
    if [ $1 -eq 0 ]; then
        print_status "$2"
    else
        print_error "$2"
        OVERALL_HEALTH=1
    fi
}

print_section "Menshun PAM Health Check"

# System Resources
print_section "System Resources"

# Check disk space
DISK_USAGE=$(df / | awk 'NR==2 {print int($5)}')
if [ $DISK_USAGE -lt 90 ]; then
    print_status "Disk space: ${DISK_USAGE}% used"
else
    print_error "Disk space: ${DISK_USAGE}% used (>90%)"
    OVERALL_HEALTH=1
fi

# Check memory
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ $MEM_USAGE -lt 90 ]; then
    print_status "Memory usage: ${MEM_USAGE}%"
else
    print_warning "Memory usage: ${MEM_USAGE}% (high)"
fi

# Docker Services
print_section "Docker Services"

if command -v docker-compose >/dev/null 2>&1 && [ -f docker-compose.prod.yml ]; then
    # Check web service
    if docker-compose -f docker-compose.prod.yml ps web | grep -q "Up"; then
        print_status "Web service: Running"
        
        # Check web health endpoint
        if curl -s --max-time 10 http://localhost:8000/health/ >/dev/null; then
            print_status "Web health endpoint: Responding"
        else
            print_error "Web health endpoint: Not responding"
            OVERALL_HEALTH=1
        fi
    else
        print_error "Web service: Not running"
        OVERALL_HEALTH=1
    fi
    
    # Check database
    if docker-compose -f docker-compose.prod.yml ps db | grep -q "Up"; then
        print_status "Database service: Running"
        
        # Test database connection
        if docker-compose -f docker-compose.prod.yml exec -T db pg_isready -U postgres >/dev/null 2>&1; then
            print_status "Database connection: OK"
        else
            print_error "Database connection: Failed"
            OVERALL_HEALTH=1
        fi
    else
        print_error "Database service: Not running"
        OVERALL_HEALTH=1
    fi
    
    # Check Redis
    if docker-compose -f docker-compose.prod.yml ps redis | grep -q "Up"; then
        print_status "Redis service: Running"
        
        # Test Redis connection
        if docker-compose -f docker-compose.prod.yml exec -T redis redis-cli ping | grep -q "PONG"; then
            print_status "Redis connection: OK"
        else
            print_error "Redis connection: Failed"
            OVERALL_HEALTH=1
        fi
    else
        print_error "Redis service: Not running"
        OVERALL_HEALTH=1
    fi
    
    # Check Celery
    if docker-compose -f docker-compose.prod.yml ps celery | grep -q "Up"; then
        print_status "Celery service: Running"
    else
        print_warning "Celery service: Not running"
    fi
    
else
    print_error "Docker Compose not available or production config missing"
    OVERALL_HEALTH=1
fi

# System Services
print_section "System Services"

# Check Nginx
if systemctl is-active --quiet nginx 2>/dev/null; then
    print_status "Nginx: Active"
    
    # Test Nginx response
    if curl -s --max-time 5 http://localhost/ >/dev/null; then
        print_status "Nginx response: OK"
    else
        print_error "Nginx response: Failed"
        OVERALL_HEALTH=1
    fi
else
    print_warning "Nginx: Not active"
fi

# Check systemd services
for service in menshun-web menshun-monitor; do
    if systemctl is-active --quiet $service 2>/dev/null; then
        print_status "$service: Active"
    else
        print_warning "$service: Not active"
    fi
done

# SSL Certificate
print_section "SSL Certificate"
if [ -f /opt/menshun/ssl/menshun.crt ]; then
    if openssl x509 -in /opt/menshun/ssl/menshun.crt -noout -checkend 0 >/dev/null 2>&1; then
        DAYS_LEFT=$(openssl x509 -in /opt/menshun/ssl/menshun.crt -noout -dates | grep "notAfter" | cut -d= -f2 | xargs -I {} date -d {} +%s)
        CURRENT=$(date +%s)
        DAYS_REMAINING=$(( (DAYS_LEFT - CURRENT) / 86400 ))
        
        if [ $DAYS_REMAINING -gt 30 ]; then
            print_status "SSL certificate: Valid ($DAYS_REMAINING days remaining)"
        else
            print_warning "SSL certificate: Expires soon ($DAYS_REMAINING days remaining)"
        fi
    else
        print_error "SSL certificate: Expired"
        OVERALL_HEALTH=1
    fi
else
    print_warning "SSL certificate: Not found"
fi

# Network Connectivity
print_section "Network Connectivity"

# Test external connectivity
if curl -s --max-time 5 https://google.com >/dev/null; then
    print_status "External connectivity: OK"
else
    print_warning "External connectivity: Limited"
fi

# Final Status
print_section "Overall Health"
if [ $OVERALL_HEALTH -eq 0 ]; then
    print_status "System health: All checks passed ✅"
    exit 0
else
    print_error "System health: Issues detected ❌"
    exit 1
fi