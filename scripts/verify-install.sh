#!/bin/bash
# Installation verification script for Menshun PAM

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

VERIFICATION_PASSED=0

print_section "Menshun PAM Installation Verification"

# Check required files
print_section "Configuration Files"

required_files=(
    "Makefile"
    "docker-compose.prod.yml"
    "Dockerfile.prod" 
    ".env.production"
    "config/nginx/nginx.conf"
    "config/nginx/sites-available/menshun.conf"
    "config/settings/production.py"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        print_status "$file: Present"
    else
        print_error "$file: Missing"
        VERIFICATION_PASSED=1
    fi
done

# Check scripts
print_section "Installation Scripts"

required_scripts=(
    "scripts/check-requirements.sh"
    "scripts/install-docker.sh"
    "scripts/setup-environment.sh"
    "scripts/setup-nginx.sh"
    "scripts/setup-ssl.sh"
    "scripts/install-systemd-services.sh"
    "scripts/backup.sh"
    "scripts/health-check.sh"
)

for script in "${required_scripts[@]}"; do
    if [ -f "$script" ] && [ -x "$script" ]; then
        print_status "$script: Present and executable"
    elif [ -f "$script" ]; then
        print_warning "$script: Present but not executable"
        chmod +x "$script"
        print_status "$script: Made executable"
    else
        print_error "$script: Missing"
        VERIFICATION_PASSED=1
    fi
done

# Check directories
print_section "Directory Structure"

required_dirs=(
    "config/nginx"
    "config/settings"
    "scripts"
)

for dir in "${required_dirs[@]}"; do
    if [ -d "$dir" ]; then
        print_status "$dir/: Present"
    else
        print_error "$dir/: Missing"
        VERIFICATION_PASSED=1
    fi
done

# Check system directories (if they should exist)
print_section "System Directories"

system_dirs=(
    "/opt/menshun"
    "/opt/menshun/data"
    "/opt/menshun/logs"
    "/opt/menshun/backups"
    "/opt/menshun/ssl"
)

for dir in "${system_dirs[@]}"; do
    if [ -d "$dir" ]; then
        print_status "$dir: Present"
    else
        print_warning "$dir: Not yet created (will be created during 'make init')"
    fi
done

# Check Docker and Docker Compose
print_section "Dependencies"

if command -v docker >/dev/null 2>&1; then
    print_status "Docker: $(docker --version | cut -d' ' -f3 | cut -d',' -f1)"
else
    print_warning "Docker: Not installed (will be installed during 'make init')"
fi

if command -v docker-compose >/dev/null 2>&1; then
    print_status "Docker Compose: $(docker-compose --version | cut -d' ' -f3 | cut -d',' -f1)"
else
    print_warning "Docker Compose: Not installed (will be installed during 'make init')"
fi

# Test Makefile syntax
print_section "Makefile Syntax"

if make -n help >/dev/null 2>&1; then
    print_status "Makefile syntax: Valid"
else
    print_error "Makefile syntax: Invalid"
    VERIFICATION_PASSED=1
fi

# Check environment template
print_section "Environment Configuration"

if [ -f ".env.production" ]; then
    print_status "Environment file: Present"
    
    # Check for required variables
    required_vars=("SECRET_KEY" "DATABASE_PASSWORD" "ALLOWED_HOSTS")
    for var in "${required_vars[@]}"; do
        if grep -q "^${var}=" .env.production; then
            print_status "Environment variable $var: Set"
        else
            print_warning "Environment variable $var: Not set"
        fi
    done
else
    print_warning "Environment file: Will be created during 'make init'"
fi

# Final verification
print_section "Verification Summary"

if [ $VERIFICATION_PASSED -eq 0 ]; then
    print_status "✅ Installation verification passed!"
    echo ""
    echo -e "${GREEN}Ready to run: make init${NC}"
    exit 0
else
    print_error "❌ Installation verification failed!"
    echo ""
    echo -e "${RED}Please resolve the issues above before running 'make init'${NC}"
    exit 1
fi