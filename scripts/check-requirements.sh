#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    print_error "Please do not run this script as root. Use a regular user with sudo privileges."
    exit 1
fi

print_section "System Requirements Check"

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    print_status "Operating System: $PRETTY_NAME"
    
    # Check if it's a supported OS
    case $ID in
        ubuntu|debian|centos|rhel|rocky|alma)
            print_status "Supported OS detected"
            ;;
        *)
            print_warning "This OS may not be fully supported. Proceed with caution."
            ;;
    esac
else
    print_warning "Cannot determine OS version"
fi

# Check architecture
ARCH=$(uname -m)
print_status "Architecture: $ARCH"
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
    print_warning "Architecture $ARCH may not be fully supported"
fi

# Check minimum system requirements
print_section "Hardware Requirements"

# Check RAM (minimum 4GB recommended)
RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
RAM_GB=$((RAM_KB / 1024 / 1024))
print_status "RAM: ${RAM_GB}GB"

if [ $RAM_GB -lt 2 ]; then
    print_error "Insufficient RAM. Minimum 2GB required, 4GB recommended."
    exit 1
elif [ $RAM_GB -lt 4 ]; then
    print_warning "Low RAM detected. 4GB or more is recommended for optimal performance."
fi

# Check disk space (minimum 10GB free)
DISK_AVAIL_KB=$(df / | tail -1 | awk '{print $4}')
DISK_AVAIL_GB=$((DISK_AVAIL_KB / 1024 / 1024))
print_status "Available disk space: ${DISK_AVAIL_GB}GB"

if [ $DISK_AVAIL_GB -lt 5 ]; then
    print_error "Insufficient disk space. Minimum 5GB required, 20GB recommended."
    exit 1
elif [ $DISK_AVAIL_GB -lt 20 ]; then
    print_warning "Low disk space. 20GB or more is recommended."
fi

# Check CPU cores
CPU_CORES=$(nproc)
print_status "CPU cores: $CPU_CORES"

if [ $CPU_CORES -lt 2 ]; then
    print_warning "Single core detected. Multi-core CPU recommended for better performance."
fi

# Check required commands
print_section "Software Requirements"

MISSING_COMMANDS=()

check_command() {
    if command -v $1 >/dev/null 2>&1; then
        print_status "$1: $(command -v $1)"
    else
        print_error "$1: Not found"
        MISSING_COMMANDS+=($1)
    fi
}

# Essential commands
check_command "curl"
check_command "wget"
check_command "git"
check_command "sudo"
check_command "systemctl"

# Check if user has sudo privileges
if sudo -n true 2>/dev/null; then
    print_status "Sudo privileges: Available"
else
    print_error "Sudo privileges: Not available or password required"
    print_error "Please ensure your user has passwordless sudo or be prepared to enter password"
fi

# Check network connectivity
print_section "Network Connectivity"

check_connectivity() {
    if curl -s --max-time 5 $1 >/dev/null; then
        print_status "$1: Reachable"
    else
        print_error "$1: Not reachable"
        return 1
    fi
}

print_status "Testing internet connectivity..."
if ! check_connectivity "https://google.com"; then
    print_error "Internet connectivity required for installation"
    exit 1
fi

print_status "Testing Docker registry connectivity..."
check_connectivity "https://registry-1.docker.io"

print_status "Testing GitHub connectivity..."
check_connectivity "https://github.com"

# Check ports
print_section "Port Availability"

check_port() {
    if ss -ln | grep -q ":$1 "; then
        print_warning "Port $1: In use"
        return 1
    else
        print_status "Port $1: Available"
        return 0
    fi
}

REQUIRED_PORTS=(80 443 5432 6379 8000)
UNAVAILABLE_PORTS=()

for port in "${REQUIRED_PORTS[@]}"; do
    if ! check_port $port; then
        UNAVAILABLE_PORTS+=($port)
    fi
done

# Check firewall status
print_section "Firewall Status"

if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status | head -1)
    print_status "UFW: $UFW_STATUS"
elif command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
        print_status "Firewalld: Active"
    else
        print_status "Firewalld: Inactive"
    fi
elif command -v iptables >/dev/null 2>&1; then
    print_status "iptables: Available"
else
    print_warning "No known firewall detected"
fi

# Summary
print_section "Requirements Summary"

if [ ${#MISSING_COMMANDS[@]} -eq 0 ] && [ ${#UNAVAILABLE_PORTS[@]} -eq 0 ]; then
    print_status "✅ All requirements met! System is ready for Menshun PAM installation."
    exit 0
else
    if [ ${#MISSING_COMMANDS[@]} -gt 0 ]; then
        print_error "Missing commands: ${MISSING_COMMANDS[*]}"
        print_error "Please install missing software before proceeding"
    fi
    
    if [ ${#UNAVAILABLE_PORTS[@]} -gt 0 ]; then
        print_error "Ports in use: ${UNAVAILABLE_PORTS[*]}"
        print_error "Please stop services using these ports or modify configuration"
    fi
    
    print_error "❌ System is not ready for installation. Please resolve the above issues."
    exit 1
fi