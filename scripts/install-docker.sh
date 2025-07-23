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

# Check if Docker is already installed
if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
    print_status "Docker is already installed: $DOCKER_VERSION"
    
    # Check if docker-compose is installed
    if command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_VERSION=$(docker-compose --version | cut -d' ' -f3 | cut -d',' -f1)
        print_status "Docker Compose is already installed: $COMPOSE_VERSION"
        
        # Check if docker group exists and if user is in it
        if getent group docker >/dev/null 2>&1; then
            if groups | grep -q docker; then
                print_status "User is already in docker group"
                print_status "✅ Docker setup is complete!"
                exit 0
            else
                print_warning "User is not in docker group. Adding user to docker group..."
                sudo usermod -aG docker $USER
                print_status "✅ User added to docker group. Please log out and log back in for changes to take effect."
                exit 0
            fi
        else
            print_warning "Docker group doesn't exist. This suggests Docker was not installed properly."
            print_status "Proceeding with Docker installation to fix this..."
        fi
    fi
else
    print_status "Installing Docker..."
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    print_error "Cannot detect OS. Manual installation required."
    exit 1
fi

print_status "Detected OS: $OS $VERSION"

# Install Docker based on OS
case $OS in
    ubuntu|debian)
        print_status "Installing Docker on Ubuntu/Debian..."
        
        # Update package index
        sudo apt-get update
        
        # Install prerequisites
        sudo apt-get install -y \
            ca-certificates \
            curl \
            gnupg \
            lsb-release
        
        # Add Docker's official GPG key
        sudo mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        
        # Set up the repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
          $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Update package index again
        sudo apt-get update
        
        # Install Docker Engine
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # Install standalone docker-compose (for compatibility)
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        ;;
        
    centos|rhel|rocky|alma)
        print_status "Installing Docker on CentOS/RHEL/Rocky/Alma..."
        
        # Remove old versions
        sudo yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
        
        # Install prerequisites
        sudo yum install -y yum-utils
        
        # Set up the repository
        sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        
        # Install Docker Engine
        sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
        
        # Install standalone docker-compose
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
        ;;
        
    *)
        print_error "Unsupported OS: $OS"
        print_error "Please install Docker manually: https://docs.docker.com/engine/install/"
        exit 1
        ;;
esac

# Start and enable Docker service
print_status "Starting Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group
print_status "Adding user $USER to docker group..."
sudo usermod -aG docker $USER

# Verify installation
print_status "Verifying Docker installation..."
sudo docker --version
sudo docker-compose --version

# Test Docker with hello-world
print_status "Testing Docker installation..."
sudo docker run --rm hello-world

# Set up Docker daemon configuration for production
print_status "Configuring Docker daemon..."
sudo mkdir -p /etc/docker

cat << EOF | sudo tee /etc/docker/daemon.json
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "live-restore": true,
    "userland-proxy": false,
    "no-new-privileges": true,
    "seccomp-profile": "/etc/docker/seccomp.json"
}
EOF

# Restart Docker to apply configuration
sudo systemctl restart docker

print_status "✅ Docker installation completed successfully!"
print_warning "⚠️  Please log out and log back in (or run 'newgrp docker') for group changes to take effect."

# Verify user can run docker without sudo (after group change)
print_status "After logging back in, verify with: docker run --rm hello-world"