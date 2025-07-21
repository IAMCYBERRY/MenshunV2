#!/usr/bin/env python3
"""
Port availability checker and Docker Compose port configurator
"""
import socket
import subprocess
import sys
import os


def is_port_in_use(port, host='localhost'):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def find_available_port(start_port, host='localhost'):
    """Find the next available port starting from start_port"""
    port = start_port
    while port < start_port + 100:  # Check up to 100 ports ahead
        if not is_port_in_use(port, host):
            return port
        port += 1
    raise Exception(f"No available ports found starting from {start_port}")


def generate_docker_compose_with_ports():
    """Generate docker-compose.yml with available ports"""
    
    # Default ports we want to try
    preferred_ports = {
        'postgres': 5432,
        'redis': 6379,
        'web': 8000
    }
    
    # Find available ports
    available_ports = {}
    for service, preferred_port in preferred_ports.items():
        if is_port_in_use(preferred_port):
            available_port = find_available_port(preferred_port + 1)
            print(f"⚠️  Port {preferred_port} is in use for {service}, using {available_port} instead")
        else:
            available_port = preferred_port
            print(f"✅ Port {preferred_port} is available for {service}")
        
        available_ports[service] = available_port
    
    # Create the docker-compose content
    docker_compose_content = f"""version: '3.8'

services:
  db:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    environment:
      POSTGRES_DB: menshen_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "{available_ports['postgres']}:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "{available_ports['redis']}:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  web:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
    volumes:
      - .:/app
    ports:
      - "{available_ports['web']}:8000"
    environment:
      - DEBUG=True
      - DATABASE_NAME=menshen_db
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=postgres
      - DATABASE_HOST=db
      - DATABASE_PORT=5432
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - SECRET_KEY=django-insecure-development-key-change-in-production
      - ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

  celery:
    build: .
    command: celery -A menshen worker -l info
    volumes:
      - .:/app
    environment:
      - DEBUG=True
      - DATABASE_NAME=menshen_db
      - DATABASE_USER=postgres
      - DATABASE_PASSWORD=postgres
      - DATABASE_HOST=db
      - DATABASE_PORT=5432
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - SECRET_KEY=django-insecure-development-key-change-in-production
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  postgres_data:
"""
    
    # Write the docker-compose.yml file
    with open('docker-compose.yml', 'w') as f:
        f.write(docker_compose_content)
    
    # Update .env file with the correct ports
    env_updates = []
    if available_ports['postgres'] != 5432:
        env_updates.append(f"DATABASE_PORT={available_ports['postgres']}")
    if available_ports['redis'] != 6379:
        env_updates.append(f"REDIS_PORT={available_ports['redis']}")
    
    if env_updates:
        print(f"\n📝 Updating .env file with new ports...")
        
        # Read existing .env file
        env_content = ""
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                env_content = f.read()
        
        # Update or add port configurations
        for update in env_updates:
            key, value = update.split('=')
            lines = env_content.split('\n')
            updated = False
            
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = update
                    updated = True
                    break
            
            if not updated:
                lines.append(update)
            
            env_content = '\n'.join(lines)
        
        # Write updated .env file
        with open('.env', 'w') as f:
            f.write(env_content)
    
    print(f"\n🐳 Docker Compose configured with ports:")
    print(f"   PostgreSQL: localhost:{available_ports['postgres']}")
    print(f"   Redis: localhost:{available_ports['redis']}")
    print(f"   Web App: http://localhost:{available_ports['web']}")
    
    return available_ports


def main():
    """Main function"""
    print("🔍 Checking port availability...")
    
    try:
        ports = generate_docker_compose_with_ports()
        
        print(f"\n✅ Configuration complete!")
        print(f"\n🚀 To start the services, run:")
        print(f"   docker-compose up --build")
        print(f"\n🌐 Access the application at:")
        print(f"   Dashboard: http://localhost:{ports['web']}")
        print(f"   Admin Panel: http://localhost:{ports['web']}/admin")
        print(f"   API Browser: http://localhost:{ports['web']}/api")
        
        # Return non-zero exit code if ports were changed
        default_ports = {'postgres': 5432, 'redis': 6379, 'web': 8000}
        if ports != default_ports:
            return 1
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())