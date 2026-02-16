# Menshun PAM - Environment Management

This document explains how to set up and manage development and production environments for Menshun PAM.

## Quick Start

### Development Environment
```bash
# Start development environment with auto-setup
./start-dev.sh

# Or manually:
docker-compose up --build
```

### Production Environment
```bash
# Create .env file first (see Production Setup below)
./start-prod.sh

# Or manually:
docker-compose -f docker-compose.prod.yml up --build -d
```

## Environment Comparison

| Feature | Development | Production |
|---------|------------|------------|
| **Access** | http://localhost:8001 | https://yourdomain.com |
| **Command** | `./start-dev.sh` | `./start-prod.sh` |
| **Docker Compose** | `docker-compose.yml` | `docker-compose.prod.yml` |
| **Dockerfile** | `Dockerfile.dev` | `Dockerfile.prod` |
| **Django Settings** | `menshen.settings.base` | `menshen.settings.production` |
| **Debug Mode** | Enabled | Disabled |
| **Auto-reload** | Yes | No |
| **Web Server** | Django runserver | Gunicorn + Nginx |
| **SSL** | No | Yes (with certificates) |
| **Data Persistence** | Docker volumes | Host bind mounts |
| **Resource Limits** | None | CPU/Memory limits |
| **Health Checks** | Basic | Comprehensive |

## Development Environment

### Features
- **Auto-Setup**: Automatically creates users, groups, and sample data
- **Hot Reload**: Code changes are reflected immediately
- **Debug Mode**: Detailed error pages and Django debug toolbar
- **Test Users**: Pre-created users for different roles

### Test Users
The development environment automatically creates these users:

| Username | Password | Role | Access Level |
|----------|----------|------|--------------|
| `admin` | `admin123` | Superuser | Full system access |
| `vault_admin` | `admin123` | Vault Admin | Full vault management |
| `vault_editor` | `editor123` | Vault Editor | Create/edit vault entries |
| `vault_viewer` | `viewer123` | Vault Viewer | Read-only access |

### Development Commands
```bash
# Start development environment
./start-dev.sh

# View logs
docker-compose logs -f

# Access Django shell
docker-compose exec web python manage.py shell

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Reset development data
docker-compose exec web python manage.py setup_dev_data --reset

# Stop environment
docker-compose down
```

## Production Environment

### Setup Requirements
1. **Create .env file** with production settings
2. **SSL Certificates** in `$HOME/opt/menshun/ssl/`
3. **Host directories** for persistent data

### Required .env Variables
```bash
# Security
SECRET_KEY=your-secret-key-here
DATABASE_PASSWORD=secure-database-password

# Domain
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database
DATABASE_NAME=menshen_db
DATABASE_USER=postgres

# Azure AD (if using)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id  
AZURE_CLIENT_SECRET=your-client-secret
AZURE_REDIRECT_URI=https://yourdomain.com/auth/microsoft/complete

# Optional: Email settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
```

### Production Directory Structure
The production environment creates this directory structure:
```
$HOME/opt/menshun/
├── data/
│   ├── postgres/     # Database files
│   ├── redis/        # Redis data
│   ├── static/       # Static files
│   └── media/        # Uploaded files
├── logs/             # Application logs
├── backups/
│   └── postgres/     # Database backups
└── ssl/              # SSL certificates
    ├── cert.pem
    └── key.pem
```

### Production Commands
```bash
# Start production environment
./start-prod.sh

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Access Django shell
docker-compose -f docker-compose.prod.yml exec web python manage.py shell

# Create superuser
docker-compose -f docker-compose.prod.yml exec web python manage.py createsuperuser

# Backup database
docker-compose -f docker-compose.prod.yml exec db pg_dump -U postgres menshen_db > backup.sql

# Stop environment
docker-compose -f docker-compose.prod.yml down
```

## Data Persistence

### Development
- Uses Docker volumes for data storage
- Data persists between container restarts
- Data is lost when volumes are removed (`docker-compose down -v`)

### Production
- Uses host bind mounts for data storage
- Data persists on the host filesystem
- Survives container recreation and system reboots
- Located in `$HOME/opt/menshun/data/`

## Environment Switching

### From Development to Production
1. Commit your changes to git
2. Stop development environment: `docker-compose down`
3. Create production `.env` file
4. Start production environment: `./start-prod.sh`

### From Production to Development
1. Stop production environment: `docker-compose -f docker-compose.prod.yml down`
2. Start development environment: `./start-dev.sh`

## Troubleshooting

### Development Issues
```bash
# Rebuild containers
docker-compose down && docker-compose up --build

# Reset development data
docker-compose exec web python manage.py setup_dev_data --reset

# Clear volumes
docker-compose down -v && docker-compose up
```

### Production Issues
```bash
# Check logs
docker-compose -f docker-compose.prod.yml logs

# Restart services
docker-compose -f docker-compose.prod.yml restart

# Health check
docker-compose -f docker-compose.prod.yml exec web python manage.py check
```

### Port Conflicts
If you get port conflicts, the ports used are:

**Development:**
- Web: 8001
- Database: 5435  
- Redis: 6382

**Production:**
- Web: 8003 (behind Nginx)
- Database: 5436
- Redis: 6383
- Nginx: 80, 443

## Backup and Restore

### Development Backup
```bash
# Export data
docker-compose exec web python manage.py dumpdata > dev_backup.json

# Import data
docker-compose exec web python manage.py loaddata dev_backup.json
```

### Production Backup
```bash
# Database backup
docker-compose -f docker-compose.prod.yml exec db pg_dump -U postgres menshen_db > prod_backup.sql

# Media files backup
tar -czf media_backup.tar.gz $HOME/opt/menshun/data/media/
```