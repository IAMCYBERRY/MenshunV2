# Menshun PAM - Development Setup Guide

This guide will walk you through setting up Menshun PAM for **development** use. Follow each step in order.

## 📋 Prerequisites

Before starting, ensure you have:
- [ ] **Docker** installed and running
- [ ] **Docker Compose** installed  
- [ ] **Git** installed
- [ ] **8GB+ RAM** available
- [ ] **5GB+ disk space** available

### Verify Prerequisites

**Step 1.1:** Check Docker installation
```bash
docker --version
docker-compose --version
```
You should see version numbers for both commands.

**Step 1.2:** Verify Docker is running
```bash
docker info
```
If you get an error, start Docker Desktop or the Docker service.

## 🚀 Quick Setup (Recommended)

**Step 2.1:** Clone the repository
```bash
git clone <your-repo-url>
cd MenshunV2
```

**Step 2.2:** Switch to development branch (if not already)
```bash
git checkout dev/vm-optimization
```

**Step 2.3:** Start development environment
```bash
./start-dev.sh
```

**Step 2.4:** Wait for setup to complete
You'll see output like:
```
🚀 Starting Menshun Development Environment Setup...
⏳ Waiting for database...
🔄 Running database migrations...
🎯 Setting up development data...
🎉 Development environment ready!
```

**Step 2.5:** Access the application
Open your browser and go to: **http://localhost:8001**

**Step 2.6:** Test login with development users

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Superuser |
| `vault_admin` | `admin123` | Vault Admin |
| `vault_editor` | `editor123` | Vault Editor |
| `vault_viewer` | `viewer123` | Vault Viewer |

✅ **Setup Complete!** Skip to the [Usage](#usage) section.

---

## 🔧 Manual Setup (Alternative)

If the quick setup doesn't work, follow these manual steps:

**Step 3.1:** Clone and enter directory
```bash
git clone <your-repo-url>
cd MenshunV2
git checkout dev/vm-optimization
```

**Step 3.2:** Stop any existing containers
```bash
docker-compose down
```

**Step 3.3:** Build and start services
```bash
docker-compose up --build -d
```

**Step 3.4:** Wait for services to be healthy
```bash
docker-compose ps
```
Wait until all services show "healthy" status (may take 2-3 minutes).

**Step 3.5:** Check if data exists
```bash
docker-compose exec web python manage.py shell -c "
from django.contrib.auth import get_user_model
print(f'Users: {get_user_model().objects.count()}')
"
```

**Step 3.6:** If no users exist, create development data
```bash
docker-compose exec web python manage.py setup_dev_data
```

**Step 3.7:** Verify setup
```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/login/
```
Should return `200`.

## 📊 Usage

### Accessing Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Web App** | http://localhost:8001 | See test users above |
| **Admin Panel** | http://localhost:8001/admin/ | `admin` / `admin123` |
| **Database** | localhost:5435 | `postgres` / `postgres` |
| **Redis** | localhost:6382 | No auth |

### Development Commands

**View logs:**
```bash
docker-compose logs -f
```

**Access Django shell:**
```bash
docker-compose exec web python manage.py shell
```

**Run migrations:**
```bash
docker-compose exec web python manage.py migrate
```

**Create additional users:**
```bash
docker-compose exec web python manage.py createsuperuser
```

**Reset development data:**
```bash
docker-compose exec web python manage.py setup_dev_data --reset
```

### File Structure

Your development environment includes:
```
MenshunV2/
├── docker-compose.yml          # Development configuration
├── Dockerfile.dev              # Development container
├── start-dev.sh               # Quick start script
└── vault/management/commands/
    └── setup_dev_data.py      # Auto-setup script
```

## 🛑 Stopping the Environment

**Stop all services:**
```bash
docker-compose down
```

**Stop and remove data (⚠️ destroys all data):**
```bash
docker-compose down -v
```

## 🔍 Troubleshooting

### Port Already in Use
If you get port conflicts:

**Step T1:** Check what's using the ports
```bash
lsof -i :8001  # Web app port
lsof -i :5435  # Database port
lsof -i :6382  # Redis port
```

**Step T2:** Kill conflicting processes or change ports in `docker-compose.yml`

### Container Won't Start

**Step T3:** Check container logs
```bash
docker-compose logs web
docker-compose logs db
docker-compose logs redis
```

**Step T4:** Rebuild containers
```bash
docker-compose down
docker-compose up --build
```

### Database Connection Errors

**Step T5:** Wait for database to be ready
```bash
docker-compose exec web python manage.py dbshell
```
If this fails, wait 30 seconds and try again.

**Step T6:** Reset database (⚠️ destroys data)
```bash
docker-compose down -v
docker-compose up -d db
# Wait 30 seconds
docker-compose up web
```

### Permission Errors

**Step T7:** Fix file permissions (macOS/Linux)
```bash
sudo chown -R $USER:$USER .
chmod +x start-dev.sh
```

### Login Not Working

**Step T8:** Verify users exist
```bash
docker-compose exec web python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
for user in User.objects.all():
    print(f'{user.username} - Active: {user.is_active}')
"
```

**Step T9:** Recreate users if needed
```bash
docker-compose exec web python manage.py setup_dev_data --reset
```

### Web Page Not Loading

**Step T10:** Check container status
```bash
docker-compose ps
```
All services should show "Up" status.

**Step T11:** Test direct container access
```bash
docker-compose exec web curl http://localhost:8000/login/
```

### Complete Reset

**Step T12:** Nuclear option (⚠️ destroys everything)
```bash
docker-compose down -v
docker system prune -f
docker-compose up --build
```

## 🎯 What You Get

After successful setup, you'll have:

✅ **Automatic Setup**: Users, groups, and sample data created automatically  
✅ **Hot Reload**: Code changes reflect immediately  
✅ **Test Data**: 3 sample vault entries for testing  
✅ **Multiple Users**: Different permission levels to test with  
✅ **Persistent Data**: Survives container restarts  
✅ **Development Tools**: Debug mode, detailed errors  

## 🔄 Daily Workflow

**Start working:**
```bash
./start-dev.sh
```

**Make code changes** → They appear immediately at http://localhost:8001

**View logs:**
```bash
docker-compose logs -f
```

**Stop working:**
```bash
docker-compose down
```

## 📝 Next Steps

1. **Explore the application** at http://localhost:8001
2. **Check out the admin panel** at http://localhost:8001/admin/
3. **Review the sample vault entries** created automatically
4. **Start developing** your features
5. **See SETUP-PRODUCTION.md** when ready to deploy to production

## ❓ Support

If you encounter issues:
1. Check the [Troubleshooting](#troubleshooting) section above
2. Review container logs: `docker-compose logs`
3. Ensure all prerequisites are met
4. Try the "Complete Reset" option if all else fails

---
**🎉 Happy Developing! Your Menshun PAM development environment is ready to use.**