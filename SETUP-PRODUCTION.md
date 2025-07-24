# Menshun PAM - Production Setup Guide

This guide will walk you through setting up Menshun PAM for **production** use. Follow each step in order.

## 📋 Prerequisites

Before starting, ensure you have:
- [ ] **Linux server** (Ubuntu 20.04+ recommended)
- [ ] **Docker** and **Docker Compose** installed
- [ ] **16GB+ RAM** available
- [ ] **50GB+ disk space** available
- [ ] **Domain name** pointing to your server
- [ ] **SSL certificate** (Let's Encrypt or commercial)
- [ ] **Root/sudo access** to the server

### Verify Prerequisites

**Step 1.1:** Check system resources
```bash
free -h    # Should show 16GB+ RAM
df -h      # Should show 50GB+ available space
```

**Step 1.2:** Verify Docker installation
```bash
docker --version
docker-compose --version
systemctl status docker
```

**Step 1.3:** Test Docker permissions
```bash
docker run hello-world
```

## 🚀 Server Preparation

**Step 2.1:** Update system packages
```bash
sudo apt update && sudo apt upgrade -y
```

**Step 2.2:** Install required packages
```bash
sudo apt install -y curl wget git htop ufw fail2ban
```

**Step 2.3:** Configure firewall
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

**Step 2.4:** Create application user (optional but recommended)
```bash
sudo useradd -m -s /bin/bash menshun
sudo usermod -aG docker menshun
sudo su - menshun
```

## 📁 Application Setup

**Step 3.1:** Clone the repository
```bash
cd /home/menshun  # or your preferred directory
git clone <your-repo-url> menshun-pam
cd menshun-pam
git checkout dev/vm-optimization  # or your production branch
```

**Step 3.2:** Create production directories
```bash
mkdir -p $HOME/opt/menshun/data/{postgres,redis,static,media}
mkdir -p $HOME/opt/menshun/logs/nginx
mkdir -p $HOME/opt/menshun/backups/postgres
mkdir -p $HOME/opt/menshun/ssl
```

**Step 3.3:** Set proper permissions
```bash
sudo chown -R menshun:menshun $HOME/opt/menshun
chmod 755 $HOME/opt/menshun/data/postgres
```

## 🔐 SSL Certificate Setup

### Option A: Let's Encrypt (Free)

**Step 4.1:** Install Certbot
```bash
sudo apt install -y certbot
```

**Step 4.2:** Stop any existing web servers
```bash
sudo systemctl stop nginx apache2 2>/dev/null || true
```

**Step 4.3:** Generate SSL certificate
```bash
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
```

**Step 4.4:** Copy certificates to application directory
```bash
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem $HOME/opt/menshun/ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem $HOME/opt/menshun/ssl/key.pem
sudo chown menshun:menshun $HOME/opt/menshun/ssl/*.pem
```

### Option B: Commercial Certificate

**Step 4.5:** Copy your certificate files
```bash
# Copy your SSL certificate and private key to:
cp your-certificate.pem $HOME/opt/menshun/ssl/cert.pem
cp your-private-key.pem $HOME/opt/menshun/ssl/key.pem
chmod 600 $HOME/opt/menshun/ssl/*.pem
```

## ⚙️ Environment Configuration

**Step 5.1:** Create production environment file
```bash
cd /home/menshun/menshun-pam
cp .env.example .env  # if it exists, or create new file
nano .env
```

**Step 5.2:** Configure .env file with these required settings:
```bash
# Security (REQUIRED)
SECRET_KEY=your-super-secret-key-change-this-value-minimum-50-characters
DATABASE_PASSWORD=your-secure-database-password-change-this

# Domain Configuration (REQUIRED)
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database Settings
DATABASE_NAME=menshen_db
DATABASE_USER=postgres

# Redis Settings
REDIS_DB=0

# Security Settings
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000

# Performance Settings
GUNICORN_WORKERS=4
GUNICORN_THREADS=2

# Optional: Azure AD Integration
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_REDIRECT_URI=https://yourdomain.com/auth/microsoft/complete

# Optional: Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@company.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_USE_TLS=true
DEFAULT_FROM_EMAIL=noreply@yourdomain.com

# Optional: Logging
LOG_LEVEL=INFO
SENTRY_DSN=your-sentry-dsn-for-error-tracking

# Optional: Microsoft Sentinel Integration
SENTINEL_ENABLED=false
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_DATA_COLLECTION_ENDPOINT=your-endpoint
SENTINEL_DATA_COLLECTION_RULE_ID=your-rule-id
```

**Step 5.3:** Secure the .env file
```bash
chmod 600 .env
```

**Step 5.4:** Generate a secure secret key
```bash
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```
Copy this output and use it as your SECRET_KEY in the .env file.

## 🚀 Deploy Application

**Step 6.1:** Make startup script executable
```bash
chmod +x start-prod.sh
```

**Step 6.2:** Start production environment
```bash
./start-prod.sh
```

You should see output like:
```
🚀 Starting Menshun Production Environment...
📁 Creating required directories...
🛑 Stopping existing containers...
🏗️  Building and starting production environment...
⏳ Waiting for services to start...
🎉 Production environment started!
```

**Step 6.3:** Wait for all services to be healthy
```bash
docker-compose -f docker-compose.prod.yml ps
```

All services should show "Up" and "healthy" status. This may take 3-5 minutes.

## 👤 Create Admin User

**Step 7.1:** Create Django superuser
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py createsuperuser
```

Enter your admin credentials when prompted:
- Username: `admin` (or your preferred username)
- Email: `admin@yourdomain.com`
- Password: (use a strong password)

**Step 7.2:** Set up groups and permissions
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py setup_groups
```

**Step 7.3:** Create credential types
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py setup_sample_data
```

## 🌐 Domain and DNS Configuration

**Step 8.1:** Update DNS records
Point your domain to your server's IP address:
```
A Record: yourdomain.com → YOUR_SERVER_IP
A Record: www.yourdomain.com → YOUR_SERVER_IP
```

**Step 8.2:** Test domain resolution
```bash
nslookup yourdomain.com
```

**Step 8.3:** Test HTTPS access
Open your browser and go to: **https://yourdomain.com**

You should see the Menshun PAM login page.

## 🔧 Production Configuration

**Step 9.1:** Configure automatic SSL renewal (Let's Encrypt only)
```bash
sudo crontab -e
```

Add this line:
```
0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem /home/menshun/opt/menshun/ssl/cert.pem && cp /etc/letsencrypt/live/yourdomain.com/privkey.pem /home/menshun/opt/menshun/ssl/key.pem && docker-compose -f /home/menshun/menshun-pam/docker-compose.prod.yml restart nginx
```

**Step 9.2:** Set up log rotation
```bash
sudo nano /etc/logrotate.d/menshun
```

Add:
```
/home/menshun/opt/menshun/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

**Step 9.3:** Configure systemd service (optional)
```bash
sudo nano /etc/systemd/system/menshun.service
```

Add:
```ini
[Unit]
Description=Menshun PAM
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/menshun/menshun-pam
ExecStart=/usr/bin/docker-compose -f docker-compose.prod.yml up -d
ExecStop=/usr/bin/docker-compose -f docker-compose.prod.yml down
User=menshun

[Install]
WantedBy=multi-user.target
```

**Step 9.4:** Enable automatic startup
```bash
sudo systemctl daemon-reload
sudo systemctl enable menshun
```

## 📊 Verification and Testing

**Step 10.1:** Check all services are running
```bash
docker-compose -f docker-compose.prod.yml ps
```

**Step 10.2:** Test web application
```bash
curl -k https://yourdomain.com/health/
```
Should return: `{"status": "ok"}`

**Step 10.3:** Test login functionality
1. Go to https://yourdomain.com
2. Login with your admin credentials
3. Verify you can access the admin panel at https://yourdomain.com/admin/

**Step 10.4:** Check logs for errors
```bash
docker-compose -f docker-compose.prod.yml logs --tail=50
```

## 🔒 Security Hardening

**Step 11.1:** Configure fail2ban for additional security
```bash
sudo nano /etc/fail2ban/jail.local
```

Add:
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true
port = http,https
logpath = /home/menshun/opt/menshun/logs/nginx/access.log
```

**Step 11.2:** Restart fail2ban
```bash
sudo systemctl restart fail2ban
```

**Step 11.3:** Configure automated backups
```bash
nano $HOME/backup-menshun.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/home/menshun/opt/menshun/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
docker-compose -f /home/menshun/menshun-pam/docker-compose.prod.yml exec -T db pg_dump -U postgres menshen_db > "$BACKUP_DIR/postgres/db_backup_$DATE.sql"

# Media files backup
tar -czf "$BACKUP_DIR/media_backup_$DATE.tar.gz" -C /home/menshun/opt/menshun/data media/

# Keep only last 30 days of backups
find "$BACKUP_DIR" -name "*.sql" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
```

**Step 11.4:** Make backup script executable and schedule it
```bash
chmod +x $HOME/backup-menshun.sh
crontab -e
```

Add:
```
0 2 * * * /home/menshun/backup-menshun.sh
```

## 📈 Monitoring Setup

**Step 12.1:** Check container health
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py check --deploy
```

**Step 12.2:** Monitor resource usage
```bash
htop
docker stats
```

**Step 12.3:** Set up log monitoring (optional)
```bash
tail -f $HOME/opt/menshun/logs/nginx/access.log
tail -f $HOME/opt/menshun/logs/nginx/error.log
```

## 🔄 Maintenance Commands

### Daily Operations

**View application logs:**
```bash
docker-compose -f docker-compose.prod.yml logs -f web
```

**Check service status:**
```bash
docker-compose -f docker-compose.prod.yml ps
```

**Restart services:**
```bash
docker-compose -f docker-compose.prod.yml restart
```

### Updates and Maintenance

**Update application:**
```bash
git pull origin main  # or your production branch
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up --build -d
```

**Database migrations:**
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py migrate
```

**Collect static files:**
```bash
docker-compose -f docker-compose.prod.yml exec web python manage.py collectstatic --noinput
```

## 🛑 Stopping the Environment

**Step 13.1:** Graceful shutdown
```bash
docker-compose -f docker-compose.prod.yml down
```

**Step 13.2:** Complete shutdown with data removal (⚠️ DANGEROUS)
```bash
docker-compose -f docker-compose.prod.yml down -v
sudo rm -rf $HOME/opt/menshun/data/*
```

## 🔍 Troubleshooting

### Service Won't Start

**Check logs:**
```bash
docker-compose -f docker-compose.prod.yml logs [service-name]
```

**Rebuild containers:**
```bash
docker-compose -f docker-compose.prod.yml down
docker-compose -f docker-compose.prod.yml up --build -d
```

### SSL Certificate Issues

**Check certificate files:**
```bash
ls -la $HOME/opt/menshun/ssl/
openssl x509 -in $HOME/opt/menshun/ssl/cert.pem -text -noout
```

**Test SSL configuration:**
```bash
openssl s_client -connect yourdomain.com:443
```

### Database Connection Problems

**Check database logs:**
```bash
docker-compose -f docker-compose.prod.yml logs db
```

**Access database directly:**
```bash
docker-compose -f docker-compose.prod.yml exec db psql -U postgres -d menshen_db
```

### Permission Issues

**Fix file permissions:**
```bash
sudo chown -R menshun:menshun $HOME/opt/menshun
chmod -R 755 $HOME/opt/menshun/data
chmod 600 $HOME/opt/menshun/ssl/*.pem
```

### Performance Issues

**Check resource usage:**
```bash
docker stats
htop
```

**Scale services:**
```bash
# Edit docker-compose.prod.yml to increase resources
# Then restart:
docker-compose -f docker-compose.prod.yml up -d --scale web=2
```

## ✅ Production Checklist

After setup, verify:

- [ ] ✅ Application accessible at https://yourdomain.com
- [ ] ✅ SSL certificate valid and working
- [ ] ✅ Admin login works
- [ ] ✅ Database is persistent and backed up
- [ ] ✅ Logs are being generated
- [ ] ✅ Email notifications work (if configured)
- [ ] ✅ Azure AD integration works (if configured)
- [ ] ✅ Firewall is configured correctly
- [ ] ✅ Automated backups are scheduled
- [ ] ✅ SSL auto-renewal is configured
- [ ] ✅ Monitoring is in place
- [ ] ✅ Documentation is updated with your specifics

## 🎯 What You Get

After successful production setup:

✅ **High Availability**: Multiple replicas and health checks  
✅ **Security**: SSL/TLS, security headers, and hardening  
✅ **Performance**: Gunicorn + Nginx, optimized for production  
✅ **Monitoring**: Health checks and logging  
✅ **Backup**: Automated database and file backups  
✅ **Scalability**: Can be easily scaled horizontally  
✅ **Maintenance**: Easy updates and rollbacks  

## 📞 Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review all logs: `docker-compose -f docker-compose.prod.yml logs`
3. Verify all environment variables in `.env` file
4. Ensure SSL certificates are valid
5. Check firewall and DNS settings
6. Test with a minimal configuration first

---

**🎉 Congratulations! Your Menshun PAM production environment is ready for use.**

**Next Steps:**
1. Configure your first vault entries
2. Set up user groups and permissions
3. Configure Azure AD integration (if needed)
4. Set up monitoring and alerting
5. Plan regular maintenance windows