# Menshun PAM - VM Deployment Makefile
# Simple commands for production deployment and management

.PHONY: help init deploy start stop restart status logs backup restore update clean quick-deploy deploy-stop deploy-logs deploy-status dev-start dev-stop

# Default target
help: ## Show this help message
	@echo "Menshun PAM - VM Deployment Commands"
	@echo "===================================="
	@echo ""
	@echo "Quick Start Commands:"
	@echo "  make init     - Initialize VM for first-time deployment"
	@echo "  make deploy   - Deploy/update Menshun in production mode"
	@echo "  make start    - Start all services"
	@echo "  make stop     - Stop all services"
	@echo "  make restart  - Restart all services"
	@echo ""
	@echo "Management Commands:"
	@echo "  make status   - Show service status"
	@echo "  make logs     - Show application logs"
	@echo "  make backup   - Create full system backup"
	@echo "  make restore  - Restore from backup"
	@echo "  make update   - Update to latest version"
	@echo "  make clean    - Clean up unused resources"
	@echo ""
	@echo "Development Commands:"
	@echo "  make dev-start - Start in development mode"
	@echo "  make dev-stop  - Stop development environment"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Variables
COMPOSE_PROD = docker-compose -f docker-compose.prod.yml
COMPOSE_DEPLOY = docker compose -f docker-compose.deploy.yml
COMPOSE_DEV = docker-compose -f docker-compose.yml
BACKUP_DIR = $${HOME}/opt/menshun/backups
LOG_DIR = $${HOME}/opt/menshun/logs
ENV_FILE = .env

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

define print_status
	@echo "$(GREEN)[INFO]$(NC) $(1)"
endef

define print_warning
	@echo "$(YELLOW)[WARN]$(NC) $(1)"
endef

define print_error
	@echo "$(RED)[ERROR]$(NC) $(1)"
endef

init: ## Initialize VM for first-time Menshun deployment
	$(call print_status,"🚀 Initializing Menshun PAM on VM...")
	@echo "$(BLUE)Step 1/8:$(NC) Checking system requirements..."
	@./scripts/check-requirements.sh
	@echo "$(BLUE)Step 2/8:$(NC) Installing Docker and Docker Compose..."
	@./scripts/install-docker.sh
	@echo "$(BLUE)Step 3/8:$(NC) Creating directory structure..."
	@mkdir -p $${HOME}/opt/menshun/{data,logs,backups,ssl,config}
	@mkdir -p $${HOME}/opt/menshun/data/{postgres,redis,static,media}
	@echo "$(BLUE)Step 4/8:$(NC) Setting up environment configuration..."
	@./scripts/setup-environment.sh
	@echo "$(BLUE)Step 5/8:$(NC) Configuring Nginx reverse proxy..."
	@./scripts/setup-nginx.sh
	@echo "$(BLUE)Step 6/8:$(NC) Setting up SSL certificates..."
	@./scripts/setup-ssl.sh
	@echo "$(BLUE)Step 7/8:$(NC) Creating systemd services..."
	@sudo ./scripts/install-systemd-services.sh
	@echo "$(BLUE)Step 8/8:$(NC) Starting services..."
	@$(MAKE) deploy
	$(call print_status,"✅ Menshun PAM initialization complete!")
	@echo ""
	@echo "$(GREEN)🎉 Menshun PAM is now running!$(NC)"
	@echo "   Web Interface: https://$(shell hostname -I | cut -d' ' -f1)"
	@echo "   Admin Panel:   https://$(shell hostname -I | cut -d' ' -f1)/admin"
	@echo ""
	@echo "$(YELLOW)Next Steps:$(NC)"
	@echo "1. Configure your domain name and SSL certificate"
	@echo "2. Set up Entra ID integration"
	@echo "3. Configure Microsoft Sentinel (optional)"
	@echo "4. Create your first admin user: make create-admin"

deploy: ## Deploy/update Menshun in production mode
	$(call print_status,"🚀 Deploying Menshun PAM...")
	@if [ ! -f $(ENV_FILE) ]; then \
		$(call print_error,Production environment file not found. Run make init first.); \
		exit 1; \
	fi
	@if ! groups | grep -q docker; then \
		$(call print_error,Current user is not in docker group. Please log out and log back in or run newgrp docker.); \
		$(call print_error,Then run make deploy again.); \
		exit 1; \
	fi
	@echo "$(BLUE)Building production images...$(NC)"
	@$(COMPOSE_PROD) build --no-cache
	@echo "$(BLUE)Starting database migrations...$(NC)"
	@$(COMPOSE_PROD) up -d db redis
	@sleep 10
	@$(COMPOSE_PROD) run --rm web python manage.py migrate
	@echo "$(BLUE)Collecting static files...$(NC)"
	@$(COMPOSE_PROD) run --rm web python manage.py collectstatic --noinput
	@echo "$(BLUE)Starting all services...$(NC)"
	@$(COMPOSE_PROD) up -d
	@sleep 5
	@$(MAKE) status
	$(call print_status,"✅ Deployment complete!")

start: ## Start all services
	$(call print_status,"🚀 Starting Menshun services...")
	@$(COMPOSE_PROD) up -d
	@sleep 5
	@$(MAKE) status

stop: ## Stop all services
	$(call print_status,"🛑 Stopping Menshun services...")
	@$(COMPOSE_PROD) down

restart: ## Restart all services
	$(call print_status,"🔄 Restarting Menshun services...")
	@$(COMPOSE_PROD) restart
	@sleep 5
	@$(MAKE) status

status: ## Show service status
	@echo "$(BLUE)Menshun PAM Service Status$(NC)"
	@echo "=========================="
	@$(COMPOSE_PROD) ps
	@echo ""
	@echo "$(BLUE)System Services$(NC)"
	@echo "==============="
	@sudo systemctl status menshun-web --no-pager -l || true
	@sudo systemctl status nginx --no-pager -l || true
	@echo ""
	@echo "$(BLUE)Health Checks$(NC)"
	@echo "============="
	@curl -s -o /dev/null -w "Web App: %{http_code}\n" https://localhost/health/ || echo "Web App: DOWN"
	@echo "Database: $$($(COMPOSE_PROD) exec -T db pg_isready -U postgres | grep -o 'accepting connections' || echo 'DOWN')"
	@echo "Redis: $$($(COMPOSE_PROD) exec -T redis redis-cli ping || echo 'DOWN')"

logs: ## Show application logs
	@echo "$(BLUE)Recent Application Logs$(NC)"
	@echo "======================="
	@$(COMPOSE_PROD) logs --tail=50 web
	@echo ""
	@echo "$(BLUE)System Logs$(NC)"
	@echo "==========="
	@sudo journalctl -u menshun-web --no-pager -n 20 || true

backup: ## Create full system backup
	$(call print_status,"💾 Creating system backup...")
	@mkdir -p $(BACKUP_DIR)
	@./scripts/backup.sh
	$(call print_status,"✅ Backup completed: $(BACKUP_DIR)/menshun-backup-$$(date +%Y%m%d-%H%M%S).tar.gz")

restore: ## Restore from backup (specify BACKUP_FILE=path/to/backup.tar.gz)
	@if [ -z "$(BACKUP_FILE)" ]; then \
		$(call print_error,"Please specify backup file: make restore BACKUP_FILE=path/to/backup.tar.gz"); \
		exit 1; \
	fi
	$(call print_status,"📥 Restoring from backup: $(BACKUP_FILE)")
	@./scripts/restore.sh $(BACKUP_FILE)
	$(call print_status,"✅ Restore completed!")

update: ## Update to latest version
	$(call print_status,"⬆️ Updating Menshun PAM...")
	@git fetch origin
	@git pull origin main
	@$(MAKE) deploy
	$(call print_status,"✅ Update completed!")

clean: ## Clean up unused resources
	$(call print_status,"🧹 Cleaning up unused resources...")
	@$(COMPOSE_PROD) down --remove-orphans
	@docker system prune -f
	@docker volume prune -f
	$(call print_status,"✅ Cleanup completed!")

# Quick deploy commands (one-touch deployment)
quick-deploy: ## One-touch deploy (git clone && ./deploy.sh)
	@./deploy.sh

deploy-stop: ## Stop quick-deploy services
	$(call print_status,"Stopping deploy services...")
	@$(COMPOSE_DEPLOY) down

deploy-logs: ## Show quick-deploy logs
	@$(COMPOSE_DEPLOY) logs --tail=50 -f

deploy-status: ## Show quick-deploy container status
	@$(COMPOSE_DEPLOY) ps

# Development commands
dev-start: ## Start in development mode
	$(call print_status,"🛠️ Starting development environment...")
	@$(COMPOSE_DEV) up -d
	@sleep 5
	@$(COMPOSE_DEV) ps
	@echo ""
	@echo "$(GREEN)Development server running at: http://localhost:8001$(NC)"

dev-stop: ## Stop development environment
	$(call print_status,"🛑 Stopping development environment...")
	@$(COMPOSE_DEV) down

# Additional utility commands
create-admin: ## Create superuser account
	$(call print_status,"👤 Creating admin user...")
	@$(COMPOSE_PROD) exec -T web python manage.py createsuperuser

shell: ## Open Django shell
	@$(COMPOSE_PROD) exec web python manage.py shell

db-shell: ## Open database shell
	@$(COMPOSE_PROD) exec db psql -U postgres -d menshen_db

migrate: ## Run database migrations
	@$(COMPOSE_PROD) exec -T web python manage.py migrate

collect-static: ## Collect static files
	@$(COMPOSE_PROD) exec -T web python manage.py collectstatic --noinput

test: ## Run test suite
	@$(COMPOSE_PROD) exec -T web python manage.py test

health-check: ## Run comprehensive health check
	@./scripts/health-check.sh

ssl-renew: ## Renew SSL certificates
	$(call print_status,"🔒 Renewing SSL certificates...")
	@sudo certbot renew --nginx
	@sudo systemctl reload nginx
	$(call print_status,"✅ SSL certificates renewed!")

# Monitoring commands
monitor: ## Show real-time system monitoring
	@echo "$(BLUE)System Resources$(NC)"
	@echo "=================="
	@./scripts/monitor.sh

performance: ## Show performance metrics
	@echo "$(BLUE)Performance Metrics$(NC)"
	@echo "==================="
	@$(COMPOSE_PROD) exec -T web python manage.py shell -c "from django.db import connection; print('Database connections:', len(connection.queries))"

# Security commands
security-scan: ## Run security scan
	$(call print_status,"🔍 Running security scan...")
	@./scripts/security-scan.sh

update-deps: ## Update dependencies
	$(call print_status,"📦 Updating dependencies...")
	@pip-compile requirements.in
	@$(MAKE) deploy

# Configuration commands
config-check: ## Validate configuration
	@$(COMPOSE_PROD) exec -T web python manage.py check --deploy

show-config: ## Show current configuration
	@echo "$(BLUE)Current Configuration$(NC)"
	@echo "====================="
	@$(COMPOSE_PROD) exec -T web python manage.py diffsettings | head -20

# Database commands
db-backup: ## Backup database only
	$(call print_status,"💾 Backing up database...")
	@./scripts/db-backup.sh

db-restore: ## Restore database (specify DB_BACKUP_FILE=path/to/backup.sql)
	@if [ -z "$(DB_BACKUP_FILE)" ]; then \
		$(call print_error,"Please specify backup file: make db-restore DB_BACKUP_FILE=path/to/backup.sql"); \
		exit 1; \
	fi
	$(call print_status,"📥 Restoring database from: $(DB_BACKUP_FILE)")
	@./scripts/db-restore.sh $(DB_BACKUP_FILE)

# Network commands
network-test: ## Test network connectivity
	@echo "$(BLUE)Network Connectivity Test$(NC)"
	@echo "============================"
	@./scripts/network-test.sh

# Installation verification
verify-install: ## Verify installation integrity
	$(call print_status,"✅ Verifying installation...")
	@./scripts/verify-install.sh