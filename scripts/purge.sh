#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_section() { echo -e "${BLUE}=== $1 ===${NC}"; }

print_section "MENSHUN PAM - COMPLETE SYSTEM PURGE"
echo ""
print_warning "This will PERMANENTLY remove:"
echo "  • All Docker containers, images, and volumes for this project"
echo "  • All application data  (database, media, static files)"
echo "  • All logs and backups  (~/opt/menshun/)"
echo "  • All systemd services  (menshun-web, menshun-monitor, menshun-backup)"
echo "  • Nginx site config for Menshun"
echo "  • The .env configuration file"
echo ""
print_warning "This action is IRREVERSIBLE. All data will be permanently lost."
echo ""
echo -n "Type PURGE to confirm, or anything else to cancel: "
read -r CONFIRM

if [ "$CONFIRM" != "PURGE" ]; then
    print_status "Purge cancelled. Nothing was changed."
    exit 0
fi

echo ""
print_section "Step 1/8: Stopping and removing containers and volumes"
docker compose -f docker-compose.prod.yml down -v --remove-orphans 2>/dev/null \
    && print_status "Containers and volumes removed." \
    || print_warning "docker-compose.prod.yml teardown skipped (may already be down)."
docker compose -f docker-compose.deploy.yml down -v --remove-orphans 2>/dev/null || true

print_section "Step 2/8: Removing project Docker images"
docker images --format '{{.Repository}} {{.ID}}' \
    | grep -E '^menshunv2' \
    | awk '{print $2}' \
    | xargs -r docker rmi -f 2>/dev/null \
    && print_status "Docker images removed." \
    || print_warning "No project images found to remove."

print_section "Step 3/8: Removing Docker networks"
docker network rm menshunv2_menshun_network 2>/dev/null \
    && print_status "Docker network removed." \
    || print_warning "Docker network not found (already removed)."
docker network prune -f 2>/dev/null || true
print_status "Unused Docker networks pruned."

print_section "Step 4/8: Removing systemd services"
for svc in menshun-web.service menshun-monitor.service menshun-backup.service menshun-backup.timer menshun.target; do
    sudo systemctl stop    "$svc" 2>/dev/null || true
    sudo systemctl disable "$svc" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$svc"
    print_status "Removed: $svc"
done
sudo systemctl daemon-reload
sudo systemctl reset-failed 2>/dev/null || true
print_status "Systemd services removed."

print_section "Step 5/8: Removing logrotate and tmpfiles configuration"
sudo rm -f /etc/logrotate.d/menshun
sudo rm -f /etc/tmpfiles.d/menshun.conf
print_status "Config files removed."

print_section "Step 6/8: Removing Nginx site configuration"
sudo rm -f /etc/nginx/sites-enabled/menshun*  2>/dev/null || true
sudo rm -f /etc/nginx/sites-available/menshun* 2>/dev/null || true
sudo rm -f /etc/nginx/conf.d/menshun*          2>/dev/null || true
if sudo nginx -t 2>/dev/null; then
    sudo systemctl reload nginx 2>/dev/null || true
    print_status "Nginx config removed and reloaded."
else
    print_warning "Nginx not running or config reload skipped."
fi

print_section "Step 7/8: Removing application data directories"
sudo rm -rf "${HOME}/opt/menshun/"
print_status "Data directories removed."

print_section "Step 8/8: Removing .env and pruning dangling Docker resources"
rm -f .env
print_status ".env removed."
docker system prune -f 2>/dev/null || true
print_status "Dangling Docker resources pruned."

echo ""
print_section "Purge Complete"
print_status "Menshun PAM has been completely removed from this system."
print_status "Run 'make init' to perform a fresh deployment."
