#!/usr/bin/env bash
set -euo pipefail

# Line-buffered output
exec 1> >(stdbuf -oL cat)
exec 2> >(stdbuf -oL cat >&2)

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Config
SERVICE_NAME=w9
INSTALL_DIR=/opt/w9
SERVICE_USER=w9
DATA_DIR=$INSTALL_DIR/data
UPLOADS_DIR=$INSTALL_DIR/uploads
APP_PORT=${APP_PORT:-10105}
DOMAIN=${DOMAIN:-w9.se}
BASE_URL=${BASE_URL:-https://$DOMAIN}
FRONTEND_PUBLIC=/var/www/w9

# Stop service and kill any stuck processes
echo "Stopping w9 service..."
sudo systemctl stop $SERVICE_NAME 2>/dev/null || true
sleep 2

# Kill any processes using port 10105
echo "Killing processes on port $APP_PORT..."
sudo fuser -k $APP_PORT/tcp 2>/dev/null || true
sleep 1

# Kill any w9 binary processes
echo "Killing any remaining w9 processes..."
sudo pkill -9 -f "/opt/w9/w9" 2>/dev/null || true
sudo pkill -9 w9 2>/dev/null || true
sudo killall -9 w9 2>/dev/null || true
sleep 2

# Verify port is free
if sudo ss -tulpn | grep -q ":$APP_PORT "; then
    echo "ERROR: Port $APP_PORT is still in use!"
    sudo ss -tulpn | grep ":$APP_PORT"
    exit 1
fi
echo "Port $APP_PORT is free"

# Build user
BUILD_USER="${SUDO_USER:-$(whoami)}"
[ "$BUILD_USER" = "root" ] && BUILD_USER=$(stat -c '%U' "$ROOT_DIR")

# Install packages (only if needed)
echo "Checking packages..."
sudo apt-get update -qq >/dev/null 2>&1 || true
sudo apt-get install -y build-essential pkg-config libsqlite3-dev sqlite3 nodejs npm nginx ufw openssl >/dev/null 2>&1 || true
echo "✓ Packages ready"

# Create service user
id -u $SERVICE_USER >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir $INSTALL_DIR --shell /usr/sbin/nologin $SERVICE_USER

# Build backend
echo "Building backend..."
if [ "$BUILD_USER" != "root" ]; then
  sudo -u $BUILD_USER bash -lc "cd '$ROOT_DIR' && cargo build --release" 2>&1 | tail -2
else
  bash -lc "cd '$ROOT_DIR' && cargo build --release" 2>&1 | tail -2
fi

# Build frontend
echo "Building frontend..."
cd "$ROOT_DIR/frontend"
npm install --silent 2>&1 | tail -1
npm run build 2>&1 | tail -1

# Install binary
echo "Installing binary..."
sudo mkdir -p $INSTALL_DIR $DATA_DIR $UPLOADS_DIR
sudo cp "$ROOT_DIR/target/release/w9" "$INSTALL_DIR/w9"
sudo chown root:$SERVICE_USER "$INSTALL_DIR/w9"
sudo chmod 750 "$INSTALL_DIR/w9"
sudo chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR $UPLOADS_DIR

# Install frontend
echo "Installing frontend..."
sudo mkdir -p $FRONTEND_PUBLIC
sudo rm -rf $FRONTEND_PUBLIC/* 2>/dev/null || true
sudo cp -r "$ROOT_DIR/frontend/dist"/* $FRONTEND_PUBLIC/
sudo chown -R root:root $FRONTEND_PUBLIC

# Env file
sudo tee /etc/default/$SERVICE_NAME >/dev/null <<EOF
HOST=0.0.0.0
PORT=$APP_PORT
BASE_URL=$BASE_URL
DATABASE_PATH=$DATA_DIR/w9.db
UPLOADS_DIR=$UPLOADS_DIR
EOF

# Systemd unit
sudo tee /etc/systemd/system/$SERVICE_NAME.service >/dev/null <<EOF
[Unit]
Description=w9 - Link & file sharer
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/$SERVICE_NAME
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/w9
User=$SERVICE_USER
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Generate self-signed certificate
SSL_DIR="/etc/nginx/ssl/$DOMAIN"
sudo mkdir -p $SSL_DIR
if [ ! -f "$SSL_DIR/cert.pem" ]; then
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" \
    -out "$SSL_DIR/cert.pem" \
    -subj "/CN=$DOMAIN" 2>/dev/null
  sudo chmod 600 "$SSL_DIR/key.pem"
  sudo chmod 644 "$SSL_DIR/cert.pem"
  echo "✓ Self-signed certificate created"
fi

# Nginx config
echo "Configuring nginx..."
cat > /tmp/nginx_$SERVICE_NAME.conf << 'NGINX_EOF'
# HTTP server (redirect to HTTPS)
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

# HTTPS server
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;

    ssl_certificate SSL_DIR_PLACEHOLDER/cert.pem;
    ssl_certificate_key SSL_DIR_PLACEHOLDER/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 1024M;
    root FRONTEND_PUBLIC_PLACEHOLDER;
    index index.html;

    # Backend proxies
    location /health { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; }
    location /api/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /r/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /s/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /files/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }

    # Frontend SPA
    location / { try_files $uri $uri/ /index.html; }

    # Caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|webmanifest)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
NGINX_EOF

# Replace placeholders
sed -i "s|SSL_DIR_PLACEHOLDER|$SSL_DIR|g" /tmp/nginx_$SERVICE_NAME.conf
sed -i "s|FRONTEND_PUBLIC_PLACEHOLDER|$FRONTEND_PUBLIC|g" /tmp/nginx_$SERVICE_NAME.conf
sed -i "s|APP_PORT_PLACEHOLDER|$APP_PORT|g" /tmp/nginx_$SERVICE_NAME.conf

# Install config
sudo cp /tmp/nginx_$SERVICE_NAME.conf /etc/nginx/sites-available/$SERVICE_NAME
rm /tmp/nginx_$SERVICE_NAME.conf

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/$SERVICE_NAME

# Start services
echo "Starting services..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME nginx
sudo systemctl restart $SERVICE_NAME nginx
sudo ufw allow 80/tcp 443/tcp 2>/dev/null || true

# Verify deployment
echo ""
echo "=== VERIFICATION ==="
sleep 2

# Check services
for service in $SERVICE_NAME nginx; do
    if sudo systemctl is-active --quiet $service; then
        echo "✓ $service running"
    else
        echo "✗ $service FAILED"
        exit 1
    fi
done

# Check backend
if curl -sf http://127.0.0.1:$APP_PORT/health >/dev/null; then
    echo "✓ Backend healthy"
else
    echo "✗ Backend unhealthy"
    exit 1
fi

echo ""
echo "✓ Deploy successful!"
echo "Domain: $DOMAIN"
echo "Status: sudo systemctl status $SERVICE_NAME"
echo "Logs: sudo journalctl -u $SERVICE_NAME -f"
