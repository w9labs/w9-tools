#!/usr/bin/env bash
set -euo pipefail

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

# Stop service
sudo systemctl stop $SERVICE_NAME 2>/dev/null || true

# Build user
BUILD_USER="${SUDO_USER:-$(whoami)}"
[ "$BUILD_USER" = "root" ] && BUILD_USER=$(stat -c '%U' "$ROOT_DIR")

# Install packages
sudo apt-get update -qq
sudo apt-get install -y build-essential pkg-config libsqlite3-dev nodejs npm nginx ufw openssl >/dev/null

# Create service user
id -u $SERVICE_USER >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir $INSTALL_DIR --shell /usr/sbin/nologin $SERVICE_USER

# Build backend
if [ "$BUILD_USER" != "root" ]; then
  sudo -u $BUILD_USER bash -lc "cd '$ROOT_DIR' && cargo build --release"
else
  bash -lc "cd '$ROOT_DIR' && cargo build --release"
fi

# Build frontend
cd "$ROOT_DIR/frontend"
npm install --silent
npm run build

# Install binary
sudo mkdir -p $INSTALL_DIR $DATA_DIR $UPLOADS_DIR
sudo cp -f "$ROOT_DIR/target/release/w9" "$INSTALL_DIR/w9"
sudo chown root:$SERVICE_USER "$INSTALL_DIR/w9"
sudo chmod 750 "$INSTALL_DIR/w9"
sudo chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR $UPLOADS_DIR

# Install frontend
sudo mkdir -p $FRONTEND_PUBLIC
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
sudo tee /etc/nginx/sites-available/$SERVICE_NAME >/dev/null <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    client_max_body_size 1024M;
    root $FRONTEND_PUBLIC;
    index index.html;

    location /health { proxy_pass http://127.0.0.1:$APP_PORT; }
    location /api/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /admin/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /r/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /s/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /files/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location / { try_files \$uri \$uri/ /index.html; }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name _;

    ssl_certificate $SSL_DIR/cert.pem;
    ssl_certificate_key $SSL_DIR/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 1024M;
    root $FRONTEND_PUBLIC;
    index index.html;

    location /health { proxy_pass http://127.0.0.1:$APP_PORT; }
    location /api/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /admin/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /r/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /s/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location /files/ { proxy_pass http://127.0.0.1:$APP_PORT; proxy_set_header Host \$host; }
    location / { try_files \$uri \$uri/ /index.html; }
}
EOF

sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/$SERVICE_NAME

# Start services
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME
sudo systemctl enable nginx
sudo systemctl restart nginx
sudo ufw allow 80/tcp 2>/dev/null || true
sudo ufw allow 443/tcp 2>/dev/null || true

# Wait & verify
sleep 2
sudo systemctl is-active --quiet $SERVICE_NAME && echo "✓ Service running" || echo "✗ Service failed"
sudo systemctl is-active --quiet nginx && echo "✓ Nginx running" || echo "✗ Nginx failed"
curl -sf http://127.0.0.1:$APP_PORT/health >/dev/null && echo "✓ Backend healthy" || echo "✗ Backend unhealthy"

echo "
✓ Done!
Domain: $DOMAIN
Backend: http://127.0.0.1:$APP_PORT
Frontend: $FRONTEND_PUBLIC
SSL: Self-signed certificate at $SSL_DIR

Cloudflare SSL modes:
  - Flexible: Cloudflare uses HTTPS, origin uses HTTP (port 80)
  - Full: Cloudflare uses HTTPS, origin uses HTTPS (port 443, self-signed OK)
  - Full Strict: Requires valid CA-signed certificate

Status: sudo systemctl status $SERVICE_NAME
Logs: sudo journalctl -u $SERVICE_NAME -f
"
