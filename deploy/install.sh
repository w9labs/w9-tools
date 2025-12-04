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

# Backup for rollback
BACKUP_DIR=/tmp/w9_backup_$$
NEED_ROLLBACK=false

cleanup() {
    if [ "$NEED_ROLLBACK" = "true" ]; then
        echo "ERROR: Deployment failed, rolling back..."
        if [ -f "$BACKUP_DIR/w9" ]; then
            sudo cp "$BACKUP_DIR/w9" "$INSTALL_DIR/w9" 2>/dev/null || true
        fi
        if [ -d "$BACKUP_DIR/frontend" ]; then
            sudo rm -rf "$FRONTEND_PUBLIC"
            sudo cp -r "$BACKUP_DIR/frontend" "$FRONTEND_PUBLIC" 2>/dev/null || true
        fi
        sudo systemctl start $SERVICE_NAME 2>/dev/null || true
        echo "Rollback attempted"
    fi
    rm -rf "$BACKUP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Build user
BUILD_USER="${SUDO_USER:-$(whoami)}"
[ "$BUILD_USER" = "root" ] && BUILD_USER=$(stat -c '%U' "$ROOT_DIR")

# Install packages (only if needed)
echo "Checking packages..."
REQUIRED_PKGS="build-essential pkg-config libsqlite3-dev sqlite3 nodejs npm nginx ufw openssl"
MISSING_PKGS=""
for pkg in $REQUIRED_PKGS; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done
if [ -n "$MISSING_PKGS" ]; then
    echo "Installing missing packages:$MISSING_PKGS"
    sudo apt-get update -qq >/dev/null 2>&1 || true
    sudo apt-get install -y $MISSING_PKGS >/dev/null 2>&1 || true
fi
echo "✓ Packages ready"

# Create service user
id -u $SERVICE_USER >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir $INSTALL_DIR --shell /usr/sbin/nologin $SERVICE_USER

# Check if rebuild is needed
BACKEND_NEEDS_BUILD=true
FRONTEND_NEEDS_BUILD=true

# Auto-update Rust toolchain and Rust dependencies (if possible)
echo "Checking Rust toolchain and dependencies..."
if command -v rustup >/dev/null 2>&1; then
    echo "Updating Rust toolchain with rustup..."
    if [ "$BUILD_USER" != "root" ]; then
        sudo -u "$BUILD_USER" bash -lc 'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi; rustup update stable && rustup default stable' \
          || echo "⚠ rustup update failed (continuing with existing toolchain)"
    else
        bash -lc 'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi; rustup update stable && rustup default stable' \
          || echo "⚠ rustup update failed (continuing with existing toolchain)"
    fi
else
    echo "⚠ rustup not found, skipping Rust toolchain auto-update"
fi

echo "Updating Rust crate dependencies with cargo update..."
if [ "$BUILD_USER" != "root" ]; then
    sudo -u "$BUILD_USER" bash -lc 'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi; cd "'"$ROOT_DIR"'" && cargo update' \
      || echo "⚠ cargo update failed (continuing with existing Cargo.lock)"
else
    bash -lc 'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi; cd "'"$ROOT_DIR"'" && cargo update' \
      || echo "⚠ cargo update failed (continuing with existing Cargo.lock)"
fi

if [ -f "$ROOT_DIR/target/release/w9" ]; then
    BINARY_TIME=$(stat -c %Y "$ROOT_DIR/target/release/w9" 2>/dev/null || echo 0)
    NEWEST_SRC=$(find "$ROOT_DIR/server" "$ROOT_DIR/Cargo.toml" -type f -name "*.rs" -o -name "Cargo.toml" 2>/dev/null | xargs stat -c %Y 2>/dev/null | sort -n | tail -1)
    [ "$NEWEST_SRC" -lt "$BINARY_TIME" ] && BACKEND_NEEDS_BUILD=false
fi

if [ -d "$ROOT_DIR/frontend/out" ]; then
    DIST_TIME=$(stat -c %Y "$ROOT_DIR/frontend/out" 2>/dev/null || echo 0)
    NEWEST_FE=$(find "$ROOT_DIR/frontend/app" "$ROOT_DIR/frontend/public" "$ROOT_DIR/frontend/package.json" "$ROOT_DIR/frontend/next.config.mjs" -type f 2>/dev/null | xargs stat -c %Y 2>/dev/null | sort -n | tail -1)
    [ "$NEWEST_FE" -lt "$DIST_TIME" ] && FRONTEND_NEEDS_BUILD=false
fi

# Build backend (if needed)
if [ "$BACKEND_NEEDS_BUILD" = "true" ]; then
    echo "Building backend..."
    if [ "$BUILD_USER" != "root" ]; then
        sudo -u $BUILD_USER bash -lc "cd '$ROOT_DIR' && cargo build --release"
    else
        bash -lc "cd '$ROOT_DIR' && cargo build --release"
    fi
else
    echo "✓ Backend is up to date, skipping rebuild"
fi

# Build frontend (if needed)
if [ "$FRONTEND_NEEDS_BUILD" = "true" ]; then
    echo "Building frontend..."
    cd "$ROOT_DIR/frontend"
    # Optionally update package.json versions with npm-check-updates
    if [ "${AUTO_UPDATE_PACKAGE_JSON:-1}" != "0" ]; then
        if [ "${AUTO_UPDATE_CORE_DEPS:-0}" != "0" ]; then
            echo "Updating package.json with npm-check-updates (including React/Next), then capping to tested versions..."
            npx npm-check-updates@latest -u 2>&1 | tail -1 \
              || echo "⚠ npm-check-updates failed (continuing with existing ranges)"
            # Force core deps to known-good, published versions to avoid requesting non-existent releases
            node <<'EOF' || echo "⚠ Failed to cap core deps; keep existing versions"
const fs = require('fs');
const path = require('path');
const pkgPath = path.join(__dirname, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
pkg.dependencies = pkg.dependencies || {};
pkg.devDependencies = pkg.devDependencies || {};
pkg.dependencies.react = "^18.3.1";
pkg.dependencies["react-dom"] = "^18.3.1";
pkg.dependencies.next = "16.0.7";
if (pkg.devDependencies["eslint-config-next"] !== undefined) {
  pkg.devDependencies["eslint-config-next"] = "16.0.7";
}
if (pkg.devDependencies["@types/react"] !== undefined) {
  pkg.devDependencies["@types/react"] = "^18.2.0";
}
if (pkg.devDependencies["@types/react-dom"] !== undefined) {
  pkg.devDependencies["@types/react-dom"] = "^18.2.0";
}
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
EOF
        else
            echo "Updating package.json dependency ranges with npm-check-updates (best-effort, core deps pinned)..."
            # Default: do not auto-bump core framework deps to avoid Next/React peer conflicts
            npx npm-check-updates@latest -u --reject react,react-dom,next,eslint-config-next,@types/react,@types/react-dom 2>&1 | tail -1 \
              || echo "⚠ npm-check-updates failed (continuing with existing ranges)"
        fi
    fi

    # Always install/update to latest compatible dependencies within current ranges
    echo "Installing npm dependencies..."
    if [ "${AUTO_UPDATE_CORE_DEPS:-0}" != "0" ]; then
        # When core deps move, allow npm to relax peer resolution to avoid ERESOLVE loops
        npm install --prefer-offline --no-audit --legacy-peer-deps 2>&1 | tail -1 || {
            echo "ERROR: npm install failed (even with --legacy-peer-deps)"
            exit 1
        }
    else
        npm install --prefer-offline --no-audit 2>&1 | tail -1 || {
            echo "ERROR: npm install failed"
            exit 1
        }
    fi

    echo "Updating npm packages to latest compatible versions..."
    npm update --no-audit 2>&1 | tail -1 || echo "⚠ npm update failed (continuing with installed versions)"

    echo "Running npm audit fix (best effort)..."
    npm audit fix --force --legacy-peer-deps 2>&1 | tail -1 || echo "⚠ npm audit fix failed (continuing)"

    # Build with Turnstile site key if provided (support legacy VITE_ and new NEXT_PUBLIC_ names)
    if [ -n "${NEXT_PUBLIC_TURNSTILE_SITE_KEY:-}" ]; then
        NEXT_PUBLIC_TURNSTILE_SITE_KEY="$NEXT_PUBLIC_TURNSTILE_SITE_KEY" npm run build 2>&1 | tail -1
    elif [ -n "${VITE_TURNSTILE_SITE_KEY:-}" ]; then
        NEXT_PUBLIC_TURNSTILE_SITE_KEY="$VITE_TURNSTILE_SITE_KEY" npm run build 2>&1 | tail -1
    else
        npm run build 2>&1 | tail -1
    fi
else
    echo "✓ Frontend is up to date, skipping rebuild"
fi

# Stop service before deployment
echo "Stopping w9 service..."
sudo systemctl stop $SERVICE_NAME 2>/dev/null || true
sleep 1

# Kill any processes using the port
sudo fuser -k $APP_PORT/tcp 2>/dev/null || true
sleep 1

# Verify port is free
if sudo ss -tulpn | grep -q ":$APP_PORT "; then
    echo "WARNING: Port $APP_PORT still in use, forcing cleanup..."
    sudo pkill -9 w9 2>/dev/null || true
    sleep 1
fi

# Enable rollback on failure from this point
NEED_ROLLBACK=true

# Backup existing installation
echo "Creating backup..."
mkdir -p "$BACKUP_DIR"
[ -f "$INSTALL_DIR/w9" ] && cp "$INSTALL_DIR/w9" "$BACKUP_DIR/w9" 2>/dev/null || true
[ -d "$FRONTEND_PUBLIC" ] && cp -r "$FRONTEND_PUBLIC" "$BACKUP_DIR/frontend" 2>/dev/null || true

# Install binary
echo "Installing binary..."
sudo mkdir -p $INSTALL_DIR $DATA_DIR $UPLOADS_DIR
sudo cp "$ROOT_DIR/target/release/w9" "$INSTALL_DIR/w9"
sudo chown root:$SERVICE_USER "$INSTALL_DIR/w9"
sudo chmod 750 "$INSTALL_DIR/w9"
sudo chown -R $SERVICE_USER:$SERVICE_USER $DATA_DIR $UPLOADS_DIR
sudo chmod -R 755 $DATA_DIR $UPLOADS_DIR
sudo chmod 644 $DATA_DIR/* 2>/dev/null || true

# Install frontend
echo "Installing frontend..."
sudo mkdir -p $FRONTEND_PUBLIC
sudo rm -rf $FRONTEND_PUBLIC/* 2>/dev/null || true
if [ -d "$ROOT_DIR/frontend/out" ]; then
    sudo cp -r "$ROOT_DIR/frontend/out"/* $FRONTEND_PUBLIC/
else
    echo "WARNING: frontend/out not found; did Next.js export succeed?"
fi
sudo chown -R root:root $FRONTEND_PUBLIC

# Env file
DEFAULT_FROM=${EMAIL_FROM_ADDRESS:-"W9 Tools <no-reply@$DOMAIN>"}
RESET_BASE=${PASSWORD_RESET_BASE_URL:-"$BASE_URL/reset-password"}
VERIFY_BASE=${VERIFICATION_BASE_URL:-"$BASE_URL/verify"}

sudo tee /etc/default/$SERVICE_NAME >/dev/null <<EOF
HOST=0.0.0.0
PORT=$APP_PORT
BASE_URL=$BASE_URL
DATABASE_PATH=$DATA_DIR/w9.db
UPLOADS_DIR=$UPLOADS_DIR
W9_MAIL_API_URL=${W9_MAIL_API_URL:-https://w9.nu}
W9_MAIL_API_TOKEN=${W9_MAIL_API_TOKEN:-}
JWT_SECRET=${JWT_SECRET:-change-me-in-production}
EMAIL_FROM_ADDRESS="$DEFAULT_FROM"
PASSWORD_RESET_BASE_URL="$RESET_BASE"
VERIFICATION_BASE_URL="$VERIFY_BASE"
TURNSTILE_SECRET_KEY=${TURNSTILE_SECRET_KEY:-}
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

    # Backend proxies (must be before regex locations)
    location /health { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; }
    location /api/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /r/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /s/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    location /n/ { proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER; proxy_set_header Host $host; }
    
    # Files - serve with caching headers
    location /files/ {
        proxy_pass http://127.0.0.1:APP_PORT_PLACEHOLDER;
        proxy_set_header Host $host;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Frontend SPA
    location / { try_files $uri $uri/ /index.html; }

    # Caching for frontend assets only (not /files/)
    location ~ ^/(?!files/).*\.(js|css|png|jpg|jpeg|gif|ico|svg|webmanifest)$ {
        try_files $uri =404;
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
sudo systemctl enable $SERVICE_NAME nginx 2>&1 | grep -v "Created symlink" || true

# Reload nginx config (faster than restart if already running)
if sudo systemctl is-active --quiet nginx; then
    sudo nginx -t && sudo systemctl reload nginx || sudo systemctl restart nginx
else
    sudo systemctl start nginx
fi

# Start w9 service
sudo systemctl start $SERVICE_NAME

# Enable firewall rules
sudo ufw allow 80/tcp 443/tcp 2>/dev/null || true

# Verify deployment
echo ""
echo "=== VERIFICATION ==="

# Wait for service to start with timeout
echo -n "Waiting for service to start"
for i in {1..15}; do
    sleep 1
    echo -n "."
    if sudo systemctl is-active --quiet $SERVICE_NAME; then
        break
    fi
    if [ $i -eq 15 ]; then
        echo ""
        echo "✗ Service failed to start"
        sudo journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
done
echo ""

# Check services
for service in $SERVICE_NAME nginx; do
    if sudo systemctl is-active --quiet $service; then
        echo "✓ $service running"
    else
        echo "✗ $service FAILED"
        sudo journalctl -u $service --no-pager -n 10
        exit 1
    fi
done

# Check backend health with retries
echo -n "Checking backend health"
for i in {1..10}; do
    sleep 1
    echo -n "."
    if curl -sf http://127.0.0.1:$APP_PORT/health >/dev/null 2>&1; then
        echo ""
        echo "✓ Backend healthy"
        NEED_ROLLBACK=false
        break
    fi
    if [ $i -eq 10 ]; then
        echo ""
        echo "✗ Backend unhealthy"
        sudo journalctl -u $SERVICE_NAME --no-pager -n 20
        exit 1
    fi
done

echo ""
echo "========================================="
echo "✓ Deployment successful!"
echo "========================================="
echo "Domain:  $DOMAIN"
echo "Status:  sudo systemctl status $SERVICE_NAME"
echo "Logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "Restart: sudo systemctl restart $SERVICE_NAME"
echo "========================================="
