#!/usr/bin/env bash
set -euo pipefail

# Idempotent installer for w9 (Cloudflare-proxied setup)
# - Install required packages (Debian/Ubuntu)
# - Create system user and runtime dirs
# - Ensure Rust toolchain
# - Build release binary
# - Install to /opt/w9
# - Setup systemd service
# - Configure nginx HTTP reverse proxy (Cloudflare handles HTTPS)
# Usage: sudo ./deploy/install.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "Repo root: $ROOT_DIR"

# Configuration
SERVICE_NAME=${SERVICE_NAME:-w9}
BIN_NAME=${BIN_NAME:-w9}
INSTALL_DIR=${INSTALL_DIR:-/opt/w9}
SERVICE_USER=${SERVICE_USER:-w9}
SERVICE_GROUP=${SERVICE_GROUP:-$SERVICE_USER}
DATA_DIR=${DATA_DIR:-$INSTALL_DIR/data}
UPLOADS_DIR=${UPLOADS_DIR:-$INSTALL_DIR/uploads}
ENV_FILE=${ENV_FILE:-/etc/default/$SERVICE_NAME}
SYSTEMD_UNIT=${SYSTEMD_UNIT:-/etc/systemd/system/$SERVICE_NAME.service}
NGINX_SITE_PATH=${NGINX_SITE_PATH:-/etc/nginx/sites-available/$SERVICE_NAME}
APP_PORT=${APP_PORT:-10105}
DOMAIN=${DOMAIN:-w9.se}
BASE_URL=${BASE_URL:-https://$DOMAIN}
ENV_OVERWRITE=${ENV_OVERWRITE:-1}

# Feature flags
APT_INSTALL=${APT_INSTALL:-1}
SYSTEMD_ENABLE=${SYSTEMD_ENABLE:-1}
NGINX_ENABLE=${NGINX_ENABLE:-1}
BUILD_SOURCE=${BUILD_SOURCE:-auto}
BINARY_PATH=${BINARY_PATH:-}
SETUP_SSL=${SETUP_SSL:-1}  # Generates self-signed cert + HTTPS server for Cloudflare "Full" mode

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y|on|ON|enable|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

stop_existing_service() {
  if command -v systemctl >/dev/null 2>&1; then
    if sudo systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
      if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "Stopping existing $SERVICE_NAME service"
        sudo systemctl stop "$SERVICE_NAME" || true
        sleep 1
      fi
      # prevent systemd from auto-restarting while install runs
      if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        echo "Temporarily disabling $SERVICE_NAME to avoid auto-restarts"
        sudo systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
      fi
    fi
  fi
}

kill_processes_on_port() {
  if command -v ss >/dev/null 2>&1; then
    local pids
    pids=$(sudo ss -ltnp 2>/dev/null | awk -v port=":$APP_PORT " '$0 ~ port {print $7}' | sed 's/users:(//' | sed 's/)//' | sed 's/"//g' | tr ',' '\n' | sed -n 's/^pid=\([0-9]\+\).*$/\1/p' | sort -u)
    if [ -n "$pids" ]; then
      echo "Killing processes using port $APP_PORT: $pids"
      for pid in $pids; do
        sudo kill "$pid" 2>/dev/null || true
      done
      sleep 1
    fi
  elif command -v fuser >/dev/null 2>&1; then
    sudo fuser -k "${APP_PORT}/tcp" 2>/dev/null || true
  fi
}

stop_existing_service
kill_processes_on_port

# Choose a non-root user for building when possible
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  BUILD_USER="$SUDO_USER"
elif [ -f "$ROOT_DIR/.git" ]; then
  BUILD_USER=$(stat -c '%U' "$ROOT_DIR")
else
  BUILD_USER=$(whoami)
fi

echo "Building release (as user: $BUILD_USER)"
# Install packages (Debian/Ubuntu)
if [ -f /etc/debian_version ]; then
  if is_enabled "$APT_INSTALL"; then
    echo "Installing system packages..."
    APT_PKGS="build-essential pkg-config libsqlite3-dev ca-certificates curl git nodejs npm openssl"
    if is_enabled "$NGINX_ENABLE"; then
      APT_PKGS="$APT_PKGS nginx ufw"
    fi
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends $APT_PKGS || true
  else
    echo "APT_INSTALL disabled; skipping package installation."
  fi
else
  echo "Non-Debian OS detected. Skipping package install."
fi

# Ensure a system user exists (service user)
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "Creating system user '$SERVICE_USER'"
  sudo useradd --system --create-home --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER" || true
fi

# Ensure rustup/cargo is available for the build user; install rustup if missing
if [ "$BUILD_USER" = "root" ]; then
  if ! bash -lc 'source "$HOME/.cargo/env" 2>/dev/null || true; command -v cargo >/dev/null 2>&1'; then
    echo "Installing rustup for user root"
    bash -lc 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
  fi
else
  if ! sudo -u "$BUILD_USER" -H bash -lc 'source "$HOME/.cargo/env" 2>/dev/null || true; command -v cargo >/dev/null 2>&1'; then
    echo "Installing rustup for user $BUILD_USER"
    sudo -u "$BUILD_USER" -H bash -lc 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'
  fi
fi

echo "Building backend release (as user: $BUILD_USER)"
if [ "$(id -u)" -eq 0 ] && [ "$BUILD_USER" != "root" ]; then
  sudo -u "$BUILD_USER" -H bash -lc "source \"\$HOME/.cargo/env\" 2>/dev/null || true; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd '$ROOT_DIR' && cargo build --release"
else
  bash -lc "source \"\$HOME/.cargo/env\" 2>/dev/null || true; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd '$ROOT_DIR' && cargo build --release"
fi

# Build frontend
echo "Building frontend..."
FRONTEND_DIR="$ROOT_DIR/frontend"
FRONTEND_DIST="$FRONTEND_DIR/dist"
FRONTEND_PUBLIC=${FRONTEND_PUBLIC:-/var/www/w9}
if [ -d "$FRONTEND_DIR" ]; then
  cd "$FRONTEND_DIR"
  npm install --prefer-offline
  npm run build
  echo "Frontend built to $FRONTEND_DIST"
else
  echo "Frontend directory not found at $FRONTEND_DIR"
  exit 1
fi

# Determine which binary to install
BIN_TARGET="$INSTALL_DIR/$BIN_NAME"
if [ -n "$BINARY_PATH" ]; then
  BIN_PATH="$BINARY_PATH"
  echo "Using provided BINARY_PATH: $BIN_PATH"
else
  case "$BUILD_SOURCE" in
    server)
      CANDIDATES=("$ROOT_DIR/server/target/release/$BIN_NAME")
      ;;
    root)
      CANDIDATES=("$ROOT_DIR/target/release/$BIN_NAME")
      ;;
    *)
      CANDIDATES=(
        "$ROOT_DIR/target/release/$BIN_NAME"
        "$ROOT_DIR/server/target/release/$BIN_NAME"
      )
      ;;
  esac
  BIN_PATH=""
  for c in "${CANDIDATES[@]}"; do
    if [ -f "$c" ]; then
      BIN_PATH="$c"
      break
    fi
  done
fi

if [ -z "${BIN_PATH:-}" ] || [ ! -f "$BIN_PATH" ]; then
  echo "ERROR: build failed, binary not found at expected locations:" >&2
  echo "  - $ROOT_DIR/target/release/$BIN_NAME" >&2
  echo "  - $ROOT_DIR/server/target/release/$BIN_NAME" >&2
  exit 2
fi

echo "Installing binary to $BIN_TARGET"
sudo mkdir -p "$INSTALL_DIR"
sudo cp -f "$BIN_PATH" "$BIN_TARGET"
# Ensure the directory and binary are owned so the service user can execute
sudo chown root:"$SERVICE_GROUP" "$INSTALL_DIR"
sudo chmod 750 "$INSTALL_DIR"
sudo chown root:"$SERVICE_GROUP" "$BIN_TARGET" || true
sudo chmod 750 "$BIN_TARGET"
sudo mkdir -p "$UPLOADS_DIR" "$DATA_DIR"
sudo chown -R "$SERVICE_USER":"$SERVICE_GROUP" "$UPLOADS_DIR" "$DATA_DIR"
sudo chmod 750 "$UPLOADS_DIR" "$DATA_DIR"

# Install frontend to /var/www/w9
echo "Installing frontend to $FRONTEND_PUBLIC"
sudo mkdir -p "$FRONTEND_PUBLIC"
sudo cp -r "$FRONTEND_DIST"/* "$FRONTEND_PUBLIC/"
sudo chown -R root:root "$FRONTEND_PUBLIC"
sudo chmod 755 "$FRONTEND_PUBLIC"
echo "✓ Frontend installed"

# Note: SSL handled by Cloudflare (no certificate management needed)

# Write (or update) env file for systemd
write_env_file() {
  sudo tee "$ENV_FILE" > /dev/null <<ENVV
HOST=0.0.0.0
PORT=$APP_PORT
BASE_URL=$BASE_URL
DATABASE_PATH=$DATA_DIR/w9.db
UPLOADS_DIR=$UPLOADS_DIR
ENVV
}

if [ ! -f "$ENV_FILE" ]; then
  echo "Writing $ENV_FILE"
  write_env_file
elif is_enabled "$ENV_OVERWRITE"; then
  echo "Updating $ENV_FILE (ENV_OVERWRITE enabled)"
  sudo cp "$ENV_FILE" "${ENV_FILE}.bak.$(date +%s)" || true
  write_env_file
else
  echo "Existing $ENV_FILE detected; ENV_OVERWRITE disabled, skipping update"
fi

# Systemd unit
if is_enabled "$SYSTEMD_ENABLE"; then
  echo "Writing systemd unit $SYSTEMD_UNIT"
  sudo tee "$SYSTEMD_UNIT" > /dev/null <<UNIT
[Unit]
Description=w9 - Link & file sharer service
After=network.target

[Service]
Type=simple
EnvironmentFile=-$ENV_FILE
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN_TARGET
User=$SERVICE_USER
Group=$SERVICE_GROUP
Restart=always
RestartSec=2
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNIT

  echo "Reloading systemd and enabling service"
  sudo systemctl daemon-reload
  sudo systemctl enable "$SERVICE_NAME" || true
fi

# Setup nginx (HTTP only - Cloudflare handles HTTPS)
if is_enabled "$NGINX_ENABLE"; then
  echo "Configuring nginx for frontend + API on $DOMAIN"
  
  SERVER_NAMES="$DOMAIN _"
  if [[ "$DOMAIN" == www.* ]]; then
    ROOT_DOMAIN="${DOMAIN#www.}"
    if [ -n "$ROOT_DOMAIN" ]; then
      SERVER_NAMES="$SERVER_NAMES $ROOT_DOMAIN"
    fi
  else
    SERVER_NAMES="$SERVER_NAMES www.$DOMAIN"
  fi

  ALT_DOMAIN="${DOMAIN#www.}"
  if [ -z "$ALT_DOMAIN" ] || [ "$ALT_DOMAIN" = "$DOMAIN" ]; then
    ALT_DOMAIN="www.$DOMAIN"
  fi

  SSL_DIR="/etc/nginx/ssl/$DOMAIN"
  SSL_CERT="$SSL_DIR/cert.pem"
  SSL_KEY="$SSL_DIR/key.pem"
  if is_enabled "$SETUP_SSL"; then
    echo "Ensuring self-signed certificate in $SSL_DIR"
    sudo mkdir -p "$SSL_DIR"
    if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
      echo "Generating self-signed certificate for $DOMAIN (Cloudflare Full mode support)"
      sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN,DNS:$ALT_DOMAIN" >/dev/null 2>&1 || \
      sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$DOMAIN"
      sudo chmod 600 "$SSL_KEY"
      sudo chmod 644 "$SSL_CERT"
    fi
  fi
  
  sudo tee "$NGINX_SITE_PATH" > /dev/null <<NGX
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${SERVER_NAMES};

    client_max_body_size 1024M;
    root $FRONTEND_PUBLIC;
    index index.html;

    # Health check endpoint - proxy to backend
    location /health {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_connect_timeout 2s;
        proxy_read_timeout 2s;
        access_log off;
    }

    # API routes and uploads - proxy to backend
    location /api/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_read_timeout 90s;
    }

    location /admin/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_read_timeout 90s;
    }

    location /r/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    location /s/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    location /files/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    # Frontend - serve index.html for all non-existent routes (SPA)
    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGX

  if is_enabled "$SETUP_SSL"; then
    sudo tee -a "$NGINX_SITE_PATH" > /dev/null <<NGXSSL
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${SERVER_NAMES};

    ssl_certificate $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 1024M;
    root $FRONTEND_PUBLIC;
    index index.html;

    location /health {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_connect_timeout 2s;
        proxy_read_timeout 2s;
        access_log off;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_read_timeout 90s;
    }

    location /admin/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
        proxy_read_timeout 90s;
    }

    location /r/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    location /s/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    location /files/ {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$remote_addr;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGXSSL
  fi

  # Remove old sites to avoid conflicts
  sudo rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/ping0 2>/dev/null
  
  # Enable only the w9 site
  sudo ln -sf "$NGINX_SITE_PATH" "/etc/nginx/sites-enabled/$SERVICE_NAME"
  sudo nginx -t && echo "✓ Nginx config valid"

  # Allow HTTP port
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 80/tcp || true
  fi
fi

if is_enabled "$SYSTEMD_ENABLE"; then
  echo "Starting (or restarting) $SERVICE_NAME service"
  sudo systemctl restart "$SERVICE_NAME" || sudo systemctl start "$SERVICE_NAME"
  
  # Wait for service to start
  echo "Waiting for service to start..."
  for i in {1..10}; do
    if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
      break
    fi
    sleep 1
  done
  
  if sudo systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "✓ Service is running"
    # Verify the service is listening on the expected port
    if command -v ss >/dev/null 2>&1; then
      if ss -tln | grep -q ":$APP_PORT "; then
        echo "✓ Service is listening on port $APP_PORT"
      else
        echo "WARNING: Service may not be listening on port $APP_PORT" >&2
      fi
    fi
    
    # Health check - verify backend actually responds
    echo "Verifying backend health..."
    sleep 1
    if command -v curl >/dev/null 2>&1; then
      HEALTH_RESPONSE=$(curl -s -f -m 3 "http://127.0.0.1:$APP_PORT/health" 2>/dev/null || echo "")
      if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
        echo "✓ Backend health check passed"
      else
        echo "WARNING: Backend health check failed (may still be starting)" >&2
        echo "  Response: ${HEALTH_RESPONSE:-no response}" >&2
        echo "  Check logs: sudo journalctl -u $SERVICE_NAME -n 50" >&2
      fi
    fi
  else
    echo "ERROR: Service failed to start" >&2
    sudo systemctl status "$SERVICE_NAME" --no-pager -l || true
    echo "Check logs with: sudo journalctl -u $SERVICE_NAME -n 50" >&2
    if command -v journalctl >/dev/null 2>&1; then
      echo "------ Last 50 log lines ($SERVICE_NAME) ------"
      sudo journalctl -u "$SERVICE_NAME" -n 50 --no-pager || true
      echo "----------------------------------------------"
    fi
    exit 1
  fi
  sudo systemctl status "$SERVICE_NAME" --no-pager -l || true
fi

if is_enabled "$NGINX_ENABLE"; then
  echo "Reloading nginx (if installed)"
  if command -v nginx >/dev/null 2>&1; then
    sudo systemctl enable nginx || true
    sudo systemctl reload nginx || sudo systemctl restart nginx || true
    sleep 2
    
    if ! sudo systemctl is-active --quiet nginx; then
      echo "ERROR: nginx failed to start" >&2
      sudo systemctl status nginx --no-pager -l || true
      exit 1
    else
      echo "✓ Nginx is running"
      
      # Verify nginx can reach backend
      if command -v curl >/dev/null 2>&1; then
        echo "Verifying nginx → backend connectivity..."
        NGINX_HEALTH=$(curl -s -f -m 3 "http://127.0.0.1/health" 2>/dev/null || echo "")
        if echo "$NGINX_HEALTH" | grep -q "healthy"; then
          echo "✓ Nginx can reach backend successfully"
        else
          echo "WARNING: Nginx health check failed" >&2
          echo "  Response: ${NGINX_HEALTH:-no response}" >&2
          echo "  This may cause Cloudflare 521 errors" >&2
          echo "  Check nginx logs: sudo journalctl -u nginx -n 50" >&2
        fi
        
        # DNS and proxy diagnostics
        if [ -n "${DOMAIN:-}" ]; then
          echo ""
          echo "🔍 DNS & Cloudflare Proxy Diagnostics:"
          
          # Get VPS public IP
          VPS_IP=$(curl -s -m 3 https://api.ipify.org 2>/dev/null || curl -s -m 3 https://ifconfig.me 2>/dev/null || echo "unknown")
          echo "  VPS Public IP: $VPS_IP"
          
          # Check DNS resolution
          if command -v dig >/dev/null 2>&1; then
            DNS_RESULT=$(dig +short "$DOMAIN" @8.8.8.8 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "")
            if [ -n "$DNS_RESULT" ]; then
              echo "  DNS resolves to: $DNS_RESULT"
              
              # Check if it's a Cloudflare IP (common ranges)
              if echo "$DNS_RESULT" | grep -qE '^(104\.|172\.64\.|172\.65\.|172\.66\.|172\.67\.|172\.68\.|172\.69\.|172\.70\.|172\.71\.|198\.41\.|173\.245\.)'; then
                echo "  ✓ DNS points to Cloudflare IPs (proxy is ON)"
                echo "  📝 IMPORTANT: Set Cloudflare SSL/TLS mode to 'Flexible'"
                echo "     Dashboard → SSL/TLS → Overview → Set to 'Flexible'"
                echo "     This allows Cloudflare to connect via HTTP (port 80)"
              elif [ "$DNS_RESULT" != "$VPS_IP" ] && [ "$VPS_IP" != "unknown" ]; then
                echo "  ⚠️  WARNING: DNS ($DNS_RESULT) doesn't match VPS IP ($VPS_IP)" >&2
                echo "     Update DNS A record to point to: $VPS_IP" >&2
              else
                echo "  ✓ DNS correctly points to VPS IP"
              fi
            else
              echo "  ⚠️  WARNING: Could not resolve DNS for $DOMAIN" >&2
            fi
          fi
          
          # Test domain access (HTTP - for Cloudflare Flexible mode)
          echo "  Testing domain access via HTTP..."
          DOMAIN_TEST=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "http://$DOMAIN/health" 2>/dev/null || echo "000")
          if [ "$DOMAIN_TEST" = "200" ]; then
            echo "  ✓ Domain is accessible via HTTP (Cloudflare Flexible mode ready)"
          elif [ "$DOMAIN_TEST" = "000" ]; then
            echo "  ⚠️  Domain not reachable via HTTP" >&2
            if echo "$DNS_RESULT" | grep -qE '^(104\.|172\.64\.|172\.65\.|172\.66\.|172\.67\.|172\.68\.|172\.69\.|172\.70\.|172\.71\.|198\.41\.|173\.245\.)'; then
              echo "     Cloudflare proxy is ON - check SSL/TLS mode:" >&2
              echo "     1. Go to Cloudflare Dashboard → SSL/TLS → Overview" >&2
              echo "     2. Set mode to 'Flexible' (not 'Full' or 'Full Strict')" >&2
              echo "     3. Wait 1-2 minutes for changes to propagate" >&2
            else
              echo "     This is normal if DNS hasn't propagated yet" >&2
            fi
          else
            echo "  ⚠️  Domain returned HTTP $DOMAIN_TEST" >&2
          fi
          
          # Test HTTPS access (should work if proxy is ON and Flexible mode)
          if echo "$DNS_RESULT" | grep -qE '^(104\.|172\.64\.|172\.65\.|172\.66\.|172\.67\.|172\.68\.|172\.69\.|172\.70\.|172\.71\.|198\.41\.|173\.245\.)'; then
            echo "  Testing HTTPS access (via Cloudflare)..."
            HTTPS_TEST=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "https://$DOMAIN/health" 2>/dev/null || echo "000")
            if [ "$HTTPS_TEST" = "200" ]; then
              echo "  ✓ HTTPS is working via Cloudflare proxy"
            elif [ "$HTTPS_TEST" = "521" ]; then
              echo "  ⚠️  Cloudflare 521 error detected" >&2
              echo "     Fix: Set SSL/TLS mode to 'Flexible' in Cloudflare dashboard" >&2
            else
              echo "  ⚠️  HTTPS returned HTTP $HTTPS_TEST" >&2
            fi
          fi
        fi
      fi
    fi
  fi
fi

echo ""
echo "✓ Done! Service is running."
echo ""
echo "========== Installation Summary =========="
echo "Domain:      $DOMAIN"
echo "Backend:     $INSTALL_DIR/$BIN_NAME (port $APP_PORT)"
echo "Frontend:    /var/www/w9"
echo "Data:        $DATA_DIR"
echo "Uploads:     $UPLOADS_DIR"
echo "Nginx:       Port 80"
echo "SSL:         Cloudflare (auto)"
echo ""
echo "Routes:"
echo "  /              → Frontend"
echo "  /api/*         → Backend API"
echo "  /admin/*       → Backend Admin"
echo "  /r/:code       → Redirect"
echo "  /s/:code       → Short link"
echo "  /files/*       → Uploads"
echo ""
echo "📊 Diagnostic Commands:"
echo "  Service status:  sudo systemctl status $SERVICE_NAME"
echo "  Service logs:    sudo journalctl -u $SERVICE_NAME -f"
echo "  Nginx logs:      sudo journalctl -u nginx -f"
echo "  Backend health:  curl http://127.0.0.1:$APP_PORT/health"
echo "  Via nginx:       curl http://127.0.0.1/health"
echo "  Check port:      ss -tln | grep $APP_PORT"
echo ""
echo "🔍 Troubleshooting Cloudflare 521:"
echo ""
echo "If proxy is ON (orange cloud 🔒) and you get 521 error:"
echo "  1. Go to Cloudflare Dashboard → SSL/TLS → Overview"
echo "  2. Set SSL/TLS encryption mode to 'Flexible'"
echo "     - Flexible: Cloudflare ↔ Visitors: HTTPS, Cloudflare ↔ Origin: HTTP"
echo "     - Full/Full Strict: Requires HTTPS on origin (port 443) - will cause 521"
echo "  3. Wait 1-2 minutes for changes to propagate"
echo "  4. Test: curl https://$DOMAIN/health"
echo ""
echo "If proxy is OFF (gray cloud ⚙️) and domain doesn't work:"
echo "  1. Check DNS resolution: dig +short $DOMAIN @8.8.8.8"
echo "     - Should show your VPS IP (not Cloudflare IPs like 104.x.x.x)"
echo "  2. Wait 5-10 minutes for DNS propagation"
echo "  3. Clear DNS cache:"
echo "     - Linux: sudo systemd-resolve --flush-caches"
echo "     - Browser: Use incognito/private mode"
echo "  4. Test domain directly: curl -v http://$DOMAIN/health"
echo ""
echo "General diagnostics:"
echo "  1. Verify backend: sudo systemctl status $SERVICE_NAME"
echo "  2. Check backend logs: sudo journalctl -u $SERVICE_NAME -n 50"
echo "  3. Test backend directly: curl http://127.0.0.1:$APP_PORT/health"
echo "  4. Test via nginx (IP): curl http://127.0.0.1/health"
echo "  5. Test via nginx (domain): curl -H 'Host: $DOMAIN' http://127.0.0.1/health"
echo "  6. Verify nginx config: sudo nginx -t"
echo "  7. Check firewall: sudo ufw status"
echo "  8. Check nginx access logs: sudo tail -f /var/log/nginx/access.log"
echo ""
echo "========================================"
