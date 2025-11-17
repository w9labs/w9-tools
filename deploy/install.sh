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

# Feature flags
APT_INSTALL=${APT_INSTALL:-1}
SYSTEMD_ENABLE=${SYSTEMD_ENABLE:-1}
NGINX_ENABLE=${NGINX_ENABLE:-1}
BUILD_SOURCE=${BUILD_SOURCE:-auto}
BINARY_PATH=${BINARY_PATH:-}

is_enabled() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y|on|ON|enable|enabled) return 0 ;;
    *) return 1 ;;
  esac
}

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
    APT_PKGS="build-essential pkg-config libsqlite3-dev ca-certificates curl git"
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

echo "Building release (as user: $BUILD_USER)"
if [ "$(id -u)" -eq 0 ] && [ "$BUILD_USER" != "root" ]; then
  sudo -u "$BUILD_USER" -H bash -lc "source \"\$HOME/.cargo/env\" 2>/dev/null || true; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd '$ROOT_DIR' && cargo build --release"
else
  bash -lc "source \"\$HOME/.cargo/env\" 2>/dev/null || true; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cd '$ROOT_DIR' && cargo build --release"
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

# Note: SSL handled by Cloudflare (no certificate management needed)

# Write (or update) env file for systemd
write_env_file() {
  sudo tee "$ENV_FILE" > /dev/null <<ENVV
HOST=0.0.0.0
PORT=$APP_PORT
BASE_URL=$BASE_URL
DATABASE_PATH=$DATA_DIR/w9.db
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
  echo "Configuring nginx reverse proxy for $DOMAIN"
  
  sudo tee "$NGINX_SITE_PATH" > /dev/null <<NGX
server {
    listen 80;
    server_name ${DOMAIN};

    client_max_body_size 1024M;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 90s;
    }
}
NGX

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
  sudo systemctl status "$SERVICE_NAME" --no-pager -l || true
fi

if is_enabled "$NGINX_ENABLE"; then
  echo "Reloading nginx (if installed)"
  if command -v nginx >/dev/null 2>&1; then
    sudo systemctl reload nginx || sudo systemctl restart nginx || true
  fi
fi

echo ""
echo "✓ Done! To follow logs: sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "========== Installation Summary =========="
echo "Service:     $SERVICE_NAME"
echo "Domain:      $DOMAIN"
echo "Install:     $INSTALL_DIR/$BIN_NAME"
echo "Data:        $DATA_DIR"
echo "Uploads:     $UPLOADS_DIR"
echo "App Port:    $APP_PORT (internal)"
echo "Nginx:       Port 80 → localhost:$APP_PORT"
echo "SSL:         Cloudflare (auto)"
echo "========================================"
