# W9 Tools

W9 Tools is a lightweight utility stack for instant link shortening, markdown notepads, and secure file sharing. The backend is written in Rust (Axum) and serves a React/Vite single-page frontend. The stack is intentionally minimal: a single binary, SQLite for metadata, and the local filesystem for uploads.

## Key Capabilities

- Share short links pointing to URLs, files, or markdown notepads
- Generate optional QR codes for every short link
- Admin panel for inspecting or deleting any item (links, files, notepads)
- Markdown notepad writer with custom short codes and server-side rendering
- File uploads with automatic previews for images and media

## Architecture

- **Backend:** Rust + Axum + Askama templates
- **Frontend:** React + Vite + TypeScript
- **Database:** SQLite (single file)
- **Static Assets / Uploads:** Filesystem (`uploads/`)
- **Deployment:** Systemd service + Nginx reverse proxy via `deploy/install.sh`

## Installing with `deploy/install.sh`

The repository includes an opinionated installation script that compiles the backend, builds the frontend, configures systemd + nginx, and sets up TLS with a self-signed certificate.

### Prerequisites

- Ubuntu/Debian host with sudo access
- Git, Rust toolchain, Node 18+, npm
- Domain pointing to the server (optional but recommended)

### Steps

1. Clone the repository on the target server:
   ```bash
   git clone https://github.com/ShayNeeo/w9-tools.git
   cd w9-tools/deploy
   ```
2. Set the environment variables used by the script (either export or inline):
   ```bash
   export DOMAIN=example.com
   export BASE_URL=https://example.com
   export APP_PORT=10105            # optional, default defined in script
   ```
3. Run the installer:
   ```bash
   ./install.sh
   ```
   The script performs the following:
   - Installs missing packages (Rust toolchain, Node/npm, nginx, sqlite, etc.)
   - Builds the backend (`cargo build --release`)
   - Builds the frontend (`npm ci` + `npm run build`)
   - Stops any running `w9` service, copies the binary + frontend dist
   - Writes `/etc/default/w9` and `/etc/systemd/system/w9.service`
   - Configures nginx at `/etc/nginx/sites-available/w9` with TLS under `/etc/nginx/ssl/$DOMAIN`
   - Enables and starts nginx + w9 systemd services
   - Opens ports 80/443 via ufw

4. After a successful run:
   ```bash
   systemctl status w9
   journalctl -u w9 -f
   ```
   Visit `https://DOMAIN` to confirm the UI is available.

### Redeploying

When code changes (backend or frontend) are pulled, rerun `deploy/install.sh`. It detects changes and only rebuilds what is necessary. To force a frontend rebuild (e.g., after editing `frontend/public/robots.txt`), remove the `frontend/dist` directory before running the script or touch any file under `frontend/src` or `frontend/public`.

## Local Development

```bash
# Backend
cargo watch -x "run --bin w9"

# Frontend
cd frontend
npm install
npm run dev
```

Use `VITE_API_BASE_URL` in `.env` to point the frontend dev server at the backend.

## Configuration

| Variable        | Default               | Description                               |
|-----------------|-----------------------|-------------------------------------------|
| `HOST`          | `0.0.0.0`             | Listen address for the backend             |
| `PORT`          | `8080`                | Backend port                               |
| `BASE_URL`      | `http://localhost:8080` | Public base URL used in short links         |
| `DATABASE_PATH` | `data/w9.db`          | SQLite database path                       |
| `UPLOADS_DIR`   | `uploads`             | Filesystem directory for uploaded assets   |

When deploying via `install.sh`, these values are written to `/etc/default/w9` and consumed by the systemd service.

## Usage Flow

1. Open the home page (`/`).
2. Navigate to:
   - `/short` for URL/file shortener
   - `/note` for markdown notepad (supports custom short codes)
   - `/convert` (placeholder page for upcoming tools)
3. For each short link, a QR code can be generated.
4. Notepad entries render markdown on `/n/<code>` using Askama templates.
5. Admin panel (`/admin`) requires initial credentials set on first login; this panel shows every item with delete actions.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/xyz`
3. Run rustfmt / clippy / frontend lint where applicable
4. Open a pull request describing the change and testing steps

## License

Licensed under GNU General Public License v3.0. See [LICENSE](LICENSE).