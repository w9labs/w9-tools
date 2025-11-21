# W9 Tools

W9 Tools is a lightweight utility stack for instant link shortening, markdown notepads, and secure file sharing. The backend is written in Rust (Axum) and serves a React/Vite single-page frontend. The stack is intentionally minimal: a single binary, SQLite for metadata, and the local filesystem for uploads.

## Key Capabilities

- Share short links pointing to URLs, files, or markdown notepads
- Generate optional QR codes for every short link
- Built-in authentication: register, verify email, login, password reset/change
- Markdown notepad writer with custom short codes and server-side rendering
- File uploads with automatic previews for images and media
- Admin panel for items, users, and email sender selection

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
2. Run the installer **with the required variables inline on the same command** so they are passed to `sudo`:
   ```bash
   DOMAIN=example.com \
   BASE_URL=https://example.com \
   W9_MAIL_API_TOKEN=<jwt-from-w9-mail> \
   sudo -E ./deploy/install.sh
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

| Variable                | Default                         | Description |
|------------------------|---------------------------------|-------------|
| `HOST`                 | `0.0.0.0`                       | Listen address |
| `PORT`                 | `8080`                          | Backend port |
| `BASE_URL`             | `http://localhost:8080`         | Public base URL used in short links |
| `DATABASE_PATH`        | `data/w9.db`                    | SQLite database path |
| `UPLOADS_DIR`          | `uploads`                       | Filesystem directory for uploads |
| `PASSWORD_RESET_BASE_URL` | `${BASE_URL}/reset-password` | Link used inside password reset emails |
| `VERIFICATION_BASE_URL`   | `${BASE_URL}/verify-email`   | Link used inside registration verification emails |
| `W9_MAIL_API_URL`      | `https://w9.nu`                 | w9-mail base URL for transactional email |
| `W9_MAIL_API_TOKEN`    | _(empty)_                       | JWT from w9-mail used when calling `/api/send` and sender APIs |
| `EMAIL_FROM_ADDRESS`   | `W9 Tools <no-reply@domain>`    | Fallback sender if no w9-mail sender is configured |

The installer writes these values to `/etc/default/w9`. To update secrets (like `W9_MAIL_API_TOKEN`) edit that file and run `sudo systemctl restart w9`.

When deploying via `install.sh`, these values are written to `/etc/default/w9` and consumed by the systemd service.

## Email + Verification Flow

- The backend sends verification and reset messages through w9-mail. Supply `W9_MAIL_API_TOKEN` (a JWT obtained by logging into w9-mail as an admin) so the service can call `/api/send`.
- After deployment, visit `/admin` → Email Sender tab to pick which w9-mail account/alias should send transactional mail. The choice is stored locally and used for all future emails.
- Registration requires email verification. The verification link points to `${BASE_URL}/verify-email?token=...`, which the frontend handles and automatically signs the user in if successful.

## Usage Flow

1. Open the home page (`/`).
2. Navigate to:
   - `/short` for URL/file shortener
   - `/note` for markdown notepad (supports custom short codes)
   - `/convert` (placeholder page for upcoming tools)
3. For each short link, a QR code can be generated.
4. Notepad entries render markdown on `/n/<code>` using Askama templates.
5. Admin panel (`/admin`) exposes tabs for Items, Users, and Email Sender configuration.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/xyz`
3. Run rustfmt / clippy / frontend lint where applicable
4. Open a pull request describing the change and testing steps

## License

Licensed under GNU General Public License v3.0. See [LICENSE](LICENSE).