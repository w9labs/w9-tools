# W9 Tools

Developer utilities for the W9 Network - file sharing, URL shortening, QR codes, note drops, and text converters.

## Tech Stack

- **Backend**: Rust + Axum + SurrealDB
- **Frontend**: Leptos (Full-stack SSR)
- **Authentication**: OAuth via W9 DB (db.w9.nu)

## Features

| Tool | Description | Route |
|------|-------------|-------|
| File Sharing | Upload and share files with download tracking | `/files` |
| URL Shortener | Create short URLs on w9.nu domain | `/short` |
| Note Drops | Self-destructing text notes | `/notes` |
| QR Generator | Generate QR codes for any content | `/qr` |
| Text Converters | Base64, URL encoding, case conversion | `/convert` |

## Quick Start

```bash
cargo run --package w9-tools-server
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | SurrealDB connection | `memory` |
| `W9_DB_URL` | W9 DB OAuth URL | `https://db.w9.nu` |
| `BASE_URL` | Public base URL | `https://tools.w9.nu` |
| `UPLOADS_DIR` | Upload directory path | `./uploads` |
| `PORT` | Server port | `10105` |

## Deployment

```bash
docker-compose up -d
```

Access at: `https://tools.w9.nu`

## License

GPL v3.0
