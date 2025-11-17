# w9 — Simple Link & File Sharer

[![Rust](https://img.shields.io/badge/rust-1.75+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**w9** is a minimal, fast link and file sharing web application built entirely in Rust. Paste a URL or upload a file, and get a short link instantly. Perfect for quickly sharing content without accounts or complex setups.

![w9 Screenshot](https://via.placeholder.com/800x400/000000/FFFFFF?text=w9+Screenshoot)

## ✨ Features

- 🚀 **Instant Sharing**: Upload files or paste URLs to create short links in seconds
- 📱 **QR Codes**: Generate QR codes for easy mobile access
- 🖼️ **Smart Image Previews**: Images show rich previews in chat apps (Discord, Telegram, etc.)
- 📁 **File Support**: Upload and share any file type (documents, archives, media, etc.)
- 🔒 **Admin Panel**: Manage uploaded content with a simple admin interface
- 🎨 **Clean Design**: Minimalist, monochrome interface - no JavaScript required
- ⚡ **Fast & Lightweight**: Built with Rust for maximum performance

## 🚀 Quick Start

### Option 1: Docker (Easiest)

```bash
docker run -d \
  --name w9 \
  -p 8080:8080 \
  -v ./data:/app/data \
  -v ./uploads:/app/uploads \
  -e BASE_URL=https://your-domain.com \
  ghcr.io/shayneeo/w9:latest
```

### Option 2: Binary Release

Download the latest release from the [releases page](https://github.com/ShayNeeo/W9/releases) and run:

```bash
./w9
```

Then open http://localhost:8080

### Option 3: From Source

```bash
git clone https://github.com/ShayNeeo/W9.git
cd w9
cargo build --release
./target/release/w9
```

## 📖 Usage

1. **Share a URL**: Paste any URL in the form and click "Create"
2. **Upload a File**: Drag & drop or select a file to upload
3. **Get Short Link**: Copy the generated short URL (e.g., `https://w9.se/s/abc123`)
4. **Optional QR**: Check "Generate QR Code" for mobile sharing

### Example

- Original: `https://example.com/very-long-url-with-many-parameters`
- Short: `https://w9.se/s/abc123` (with QR code for mobile)

## 🏗️ Architecture

- **Backend**: Rust + Axum web framework
- **Frontend**: React + Vite (TypeScript)
- **Database**: SQLite for metadata storage
- **Storage**: Local filesystem for uploaded files
- **API**: RESTful endpoints for uploads and link management

## 🔧 Configuration

Set these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Listen address |
| `PORT` | `8080` | Listen port |
| `BASE_URL` | `http://localhost:8080` | Public base URL |
| `DATABASE_PATH` | `data/w9.db` | SQLite database path |

## 🌟 Use Cases

- **Quick File Sharing**: Share documents, images, or any files instantly
- **URL Shortening**: Create clean, short links for long URLs
- **QR Code Generation**: Perfect for printing or mobile access
- **Team Collaboration**: Simple way to share resources without complex permissions
- **Personal Use**: Lightweight alternative to cloud storage for quick sharing

## 🤝 Contributing

Contributions welcome! Please feel free to submit issues and enhancement requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the GNUv3 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Axum](https://github.com/tokio-rs/axum) web framework
- Templates powered by [Askama](https://github.com/djc/askama)
- Icons and design inspired by minimal, functional aesthetics

---

**Made with ❤️ in Rust** • [Report Issues](https://github.com/ShayNeeo/W9/issues) • [View Demo](https://w9.se)