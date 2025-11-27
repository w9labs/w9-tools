// The final, corrected handlers.rs file

use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, request::Parts};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use axum::debug_handler;
use axum::async_trait;
use axum::extract::FromRequestParts;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation, encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use mime_guess::from_path as mime_from_path;
use nanoid::nanoid;
use qrcode::render::svg::Color;
use qrcode::QrCode;
use rusqlite::{params, Connection, Error as SqliteError, ErrorCode, OptionalExtension};
use std::path::{Path as StdPath}; // Use StdPath to avoid conflict with axum::extract::Path
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use uuid::Uuid;
use askama::Template;
use w9::templates::{ImageOgTemplate, FileInfoTemplate, PdfTemplate, VideoTemplate, NotepadTemplate};
use image::{imageops::FilterType, DynamicImage, ImageOutputFormat, GenericImageView};
use sha2::{Digest, Sha256};
use rand::{distributions::Alphanumeric, Rng};
pub async fn cors_preflight() -> impl IntoResponse {
    // Let CorsLayer attach the appropriate headers; return 204 No Content
    (StatusCode::NO_CONTENT, ())
}

// Removed CodeParams; using Path<String> directly for routes with one :code param


// Maximum file size: 1 GiB
const MAX_FILE_SIZE: usize = 1024 * 1024 * 1024;

// Allowed file extensions for uploads
const ALLOWED_EXTENSIONS: &[&str] = &[
    // images
    "jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "avif", "svg",
    // documents
    "pdf", "txt", "md", "csv", "json", "rtf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    // archives
    "zip", "tar", "gz", "rar", "7z",
    // audio
    "mp3", "wav", "flac", "ogg",
    // video
    "mp4", "mov", "webm", "avi", "mkv"
];

const IMAGE_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "avif"];

// Preview target size: strictly under 1 MiB
const PREVIEW_MAX_BYTES: usize = 1 * 1024 * 1024;

const CUSTOM_CODE_MIN_LEN: usize = 3;
const CUSTOM_CODE_MAX_LEN: usize = 32;
const RESERVED_CUSTOM_CODES: &[&str] = &[
    "admin", "api", "files", "health", "robots", "sitemap", "s", "r",
];

// ensure_dir was unused; removed to avoid dead_code warning

fn make_preview_filename(original_filename: &str) -> String {
    let stem = StdPath::new(original_filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("preview");
    format!("{}.jpg", stem)
}

fn is_image_ext(ext: &str) -> bool {
    IMAGE_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
}

fn encode_jpeg_under_limit(img: &DynamicImage, max_bytes: usize) -> Option<Vec<u8>> {
    let (w, h) = img.dimensions();
    let original_pixels = (w * h) as usize;

    // Estimate rough JPEG compression ratio (typically 10-50:1 depending on content)
    let estimated_jpeg_ratio = 20.0; // Conservative estimate
    let estimated_jpeg_size = original_pixels / estimated_jpeg_ratio as usize;

    // If already under limit, no need to compress
    if estimated_jpeg_size <= max_bytes {
        let mut buf = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buf);
        if img.write_to(&mut cursor, ImageOutputFormat::Jpeg(90)).is_ok() {
            if buf.len() <= max_bytes {
                tracing::info!("Preview: kept original size, quality=90, {}KB", buf.len() / 1024);
                return Some(buf);
            }
        }
    }

    // Smart scaling: calculate target dimensions to hit roughly our byte limit
    let target_pixels = max_bytes * 15; // More aggressive estimate for preview quality
    let scale_factor = ((target_pixels as f64) / (original_pixels as f64)).sqrt().min(1.0);

    // Create scale progression from our calculated factor
    let mut scales = Vec::new();
    let mut current_scale = scale_factor.max(0.05); // Never go below 5%
    scales.push(current_scale);

    // Add progressively smaller scales for fallback
    while current_scale > 0.1 {
        current_scale *= 0.75;
        scales.push(current_scale.max(0.05));
    }

    // Quality progression: start high, go lower
    let qualities = [90u8, 85, 80, 75, 70, 65, 60, 55, 50, 45, 40, 35, 30, 25, 20, 15, 10];

    for scale in scales {
        let target_w = ((w as f64) * scale).max(1.0) as u32;
        let target_h = ((h as f64) * scale).max(1.0) as u32;

        // Skip resizing if it's the original size
        let resized = if target_w == w && target_h == h {
            img.clone()
        } else {
            img.resize(target_w, target_h, FilterType::Lanczos3)
        };

        for &quality in &qualities {
            let mut buf = Vec::with_capacity(max_bytes / 4); // Pre-allocate reasonable size
            let mut cursor = std::io::Cursor::new(&mut buf);

            if resized.write_to(&mut cursor, ImageOutputFormat::Jpeg(quality)).is_ok() {
                let size_kb = buf.len() / 1024;
                if buf.len() <= max_bytes {
                    tracing::info!("Preview compressed: {}x{} → {}x{}, scale={:.2}, quality={}, size={}KB",
                        w, h, target_w, target_h, scale, quality, size_kb);
                    return Some(buf);
                }

                // If we're getting close (within 10%), try one more quality step down
                if buf.len() as f64 > max_bytes as f64 * 0.9 && quality > 10 {
                    continue; // Try next lower quality
                }
            }
        }
    }

    tracing::warn!("Could not compress {}x{} image under {}KB limit", w, h, max_bytes / 1024);
    None
}

fn should_generate_preview(original_path: &StdPath, preview_limit_bytes: usize) -> bool {
    match std::fs::metadata(original_path) {
        Ok(metadata) => {
            let file_size = metadata.len() as usize;
            // If original file is already small, no need for preview
            if file_size <= preview_limit_bytes {
                tracing::debug!("Skipping preview generation: original file is already {}KB", file_size / 1024);
                return false;
            }

            // For very large files, always generate preview
            if file_size > 10 * preview_limit_bytes { // >10MB
                return true;
            }

            // For medium files, check if they're already JPEG with reasonable compression
            if let Some(ext) = original_path.extension().and_then(|e| e.to_str()) {
                if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
                    // If it's already a JPEG and reasonably sized, maybe skip
                    return file_size > 2 * preview_limit_bytes; // Only if >2MB
                }
            }
        }
        Err(_) => return true, // If we can't read metadata, assume we need preview
    }
    true
}

fn try_generate_preview(original_path: &StdPath, preview_path: &StdPath) -> Result<(), String> {
    let img = image::open(original_path).map_err(|e| format!("open image: {}", e))?;

    // First try the smart compression
    if let Some(bytes) = encode_jpeg_under_limit(&img, PREVIEW_MAX_BYTES) {
        tracing::info!("Preview generated successfully: {}KB", bytes.len() / 1024);
        return std::fs::write(preview_path, &bytes).map_err(|e| format!("write preview: {}", e));
    }

    // Fallback 1: Extreme downscaling for massive images (>50MP)
    let (w, h) = img.dimensions();
    let pixel_count = (w as u64) * (h as u64);

    if pixel_count > 50_000_000 { // >50MP images
        let max_pixels = 4_000_000u64; // 2K resolution max for extreme cases
        let scale = ((max_pixels as f64) / (pixel_count as f64)).sqrt();
        let new_w = (w as f64 * scale).max(32.0) as u32; // Minimum 32px
        let new_h = (h as f64 * scale).max(32.0) as u32;

        tracing::warn!("Extreme fallback: massive image {}MP → {}x{}", pixel_count / 1_000_000, new_w, new_h);

        let fallback_img = img.resize(new_w, new_h, FilterType::Lanczos3);

        // Try very low qualities on the scaled image
        for quality in [30u8, 20, 15, 10] {
            let mut buf = Vec::new();
            let mut cur = std::io::Cursor::new(&mut buf);
            if fallback_img.write_to(&mut cur, ImageOutputFormat::Jpeg(quality)).is_ok() {
                if buf.len() <= PREVIEW_MAX_BYTES {
                    tracing::warn!("Extreme fallback succeeded: quality={}, size={}KB", quality, buf.len() / 1024);
                    return std::fs::write(preview_path, &buf).map_err(|e| format!("write preview: {}", e));
                }
            }
        }
    }

    // Fallback 2: Progressive downscaling with very low quality
    tracing::warn!("Trying progressive downscaling fallback for {}x{}", w, h);

    // Start with 25% scale and go down
    for scale in [0.25, 0.15, 0.1, 0.05] {
        let new_w = ((w as f64) * scale).max(16.0) as u32;
        let new_h = ((h as f64) * scale).max(16.0) as u32;

        let scaled_img = img.resize(new_w, new_h, FilterType::Lanczos3);

        for quality in [25u8, 15, 10] {
            let mut buf = Vec::new();
            let mut cur = std::io::Cursor::new(&mut buf);
            if scaled_img.write_to(&mut cur, ImageOutputFormat::Jpeg(quality)).is_ok() {
                if buf.len() <= PREVIEW_MAX_BYTES {
                    tracing::warn!("Progressive fallback succeeded: {}x{} scale={}, quality={}, size={}KB",
                        new_w, new_h, scale, quality, buf.len() / 1024);
                    return std::fs::write(preview_path, &buf).map_err(|e| format!("write preview: {}", e));
                }
            }
        }
    }

    // Last resort: try to create a tiny 64x64 thumbnail at minimum quality
    tracing::error!("All compression attempts failed, creating minimum thumbnail");
    let tiny_img = img.resize(64, 64, FilterType::Lanczos3);
    let mut buf = Vec::new();
    let mut cur = std::io::Cursor::new(&mut buf);
    tiny_img.write_to(&mut cur, ImageOutputFormat::Jpeg(5)).map_err(|e| format!("encode jpeg: {}", e))?;
    tracing::warn!("Last resort thumbnail: 64x64, quality=5, size={}KB", buf.len() / 1024);
    std::fs::write(preview_path, &buf).map_err(|e| format!("write preview: {}", e))
}

#[derive(Clone)]
pub struct AppState { 
    pub db_path: String, 
    pub base_url: String,
    pub uploads_dir: String,
    pub w9_mail_api_url: String,
    pub jwt_secret: String,
    pub password_reset_base_url: String,
    pub verification_base_url: String,
    pub w9_mail_api_token: Option<String>,
    pub email_sender: Arc<RwLock<Option<EmailSenderConfig>>>,
    pub turnstile_secret: Option<String>,
    pub qr_logo_path: Option<String>,
}

const PASSWORD_MIN_LEN: usize = 8;
const PASSWORD_RESET_TOKEN_TTL_MINUTES: i64 = 30;
const EMAIL_VERIFICATION_TOKEN_TTL_MINUTES: i64 = 30;
const EMAIL_SENDER_SETTING_KEY: &str = "email_sender";

async fn verify_turnstile(secret: &str, token: &str) -> Result<bool, String> {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "secret": secret,
        "response": token,
    });
    
    match client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(data) => {
                    let success = data.get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    Ok(success)
                }
                Err(e) => Err(format!("Failed to parse Turnstile response: {}", e))
            }
        }
        Err(e) => Err(format!("Failed to verify Turnstile token: {}", e))
    }
}

#[derive(Debug, Clone)]
struct UserRecord {
    id: String,
    email: String,
    password_hash: String,
    salt: String,
    role: String,
    must_change_password: bool,
    is_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSenderConfig {
    pub sender_type: Option<String>,
    pub sender_id: Option<String>,
    pub email: String,
    pub display_label: Option<String>,
    pub via_display: Option<String>,
}

fn normalize_email(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("Email is required");
    }
    if !trimmed.contains('@') || trimmed.starts_with('@') || trimmed.ends_with('@') {
        return Err("Invalid email address");
    }
    Ok(trimmed)
}

fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < PASSWORD_MIN_LEN {
        Err("Password must be at least 8 characters")
    } else {
        Ok(())
    }
}

pub async fn verify_email_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> impl IntoResponse {
    if payload.token.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Token is required"})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let token_row = match consume_email_verification_token(&conn, &payload.token) {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid or expired token"})),
            );
        }
        Err(e) => {
            tracing::error!("Failed to read verification token: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let (user_id, expires_at) = token_row;
    if expires_at < Utc::now().timestamp() {
        let _ = delete_email_verification_token(&conn, &payload.token);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Token expired"})),
        );
    }

    let Some(mut user) = fetch_user_by_id(&conn, &user_id).unwrap_or(None) else {
        let _ = delete_email_verification_token(&conn, &payload.token);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "User no longer exists"})),
        );
    };

    if let Err(e) = conn.execute(
        "UPDATE users SET is_verified = 1 WHERE id = ?1",
        params![user.id],
    ) {
        tracing::error!("Failed to update verification status: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to verify user"})),
        );
    }

    let _ = delete_email_verification_token(&conn, &payload.token);
    user.is_verified = true;

    let token = match issue_jwt(&state, &user) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to issue JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to create session"})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Email verified. You are now signed in.",
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "must_change_password": user.must_change_password,
                "is_verified": true
            }
        })),
    )
}

fn fetch_user_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, email, password_hash, salt, role, COALESCE(must_change_password, 0), COALESCE(is_verified, 1) FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                email: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?,
                role: row.get(4)?,
                must_change_password: row.get::<_, i64>(5)? != 0,
                is_verified: row.get::<_, i64>(6)? != 0,
            })
        },
    )
    .optional()
}

fn fetch_user_by_id(conn: &Connection, user_id: &str) -> rusqlite::Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, email, password_hash, salt, role, COALESCE(must_change_password, 0), COALESCE(is_verified, 1) FROM users WHERE id = ?1",
        params![user_id],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                email: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?,
                role: row.get(4)?,
                must_change_password: row.get::<_, i64>(5)? != 0,
                is_verified: row.get::<_, i64>(6)? != 0,
            })
        },
    )
    .optional()
}

fn issue_jwt(state: &AppState, user: &UserRecord) -> Result<String, String> {
    let exp = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .ok_or_else(|| "Failed to compute expiration".to_string())?
        .timestamp() as usize;
    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

fn store_password_reset_token(
    conn: &Connection,
    user_id: &str,
    token: &str,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM password_reset_tokens WHERE user_id = ?1 OR expires_at <= strftime('%s','now')",
        params![user_id],
    )?;
    conn.execute(
        "INSERT INTO password_reset_tokens(token, user_id, expires_at, created_at, consumed) VALUES (?1, ?2, ?3, strftime('%s','now'), 0)",
        params![token, user_id, expires_at],
    )?;
    Ok(())
}

fn mark_token_consumed(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM password_reset_tokens WHERE token = ?1",
        params![token],
    )?;
    Ok(())
}

fn store_email_verification_token(
    conn: &Connection,
    user_id: &str,
    token: &str,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM email_verification_tokens WHERE user_id = ?1 OR expires_at <= strftime('%s','now')",
        params![user_id],
    )?;
    conn.execute(
        "INSERT INTO email_verification_tokens(token, user_id, expires_at, created_at, consumed) VALUES (?1, ?2, ?3, strftime('%s','now'), 0)",
        params![token, user_id, expires_at],
    )?;
    Ok(())
}

fn consume_email_verification_token(
    conn: &Connection,
    token: &str,
) -> rusqlite::Result<Option<(String, i64)>> {
    conn.query_row(
        "SELECT user_id, expires_at FROM email_verification_tokens WHERE token = ?1",
        params![token],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

fn delete_email_verification_token(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM email_verification_tokens WHERE token = ?1",
        params![token],
    )?;
    Ok(())
}

fn build_reset_link(base: &str, token: &str) -> String {
    let separator = if base.contains('?') { "&" } else { "?" };
    format!(
        "{}{}token={}",
        base.trim_end_matches('/'),
        separator,
        urlencoding::encode(token)
    )
}

fn password_update_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "Password update required"})),
    )
        .into_response()
}

fn ensure_password_current(user: &AuthUser) -> Result<(), Response> {
    if user.must_change_password {
        Err(password_update_required_response())
    } else {
        Ok(())
    }
}

fn build_verify_link(base: &str, token: &str) -> String {
    let separator = if base.contains('?') { "&" } else { "?" };
    format!(
        "{}{}token={}",
        base.trim_end_matches('/'),
        separator,
        urlencoding::encode(token)
    )
}

fn get_setting(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM app_settings WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
}

fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO app_settings(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn load_email_sender(conn: &Connection) -> rusqlite::Result<Option<EmailSenderConfig>> {
    if let Some(value) = get_setting(conn, EMAIL_SENDER_SETTING_KEY)? {
        serde_json::from_str(&value)
            .map(Some)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
    } else {
        Ok(None)
    }
}

pub fn save_email_sender(conn: &Connection, sender: &EmailSenderConfig) -> rusqlite::Result<()> {
    let value = serde_json::to_string(sender).map_err(|e| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(e))
    })?;
    set_setting(conn, EMAIL_SENDER_SETTING_KEY, &value)
}

async fn current_email_sender(state: &AppState) -> Option<EmailSenderConfig> {
    state.email_sender.read().await.clone()
}

fn render_transactional_email(
    title: &str,
    body_lines: &[String],
    button_text: &str,
    button_url: &str,
) -> String {
    let paragraphs = body_lines
        .iter()
        .map(|line| {
            format!(
                "<p style=\"margin:0 0 16px;color:#fdfdfd;font-size:15px;line-height:1.6;font-family:'Courier New',Courier,monospace;\">{}</p>",
                html_escape::encode_text(line)
            )
        })
        .collect::<String>();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
</head>
<body style="background:#050505;padding:32px;font-family:'Courier New',Courier,monospace;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
    <tr>
      <td align="center">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:640px;border:2px solid #fdfdfd;padding:28px;background:#000;">
          <tr><td style="text-align:left;">
            <table role="presentation" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
              <tr>
                <td style="width:42px;height:42px;border:2px solid #fdfdfd;text-align:center;vertical-align:middle;font-weight:bold;color:#fdfdfd;line-height:42px;font-size:16px;padding:0;margin:0;">W9</td>
                <td style="padding-left:12px;vertical-align:middle;">
                  <div style="color:#fdfdfd;font-size:18px;letter-spacing:0.1em;text-transform:uppercase;">W9 Tools</div>
                  <div style="color:#9a9a9a;font-size:12px;">Fast drops • Short links • Secure notes</div>
                </td>
              </tr>
            </table>
            <h1 style="margin:0 0 20px;font-size:22px;letter-spacing:0.08em;text-transform:uppercase;color:#fdfdfd;">{title}</h1>
            {paragraphs}
            <div style="margin:32px 0;">
              <a href="{button_url}" style="text-decoration:none;display:inline-block;border:2px solid #fdfdfd;padding:14px 28px;color:#fdfdfd;text-transform:uppercase;font-weight:bold;font-size:12px;letter-spacing:0.2em;">{button_text}</a>
            </div>
            <p style="margin:0 0 8px;color:#9a9a9a;font-size:12px;line-height:1.5;word-break:break-word;">If the button doesn't work, copy and paste this link:<br />{button_url}</p>
            <hr style="border:none;border-top:2px solid #1a1a1a;margin:32px 0;" />
            <p style="margin:0;color:#686868;font-size:11px;line-height:1.4;">Automated message from W9 Tools. Replies are not monitored.</p>
          </td></tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"#,
        title = html_escape::encode_text(title),
        paragraphs = paragraphs,
        button_text = html_escape::encode_text(button_text),
        button_url = html_escape::encode_text(button_url),
    )
}

async fn send_transactional_email(
    state: &AppState,
    to: &str,
    subject: &str,
    html_body: &str,
) -> Result<(), String> {
    let Some(token) = state.w9_mail_api_token.as_ref() else {
        return Err("Email service not configured".into());
    };
    let Some(sender) = current_email_sender(state).await else {
        return Err("Default sender not configured".into());
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/send", state.w9_mail_api_url.trim_end_matches('/')))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "from": sender.email,
            "to": to,
            "subject": subject,
            "body": html_body,
            "isHtml": true
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("Email service responded with {}", resp.status()));
    }

    Ok(())
}

async fn send_password_reset_email(
    state: &AppState,
    to: &str,
    reset_link: &str,
) -> Result<(), String> {
    let subject = "Reset your W9 Tools password";
    let body_lines = vec![
        format!("We received a password reset request for {}.", to),
        "This link expires in 30 minutes. If you didn't request it, you can ignore this message.".to_string(),
    ];
    let html = render_transactional_email(subject, &body_lines, "Reset password", reset_link);
    send_transactional_email(state, to, subject, &html).await
}

async fn send_verification_email(
    state: &AppState,
    to: &str,
    verify_link: &str,
) -> Result<(), String> {
    let subject = "Verify your W9 Tools account";
    let body_lines = vec![
        format!("Thanks for creating a W9 Tools account with {}.", to),
        "Click the button below to verify your email and unlock uploads, short links, and secure notes."
            .to_string(),
        "The link expires in 30 minutes. If this wasn't you, feel free to ignore this email.".to_string(),
    ];
    let html = render_transactional_email(subject, &body_lines, "Verify account", verify_link);
    send_transactional_email(state, to, subject, &html).await
}

fn normalize_custom_code(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Custom code cannot be empty");
    }
    if trimmed.len() < CUSTOM_CODE_MIN_LEN || trimmed.len() > CUSTOM_CODE_MAX_LEN {
        return Err("Custom code must be between 3 and 32 characters");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("Custom code can only use letters, numbers, '-' and '_'");
    }
    if RESERVED_CUSTOM_CODES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(trimmed))
    {
        return Err("This code is reserved");
    }
    Ok(trimmed.to_ascii_lowercase())
}

enum SaveItemError {
    Database(String),
    CodeExists,
}

fn code_exists_for_kind(db_path: &str, code: &str, kind: &str) -> bool {
    if let Ok(conn) = Connection::open(db_path) {
        if let Ok(mut stmt) = conn.prepare("SELECT 1 FROM items WHERE code = ?1 AND kind = ?2 LIMIT 1") {
            return stmt.query_row(params![code, kind], |_| Ok(())).is_ok();
        }
    }
    false
}

fn insert_item_record(db_path: &str, code: &str, kind: &str, value: &str, user_id: Option<&str>) -> Result<(), SaveItemError> {
    // Check if code already exists for this specific kind
    if code_exists_for_kind(db_path, code, kind) {
        return Err(SaveItemError::CodeExists);
    }
    
    let conn = Connection::open(db_path).map_err(|e| SaveItemError::Database(e.to_string()))?;
    match conn.execute(
        "INSERT INTO items(code, kind, value, created_at, user_id) VALUES (?1, ?2, ?3, strftime('%s','now'), ?4)",
        params![code, kind, value, user_id],
    ) {
        Ok(_) => Ok(()),
        Err(SqliteError::SqliteFailure(err, _)) if err.code == ErrorCode::ConstraintViolation => {
            Err(SaveItemError::CodeExists)
        }
        Err(e) => Err(SaveItemError::Database(e.to_string())),
    }
}

fn save_item(
    db_path: &str,
    preferred_code: Option<&String>,
    kind: &str,
    value: &str,
    user_id: Option<&str>,
) -> Result<String, SaveItemError> {
    if let Some(code) = preferred_code {
        insert_item_record(db_path, code, kind, value, user_id)?;
        return Ok(code.clone());
    }

    for _ in 0..5 {
        let generated = nanoid!(8);
        match insert_item_record(db_path, &generated, kind, value, user_id) {
            Ok(_) => return Ok(generated),
            Err(SaveItemError::CodeExists) => continue,
            Err(e) => return Err(e),
        }
    }

    Err(SaveItemError::Database(
        "Failed to allocate unique short code".into(),
    ))
}

fn is_allowed_extension(ext: &str) -> bool {
    ALLOWED_EXTENSIONS.iter().any(|&allowed| allowed.eq_ignore_ascii_case(ext))
}

fn ensure_absolute(base: &str, url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), url.trim_start_matches('/'))
    }
}

pub async fn result_handler(State(state): State<AppState>, Path(code): Path<String>, Query(q): Query<std::collections::HashMap<String,String>>) -> (StatusCode, String) {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"Database error"}"#.to_string()),
    };
    // Get any item with this code (for backward compatibility with /r/ endpoint)
    let mut stmt = match conn.prepare("SELECT kind, value FROM items WHERE code = ?1 LIMIT 1") {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":"Database error"}"#.to_string()),
    };
    let (_kind, _value) = match stmt.query_row(params![code.clone()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
        Ok(v) => v,
        Err(_) => return (StatusCode::NOT_FOUND, r#"{"error":"Not found"}"#.to_string()),
    };
    let short_link = format!("{}/s/{}", state.base_url, code);
    let qr_svg = if q.get("qr").map(|v| v=="1").unwrap_or(false) {
        let qr_target = ensure_absolute(&state.base_url, &short_link);
        generate_qr_code_with_border(&qr_target, state.qr_logo_path.as_deref()).unwrap_or_default()
    } else { String::new() };
    let body = format!(
        r#"{{"code":"{}","short_link":"{}","qr_svg":"{}"}}"#,
        code,
        short_link,
        qr_svg.replace('"', "\\\"")
    );
    (StatusCode::OK, body)
}

pub async fn short_handler(State(state): State<AppState>, Path(code): Path<String>, headers: HeaderMap) -> axum::response::Response {
    let (kind, value) = {
        let conn = match Connection::open(&state.db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to open database: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        };
        // Try to get url or file (not notepad) - /s/ is for short links
        let mut stmt = match conn.prepare("SELECT kind, value FROM items WHERE code = ?1 AND kind IN ('url', 'file') LIMIT 1") {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        };
        match stmt.query_row(params![code.clone()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return (StatusCode::NOT_FOUND, "Not found").into_response();
            }
            Err(e) => {
                tracing::error!("Database query error: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    };

    match kind.as_str() {
        "url" => Redirect::permanent(&value).into_response(),
        "file" => {
            let filename = value.strip_prefix("file:").unwrap_or(&value);
            if let Some(ext) = StdPath::new(filename).extension().and_then(|e| e.to_str()) {
                let mime = mime_from_path(filename).first_or_octet_stream();
                if is_image_ext(ext) || ext.eq_ignore_ascii_case("svg") {
                    let page_url = format!("{}/s/{}", state.base_url, code);
                    let image_url_full = format!("{}/files/{}", state.base_url, filename);
                    // For raster images: if original <= 1MB, use original; else generate a preview
                    let og_image_url = if !ext.eq_ignore_ascii_case("svg") {
                        let original_fs_path = StdPath::new(&state.uploads_dir).join(filename);
                        let original_is_small = std::fs::metadata(&original_fs_path)
                            .map(|m| m.len() as usize <= PREVIEW_MAX_BYTES)
                            .unwrap_or(false);
                        if original_is_small {
                            image_url_full.clone()
                        } else {
                            let preview_dir = StdPath::new(&state.uploads_dir).join("previews");
                            let preview_name = make_preview_filename(filename);
                            let preview_fs_path = preview_dir.join(&preview_name);
                            let preview_web_path = format!("previews/{}", preview_name);
                            if !preview_fs_path.exists() && should_generate_preview(&original_fs_path, PREVIEW_MAX_BYTES) {
                                // Generate preview asynchronously in background
                                let orig_path = original_fs_path.clone();
                                let prev_path = preview_fs_path.clone();
                                let prev_dir = preview_dir.clone();
                                tokio::spawn(async move {
                                    let _ = tokio::fs::create_dir_all(&prev_dir).await;
                                    // Run CPU-intensive preview generation in blocking thread
                                    let _ = tokio::task::spawn_blocking(move || {
                                        try_generate_preview(&orig_path, &prev_path)
                                    }).await;
                                });
                            }
                            // Use preview if exists, otherwise fall back to original
                            if preview_fs_path.exists() {
                                format!("{}/files/{}", state.base_url, preview_web_path)
                            } else {
                                image_url_full.clone()
                            }
                        }
                    } else {
                        // For SVG use the original (usually tiny)
                        image_url_full.clone()
                    };
                    // Content negotiation: return HTML by default (for browsers)
                    // Only return raw image if explicitly requesting non-HTML (e.g., for embeds)
                    let accept = headers
                        .get(axum::http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("*/*")
                        .to_ascii_lowercase();
                    // Check if the primary/preferred content type is an image
                    let wants_raw_image = accept.starts_with("image/") || 
                                         accept.split(',')
                                               .next()
                                               .and_then(|first| first.split(';').next())
                                               .map(|mime| mime.trim().starts_with("image/"))
                                               .unwrap_or(false);
                    if wants_raw_image {
                        // For non-HTML (e.g., direct image fetch), stream the file instead of redirecting to avoid user-agent caching/transform issues
                        let fs_path = StdPath::new(&state.uploads_dir).join(filename);
                        if let Ok(bytes) = std::fs::read(&fs_path) {
                            let mut resp = axum::response::Response::new(bytes.into());
                            resp.headers_mut().insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_str(mime.as_ref()).unwrap_or(axum::http::HeaderValue::from_static("image/jpeg")));
                            return resp;
                        }
                        return Redirect::permanent(&image_url_full).into_response();
                    }
                    let tpl = ImageOgTemplate {
                        og_image_url: og_image_url,
                        full_image_url: image_url_full,
                        page_url,
                        title: "Shared Image".to_string(),
                        description: "Shared via w9.se".to_string(),
                    };
                    let html = Html(tpl.render().unwrap_or_else(|_| "Template error".to_string()));
                    let mut response = html.into_response();
                    // Add cache headers for better performance
                    response.headers_mut().insert(
                        axum::http::header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600")
                    );
                    return response;
                }
                let filename_display = StdPath::new(filename).file_name().and_then(|f| f.to_str()).unwrap_or(filename).to_string();
                let file_url = format!("{}/files/{}", state.base_url, filename);
                let page_url = format!("{}/s/{}", state.base_url, code);
                
                // PDF files: embedded viewer
                if ext.eq_ignore_ascii_case("pdf") {
                    let tpl = PdfTemplate { filename: filename_display, file_url, page_url };
                    let html = Html(tpl.render().unwrap_or_else(|_| "Template error".to_string()));
                    let mut response = html.into_response();
                    response.headers_mut().insert(
                        axum::http::header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600")
                    );
                    return response;
                }
                
                // Video files: HTML5 player
                if ext.eq_ignore_ascii_case("mp4") || ext.eq_ignore_ascii_case("webm") || 
                   ext.eq_ignore_ascii_case("mov") || ext.eq_ignore_ascii_case("avi") || 
                   ext.eq_ignore_ascii_case("mkv") {
                    let tpl = VideoTemplate { 
                        filename: filename_display, 
                        file_url, 
                        mime: mime.to_string(), 
                        page_url 
                    };
                    let html = Html(tpl.render().unwrap_or_else(|_| "Template error".to_string()));
                    let mut response = html.into_response();
                    response.headers_mut().insert(
                        axum::http::header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=3600")
                    );
                    return response;
                }
                
                // Other files: generic download page
                let tpl = FileInfoTemplate { filename: filename_display, file_url, mime: mime.to_string(), page_url };
                let html = Html(tpl.render().unwrap_or_else(|_| "Template error".to_string()));
                let mut response = html.into_response();
                response.headers_mut().insert(
                    axum::http::header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=3600")
                );
                return response;
            }
            (StatusCode::NOT_FOUND, "File not found").into_response()
        }
        _ => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

pub(crate) fn hash_with_salt(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub(crate) fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

// Generate QR code with styling to match frontend design (monochrome black/white)
// Optionally includes a logo in the center if logo_path is provided
fn generate_qr_code_with_border(url: &str, logo_path: Option<&str>) -> Option<String> {
    match QrCode::new(url.as_bytes()) {
        Ok(c) => {
            let qr_svg = c
                .render::<Color>()
                .min_dimensions(320, 320)
                .quiet_zone(true)
                .dark_color(Color("#000000"))
                .light_color(Color("#ffffff"))
                .build();
            
            // If logo path is provided, embed the logo in the center
            if let Some(logo) = logo_path {
                if let Ok(logo_data) = embed_logo_in_qr(&qr_svg, logo) {
                    return Some(logo_data);
                }
            }
            
            Some(qr_svg)
        }
        Err(_) => None,
    }
}

// Embed logo in the center of QR code SVG
fn embed_logo_in_qr(qr_svg: &str, logo_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    use base64::{Engine as _, engine::general_purpose};
    
    // Read logo file
    let logo_bytes = std::fs::read(logo_path)?;
    
    // Determine MIME type from file extension
    let mime_type = if logo_path.to_lowercase().ends_with(".png") {
        "image/png"
    } else if logo_path.to_lowercase().ends_with(".jpg") || logo_path.to_lowercase().ends_with(".jpeg") {
        "image/jpeg"
    } else if logo_path.to_lowercase().ends_with(".svg") {
        "image/svg+xml"
    } else {
        "image/png" // default
    };
    
    // Convert to base64
    let logo_base64 = general_purpose::STANDARD.encode(&logo_bytes);
    let logo_data_uri = format!("data:{};base64,{}", mime_type, logo_base64);
    
    // Parse SVG to find viewBox dimensions
    // QR code SVG typically has viewBox="0 0 320 320" or similar
    let qr_size = if let Some(viewbox_start) = qr_svg.find(r#"viewBox=""#) {
        let viewbox_content_start = viewbox_start + 9; // length of 'viewBox="'
        if let Some(viewbox_end) = qr_svg[viewbox_content_start..].find('"') {
            let viewbox_str = &qr_svg[viewbox_content_start..viewbox_content_start + viewbox_end];
            let coords: Vec<f64> = viewbox_str.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if coords.len() >= 4 {
                coords[2] // width is the third coordinate
            } else {
                320.0 // default
            }
        } else {
            320.0
        }
    } else {
        320.0 // default if no viewBox found
    };
    
    // Logo should be small enough to avoid covering finder patterns (~18% of size)
    let logo_size = qr_size * 0.18;
    let logo_x = (qr_size - logo_size) / 2.0;
    let logo_y = (qr_size - logo_size) / 2.0;
    let logo_bg_padding = logo_size * 0.15;
    let bg_x = logo_x - logo_bg_padding;
    let bg_y = logo_y - logo_bg_padding;
    let bg_size = logo_size + (logo_bg_padding * 2.0);
    
    // Find the closing </svg> tag and insert logo before it
    if let Some(pos) = qr_svg.rfind("</svg>") {
        let mut result = qr_svg[..pos].to_string();
        result.push_str(&format!(
            r#"<rect x="{bg_x}" y="{bg_y}" width="{bg_size}" height="{bg_size}" rx="{radius}" fill="#ffffff"/><image href="{logo_data_uri}" x="{logo_x}" y="{logo_y}" width="{logo_size}" height="{logo_size}" preserveAspectRatio="xMidYMid meet"/>"#,
            bg_x = bg_x,
            bg_y = bg_y,
            bg_size = bg_size,
            radius = logo_size * 0.08,
            logo_data_uri = logo_data_uri,
            logo_x = logo_x,
            logo_y = logo_y,
            logo_size = logo_size
        ));
        result.push_str("</svg>");
        Ok(result)
    } else {
        Err("Invalid SVG format".into())
    }
}

// Generate QR code as data URL for API responses
fn generate_qr_code_data_url(url: &str, logo_path: Option<&str>) -> Option<String> {
    generate_qr_code_with_border(url, logo_path).map(|svg| {
        format!("data:image/svg+xml;utf8,{}", urlencoding::encode(&svg))
    })
}


// JWT Claims from w9-mail
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    email: String,
    role: String,
    exp: usize,
}

// Authenticated user
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub role: String,
    pub must_change_password: bool,
}

// Extract AuthUser from JWT token
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    State<AppState>: FromRequestParts<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok().map(|s| s.to_string()))
            .ok_or((StatusCode::UNAUTHORIZED, "Missing authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid authorization header"))?;

        let State(app_state) =
            State::<AppState>::from_request_parts(parts, state).await.map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to extract application state",
                )
            })?;

        let decoding_key = DecodingKey::from_secret(app_state.jwt_secret.as_bytes());
        let token_data = decode::<Claims>(token, &decoding_key, &Validation::default())
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        let conn = Connection::open(&app_state.db_path)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;
        let user = fetch_user_by_id(&conn, &token_data.claims.sub)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?
            .ok_or((StatusCode::UNAUTHORIZED, "User not found"))?;

        Ok(AuthUser {
            id: user.id,
            email: user.email,
            role: user.role,
            must_change_password: user.must_change_password,
        })
    }
}

// Optional AuthUser (for endpoints that work with or without auth)
pub struct OptionalAuthUser(pub Option<AuthUser>);

#[async_trait]
impl<S> FromRequestParts<S> for OptionalAuthUser
where
    State<AppState>: FromRequestParts<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(user) => Ok(OptionalAuthUser(Some(user))),
            Err(_) => Ok(OptionalAuthUser(None)),
        }
    }
}

// Admin user - requires admin role
pub struct AdminUser(pub AuthUser);

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    State<AppState>: FromRequestParts<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if user.must_change_password {
            return Err((StatusCode::FORBIDDEN, "Password update required"));
        }
        if user.role.to_lowercase() != "admin" {
            return Err((StatusCode::FORBIDDEN, "Admin access required"));
        }
        Ok(AdminUser(user))
    }
}


#[debug_handler]
pub async fn admin_items(State(state): State<AppState>, AdminUser(_): AdminUser) -> impl IntoResponse {
    
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"Database error"}))).into_response();
        }
    };
    
    let mut stmt = match conn.prepare("SELECT code, kind, value, created_at FROM items ORDER BY created_at DESC LIMIT 500") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare statement: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"Query error"}))).into_response();
        }
    };
    
    let rows = match stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to query items: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"Query error"}))).into_response();
        }
    };
    
    let mut items: Vec<serde_json::Value> = Vec::new();
    for row in rows {
        if let Ok((code, kind, value, created_at)) = row {
            items.push(serde_json::json!({
                "code": code,
                "kind": kind,
                "value": value,
                "created_at": created_at
            }));
        }
    }
    
    (StatusCode::OK, Json(items)).into_response()
}

#[debug_handler]
pub async fn admin_delete_item_with_kind(
    State(state): State<AppState>,
    Path((code, kind)): Path<(String, String)>,
    AdminUser(_): AdminUser,
) -> impl IntoResponse {
    
    let code_to_delete = code;
    let kind_to_delete = Some(kind);

    // Query needed info inside a short-lived DB connection
    let items_to_delete: Vec<(String, String)> = {
        let conn = Connection::open(&state.db_path).unwrap();
        if let Some(kind) = &kind_to_delete {
            conn.prepare("SELECT kind, value FROM items WHERE code = ?1 AND kind = ?2")
                .and_then(|mut stmt| {
                    stmt.query_map(params![code_to_delete, kind], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })
                    .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
                })
                .unwrap_or_default()
        } else {
            // If no kind specified, get all items with this code (for backward compatibility)
            conn.prepare("SELECT kind, value FROM items WHERE code = ?1")
                .and_then(|mut stmt| {
                    stmt.query_map(params![code_to_delete], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                    })
                    .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
                })
                .unwrap_or_default()
        }
    };

    // Delete associated files for file items
    for (kind, value) in &items_to_delete {
        if kind == "file" {
            if let Some(fname) = value.strip_prefix("file:") {
                let path_to_delete = std::path::PathBuf::from(&state.uploads_dir).join(fname);
                let _ = tokio::fs::remove_file(&path_to_delete).await;
                let preview_name = make_preview_filename(fname);
                let preview_path = std::path::PathBuf::from(&state.uploads_dir).join("previews").join(preview_name);
                let _ = tokio::fs::remove_file(preview_path).await;
            }
        }
    }

    // Now delete the DB row(s) in a fresh connection
    {
        let conn = Connection::open(&state.db_path).unwrap();
        if let Some(kind) = &kind_to_delete {
            let _ = conn.execute("DELETE FROM items WHERE code = ?1 AND kind = ?2", params![code_to_delete, kind]);
        } else {
            // Delete all items with this code (backward compatibility)
            let _ = conn.execute("DELETE FROM items WHERE code = ?1", params![code_to_delete]);
        }
    }
    (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response()
}

#[debug_handler]
pub async fn admin_delete_item(
    State(state): State<AppState>,
    Path(code): Path<String>,
    AdminUser(_): AdminUser,
) -> impl IntoResponse {
    
    // For backward compatibility, delete all items with this code
    let code_to_delete = code;

    // Query needed info inside a short-lived DB connection
    let items_to_delete: Vec<(String, String)> = {
        let conn = Connection::open(&state.db_path).unwrap();
        conn.prepare("SELECT kind, value FROM items WHERE code = ?1")
            .and_then(|mut stmt| {
                stmt.query_map(params![code_to_delete], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
            })
            .unwrap_or_default()
    };

    // Delete associated files for file items
    for (kind, value) in &items_to_delete {
        if kind == "file" {
            if let Some(fname) = value.strip_prefix("file:") {
                let path_to_delete = std::path::PathBuf::from(&state.uploads_dir).join(fname);
                let _ = tokio::fs::remove_file(&path_to_delete).await;
                let preview_name = make_preview_filename(fname);
                let preview_path = std::path::PathBuf::from(&state.uploads_dir).join("previews").join(preview_name);
                let _ = tokio::fs::remove_file(preview_path).await;
            }
        }
    }

    // Now delete the DB row(s) in a fresh connection
    {
        let conn = Connection::open(&state.db_path).unwrap();
        let _ = conn.execute("DELETE FROM items WHERE code = ?1", params![code_to_delete]);
    }
    (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response()
}


#[debug_handler]
pub async fn api_upload(State(state): State<AppState>, headers: HeaderMap, mut multipart: Multipart) -> axum::response::Response {
    // Extract user_id from Authorization header if present
    let user_id = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .and_then(|token| {
            let jwt_secret = state.jwt_secret.clone();
            let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
            decode::<Claims>(token, &decoding_key, &Validation::default())
                .ok()
                .map(|data| data.claims.sub)
        });
    let mut link_value: Option<String> = None;
    let mut saved_filename: Option<String> = None;
    let mut qr_required: bool = false;
    let mut custom_code_raw: Option<String> = None;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "content" => {
                if let Some(fname) = field.file_name().map(|s| s.to_string()) {
                    let ext = StdPath::new(&fname).extension().and_then(|e| e.to_str()).unwrap_or("bin");
                    if !is_allowed_extension(ext) { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "File type not allowed"}))).into_response(); }
                    if let Err(e) = fs::create_dir_all(&state.uploads_dir).await { tracing::error!("create uploads dir: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": "Server error"}))).into_response(); }
                    let id = Uuid::new_v4();
                    let filename_saved = format!("{}.{}", id, ext);
                    let path = format!("{}/{}", state.uploads_dir, filename_saved);
                    let mut out = match tokio::fs::File::create(&path).await { Ok(f) => f, Err(e) => { tracing::error!("create file: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": "Server error"}))).into_response(); } };
                    let mut written: usize = 0;
                    while let Ok(Some(chunk)) = field.chunk().await {
                        written = written.saturating_add(chunk.len());
                        if written > MAX_FILE_SIZE { let _ = tokio::fs::remove_file(&path).await; return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"success": false, "error": "File too large"}))).into_response(); }
                        if let Err(e) = out.write_all(&chunk).await { tracing::error!("write: {}", e); let _ = tokio::fs::remove_file(&path).await; return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": "Server error"}))).into_response(); }
                    }
                    saved_filename = Some(filename_saved);
                } else if let Ok(text) = field.text().await {
                    if !text.trim().is_empty() { link_value = Some(text.trim().to_string()); }
                }
            }
            "qr_required" => {
                if let Ok(v) = field.text().await { qr_required = v.trim().eq_ignore_ascii_case("true"); }
            }
            "custom_code" => {
                if let Ok(v) = field.text().await {
                    custom_code_raw = Some(v);
                }
            }
            _ => {}
        }
    }

    let custom_code = match custom_code_raw {
        Some(raw) if !raw.trim().is_empty() => match normalize_custom_code(&raw) {
            Ok(code) => Some(code),
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"success": false, "error": msg})),
                )
                    .into_response()
            }
        },
        _ => None,
    };

    if let Some(filename_saved) = saved_filename {
        let original = format!("file:{}", filename_saved);
        let short_code = match save_item(&state.db_path, custom_code.as_ref(), "file", &original, user_id.as_deref()) {
            Ok(code) => code,
            Err(SaveItemError::CodeExists) => {
                let msg = if custom_code.is_some() {
                    "Custom code already exists"
                } else {
                    "Please retry generating short code"
                };
                return (
                    if custom_code.is_some() {
                        StatusCode::CONFLICT
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    },
                    Json(serde_json::json!({"success": false, "error": msg})),
                )
                    .into_response();
            }
            Err(SaveItemError::Database(err)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"success": false, "error": err})),
                )
                    .into_response()
            }
        };
        let short_url = format!("{}/s/{}", state.base_url, short_code);
        let qr_code_data = if qr_required {
            let qr_target = ensure_absolute(&state.base_url, &short_url);
            generate_qr_code_data_url(&qr_target, state.qr_logo_path.as_deref())
        } else { None };
        return Json(serde_json::json!({"success": true, "short_url": short_url, "qr_code_data": qr_code_data})).into_response();
    }

    if let Some(link) = link_value {
        if !link.starts_with("http://") && !link.starts_with("https://") { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "Invalid URL"}))).into_response(); }
        let short_code = match save_item(&state.db_path, custom_code.as_ref(), "url", &link, user_id.as_deref()) {
            Ok(code) => code,
            Err(SaveItemError::CodeExists) => {
                let msg = if custom_code.is_some() {
                    "Custom code already exists"
                } else {
                    "Please retry generating short code"
                };
                return (
                    if custom_code.is_some() {
                        StatusCode::CONFLICT
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    },
                    Json(serde_json::json!({"success": false, "error": msg})),
                )
                    .into_response();
            }
            Err(SaveItemError::Database(err)) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"success": false, "error": err})),
                )
                    .into_response()
            }
        };
        let short_url = format!("{}/s/{}", state.base_url, short_code);
        let qr_code_data = if qr_required {
            let qr_target = ensure_absolute(&state.base_url, &short_url);
            generate_qr_code_data_url(&qr_target, state.qr_logo_path.as_deref())
        } else { None };
        return Json(serde_json::json!({"success": true, "short_url": short_url, "qr_code_data": qr_code_data})).into_response();
    }

    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "Provide content or file"}))).into_response()
}

fn render_markdown(md: &str) -> String {
    use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};

    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(md, options);
    let mut events: Vec<Event> = Vec::new();
    let mut code_block_depth = 0usize;

    for event in parser {
        match &event {
            Event::Start(Tag::CodeBlock(_)) => {
                code_block_depth += 1;
                events.push(event);
            }
            Event::End(Tag::CodeBlock(_)) => {
                if code_block_depth > 0 {
                    code_block_depth -= 1;
                }
                events.push(event);
            }
            Event::Text(text) if code_block_depth == 0 => {
                let transformed = transform_math_segments(text);
                if transformed.is_empty() {
                    events.push(Event::Text(CowStr::Boxed(text.to_string().into_boxed_str())));
                } else {
                    events.extend(transformed);
                }
            }
            _ => events.push(event),
        }
    }

    let mut html_output = String::new();
    html::push_html(&mut html_output, events.into_iter());
    html_output
}

fn transform_math_segments(text: &str) -> Vec<pulldown_cmark::Event<'static>> {
    use pulldown_cmark::{CowStr, Event};

    let segments = split_math_segments(text);
    let contains_math = segments
        .iter()
        .any(|segment| matches!(segment, MathSegment::Inline(_) | MathSegment::Block(_)));

    if !contains_math {
        return Vec::new();
    }

    let mut events = Vec::with_capacity(segments.len());
    for segment in segments {
        match segment {
            MathSegment::Plain(s) => {
                if !s.is_empty() {
                    events.push(Event::Text(CowStr::Boxed(s.into_boxed_str())));
                }
            }
            MathSegment::Inline(tex) => {
                let encoded = html_escape::encode_double_quoted_attribute(&tex);
                let html = format!(
                    r#"<span class="math-fragment math-inline" data-math="inline" data-tex="{}"></span>"#,
                    encoded
                );
                events.push(Event::Html(CowStr::Boxed(html.into_boxed_str())));
            }
            MathSegment::Block(tex) => {
                let encoded = html_escape::encode_double_quoted_attribute(&tex);
                let html = format!(
                    r#"<div class="math-fragment math-block" data-math="block" data-tex="{}"></div>"#,
                    encoded
                );
                events.push(Event::Html(CowStr::Boxed(html.into_boxed_str())));
            }
        }
    }

    events
}

#[derive(Debug)]
enum MathSegment {
    Plain(String),
    Inline(String),
    Block(String),
}

fn split_math_segments(text: &str) -> Vec<MathSegment> {
    let mut segments = Vec::new();
    let mut buffer = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut idx = 0usize;

    while idx < chars.len() {
        let ch = chars[idx];

        if ch == '\\' {
            if idx + 1 < chars.len() && (chars[idx + 1] == '$' || chars[idx + 1] == '\\') {
                buffer.push(chars[idx + 1]);
                idx += 2;
                continue;
            }
            buffer.push(ch);
            idx += 1;
            continue;
        }

        if ch == '$' {
            let delimiter = if idx + 1 < chars.len() && chars[idx + 1] == '$' {
                2
            } else {
                1
            };

            if let Some((next_idx, content)) = find_math_content(&chars, idx, delimiter) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    if !buffer.is_empty() {
                        segments.push(MathSegment::Plain(std::mem::take(&mut buffer)));
                    }

                    if delimiter == 2 {
                        segments.push(MathSegment::Block(trimmed.to_string()));
                    } else {
                        segments.push(MathSegment::Inline(trimmed.to_string()));
                    }

                    idx = next_idx;
                    continue;
                } else {
                    let raw: String = chars[idx..next_idx].iter().collect();
                    buffer.push_str(&raw);
                    idx = next_idx;
                    continue;
                }
            }
        }

        buffer.push(ch);
        idx += 1;
    }

    if !buffer.is_empty() {
        segments.push(MathSegment::Plain(buffer));
    }

    segments
}

fn find_math_content(chars: &[char], start: usize, delimiter: usize) -> Option<(usize, String)> {
    let open_end = start + delimiter;
    if open_end >= chars.len() {
        return None;
    }

    let mut idx = open_end;
    while idx < chars.len() {
        if chars[idx] == '\\' {
            idx += 2;
            continue;
        }

        if delimiter == 2 {
            if idx + 1 < chars.len() && chars[idx] == '$' && chars[idx + 1] == '$' {
                let content: String = chars[open_end..idx].iter().collect();
                return Some((idx + 2, content));
            }
        } else if chars[idx] == '$' {
            let content: String = chars[open_end..idx].iter().collect();
            if content.contains('\n') {
                return None;
            }
            return Some((idx + 1, content));
        }

        idx += 1;
    }

    None
}

#[debug_handler]
pub async fn api_notepad(State(state): State<AppState>, headers: HeaderMap, mut multipart: Multipart) -> axum::response::Response {
    // Extract user_id from Authorization header if present
    let user_id = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .and_then(|token| {
            let jwt_secret = state.jwt_secret.clone();
            let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
            decode::<Claims>(token, &decoding_key, &Validation::default())
                .ok()
                .map(|data| data.claims.sub)
        });
    
    let mut content: Option<String> = None;
    let mut custom_code_raw: Option<String> = None;
    let mut qr_required: bool = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "content" => {
                if let Ok(text) = field.text().await {
                    if !text.trim().is_empty() {
                        content = Some(text.trim().to_string());
                    }
                }
            }
            "custom_code" => {
                if let Ok(v) = field.text().await {
                    custom_code_raw = Some(v);
                }
            }
            "qr_required" => {
                if let Ok(v) = field.text().await { qr_required = v.trim().eq_ignore_ascii_case("true"); }
            }
            _ => {}
        }
    }

    let content = match content {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "Content is required"})),
            )
            .into_response()
        }
    };

    let custom_code = match custom_code_raw {
        Some(raw) if !raw.trim().is_empty() => match normalize_custom_code(&raw) {
            Ok(code) => Some(code),
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"success": false, "error": msg})),
                )
                .into_response()
            }
        },
        _ => None,
    };

    let code = match save_item(&state.db_path, custom_code.as_ref(), "notepad", &content, user_id.as_deref()) {
        Ok(c) => c,
        Err(SaveItemError::CodeExists) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"success": false, "error": "Custom code already exists"})),
            )
            .into_response()
        }
        Err(SaveItemError::Database(msg)) => {
            tracing::error!("Database error saving notepad: {}", msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"success": false, "error": "Database error"})),
            )
            .into_response()
        }
    };

    let short_url = format!("{}/n/{}", state.base_url, code);
    let qr_code_data = if qr_required {
        let qr_target = ensure_absolute(&state.base_url, &short_url);
        generate_qr_code_data_url(&qr_target, state.qr_logo_path.as_deref())
    } else { None };
    Json(serde_json::json!({"success": true, "short_url": short_url, "qr_code_data": qr_code_data})).into_response()
}

pub async fn notepad_handler(State(state): State<AppState>, Path(code): Path<String>) -> axum::response::Response {
    let value = {
        let conn = match Connection::open(&state.db_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to open database: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        };
        let mut stmt = match conn.prepare("SELECT value FROM items WHERE code = ?1 AND kind = ?2") {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to prepare statement: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        };
        match stmt.query_row(params![code.clone(), "notepad"], |r| r.get::<_, String>(0)) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return (StatusCode::NOT_FOUND, "Not found").into_response();
            }
            Err(e) => {
                tracing::error!("Database query error: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    };

    let page_url = format!("{}/n/{}", state.base_url, code);
    
    // Render markdown with error handling
    let html_content = render_markdown(&value);
    
    let tpl = NotepadTemplate {
        content: html_content,
        page_url,
    };
    
    let rendered_html = match tpl.render() {
        Ok(html) => html,
        Err(e) => {
            tracing::error!("Template rendering error for code {}: {}", code, e);
            format!("<html><head><title>Error</title></head><body><h1>Template Error</h1><p>Failed to render notepad content.</p></body></html>")
        }
    };
    
    let html = Html(rendered_html);
    let mut response = html.into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

// Login endpoint - forwards to w9-mail
#[derive(Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

pub async fn login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Security check failed"})),
                    )
                }
                Err(e) => {
                    tracing::warn!("Turnstile verification error: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Security check error"})),
                    )
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Security check required"})),
            )
        }
    }

    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
        }
    };

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let user = match fetch_user_by_email(&conn, &email) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid email or password"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to query user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let hashed = hash_with_salt(&payload.password, &user.salt);
    if hashed != user.password_hash {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid email or password"})),
        );
    }

    if !user.is_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Please verify your email before logging in"})),
        );
    }

    let token = match issue_jwt(&state, &user) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to issue JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to create session"})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": token,
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "must_change_password": user.must_change_password,
                "is_verified": user.is_verified
            }
        })),
    )
}

// Register endpoint - forwards to w9-mail
#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

pub async fn register(State(state): State<AppState>, Json(payload): Json<RegisterRequest>) -> impl IntoResponse {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Security check failed"})),
                    )
                }
                Err(e) => {
                    tracing::warn!("Turnstile verification error: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Security check error"})),
                    )
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Security check required"})),
            )
        }
    }

    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
        }
    };

    if let Err(msg) = validate_password(&payload.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    if let Ok(Some(_)) = fetch_user_by_email(&conn, &email) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Email already registered"})),
        );
    }

    let user_id = Uuid::new_v4().to_string();
    let salt = generate_token(32);
    let password_hash = hash_with_salt(&payload.password, &salt);
    let created_at = Utc::now().timestamp();
    match conn.execute(
        "INSERT INTO users(id, email, password_hash, salt, role, must_change_password, created_at, is_verified) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0)",
        params![user_id, email.clone(), password_hash, salt, "user", created_at],
    ) {
        Ok(_) => {}
        Err(SqliteError::SqliteFailure(err, _)) if err.code == ErrorCode::ConstraintViolation => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Email already registered"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to insert user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to create user"})),
            );
        }
    }

    let verify_token = generate_token(64);
    let verify_expires = Utc::now()
        .checked_add_signed(Duration::minutes(EMAIL_VERIFICATION_TOKEN_TTL_MINUTES))
        .unwrap_or_else(|| Utc::now())
        .timestamp();

    if let Err(e) = store_email_verification_token(&conn, &user_id, &verify_token, verify_expires) {
        tracing::error!("Failed to store verification token: {}", e);
    } else {
        let verify_link = build_verify_link(&state.verification_base_url, &verify_token);
        if let Err(e) = send_verification_email(&state, &email, &verify_link).await {
            tracing::error!("Failed to send verification email: {}", e);
        }
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Account created. Check your email for a verification link before logging in."
        })),
    )
}

// Get user's items (profile)
pub async fn user_items(State(state): State<AppState>, user: AuthUser) -> impl IntoResponse {
    if let Err(resp) = ensure_password_current(&user) {
        return resp;
    }
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response();
        }
    };
    
    let mut stmt = match conn.prepare("SELECT code, kind, value, created_at FROM items WHERE user_id = ?1 ORDER BY created_at DESC") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare statement: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Query error"}))).into_response();
        }
    };
    
    let rows = match stmt.query_map(params![user.id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to query items: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Query error"}))).into_response();
        }
    };
    
    let mut items: Vec<serde_json::Value> = Vec::new();
    for row in rows {
        if let Ok((code, kind, value, created_at)) = row {
            let short_url = match kind.as_str() {
                "url" | "file" => format!("{}/s/{}", state.base_url, code),
                "notepad" => format!("{}/n/{}", state.base_url, code),
                _ => format!("{}/r/{}", state.base_url, code),
            };
            items.push(serde_json::json!({
                "code": code,
                "kind": kind,
                "value": value,
                "created_at": created_at,
                "short_url": short_url
            }));
        }
    }
    
    (StatusCode::OK, Json(items)).into_response()
}

// Delete user's item
pub async fn user_delete_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path((code, kind)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = ensure_password_current(&user) {
        return resp;
    }
    // Verify ownership
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response();
        }
    };
    
    // Check ownership
    let owner_id: Result<String, _> = conn.query_row(
        "SELECT user_id FROM items WHERE code = ?1 AND kind = ?2",
        params![code, kind],
        |r| r.get(0),
    );
    
    match owner_id {
        Ok(uid) if uid == user.id => {
            // User owns this item, proceed with deletion
        }
        Ok(_) => {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Not authorized"}))).into_response();
        }
        Err(_) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Item not found"}))).into_response();
        }
    }
    
    // Get item info for file deletion
    let item_info: Result<(String,), _> = conn.query_row(
        "SELECT value FROM items WHERE code = ?1 AND kind = ?2",
        params![code, kind],
        |r| Ok((r.get::<_, String>(0)?,)),
    );
    
    // Delete associated files
    if let Ok((value,)) = item_info {
        if kind == "file" {
            if let Some(fname) = value.strip_prefix("file:") {
                let path_to_delete = std::path::PathBuf::from(&state.uploads_dir).join(fname);
                let _ = tokio::fs::remove_file(&path_to_delete).await;
                let preview_name = make_preview_filename(fname);
                let preview_path = std::path::PathBuf::from(&state.uploads_dir).join("previews").join(preview_name);
                let _ = tokio::fs::remove_file(preview_path).await;
            }
        }
    }
    
    // Delete from database
    match conn.execute("DELETE FROM items WHERE code = ?1 AND kind = ?2", params![code, kind]) {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response(),
        Err(e) => {
            tracing::error!("Failed to delete item: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to delete"}))).into_response()
        }
    }
}

// Update user's item (change custom code)
#[derive(Deserialize)]
pub struct UpdateItemRequest {
    pub new_code: Option<String>,
}

// Admin user management - forward to w9-mail
#[derive(Serialize, Deserialize)]
pub struct AdminCreateUserRequest {
    pub email: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AdminUpdateUserRequest {
    pub role: Option<String>,
    pub must_change_password: Option<bool>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct AdminSendPasswordResetRequest {
    pub email: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize)]
struct MailAccountInfo {
    id: String,
    email: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "isActive")]
    is_active: bool,
}

#[derive(Deserialize)]
struct MailAliasInfo {
    id: String,
    #[serde(rename = "aliasEmail")]
    alias_email: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "isActive")]
    is_active: bool,
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "accountEmail")]
    account_email: String,
    #[serde(rename = "accountDisplayName")]
    account_display_name: String,
    #[serde(rename = "accountIsActive")]
    account_is_active: bool,
}

#[derive(Serialize)]
pub struct EmailSenderSummary {
    pub sender_type: String,
    pub sender_id: String,
    pub email: String,
    pub display_label: String,
    pub via_display: Option<String>,
    pub is_active: bool,
}

#[derive(Deserialize)]
pub struct UpdateEmailSenderRequest {
    pub sender_type: Option<String>,
    pub sender_id: Option<String>,
    pub email: String,
    pub display_label: Option<String>,
    pub via_display: Option<String>,
}

#[derive(Serialize)]
struct AdminUserSummary {
    id: String,
    email: String,
    role: String,
    must_change_password: bool,
    created_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
    pub confirm_password: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

pub async fn user_update_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path((code, kind)): Path<(String, String)>,
    Json(payload): Json<UpdateItemRequest>,
) -> impl IntoResponse {
    if let Err(resp) = ensure_password_current(&user) {
        return resp;
    }
    // Verify ownership
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response();
        }
    };
    
    // Check ownership
    let owner_id: Result<String, _> = conn.query_row(
        "SELECT user_id FROM items WHERE code = ?1 AND kind = ?2",
        params![code, kind],
        |r| r.get(0),
    );
    
    match owner_id {
        Ok(uid) if uid == user.id => {
            // User owns this item, proceed
        }
        Ok(_) => {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Not authorized"}))).into_response();
        }
        Err(_) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Item not found"}))).into_response();
        }
    }
    
    // If new_code is provided, update it
    if let Some(new_code) = payload.new_code {
        let normalized = match normalize_custom_code(&new_code) {
            Ok(c) => c,
            Err(msg) => {
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg}))).into_response();
            }
        };
        
        // Check if new code already exists
        if code_exists_for_kind(&state.db_path, &normalized, &kind) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Code already exists"}))).into_response();
        }
        
        // Update the code
        match conn.execute(
            "UPDATE items SET code = ?1 WHERE code = ?2 AND kind = ?3",
            params![normalized, code, kind],
        ) {
            Ok(_) => {
                let short_url = match kind.as_str() {
                    "url" | "file" => format!("{}/s/{}", state.base_url, normalized),
                    "notepad" => format!("{}/n/{}", state.base_url, normalized),
                    _ => format!("{}/r/{}", state.base_url, normalized),
                };
                (StatusCode::OK, Json(serde_json::json!({"success": true, "code": normalized, "short_url": short_url}))).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to update item: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to update"}))).into_response()
            }
        }
    } else {
        (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "new_code is required"}))).into_response()
    }
}

// Request password reset - forwards to w9-mail (public endpoint)
pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<AdminSendPasswordResetRequest>,
) -> impl IntoResponse {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Security check failed"})),
                    )
                }
                Err(e) => {
                    tracing::warn!("Turnstile verification error: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Security check error"})),
                    )
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Security check required"})),
            )
        }
    }

    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            )
        }
    };

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    if let Ok(Some(user)) = fetch_user_by_email(&conn, &email) {
        let token = generate_token(48);
        let expires_at = Utc::now()
            .checked_add_signed(Duration::minutes(PASSWORD_RESET_TOKEN_TTL_MINUTES))
            .map(|ts| ts.timestamp())
            .unwrap_or_else(|| Utc::now().timestamp());

        if let Err(e) = store_password_reset_token(&conn, &user.id, &token, expires_at) {
            tracing::error!("Failed to store password reset token: {}", e);
        } else {
            let reset_link = build_reset_link(&state.password_reset_base_url, &token);
            if let Err(e) = send_password_reset_email(&state, &user.email, &reset_link).await {
                tracing::error!("Failed to send password reset email: {}", e);
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "If the account exists, a reset link has been sent."})),
    )
}

pub async fn confirm_password_reset(
    State(state): State<AppState>,
    Json(payload): Json<PasswordResetConfirmRequest>,
) -> impl IntoResponse {
    // Verify Turnstile token if secret is configured
    if let Some(secret) = &state.turnstile_secret {
        if let Some(token) = &payload.turnstile_token {
            match verify_turnstile(secret, token).await {
                Ok(true) => {},
                Ok(false) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": "Security check failed"})),
                    )
                }
                Err(e) => {
                    tracing::warn!("Turnstile verification error: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "Security check error"})),
                    )
                }
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Security check required"})),
            )
        }
    }

    if payload.new_password != payload.confirm_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Passwords do not match"})),
        );
    }
    if let Err(msg) = validate_password(&payload.new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let token_row = conn
        .query_row(
            "SELECT user_id, expires_at FROM password_reset_tokens WHERE token = ?1",
            params![payload.token],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                ))
            },
        )
        .optional();

    let (user_id, expires_at) = match token_row {
        Ok(Some(data)) => data,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid or expired token"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to query reset token: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    if expires_at < Utc::now().timestamp() {
        let _ = mark_token_consumed(&conn, &payload.token);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Token expired"})),
        );
    }

    let Some(mut user) = fetch_user_by_id(&conn, &user_id).unwrap_or(None) else {
        let _ = mark_token_consumed(&conn, &payload.token);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "User no longer exists"})),
        );
    };

    let new_salt = generate_token(32);
    let new_hash = hash_with_salt(&payload.new_password, &new_salt);

    match conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2, must_change_password = 0 WHERE id = ?3",
        params![new_hash, new_salt, user.id],
    ) {
        Ok(_) => {
            let _ = mark_token_consumed(&conn, &payload.token);
            user.salt = new_salt;
            user.password_hash = new_hash;
            (
                StatusCode::OK,
                Json(serde_json::json!({"message": "Password reset successful"})),
            )
        }
        Err(e) => {
            tracing::error!("Failed to update password: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to update password"})),
            )
        }
    }
}

// Change password - forwards to w9-mail
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if payload.new_password != payload.confirm_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "New passwords do not match"})),
        )
        .into_response();
    }
    if let Err(msg) = validate_password(&payload.new_password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
        .into_response();
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            )
                .into_response();
        }
    };

    let Some(user_record) = fetch_user_by_id(&conn, &user.id).unwrap_or(None) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "User not found"})),
        )
            .into_response();
    };

    let current_hash = hash_with_salt(&payload.old_password, &user_record.salt);
    if current_hash != user_record.password_hash {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Current password is incorrect"})),
        )
            .into_response();
    }

    let new_salt = generate_token(32);
    let new_hash = hash_with_salt(&payload.new_password, &new_salt);

    match conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2, must_change_password = 0 WHERE id = ?3",
        params![new_hash, new_salt, user.id],
    ) {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "Password changed successfully"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update password: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to update password"})),
            )
                .into_response()
        }
    }
}

pub async fn admin_list_email_senders(State(state): State<AppState>, AdminUser(_): AdminUser) -> impl IntoResponse {
    let Some(token) = state.w9_mail_api_token.as_ref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Email integration not configured"})),
        );
    };

    let client = reqwest::Client::new();
    let base = state.w9_mail_api_url.trim_end_matches('/');

    let accounts_resp = client
        .get(format!("{}/api/accounts", base))
        .bearer_auth(token)
        .send()
        .await;
    let accounts: Vec<MailAccountInfo> = match accounts_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to parse accounts: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "Failed to parse accounts"})),
                );
            }
        },
        Ok(resp) => {
            tracing::error!("Failed to fetch accounts: {}", resp.status());
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Failed to load sender accounts"})),
            );
        }
        Err(e) => {
            tracing::error!("Failed to fetch accounts: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Failed to load sender accounts"})),
            );
        }
    };

    let aliases_resp = client
        .get(format!("{}/api/aliases", base))
        .bearer_auth(token)
        .send()
        .await;
    let aliases: Vec<MailAliasInfo> = match aliases_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to parse aliases: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "Failed to parse aliases"})),
                );
            }
        },
        Ok(resp) => {
            tracing::error!("Failed to fetch aliases: {}", resp.status());
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Failed to load sender aliases"})),
            );
        }
        Err(e) => {
            tracing::error!("Failed to fetch aliases: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Failed to load sender aliases"})),
            );
        }
    };

    let mut results = Vec::new();
    for account in accounts {
        results.push(EmailSenderSummary {
            sender_type: "account".to_string(),
            sender_id: account.id,
            email: account.email.clone(),
            display_label: format!("{} ({})", account.display_name, account.email),
            via_display: None,
            is_active: account.is_active,
        });
    }
    for alias in aliases {
        results.push(EmailSenderSummary {
            sender_type: "alias".to_string(),
            sender_id: alias.id,
            email: alias.alias_email.clone(),
            display_label: alias
                .display_name
                .clone()
                .unwrap_or_else(|| alias.alias_email.clone()),
            via_display: Some(format!(
                "{} ({})",
                alias.account_display_name, alias.account_email
            )),
            is_active: alias.is_active && alias.account_is_active,
        });
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "options": results })),
    )
}

pub async fn admin_get_email_sender(State(state): State<AppState>, AdminUser(_): AdminUser) -> impl IntoResponse {
    let sender = state.email_sender.read().await.clone();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "sender": sender })),
    )
}

pub async fn admin_set_email_sender(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(payload): Json<UpdateEmailSenderRequest>,
) -> impl IntoResponse {
    if payload.email.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Sender email is required"})),
        );
    }

    let normalized_type = payload
        .sender_type
        .as_ref()
        .map(|t| t.trim().to_ascii_lowercase());
    if normalized_type
        .as_ref()
        .map(|_| payload.sender_id.as_ref().map(|s| s.trim().is_empty()).unwrap_or(true))
        .unwrap_or(false)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "sender_id is required when sender_type is provided"})),
        );
    }
    if let Some(ref ty) = normalized_type {
        if ty != "account" && ty != "alias" {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "sender_type must be 'account', 'alias', or omitted"})),
            );
        }
    }

    let config = EmailSenderConfig {
        sender_type: normalized_type,
        sender_id: payload.sender_id,
        email: payload.email.trim().to_string(),
        display_label: payload.display_label,
        via_display: payload.via_display,
    };

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    if let Err(e) = save_email_sender(&conn, &config) {
        tracing::error!("Failed to save sender config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to persist sender"})),
        );
    }

    {
        let mut guard = state.email_sender.write().await;
        *guard = Some(config.clone());
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Default sender updated",
            "sender": config
        })),
    )
}

pub async fn admin_list_users(State(state): State<AppState>, AdminUser(_): AdminUser) -> impl IntoResponse {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let mut stmt = match conn.prepare(
        "SELECT id, email, role, COALESCE(must_change_password, 0), COALESCE(created_at, strftime('%s','now')) \
         FROM users ORDER BY created_at DESC",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            tracing::error!("Failed to prepare user query: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let users_iter = match stmt.query_map([], |row| {
        Ok(AdminUserSummary {
            id: row.get(0)?,
            email: row.get(1)?,
            role: row.get(2)?,
            must_change_password: row.get::<_, i64>(3)? != 0,
            created_at: row.get::<_, i64>(4)?,
        })
    }) {
        Ok(iter) => iter,
        Err(e) => {
            tracing::error!("Failed to iterate users: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let mut users = Vec::new();
    for user in users_iter {
        match user {
            Ok(u) => users.push(u),
        Err(e) => {
                tracing::error!("Failed to read user row: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Database error"})),
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!(users)),
    )
}

pub async fn admin_create_user(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(payload): Json<AdminCreateUserRequest>,
) -> impl IntoResponse {
    let email = match normalize_email(&payload.email) {
        Ok(email) => email,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            );
        }
    };

    if let Err(msg) = validate_password(&payload.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        );
    }

    let role = payload
        .role
        .as_deref()
        .map(|r| r.to_ascii_lowercase())
        .unwrap_or_else(|| "user".to_string());

    if !matches!(role.as_str(), "user" | "admin" | "dev") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid role"})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    if let Ok(Some(_)) = fetch_user_by_email(&conn, &email) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Email already exists"})),
        );
    }

    let salt = generate_token(32);
    let password_hash = hash_with_salt(&payload.password, &salt);
    let user_id = Uuid::new_v4().to_string();
    let created_at = Utc::now().timestamp();

    match conn.execute(
        "INSERT INTO users(id, email, password_hash, salt, role, must_change_password, created_at, is_verified) \
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, 1)",
        params![user_id, email, password_hash, salt, role, created_at],
    ) {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!(AdminUserSummary {
                id: user_id,
                email,
                role,
                must_change_password: true,
                created_at,
            })),
        ),
        Err(e) => {
            tracing::error!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to create user"})),
            )
        }
    }
}

pub async fn admin_update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(user_id): Path<String>,
    Json(payload): Json<AdminUpdateUserRequest>,
) -> impl IntoResponse {
    if payload.role.is_none() && payload.must_change_password.is_none() && payload.password.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "No changes provided"})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    let Some(mut user) = fetch_user_by_id(&conn, &user_id).unwrap_or(None) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "User not found"})),
        );
    };

    if admin.id == user.id && payload.role.as_deref().is_some() && payload.role.as_deref() != Some(&user.role) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Cannot change your own role"})),
        );
    }

    if let Some(role) = payload.role.as_ref() {
        if !matches!(role.as_str(), "user" | "admin" | "dev") {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid role"})),
            );
        }
        if let Err(e) = conn.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![role, &user.id],
        ) {
            tracing::error!("Failed to update role: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to update user"})),
            );
        }
        user.role = role.clone();
    }

    if let Some(flag) = payload.must_change_password {
        if let Err(e) = conn.execute(
            "UPDATE users SET must_change_password = ?1 WHERE id = ?2",
            params![flag as i64, &user.id],
        ) {
            tracing::error!("Failed to update must_change_password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to update user"})),
            );
        }
        user.must_change_password = flag;
    }

    if let Some(password) = payload.password.as_ref() {
        if let Err(msg) = validate_password(password) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": msg})),
            );
        }
        let new_salt = generate_token(32);
        let new_hash = hash_with_salt(password, &new_salt);
        if let Err(e) = conn.execute(
            "UPDATE users SET password_hash = ?1, salt = ?2, must_change_password = 0 WHERE id = ?3",
            params![new_hash, new_salt, &user.id],
        ) {
            tracing::error!("Failed to update password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to update user"})),
            );
        }
        user.password_hash = new_hash;
        user.salt = new_salt;
        user.must_change_password = false;
    }

    let created_at = conn
        .query_row(
            "SELECT COALESCE(created_at, strftime('%s','now')) FROM users WHERE id = ?1",
            params![&user.id],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| Utc::now().timestamp());

    (
        StatusCode::OK,
        Json(serde_json::json!(AdminUserSummary {
            id: user.id,
            email: user.email,
            role: user.role,
            must_change_password: user.must_change_password,
            created_at,
        })),
    )
}

pub async fn admin_delete_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    if admin.id == user_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Cannot delete yourself"})),
        );
    }

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Database error"})),
            );
        }
    };

    match conn.execute("DELETE FROM users WHERE id = ?1", params![user_id]) {
        Ok(affected) if affected > 0 => (
            StatusCode::OK,
            Json(serde_json::json!({"success": true})),
        ),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "User not found"})),
        ),
        Err(e) => {
            tracing::error!("Failed to delete user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to delete user"})),
            )
        }
    }
}

pub async fn admin_send_password_reset(
    State(state): State<AppState>,
    AdminUser(_): AdminUser,
    Json(payload): Json<AdminSendPasswordResetRequest>,
) -> impl IntoResponse {
    request_password_reset(State(state), Json(payload)).await
}