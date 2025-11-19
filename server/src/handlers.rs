// The final, corrected handlers.rs file

use axum::extract::{Form, Multipart, Path, Query, State};
use axum_extra::typed_header::TypedHeader;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect};
use axum::Json;
use axum::debug_handler;
use axum_extra::headers::Cookie;
use mime_guess::from_path as mime_from_path;
use nanoid::nanoid;
use qrcode::render::svg::Color;
use qrcode::QrCode;
use rusqlite::{params, Connection, Error as SqliteError, ErrorCode};
use serde::Deserialize;
use std::path::{Path as StdPath}; // Use StdPath to avoid conflict with axum::extract::Path
use tokio::fs;
use tokio::io::AsyncWriteExt;
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

// Utility to extract the admin cookie token
fn extract_admin_token(cookie: Option<TypedHeader<Cookie>>) -> Option<String> {
    cookie
        .as_ref()
        .and_then(|TypedHeader(c)| c.get("w9_admin"))
        .map(|value| value.to_string())
}

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

fn insert_item_record(db_path: &str, code: &str, kind: &str, value: &str) -> Result<(), SaveItemError> {
    // Check if code already exists for this specific kind
    if code_exists_for_kind(db_path, code, kind) {
        return Err(SaveItemError::CodeExists);
    }
    
    let conn = Connection::open(db_path).map_err(|e| SaveItemError::Database(e.to_string()))?;
    match conn.execute(
        "INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))",
        params![code, kind, value],
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
) -> Result<String, SaveItemError> {
    if let Some(code) = preferred_code {
        insert_item_record(db_path, code, kind, value)?;
        return Ok(code.clone());
    }

    for _ in 0..5 {
        let generated = nanoid!(8);
        match insert_item_record(db_path, &generated, kind, value) {
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
        QrCode::new(qr_target.as_bytes())
            .map(|c| c
                .render::<Color>()
                .min_dimensions(320,320)
                .quiet_zone(true)
                .dark_color(Color("#000000"))
                .light_color(Color("#ffffff"))
                .build())
            .unwrap_or_default()
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

fn hash_with_salt(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

fn generate_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn require_admin_token(db_path: &str, token_opt: Option<&str>) -> bool {
    if let Some(token) = token_opt {
        if let Ok(conn) = Connection::open(db_path) {
            if let Ok(mut stmt) = conn.prepare("SELECT 1 FROM sessions WHERE token = ?1") {
                let exists: Result<i32, _> = stmt.query_row(params![token], |r| r.get(0));
                return exists.is_ok();
            }
        }
    }
    false
}

#[derive(Deserialize)]
pub struct AdminLoginForm { pub username: String, pub password: String }

pub async fn admin_login_post(State(state): State<AppState>, Form(f): Form<AdminLoginForm>) -> impl IntoResponse {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response();
        }
    };

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0)).unwrap_or(0);
    if count == 0 {
        let salt = generate_token(16);
        let hash = hash_with_salt(&f.password, &salt);
        if let Err(e) = conn.execute("INSERT INTO admin (id, username, password_hash, salt) VALUES (1, ?1, ?2, ?3)", params![f.username, hash, salt]) {
            tracing::error!("Failed to create admin user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to create user"}))).into_response();
        }
        tracing::info!("Created first admin user: {}", f.username);
    }

    let row = conn
        .prepare("SELECT password_hash, salt FROM admin WHERE username = ?1")
        .and_then(|mut s| s.query_row(params![f.username], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))));
    
    let (hash, salt) = match row {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Login failed for user '{}': {}", f.username, e);
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response();
        }
    };

    if hash != hash_with_salt(&f.password, &salt) {
        tracing::warn!("Invalid password for user '{}'", f.username);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response();
    }

    let token = generate_token(48);
    if let Err(e) = conn.execute("INSERT INTO sessions (token, created_at) VALUES (?1, strftime('%s','now'))", params![token.clone()]) {
        tracing::error!("Failed to create session: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to create session"}))).into_response();
    }

    let mut headers = HeaderMap::new();
    let cookie = format!("w9_admin={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000", token);
    if let Err(e) = HeaderValue::from_str(&cookie) {
        tracing::error!("Failed to create cookie header: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Server error"}))).into_response();
    }
    headers.insert(axum::http::header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    
    tracing::info!("Successful login for user '{}'", f.username);
    (StatusCode::OK, headers, Json(serde_json::json!({"success": true}))).into_response()
}

pub async fn admin_logout(State(state): State<AppState>, cookie: Option<TypedHeader<Cookie>>) -> impl IntoResponse {
    if let Some(tok) = extract_admin_token(cookie) {
        if let Ok(conn) = Connection::open(&state.db_path) {
            let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![tok]);
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::SET_COOKIE, HeaderValue::from_static("w9_admin=; Max-Age=0; Path=/"));
    (StatusCode::OK, headers, Json(serde_json::json!({"success": true}))).into_response()
}

#[debug_handler]
pub async fn admin_items(State(state): State<AppState>, cookie: Option<TypedHeader<Cookie>>) -> impl IntoResponse {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    }
    
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
    cookie: Option<TypedHeader<Cookie>>,
) -> impl IntoResponse {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    }
    
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
    cookie: Option<TypedHeader<Cookie>>,
) -> impl IntoResponse {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    }
    
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
pub async fn api_upload(State(state): State<AppState>, mut multipart: Multipart) -> axum::response::Response {
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
        let short_code = match save_item(&state.db_path, custom_code.as_ref(), "file", &original) {
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
            match QrCode::new(qr_target.as_bytes()) {
                Ok(c) => {
                    let image = c
                        .render::<qrcode::render::svg::Color>()
                        .min_dimensions(320,320)
                        .quiet_zone(true)
                        .dark_color(Color("#000000"))
                        .light_color(Color("#ffffff"))
                        .build();
                    let data_url = format!("data:image/svg+xml;utf8,{}", urlencoding::encode(&image));
                    Some(data_url)
                }
                Err(_) => None,
            }
        } else { None };
        return Json(serde_json::json!({"success": true, "short_url": short_url, "qr_code_data": qr_code_data})).into_response();
    }

    if let Some(link) = link_value {
        if !link.starts_with("http://") && !link.starts_with("https://") { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "Invalid URL"}))).into_response(); }
        let short_code = match save_item(&state.db_path, custom_code.as_ref(), "url", &link) {
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
            match QrCode::new(qr_target.as_bytes()) {
                Ok(c) => {
                    let image = c
                        .render::<qrcode::render::svg::Color>()
                        .min_dimensions(320,320)
                        .quiet_zone(true)
                        .dark_color(Color("#000000"))
                        .light_color(Color("#ffffff"))
                        .build();
                    let data_url = format!("data:image/svg+xml;utf8,{}", urlencoding::encode(&image));
                    Some(data_url)
                }
                Err(_) => None,
            }
        } else { None };
        return Json(serde_json::json!({"success": true, "short_url": short_url, "qr_code_data": qr_code_data})).into_response();
    }

    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "Provide content or file"}))).into_response()
}

fn render_markdown(md: &str) -> String {
    use pulldown_cmark::{Parser, html};
    
    // Protect math delimiters from markdown processing
    // Replace $...$ and $$...$$ with placeholders, then restore after markdown rendering
    let mut protected = md.to_string();
    let mut math_expressions: Vec<(String, String)> = Vec::new();
    
    // Protect block math $$...$$ first (before inline $...$)
    // Use non-greedy matching to handle multiple block math expressions
    let block_pattern = match regex::Regex::new(r"\$\$[\s\S]*?\$\$") {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to compile block math regex: {}", e);
            // Fall back to simple markdown rendering without math protection
            let parser = Parser::new(md);
            let mut html_output = String::new();
            html::push_html(&mut html_output, parser);
            return html_output;
        }
    };
    
    // Collect all block math matches with their positions
    let mut block_matches: Vec<(usize, usize, String)> = block_pattern
        .find_iter(md)
        .map(|m| (m.start(), m.end(), m.as_str().to_string()))
        .collect();
    
    // Replace block math from end to start to preserve positions
    for (idx, (start, end, math_expr)) in block_matches.iter().enumerate().rev() {
        let placeholder = format!("```MATH_BLOCK_{}```", idx);
        math_expressions.push((placeholder.clone(), math_expr.clone()));
        protected.replace_range(*start..*end, &placeholder);
    }
    
    // Protect inline math $...$ (but not $$)
    // Match $ followed by non-$ characters (at least one) and ending with $
    // Use a more permissive pattern that handles edge cases
    if let Ok(inline_pattern) = regex::Regex::new(r#"\$[^$\n\r]+\$"#) {
        let mut inline_count = math_expressions.len();
        // Collect all matches with their positions from the protected string
        let mut inline_matches: Vec<(usize, usize, String)> = inline_pattern
            .find_iter(&protected)
            .map(|m| (m.start(), m.end(), m.as_str().to_string()))
            .collect();
        
        // Replace from end to start to preserve positions
        for (start, end, math_expr) in inline_matches.iter().rev() {
            let placeholder = format!("`MATH_INLINE_{}`", inline_count);
            math_expressions.push((placeholder.clone(), math_expr.clone()));
            protected.replace_range(*start..*end, &placeholder);
            inline_count += 1;
        }
    } else {
        tracing::warn!("Failed to compile inline math regex, continuing without inline math protection");
    }
    
    // Render markdown
    let parser = Parser::new(&protected);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    
    // Restore math expressions (KaTeX will render them on the client side)
    // Replace in reverse order to avoid conflicts
    // Code blocks become <pre><code>...</code></pre>, inline code becomes <code>...</code>
    for (placeholder, math_expr) in math_expressions.iter().rev() {
        if placeholder.starts_with("```") {
            // Block math: replace <pre><code>MATH_BLOCK_N</code></pre> with the actual math
            let code_content = placeholder.trim_start_matches("```").trim_end_matches("```");
            // Try multiple replacement strategies
            let escaped_content = html_escape::encode_text(code_content);
            
            // Strategy 1: Direct code block replacement (most common)
            let direct_pattern = format!(r#"<pre><code[^>]*>\s*{}\s*</code></pre>"#, regex::escape(code_content));
            if let Ok(re) = regex::Regex::new(&direct_pattern) {
                html_output = re.replace_all(&html_output, math_expr).to_string();
            }
            
            // Strategy 2: HTML-escaped version
            let escaped_pattern = format!(r#"<pre><code[^>]*>\s*{}\s*</code></pre>"#, regex::escape(&escaped_content));
            if let Ok(re) = regex::Regex::new(&escaped_pattern) {
                html_output = re.replace_all(&html_output, math_expr).to_string();
            }
            
            // Strategy 3: Simple string replace fallback
            html_output = html_output.replace(&format!("<pre><code>{}</code></pre>", code_content), math_expr);
            html_output = html_output.replace(&format!("<pre><code>{}</code></pre>", escaped_content), math_expr);

            // Strategy 4: Fallback direct placeholder replacement (handles cases where markdown simplifies code block)
            html_output = html_output.replace(code_content, math_expr);
            html_output = html_output.replace(&escaped_content, math_expr);
        } else if placeholder.starts_with('`') {
            // Inline math: replace <code>MATH_INLINE_N</code> with the actual math
            let code_content = placeholder.trim_matches('`');
            let escaped_content = html_escape::encode_text(code_content);
            
            // Strategy 1: Direct inline code replacement
            let direct_pattern = format!(r#"<code[^>]*>\s*{}\s*</code>"#, regex::escape(code_content));
            if let Ok(re) = regex::Regex::new(&direct_pattern) {
                html_output = re.replace_all(&html_output, math_expr).to_string();
            }
            
            // Strategy 2: HTML-escaped version
            let escaped_pattern = format!(r#"<code[^>]*>\s*{}\s*</code>"#, regex::escape(&escaped_content));
            if let Ok(re) = regex::Regex::new(&escaped_pattern) {
                html_output = re.replace_all(&html_output, math_expr).to_string();
            }
            
            // Strategy 3: Simple string replace fallback
            html_output = html_output.replace(&format!("<code>{}</code>", code_content), math_expr);
            html_output = html_output.replace(&format!("<code>{}</code>", escaped_content), math_expr);

            // Strategy 4: direct placeholder replacement
            html_output = html_output.replace(code_content, math_expr);
            html_output = html_output.replace(&escaped_content, math_expr);
        }
    }
    
    html_output
}

#[debug_handler]
pub async fn api_notepad(State(state): State<AppState>, mut multipart: Multipart) -> axum::response::Response {
    let mut content: Option<String> = None;
    let mut custom_code_raw: Option<String> = None;

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

    let code = match save_item(&state.db_path, custom_code.as_ref(), "notepad", &content) {
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
    Json(serde_json::json!({"success": true, "short_url": short_url})).into_response()
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