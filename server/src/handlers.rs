// The final, corrected handlers.rs file

use axum::extract::{Form, Multipart, Path, Query, State};
use axum_extra::typed_header::TypedHeader;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use axum::debug_handler;
use axum_extra::headers::Cookie;
use mime_guess::from_path as mime_from_path;
use nanoid::nanoid;
use qrcode::render::svg::Color;
use qrcode::QrCode;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::path::{Path as StdPath}; // Use StdPath to avoid conflict with axum::extract::Path
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use askama::Template;
use w9::templates::{IndexTemplate, ResultTemplate, ImageOgTemplate, FileInfoTemplate, AdminLoginTemplate, AdminHomeTemplate, AdminItemsTemplate, AdminItem};
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
    // Try multiple qualities and downscales until under limit
    // For very large images (>20MB), be more aggressive with scaling and quality reduction
    let mut scales = vec![1.0, 0.9, 0.75, 0.6, 0.5, 0.4, 0.3, 0.25, 0.2, 0.15, 0.1];
    let qualities = vec![85u8, 75, 65, 55, 45, 35, 25, 15];
    
    let (w, h) = img.dimensions();
    
    for scale in scales.drain(..) {
        let target_w = (w as f32 * scale).max(1.0) as u32;
        let target_h = (h as f32 * scale).max(1.0) as u32;
        let resized = if target_w == w && target_h == h { 
            img.clone() 
        } else { 
            img.resize(target_w, target_h, FilterType::Lanczos3) 
        };
        
        for q in &qualities {
            let mut buf = Vec::with_capacity(512 * 1024);
            let mut cursor = std::io::Cursor::new(&mut buf);
            if resized.write_to(&mut cursor, ImageOutputFormat::Jpeg(*q)).is_ok() {
                if buf.len() <= max_bytes {
                    tracing::info!("Preview compressed: scale={}, quality={}, size={}KB", scale, q, buf.len() / 1024);
                    return Some(buf);
                }
            }
        }
    }
    
    tracing::warn!("Could not compress image under {}MB limit", max_bytes / 1024 / 1024);
    None
}

fn try_generate_preview(original_path: &StdPath, preview_path: &StdPath) -> Result<(), String> {
    let img = image::open(original_path).map_err(|e| format!("open image: {}", e))?;
    match encode_jpeg_under_limit(&img, PREVIEW_MAX_BYTES) {
        Some(bytes) => {
            std::fs::write(preview_path, &bytes).map_err(|e| format!("write preview: {}", e))
        }
        None => {
            // Fallback: For very large images, aggressively scale down first
            let (w, h) = img.dimensions();
            let pixel_count = (w as u64) * (h as u64);
            let max_pixels = 1920u64 * 1080u64;  // Max ~2MP (1920x1080)
            
            let fallback_img = if pixel_count > max_pixels {
                let scale = ((max_pixels as f32) / (pixel_count as f32)).sqrt();
                let new_w = (w as f32 * scale).max(1.0) as u32;
                let new_h = (h as f32 * scale).max(1.0) as u32;
                tracing::warn!("Extreme fallback: scaling {}x{} to {}x{}", w, h, new_w, new_h);
                img.resize(new_w, new_h, FilterType::Lanczos3)
            } else {
                img.clone()
            };
            
            // Try to write at very low quality
            let mut buf = Vec::new();
            let mut cur = std::io::Cursor::new(&mut buf);
            for quality in [45u8, 35, 25, 15] {
                buf.clear();
                cur = std::io::Cursor::new(&mut buf);
                if fallback_img.write_to(&mut cur, ImageOutputFormat::Jpeg(quality)).is_ok() {
                    if buf.len() <= PREVIEW_MAX_BYTES {
                        tracing::warn!("Fallback succeeded at quality={}, size={}KB", quality, buf.len() / 1024);
                        return std::fs::write(preview_path, &buf).map_err(|e| format!("write preview: {}", e));
                    }
                }
            }
            
            // Last resort: use absolute minimum
            buf.clear();
            cur = std::io::Cursor::new(&mut buf);
            fallback_img.write_to(&mut cur, ImageOutputFormat::Jpeg(10)).map_err(|e| format!("encode jpeg: {}", e))?;
            tracing::warn!("Last resort fallback: quality=10, size={}KB", buf.len() / 1024);
            std::fs::write(preview_path, &buf).map_err(|e| format!("write preview: {}", e))
        }
    }
}

#[derive(Clone)]
pub struct AppState { pub db_path: String, pub base_url: String }

#[derive(Deserialize)]
pub struct LinkRequest { pub link: String, pub qr: Option<String> }

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

pub async fn upload_handler(State(state): State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        if name == "file" {
            let filename = field.file_name().unwrap_or("file").to_string();

            let ext = StdPath::new(&filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("bin");

            if !is_allowed_extension(ext) {
                tracing::warn!("Rejected file with extension: {}", ext);
                return (StatusCode::BAD_REQUEST, format!("File type '.{}' not allowed", ext));
            }

            let id = Uuid::new_v4();
            let filename_saved = format!("{}.{}", id, ext);
            let path = format!("uploads/{}", filename_saved);
            if let Err(e) = fs::create_dir_all("uploads").await {
                tracing::error!("Failed to create uploads dir: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create uploads directory".to_string());
            }
            let mut out = match tokio::fs::File::create(&path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("Failed to create file: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file".to_string());
                }
            };
            let mut written: usize = 0;
            while let Ok(Some(chunk)) = field.chunk().await {
                written = written.saturating_add(chunk.len());
                if written > MAX_FILE_SIZE {
                    let _ = tokio::fs::remove_file(&path).await;
                    return (StatusCode::PAYLOAD_TOO_LARGE, format!("File too large. Max size: {}MB", MAX_FILE_SIZE / 1024 / 1024));
                }
                if let Err(e) = out.write_all(&chunk).await {
                    tracing::error!("Write error: {}", e);
                    let _ = tokio::fs::remove_file(&path).await;
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file".to_string());
                }
            }

            let short_code = nanoid!(8);
            let original = format!("file:{}", filename_saved);
            let conn = Connection::open(&state.db_path).unwrap();
            conn.execute(
                "INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))",
                params![short_code, "file", original],
            ).ok();

            let short_link = format!("{}/s/{}", state.base_url, short_code);
            let qr_target = ensure_absolute(&state.base_url, &short_link);
            let qr_svg = QrCode::new(qr_target.as_bytes())
                .map(|c| c
                    .render::<Color>()
                    .min_dimensions(320, 320)
                    .quiet_zone(true)
                    .dark_color(Color("#000000"))
                    .light_color(Color("#ffffff"))
                    .build())
                .unwrap_or_default();

            let body = format!(
                "{{\"code\":\"{}\", \"short\":\"{}\", \"file\":\"{}\", \"qr_svg\": \"{}\"}}",
                short_code,
                short_link,
                filename_saved,
                qr_svg.replace('\"', "\\\""),
            );

            tracing::info!("File uploaded successfully: {}", filename_saved);
            return (StatusCode::OK, body);
        }
    }
    (StatusCode::BAD_REQUEST, "No file provided".to_string())
}

pub async fn link_handler(State(state): State<AppState>, Form(req): Form<LinkRequest>) -> impl IntoResponse {
    if req.link.is_empty() {
        return (StatusCode::BAD_REQUEST, "No link provided".to_string());
    }

    if !req.link.starts_with("http://") && !req.link.starts_with("https://") {
        return (StatusCode::BAD_REQUEST, "Invalid URL format. Must start with http:// or https://".to_string());
    }

    let short_code = nanoid!(8);
    let conn = Connection::open(&state.db_path).unwrap();
    conn.execute(
        "INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))",
        params![short_code, "url", req.link],
    ).ok();

    let short_link = format!("{}/s/{}", state.base_url, short_code);
    let qr_svg = if matches!(req.qr.as_deref(), Some("on")) {
        let qr_target = ensure_absolute(&state.base_url, &short_link);
        QrCode::new(qr_target.as_bytes())
            .map(|c| c
                .render::<Color>()
                .min_dimensions(320, 320)
                .quiet_zone(true)
                .dark_color(Color("#000000"))
                .light_color(Color("#ffffff"))
                .build())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let body = format!(
        "{{\"code\":\"{}\", \"short\":\"{}\", \"qr_svg\": \"{}\"}}",
        short_code,
        short_link,
        qr_svg.replace('\"', "\\\""),
    );

    tracing::info!("Short link created for URL: {} -> {}", req.link, short_link);
    (StatusCode::OK, body)
}

pub async fn index_handler() -> Html<String> { Html(IndexTemplate.render().unwrap_or_else(|_| "Template error".to_string())) }

pub async fn submit_handler(State(state): State<AppState>, mut multipart: Multipart) -> axum::response::Response {
    let mut link_value: Option<String> = None;
    let mut file_bytes: Option<(String, Vec<u8>)> = None;
    let mut want_qr: bool = false;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "link" => {
                if let Ok(text) = field.text().await { if !text.trim().is_empty() { link_value = Some(text.trim().to_string()); } }
            }
            "file" => {
                if let Some(fname) = field.file_name().map(|s| s.to_string()) {
                    if let Ok(bytes) = field.bytes().await { file_bytes = Some((fname, bytes.to_vec())); }
                }
            }
            "qr" => { want_qr = true; }
            _ => {}
        }
    }

    if let Some((filename, data)) = file_bytes {
        let ext = StdPath::new(&filename).extension().and_then(|e| e.to_str()).unwrap_or("bin");
        if !is_allowed_extension(ext) { return (StatusCode::BAD_REQUEST, "File type not allowed".to_string()).into_response(); }
        if data.len() > MAX_FILE_SIZE { return (StatusCode::PAYLOAD_TOO_LARGE, "File too large".to_string()).into_response(); }

        let id = Uuid::new_v4();
        let filename_saved = format!("{}.{}", id, ext);
        let path = format!("uploads/{}", filename_saved);
        if let Err(e) = fs::create_dir_all("uploads").await { tracing::error!("create uploads dir: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create uploads directory".to_string()).into_response(); }
        if let Err(e) = fs::write(&path, &data).await { tracing::error!("save file: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save file".to_string()).into_response(); }

        let short_code = nanoid!(8);
        let original = format!("file:{}", filename_saved);
        let conn = Connection::open(&state.db_path).unwrap();
        conn.execute("INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))", params![short_code, "file", original]).ok();
        let redirect_to = format!("/r/{}?qr={}", short_code, if want_qr {"1"} else {"0"});
        return Redirect::to(&redirect_to).into_response();
    }

    if let Some(link) = link_value {
        if !link.starts_with("http://") && !link.starts_with("https://") { return (StatusCode::BAD_REQUEST, "Invalid URL format".to_string()).into_response(); }
        let short_code = nanoid!(8);
        let conn = Connection::open(&state.db_path).unwrap();
        conn.execute("INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))", params![short_code, "url", link]).ok();
        let redirect_to = format!("/r/{}?qr={}", short_code, if want_qr {"1"} else {"0"});
        return Redirect::to(&redirect_to).into_response();
    }

    (StatusCode::BAD_REQUEST, "Provide a URL or a file".to_string()).into_response()
}

pub async fn result_handler(State(state): State<AppState>, Path(code): Path<String>, Query(q): Query<std::collections::HashMap<String,String>>) -> Html<String> {
    let conn = Connection::open(&state.db_path).unwrap();
    let mut stmt = conn.prepare("SELECT kind, value FROM items WHERE code = ?1").unwrap();
    let row = stmt.query_row(params![code.clone()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
    let (_kind, _value) = match row { Ok(v) => v, Err(_) => return Html("<h1>Not found</h1>".to_string()) };
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
    let tpl = ResultTemplate { code, short_link, qr_svg: if qr_svg.is_empty() { None } else { Some(qr_svg) } };
    Html(tpl.render().unwrap_or_else(|_| "Template error".to_string()))
}

pub async fn short_handler(State(state): State<AppState>, Path(code): Path<String>, headers: HeaderMap) -> axum::response::Response {
    let (kind, value) = {
        let conn = Connection::open(&state.db_path).unwrap();
        let mut stmt = conn.prepare("SELECT kind, value FROM items WHERE code = ?1").unwrap();
        let row = stmt.query_row(params![code.clone()], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
        match row { Ok(v) => v, Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response() }
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
                        let original_fs_path = StdPath::new("uploads").join(filename);
                        let original_is_small = std::fs::metadata(&original_fs_path)
                            .map(|m| m.len() as usize <= PREVIEW_MAX_BYTES)
                            .unwrap_or(false);
                        if original_is_small {
                            image_url_full.clone()
                        } else {
                            let preview_dir = StdPath::new("uploads").join("previews");
                            let preview_name = make_preview_filename(filename);
                            let preview_fs_path = preview_dir.join(&preview_name);
                            let preview_web_path = format!("previews/{}", preview_name);
                            if !preview_fs_path.exists() {
                                let _ = std::fs::create_dir_all(&preview_dir);
                                let _ = try_generate_preview(&original_fs_path, &preview_fs_path);
                            }
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
                    // Content negotiation: if the client wants HTML, return the OG preview page;
                    // otherwise (e.g., Markdown image fetch), redirect to the raw image.
                    let accept = headers
                        .get(axum::http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let wants_html = accept.contains("text/html");
                    if !wants_html {
                        // For non-HTML (e.g., direct image fetch), stream the file instead of redirecting to avoid user-agent caching/transform issues
                        let fs_path = StdPath::new("uploads").join(filename);
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
                    return Html(tpl.render().unwrap_or_else(|_| "Template error".to_string())).into_response();
                }
                let filename_display = StdPath::new(filename).file_name().and_then(|f| f.to_str()).unwrap_or(filename).to_string();
                let file_url = format!("{}/files/{}", state.base_url, filename);
                let page_url = format!("{}/s/{}", state.base_url, code);
                let tpl = FileInfoTemplate { filename: filename_display, file_url, mime: mime.to_string(), page_url };
                return Html(tpl.render().unwrap_or_else(|_| "Template error".to_string())).into_response();
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

pub async fn admin_login_get() -> Html<String> {
    Html(AdminLoginTemplate.render().unwrap_or_else(|_| "Template error".to_string()))
}

#[derive(Deserialize)]
pub struct AdminLoginForm { pub username: String, pub password: String }

pub async fn admin_login_post(State(state): State<AppState>, Form(f): Form<AdminLoginForm>) -> impl IntoResponse {
    let conn = Connection::open(&state.db_path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM admin", [], |r| r.get(0)).unwrap_or(0);
    if count == 0 {
        let salt = generate_token(16);
        let hash = hash_with_salt(&f.password, &salt);
        let _ = conn.execute("INSERT INTO admin (id, username, password_hash, salt) VALUES (1, ?1, ?2, ?3)", params![f.username, hash, salt]);
    }
    let row = conn
        .prepare("SELECT password_hash, salt FROM admin WHERE username = ?1")
        .and_then(|mut s| s.query_row(params![f.username], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))));
    let (hash, salt) = match row { Ok(v) => v, Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response() };
    if hash != hash_with_salt(&f.password, &salt) { return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(); }

    let token = generate_token(48);
    let _ = conn.execute("INSERT INTO sessions (token, created_at) VALUES (?1, strftime('%s','now'))", params![token.clone()]);
    let mut headers = HeaderMap::new();
    let cookie = format!("w9_admin={}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000", token);
    headers.insert(axum::http::header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    (headers, Redirect::to("/admin")).into_response()
}

pub async fn admin_logout(State(state): State<AppState>, cookie: Option<TypedHeader<Cookie>>) -> impl IntoResponse {
    if let Some(tok) = extract_admin_token(cookie) {
        if let Ok(conn) = Connection::open(&state.db_path) {
            let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![tok]);
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::SET_COOKIE, HeaderValue::from_static("w9_admin=; Max-Age=0; Path=/"));
    (headers, Redirect::to("/admin/login")).into_response()
}

#[debug_handler]
pub async fn admin_home(State(state): State<AppState>, cookie: Option<TypedHeader<Cookie>>) -> Response {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return Redirect::to("/admin/login").into_response();
    }
    Html(AdminHomeTemplate.render().unwrap_or_else(|_| "Template error".to_string())).into_response()
}

#[debug_handler]
pub async fn admin_items(State(state): State<AppState>, cookie: Option<TypedHeader<Cookie>>) -> Response {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return Redirect::to("/admin/login").into_response();
    }
    let conn = Connection::open(&state.db_path).unwrap();
    let mut stmt = conn.prepare("SELECT code, kind, value, created_at FROM items ORDER BY created_at DESC LIMIT 500").unwrap();
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))).unwrap();
    let mut items: Vec<AdminItem> = Vec::new();
    for row in rows {
        if let Ok((code, kind, value, created_at)) = row {
            let mime = if kind == "file" {
                value.strip_prefix("file:")
                    .map(|fname| mime_from_path(fname).first_or_octet_stream().to_string())
            } else { None };
            items.push(AdminItem { code, kind, value, created_at, mime });
        }
    }
    Html(AdminItemsTemplate { items }.render().unwrap_or_else(|_| "Template error".to_string())).into_response()
}

// THIS IS THE RESTORED AND CORRECTED FUNCTION
#[debug_handler]
pub async fn admin_delete_item(
    State(state): State<AppState>,
    Path(code): Path<String>,
    cookie: Option<TypedHeader<Cookie>>,
) -> impl IntoResponse {
    if !require_admin_token(&state.db_path, extract_admin_token(cookie).as_deref()).await {
        return Redirect::to("/admin/login").into_response();
    }
    // Query needed info inside a short-lived DB connection (avoid holding Connection across awaits)
    let kind_value: Option<(String, String)> = {
        let conn = Connection::open(&state.db_path).unwrap();
        conn.query_row(
            "SELECT kind, value FROM items WHERE code = ?1",
            params![code.clone()],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        ).ok()
    };

    if let Some((kind, value)) = kind_value {
        if kind == "file" {
            if let Some(fname) = value.strip_prefix("file:") {
                let path_to_delete = std::path::PathBuf::from("uploads").join(fname);
                let _ = tokio::fs::remove_file(&path_to_delete).await;
                let preview_name = make_preview_filename(fname);
                let preview_path = std::path::PathBuf::from("uploads").join("previews").join(preview_name);
                let _ = tokio::fs::remove_file(preview_path).await;
            }
        }
    }

    // Now delete the DB row in a fresh connection
    {
        let conn = Connection::open(&state.db_path).unwrap();
        let _ = conn.execute("DELETE FROM items WHERE code = ?1", params![code]);
    }
    Redirect::to("/admin/items").into_response()
}


#[debug_handler]
pub async fn api_upload(State(state): State<AppState>, mut multipart: Multipart) -> axum::response::Response {
    let mut link_value: Option<String> = None;
    let mut saved_filename: Option<String> = None;
    let mut qr_required: bool = false;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "content" => {
                if let Some(fname) = field.file_name().map(|s| s.to_string()) {
                    let ext = StdPath::new(&fname).extension().and_then(|e| e.to_str()).unwrap_or("bin");
                    if !is_allowed_extension(ext) { return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"success": false, "error": "File type not allowed"}))).into_response(); }
                    if let Err(e) = fs::create_dir_all("uploads").await { tracing::error!("create uploads dir: {}", e); return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"success": false, "error": "Server error"}))).into_response(); }
                    let id = Uuid::new_v4();
                    let filename_saved = format!("{}.{}", id, ext);
                    let path = format!("uploads/{}", filename_saved);
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
            _ => {}
        }
    }

    if let Some(filename_saved) = saved_filename {
        let short_code = nanoid!(8);
        {
            let conn = Connection::open(&state.db_path).unwrap();
            let original = format!("file:{}", filename_saved);
            conn.execute("INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))", params![short_code, "file", original]).ok();
        }
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
        let short_code = nanoid!(8);
        {
            let conn = Connection::open(&state.db_path).unwrap();
            conn.execute("INSERT INTO items(code, kind, value, created_at) VALUES (?1, ?2, ?3, strftime('%s','now'))", params![short_code, "url", link]).ok();
        }
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