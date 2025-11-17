use axum::routing::{get, post};
use axum::{Router, Json};
use axum::extract::DefaultBodyLimit;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use axum::http::Method;
use axum::routing::get_service;
use axum::http::StatusCode;
use serde_json::json;
use rusqlite::Connection;

mod handlers;

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "w9"
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with better formatting for production
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    // Get configuration from environment variables
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080);
    
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    
    // Set base URL for the application (guard against empty env)
    let base_url = std::env::var("BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("https://w9.se"));
    
    tracing::info!("Base URL: {}", base_url);

    // Initialize SQLite (file-based)
    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "data/w9.db".to_string());
    // Ensure database directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!("Failed to create database directory {:?}: {}", parent, e);
            return Err(anyhow::anyhow!("Failed to create database directory: {}", e));
        }
    }
    let conn = Connection::open(&db_path)
        .map_err(|e| {
            tracing::error!("Failed to open database at {}: {}", db_path, e);
            anyhow::anyhow!("Database error: {}", e)
        })?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS items (
            code TEXT PRIMARY KEY,
            kind TEXT NOT NULL,        -- 'url' | 'file'
            value TEXT NOT NULL,       -- url or 'file:filename'
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        );
        "#,
    )?;

    let base_url = std::env::var("BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("https://w9.se"));

    // Get uploads directory from environment or use default relative path
    let uploads_dir = std::env::var("UPLOADS_DIR")
        .unwrap_or_else(|_| "uploads".to_string());
    // Ensure uploads directory exists
    if let Err(e) = std::fs::create_dir_all(&uploads_dir) {
        tracing::error!("Failed to create uploads directory {}: {}", uploads_dir, e);
        return Err(anyhow::anyhow!("Failed to create uploads directory: {}", e));
    }
    tracing::info!("Uploads directory: {}", uploads_dir);

    let app_state = handlers::AppState { 
        db_path: db_path.clone(), 
        base_url: base_url.clone(),
        uploads_dir: uploads_dir.clone(),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        // CORS preflight: explicitly handle OPTIONS on API endpoints
        .route("/api/upload", axum::routing::options(handlers::cors_preflight))
        // API endpoints only (no UI)
        .route("/api/upload", post(handlers::api_upload))
        // Short link redirects
        .route("/r/:code", get(handlers::result_handler))
        .route("/s/:code", get(handlers::short_handler))
        // Admin JSON API endpoints (frontend handles UI at /admin)
        .route("/api/admin/login", post(handlers::admin_login_post))
        .route("/api/admin/logout", post(handlers::admin_logout))
        .route("/api/admin/items", get(handlers::admin_items))
        .route("/api/admin/items/:code", post(handlers::admin_delete_item))
        .with_state(app_state)
        // Set individual field limit to 1 GiB for multipart uploads
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
        // Raise max request body size to 1 GiB (inner layer)
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024))
        // CORS (outer layer) so even inner rejections (like 413) get CORS headers
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any)
                .expose_headers(Any)
        )
        .nest_service("/files", get_service(ServeDir::new(&uploads_dir)).handle_error(|_| async { (StatusCode::INTERNAL_SERVER_ERROR, "IO Error") }));

    let addr: SocketAddr = format!("{}:{}", host, port).parse()
        .map_err(|e| {
            tracing::error!("Invalid address {}:{} - {}", host, port, e);
            anyhow::anyhow!("Invalid address: {}", e)
        })?;
    tracing::info!("🚀 Server listening on {}", addr);
    
    // Axum 0.7 API: use TcpListener + axum::serve
    let listener = TcpListener::bind(addr).await
        .map_err(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            anyhow::anyhow!("Failed to bind: {}", e)
        })?;
    
    tracing::info!("✓ Server started successfully");
    axum::serve(listener, app).await
        .map_err(|e| {
            tracing::error!("Server error: {}", e);
            anyhow::anyhow!("Server error: {}", e)
        })?;

    Ok(())
}
