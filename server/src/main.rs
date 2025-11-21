use axum::routing::{get, post, patch};
use axum::{Router, Json};
use axum::extract::DefaultBodyLimit;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::services::ServeDir;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use axum::http::Method;
use axum::routing::get_service;
use axum::http::StatusCode;
use serde_json::json;
use rusqlite::{Connection, params};
use uuid::Uuid;
use chrono::Utc;

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
    // Check if table exists and needs migration
    let needs_migration = {
        let table_info: Result<String, _> = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='items'",
            [],
            |r| r.get(0),
        );
        match table_info {
            Ok(sql) => !sql.contains("PRIMARY KEY (code, kind)"),
            Err(_) => false, // Table doesn't exist, will be created with correct schema
        }
    };

    if needs_migration {
        tracing::info!("Migrating items table to support composite primary key...");
        // Create new table with correct schema (including user_id)
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS items_new (
                code TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                user_id TEXT,
                PRIMARY KEY (code, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_items_code_new ON items_new(code);
            CREATE INDEX IF NOT EXISTS idx_items_user_id_new ON items_new(user_id);
            "#,
        )?;
        
        // Copy data from old table to new table
        // Handle potential duplicates by keeping the first occurrence
        // Try to copy with user_id first, if that fails (column doesn't exist), copy without it
        match conn.execute(
            r#"
            INSERT OR IGNORE INTO items_new (code, kind, value, created_at, user_id)
            SELECT code, kind, value, created_at, user_id FROM items
            "#,
            [],
        ) {
            Ok(_) => {
                tracing::info!("Copied data with user_id column");
            }
            Err(_) => {
                // user_id column doesn't exist in old table, copy without it
                tracing::info!("Copying data without user_id (column doesn't exist in old table)");
                conn.execute(
                    r#"
                    INSERT OR IGNORE INTO items_new (code, kind, value, created_at, user_id)
                    SELECT code, kind, value, created_at, NULL FROM items
                    "#,
                    [],
                )?;
            }
        }
        
        // Drop old table and rename new one
        conn.execute("DROP TABLE items", [])?;
        conn.execute("ALTER TABLE items_new RENAME TO items", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_items_code_new", [])?;
        conn.execute("DROP INDEX IF EXISTS idx_items_user_id_new", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_code ON items(code)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", [])?;
        
        tracing::info!("Migration completed successfully");
    } else {
        // Create table with correct schema if it doesn't exist
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS items (
                code TEXT NOT NULL,
                kind TEXT NOT NULL,        -- 'url' | 'file' | 'notepad'
                value TEXT NOT NULL,       -- url or 'file:filename' or markdown content
                created_at INTEGER NOT NULL,
                user_id TEXT,              -- NULL for anonymous, user_id from w9-mail for authenticated users
                PRIMARY KEY (code, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_items_code ON items(code);
            "#,
        )?;
        
        // Always try to add user_id column if table exists (ALTER TABLE is safe - won't fail if column exists)
        tracing::info!("Ensuring user_id column exists...");
        if let Err(e) = conn.execute("ALTER TABLE items ADD COLUMN user_id TEXT", []) {
            // If this fails, it might be because column already exists or other issue
            // Try to verify by attempting to prepare a query
            match conn.prepare("SELECT user_id FROM items LIMIT 1") {
                Ok(_) => {
                    tracing::info!("user_id column exists (verified by query preparation)");
                }
                Err(_) => {
                    tracing::error!("user_id column does not exist and could not be added: {}", e);
                    return Err(anyhow::anyhow!("Failed to add user_id column: {}", e));
                }
            }
        } else {
            tracing::info!("user_id column added successfully");
        }
        
        // Create index on user_id (will fail silently if column doesn't exist, but we verified above)
        if let Err(e) = conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", []) {
            tracing::warn!("Failed to create index on user_id: {} (column should exist, continuing anyway)", e);
        }
    }
    
    // Final safety check: verify user_id column exists by attempting to prepare a query
    {
        match conn.prepare("SELECT user_id FROM items LIMIT 1") {
            Ok(_) => {
                tracing::info!("user_id column verified to exist");
                // Ensure index exists
                let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", []);
            }
            Err(e) => {
                tracing::error!("user_id column does not exist or cannot be queried: {}", e);
                // Try one more time to add it
                if let Err(e2) = conn.execute("ALTER TABLE items ADD COLUMN user_id TEXT", []) {
                    tracing::error!("Failed to add user_id column in final check: {}", e2);
                    return Err(anyhow::anyhow!("user_id column is missing and could not be added: {}", e2));
                }
                tracing::info!("user_id column added in final safety check");
                let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", []);
            }
        }
    }
    

    let base_url = std::env::var("BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("https://w9.se"));

    ensure_user_schema(&conn)?;
    ensure_default_admin(&conn)?;

    let fallback_sender_email = std::env::var("EMAIL_FROM_ADDRESS")
        .unwrap_or_else(|_| "W9 Tools <no-reply@w9.se>".to_string());

    let mut sender_config = match handlers::load_email_sender(&conn) {
        Ok(config) => config,
        Err(e) => {
            tracing::warn!("Failed to load stored sender config: {}", e);
            None
        }
    };

    if sender_config.is_none() {
        let fallback = handlers::EmailSenderConfig {
            sender_type: None,
            sender_id: None,
            email: fallback_sender_email.clone(),
            display_label: Some("W9 Tools".to_string()),
            via_display: None,
        };
        if let Err(e) = handlers::save_email_sender(&conn, &fallback) {
            tracing::warn!("Failed to persist default sender config: {}", e);
        }
        sender_config = Some(fallback);
    }

    let email_sender = Arc::new(RwLock::new(sender_config));

    // Get uploads directory from environment or use default relative path
    let uploads_dir = std::env::var("UPLOADS_DIR")
        .unwrap_or_else(|_| "uploads".to_string());
    // Ensure uploads directory exists
    if let Err(e) = std::fs::create_dir_all(&uploads_dir) {
        tracing::error!("Failed to create uploads directory {}: {}", uploads_dir, e);
        return Err(anyhow::anyhow!("Failed to create uploads directory: {}", e));
    }
    tracing::info!("Uploads directory: {}", uploads_dir);

    // Get w9-mail API URL (should be base URL like https://w9.nu, not including /api)
    let w9_mail_api_url = std::env::var("W9_MAIL_API_URL")
        .unwrap_or_else(|_| "https://w9.nu".to_string());
    
    // Get JWT secret for verifying tokens from w9-mail (should match w9-mail's JWT_SECRET)
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_string());

    let password_reset_base_url = std::env::var("PASSWORD_RESET_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{}/reset-password", base_url.trim_end_matches('/')));
    let verification_base_url = std::env::var("VERIFICATION_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{}/verify-email", base_url.trim_end_matches('/')));
    let w9_mail_api_token = std::env::var("W9_MAIL_API_TOKEN").ok().filter(|v| !v.trim().is_empty());
    
    let app_state = handlers::AppState { 
        db_path: db_path.clone(), 
        base_url: base_url.clone(),
        uploads_dir: uploads_dir.clone(),
        w9_mail_api_url: w9_mail_api_url.clone(),
        jwt_secret: jwt_secret.clone(),
        password_reset_base_url,
        verification_base_url,
        w9_mail_api_token,
        email_sender,
    };

    // File serving (no state/auth required)
    let files_service = get_service(ServeDir::new(&uploads_dir))
        .handle_error(|_| async { (StatusCode::INTERNAL_SERVER_ERROR, "IO Error") });

    let app = Router::new()
        // File serving - public, no auth
        .nest_service("/files", files_service)
        // API routes
        .route("/health", get(health_check))
        // CORS preflight: explicitly handle OPTIONS on API endpoints
        .route("/api/upload", axum::routing::options(handlers::cors_preflight))
        // API endpoints only (no UI)
        .route("/api/upload", post(handlers::api_upload))
        .route("/api/notepad", post(handlers::api_notepad))
        // Auth endpoints (local database)
        .route("/api/auth/login", post(handlers::login))
        .route("/api/auth/register", post(handlers::register))
        .route("/api/auth/password-reset", post(handlers::request_password_reset))
        .route("/api/auth/verify-email", post(handlers::verify_email_token))
        .route("/api/auth/change-password", post(handlers::change_password))
        // User profile endpoints
        .route("/api/user/items", get(handlers::user_items))
        .route("/api/user/items/:code/:kind", post(handlers::user_delete_item))
        .route("/api/user/items/:code/:kind/update", post(handlers::user_update_item))
        // Admin user management endpoints
        .route("/api/admin/users", get(handlers::admin_list_users).post(handlers::admin_create_user))
        .route("/api/admin/users/:id", patch(handlers::admin_update_user).delete(handlers::admin_delete_user))
        .route("/api/admin/users/send-reset", post(handlers::admin_send_password_reset))
        .route("/api/admin/email/senders", get(handlers::admin_list_email_senders))
        .route("/api/admin/email/sender", get(handlers::admin_get_email_sender).put(handlers::admin_set_email_sender))
        // Short link redirects
        .route("/r/:code", get(handlers::result_handler))
        .route("/s/:code", get(handlers::short_handler))
        .route("/n/:code", get(handlers::notepad_handler))
        // Admin JSON API endpoints (frontend handles UI at /admin)
        .route("/api/admin/items", get(handlers::admin_items))
        .route("/api/admin/items/:code/:kind", post(handlers::admin_delete_item_with_kind))
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
        );

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

fn ensure_user_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            is_verified INTEGER NOT NULL DEFAULT 1
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);

        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            consumed INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);

        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            consumed INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires ON email_verification_tokens(expires_at);

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        "#,
    )?;

    if let Err(e) = conn.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 1", []) {
        if !e.to_string().contains("duplicate column name") {
            tracing::debug!("is_verified column check: {}", e);
        }
    }

    Ok(())
}

fn ensure_default_admin(conn: &Connection) -> anyhow::Result<()> {
    let admin_email = std::env::var("DEFAULT_ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@w9.se".to_string());
    let admin_password = std::env::var("DEFAULT_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "Admin@123".to_string());

    let admin_count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM users WHERE role = 'admin'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if admin_count == 0 {
        let salt = handlers::generate_token(32);
        let password_hash = handlers::hash_with_salt(&admin_password, &salt);
        let created_at = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO users(id, email, password_hash, salt, role, must_change_password, created_at, is_verified) \
             VALUES (?1, ?2, ?3, ?4, 'admin', 1, ?5, 1)",
            params![Uuid::new_v4().to_string(), admin_email, password_hash, salt, created_at],
        )?;
        tracing::info!(
            "Created default admin user {} (set DEFAULT_ADMIN_EMAIL/PASSWORD to override)",
            admin_email
        );
    }

    Ok(())
}
