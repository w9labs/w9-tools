use axum::routing::{get, post, patch};
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
    // Check if table exists and needs migration
    let (needs_migration, has_user_id) = {
        // First check if table exists
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='items'",
            [],
            |r| {
                let count: i64 = r.get(0)?;
                Ok(count > 0)
            },
        ).unwrap_or(false);
        
        if !table_exists {
            (false, false) // Table doesn't exist, will be created with correct schema
        } else {
            // Check if composite primary key exists
            let table_info: Result<String, _> = conn.query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='items'",
                [],
                |r| r.get(0),
            );
            let needs_mig = match table_info {
                Ok(sql) => !sql.contains("PRIMARY KEY (code, kind)"),
                Err(_) => false,
            };
            
            // Check if user_id column exists using PRAGMA table_info
            let has_uid = conn.prepare("PRAGMA table_info(items)")
                .and_then(|mut stmt| {
                    let rows = stmt.query_map([], |row| {
                        Ok(row.get::<_, String>(1)?) // column name is at index 1
                    })?;
                    let mut found = false;
                    for row in rows {
                        if let Ok(name) = row {
                            if name == "user_id" {
                                found = true;
                                break;
                            }
                        }
                    }
                    Ok(found)
                })
                .unwrap_or(false);
            
            (needs_mig, has_uid)
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
        if has_user_id {
            conn.execute(
                r#"
                INSERT OR IGNORE INTO items_new (code, kind, value, created_at, user_id)
                SELECT code, kind, value, created_at, user_id FROM items
                "#,
                [],
            )?;
        } else {
            conn.execute(
                r#"
                INSERT OR IGNORE INTO items_new (code, kind, value, created_at, user_id)
                SELECT code, kind, value, created_at, NULL FROM items
                "#,
                [],
            )?;
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
            CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id);
            "#,
        )?;
        
        // Migrate existing items table to add user_id column if it doesn't exist
        if !has_user_id {
            tracing::info!("Adding user_id column to items table...");
            match conn.execute("ALTER TABLE items ADD COLUMN user_id TEXT", []) {
                Ok(_) => {
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", [])?;
                    tracing::info!("Migration completed: user_id column added");
                }
                Err(e) => {
                    // Column might already exist or other error - check again
                    let check_again = conn.prepare("PRAGMA table_info(items)")
                        .and_then(|mut stmt| {
                            let rows = stmt.query_map([], |row| {
                                Ok(row.get::<_, String>(1)?)
                            })?;
                            let mut found = false;
                            for row in rows {
                                if let Ok(name) = row {
                                    if name == "user_id" {
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            Ok(found)
                        })
                        .unwrap_or(false);
                    
                    if check_again {
                        tracing::info!("user_id column already exists");
                        conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", [])?;
                    } else {
                        tracing::warn!("Failed to add user_id column: {}, but continuing...", e);
                        // Try to create index anyway in case column exists but wasn't detected
                        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", []);
                    }
                }
            }
        }
    }
    
    // Final safety check: ensure user_id column exists regardless of migration path
    {
        let user_id_exists = conn.prepare("PRAGMA table_info(items)")
            .and_then(|mut stmt| {
                let rows = stmt.query_map([], |row| {
                    Ok(row.get::<_, String>(1)?)
                })?;
                let mut found = false;
                for row in rows {
                    if let Ok(name) = row {
                        if name == "user_id" {
                            found = true;
                            break;
                        }
                    }
                }
                Ok(found)
            })
            .unwrap_or(false);
        
        if !user_id_exists {
            tracing::warn!("user_id column missing after migration, attempting to add...");
            if let Err(e) = conn.execute("ALTER TABLE items ADD COLUMN user_id TEXT", []) {
                tracing::error!("Failed to add user_id column: {}", e);
                return Err(anyhow::anyhow!("Failed to add user_id column: {}", e));
            }
            let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_items_user_id ON items(user_id)", []);
            tracing::info!("user_id column added successfully");
        }
    }
    
    conn.execute_batch(
        r#"
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

    // Get w9-mail API URL
    let w9_mail_api_url = std::env::var("W9_MAIL_API_URL")
        .unwrap_or_else(|_| "https://9.nu/api".to_string());
    
    // Get JWT secret for verifying tokens from w9-mail (should match w9-mail's JWT_SECRET)
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_string());
    
    let app_state = handlers::AppState { 
        db_path: db_path.clone(), 
        base_url: base_url.clone(),
        uploads_dir: uploads_dir.clone(),
        w9_mail_api_url: w9_mail_api_url.clone(),
        jwt_secret: jwt_secret.clone(),
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
        // Auth endpoints (forward to w9-mail)
        .route("/api/auth/login", post(handlers::login))
        .route("/api/auth/register", post(handlers::register))
        .route("/api/auth/password-reset", post(handlers::request_password_reset))
        .route("/api/auth/change-password", post(handlers::change_password))
        // User profile endpoints
        .route("/api/user/items", get(handlers::user_items))
        .route("/api/user/items/:code/:kind", post(handlers::user_delete_item))
        .route("/api/user/items/:code/:kind/update", post(handlers::user_update_item))
        // Admin user management endpoints (forward to w9-mail)
        .route("/api/admin/users", get(handlers::admin_list_users).post(handlers::admin_create_user))
        .route("/api/admin/users/:id", patch(handlers::admin_update_user).delete(handlers::admin_delete_user))
        .route("/api/admin/users/send-reset", post(handlers::admin_send_password_reset))
        // Short link redirects
        .route("/r/:code", get(handlers::result_handler))
        .route("/s/:code", get(handlers::short_handler))
        .route("/n/:code", get(handlers::notepad_handler))
        // Admin JSON API endpoints (frontend handles UI at /admin)
        .route("/api/admin/login", post(handlers::admin_login_post))
        .route("/api/admin/logout", post(handlers::admin_logout))
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
