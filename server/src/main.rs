use axum::{routing::{get, post}, Router, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use tower_http::{cors::CorsLayer, trace::TraceLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({
        "status": "ok", "service": "w9-tools", "timestamp": Utc::now().to_rfc3339()
    })))
}

async fn create_short_url() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({"message": "Create short URL"})))
}

async fn create_note() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({"message": "Create note"})))
}

async fn generate_qr() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(serde_json::json!({"message": "Generate QR"})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "w9_tools=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    dotenvy::dotenv().ok();

    let port = std::env::var("PORT").unwrap_or_else(|_| "10105".to_string());

    let router = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/urls/shorten", post(create_short_url))
        .route("/api/notes", post(create_note))
        .route("/api/qr/generate", post(generate_qr))
        .nest_service("/", ServeDir::new("site/pkg"))
        .layer(tower::ServiceBuilder::new().layer(CorsLayer::permissive()));

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("W9 Tools listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
