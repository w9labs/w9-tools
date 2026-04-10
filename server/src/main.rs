use axum::{routing::get, Router, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use tower_http::{cors::CorsLayer, trace::TraceLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":"w9-tools","timestamp":Utc::now().to_rfc3339()})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "10105".into());
    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| "https://tools.w9.nu".into());
    let w9_db_url = std::env::var("W9_DB_URL").unwrap_or_else(|_| "https://db.w9.nu".into());
    let w9_mail_api = std::env::var("W9_MAIL_API_URL").unwrap_or_else(|_| "https://mail.w9.nu".into());
    let w9_mail_token = std::env::var("W9_MAIL_API_TOKEN").unwrap_or_default();
    tracing::info!("W9 Tools: base={} db={} mail={}", base_url, w9_db_url, w9_mail_api);
    let _ = (w9_mail_token);
    let router = Router::new()
        .route("/api/health", get(health_check))
        .nest_service("/", ServeDir::new("site/pkg"))
        .layer(tower::ServiceBuilder::new().layer(CorsLayer::permissive()));
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("W9 Tools listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
