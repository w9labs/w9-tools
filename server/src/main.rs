use axum::{
    extract::State, http::StatusCode, response::Html, routing::get, Router,
    body::Body, response::Response,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Client>,
}

fn html_root() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html><html><head><title>W9 Tools</title></head><body style="background:#160c13;color:#fce126;font-family:monospace;text-align:center;padding:3rem"><h1>W9 TOOLS</h1><p>Daily Tools — QR, Converter — PostgreSQL</p></body></html>"#)
}

async fn health_check(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    match state.db.query_one("SELECT 1", &[]).await {
        Ok(_) => (StatusCode::OK, axum::Json(serde_json::json!({
            "status": "ok", "service": "w9-tools", "database": "connected",
            "timestamp": Utc::now().to_rfc3339()
        }))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
            "status": "error", "service": "w9-tools", "error": e.to_string()
        }))),
    }
}

async fn generate_qr(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response<Body> {
    let text = params.get("text").cloned().unwrap_or_default();
    if text.is_empty() {
        return Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from("Missing text")).unwrap();
    }
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200' width='200' height='200'><rect fill='#fce126' width='200' height='200'/><text x='100' y='100' font-family='monospace' font-size='12' fill='#160c13' text-anchor='middle'>QR: {}</text></svg>",
        text
    );
    Response::builder()
        .header("Content-Type", "image/svg+xml")
        .body(Body::from(svg))
        .unwrap()
}

async fn convert_text(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    let text = params.get("text").cloned().unwrap_or_default();
    let action = params.get("action").cloned().unwrap_or_default();
    let result = match action.as_str() {
        "upper" => text.to_uppercase(),
        "lower" => text.to_lowercase(),
        "reverse" => text.chars().rev().collect(),
        _ => text.clone(),
    };
    axum::Json(serde_json::json!({"original": text, "action": action, "result": result}))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer()).init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "10105".into());
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://w9_admin:password@w9-postgres:5432/w9_main".into());
    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move { if let Err(e) = conn.await { tracing::error!("DB: {}", e); } });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("Connected to PostgreSQL");
    let state = AppState { db: Arc::new(client) };
    let router = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/qr", get(generate_qr))
        .route("/api/convert", get(convert_text))
        .fallback(|| async { html_root() })
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 Tools listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
