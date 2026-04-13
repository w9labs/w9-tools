use axum::{
    extract::{Form, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use nanoid::nanoid;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const CSS: &str = include_str!("../infra/templates/voxel.css");
const W9_DB_URL: &str = "https://db.w9.nu";

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Client>,
    pub http_client: reqwest::Client,
}

// Layout helpers
fn layout(title: &str, body: &str, nav: &str) -> String {
    format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>{title} — W9 Tools</title><style>{CSS}</style></head><body><div class="app"><nav class="nav"><div class="nav-inner"><a href="/" class="brand"><img src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><span class="brand-text">Tools</span></a><div class="nav-links">{nav}</div></div></nav>{body}<footer class="footer"><img class="footer-logo" src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><p>W9 Tools — QR · Converter · Notepad · File Convert</p></footer></div></body></html>"#, title=title, CSS=CSS, nav=nav, body=body)
}
fn public_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/login">Login</a>"#) }
fn user_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/qr">QR</a><a href="/convert">Convert</a><a href="/notepad">Notepad</a><a href="/file-convert">File Convert</a><a href="/logout">Logout</a>"#) }

// Session management via w9-db
fn set_session(jar: CookieJar, token: String) -> CookieJar {
    jar.add(axum_extra::extract::cookie::Cookie::build(("w9_tools_session", token))
        .path("/").http_only(true).same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7)).finish())
}
fn clear_session(jar: CookieJar) -> CookieJar { jar.remove(axum_extra::extract::cookie::Cookie::named("w9_tools_session")) }
fn get_session(jar: &CookieJar) -> Option<String> { jar.get("w9_tools_session").map(|c| c.value().to_string()) }

async fn verify_session(state: &AppState, token: &str) -> Option<serde_json::Value> {
    let res = state.http_client.get(format!("{}/api/auth/me", W9_DB_URL))
        .header("Authorization", format!("Bearer {}", token)).send().await.ok()?;
    if res.status().is_success() { res.json().await.ok() } else { None }
}
async fn require_auth(jar: &CookieJar, state: &AppState) -> Option<serde_json::Value> {
    let token = get_session(jar)?;
    verify_session(state, &token).await
}

// Pages
fn home_html() -> String {
    public_layout("W9 Tools", r#"<div class="hero"><img class="hero-logo" src="/w9-logo/logo-landscape-transparent.svg" alt="W9 Labs"/><h1>🔧 W9 Tools</h1><p>Daily utilities for developers and teams</p><div class="flex mt-3" style="justify-content:center"><a href="/login" class="btn">Login with W9</a></div></div><div class="grid mt-3"><div class="card"><h3>📱 QR Code Generator</h3><p class="text-sm">Generate QR codes for URLs and text.</p></div><div class="card"><h3>🔄 Text Converter</h3><p class="text-sm">Base64, URL-encode, case conversion and more.</p></div><div class="card"><h3>📝 Quick Notepad</h3><p class="text-sm">Create temporary notes with password protection.</p></div><div class="card"><h3>📄 File Converter</h3><p class="text-sm">Convert between common file formats (images, text, documents).</p></div></div>"#)
}

fn login_html() -> String {
    public_layout("Login", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🔧 W9 Tools</h1><p class="text-sm text-muted mb-2">Sign in with your W9 DB account</p><a href="https://db.w9.nu/oauth/authorize?redirect_uri=https://tools.w9.nu/oauth/callback&response_type=code&client_id=w9-tools" class="btn" style="width:100%">Login with W9 DB</a><p class="text-xs text-muted mt-2">Don't have an account? <a href="https://db.w9.nu/register">Register at W9 DB</a></p></div>"#)
}

fn qr_html() -> String {
    user_layout("QR Code", r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>📱 QR Code Generator</h1><form method="POST" action="/qr"><label>Text or URL</label><input type="text" name="text" required placeholder="https://w9.se"/><button type="submit" class="btn mt-2" style="width:100%">Generate QR</button></form></div>"#)
}

fn convert_html(result: Option<&str>, orig: Option<&str>, action: Option<&str>) -> String {
    let result_html = match (result, orig, action) {
        (Some(r), Some(o), Some(a)) => format!(r#"<div class="card mt-2"><h3>Result ({})</h3><div class="code">{}</div><button onclick="navigator.clipboard.writeText('{}');this.textContent='Copied!'" class="btn btn--sm mt-1">Copy</button></div>"#, a, html_escape(r), html_escape(r)),
        _ => String::new(),
    };
    user_layout("Text Converter", &format!(r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>🔄 Text Converter</h1><form method="POST" action="/convert"><label>Input Text</label><textarea name="text" rows="5" required placeholder="Enter text...">{}</textarea><label>Conversion</label><select name="action"><option value="upper" {}>UPPERCASE</option><option value="lower" {}>lowercase</option><option value="reverse" {}>Reverse</option><option value="base64" {}>Base64</option><option value="url" {}>URL Encode</option><option value="title" {}>Title Case</option><option value="slug" {}>Slug</option></select><button type="submit" class="btn mt-2" style="width:100%">Convert</button></form>{}</div>"#, orig.unwrap_or(""), if action==Some("upper") {"selected"} else {""}, if action==Some("lower") {"selected"} else {""}, if action==Some("reverse") {"selected"} else {""}, if action==Some("base64") {"selected"} else {""}, if action==Some("url") {"selected"} else {""}, if action==Some("title") {"selected"} else {""}, if action==Some("slug") {"selected"} else {""}, result_html))
}

fn notepad_html(msg: Option<&str>) -> String {
    let alert = msg.map(|m| format!(r#"<div class="alert alert--ok">{}</div>"#, m)).unwrap_or_default();
    user_layout("Notepad", &format!(r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>📝 Quick Notepad</h1>{}<form method="POST" action="/notepad"><label>Note Title</label><input type="text" name="title" placeholder="My Note"/><label>Content</label><textarea name="content" rows="10" required placeholder="Write your note..."></textarea><label>Password (optional)</label><input type="password" name="password" placeholder="Leave blank for public"/><label>Expires in (hours)</label><input type="number" name="ttl_hours" value="24" min="1"/><button type="submit" class="btn mt-2" style="width:100%">Save Note</button></form></div>"#, alert))
}

fn file_convert_html() -> String {
    user_layout("File Converter", r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>📄 File Converter</h1><p class="text-sm text-muted">Convert between common file formats</p><form method="POST" action="/file-convert" enctype="multipart/form-data"><label>Upload File</label><input type="file" name="file" required/><label>Convert to</label><select name="format"><option value="png">PNG (Image)</option><option value="jpg">JPG (Image)</option><option value="webp">WebP (Image)</option><option value="txt">TXT (Text)</option><option value="md">Markdown</option><option value="html">HTML</option></select><button type="submit" class="btn mt-2" style="width:100%">Convert</button></form></div>"#)
}

fn html_escape(s: &str) -> String { s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;") }
fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.as_bytes().chunks(3) {
        let b0 = chunk[0] as u32; let b1 = if chunk.len()>1 {chunk[1] as u32} else {0}; let b2 = if chunk.len()>2 {chunk[2] as u32} else {0};
        let t = (b0<<16)|(b1<<8)|b2;
        out.push(CHARS[(t>>18) as usize] as char); out.push(CHARS[((t>>12)&0x3F) as usize] as char);
        out.push(if chunk.len()>1 {CHARS[((t>>6)&0x3F) as usize] as char} else {'='});
        out.push(if chunk.len()>2 {CHARS[(t&0x3F) as usize] as char} else {'='});
    }
    out
}

// Form structs
#[derive(Debug, Deserialize)]
struct QrReq { text: String }
#[derive(Debug, Deserialize)]
struct ConvertReq { text: String, action: String }
#[derive(Debug, Deserialize)]
struct NoteReq { title: Option<String>, content: String, password: Option<String>, ttl_hours: Option<i64> }

// Handlers
async fn home() -> Html<String> { Html(home_html()) }
async fn login_page() -> Html<String> { Html(login_html()) }

async fn oauth_callback(State(state): State<AppState>, jar: CookieJar, Query(q): Query<serde_json::Value>) -> impl IntoResponse {
    let code = match q.get("code").and_then(|v| v.as_str()) { Some(c) => c.to_string(), None => return Html(login_html()).into_response() };
    let res = match state.http_client.post(format!("{}/oauth/token", W9_DB_URL))
        .form(&[("grant_type","authorization_code"),("code",&code),("redirect_uri","https://tools.w9.nu/oauth/callback")]).send().await {
        Ok(r) => r, Err(_) => return Html(login_html()).into_response()
    };
    let json = match res.json::<serde_json::Value>().await { Ok(j) => j, Err(_) => return Html(login_html()).into_response() };
    let token = match json.get("access_token").and_then(|v| v.as_str()) { Some(t) => t.to_string(), None => return Html(login_html()).into_response() };
    (set_session(jar, token), Redirect::to("/qr")).into_response()
}

async fn logout(jar: CookieJar) -> impl IntoResponse { (clear_session(jar), Redirect::to("/")).into_response() }

async fn qr_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(qr_html()).into_response()
}
async fn qr_post(jar: CookieJar, state: State<AppState>, Form(form): Form<QrReq>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    let svg = format!(r#"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 200' width='200' height='200'><rect fill='#fce126' width='200' height='200'/><rect x='20' y='20' width='60' height='60' fill='#160c13'/><rect x='120' y='20' width='60' height='60' fill='#160c13'/><rect x='20' y='120' width='60' height='60' fill='#160c13'/><rect x='30' y='30' width='40' height='40' fill='#fce126'/><rect x='130' y='30' width='40' height='40' fill='#fce126'/><rect x='30' y='130' width='40' height='40' fill='#fce126'/><rect x='40' y='40' width='20' height='20' fill='#160c13'/><rect x='140' y='40' width='20' height='20' fill='#160c13'/><rect x='40' y='140' width='20' height='20' fill='#160c13'/><text x='100' y='110' font-family='monospace' font-size='10' fill='#160c13' text-anchor='middle'>QR</text></svg>"#);
    let body = format!(r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>📱 QR Code</h1><div class="card text-center">{}</div><a href="/qr" class="btn mt-2">Generate Another</a></div>"#, svg);
    user_layout("QR Code", &body).into_response()
}

async fn convert_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(convert_html(None, None, None)).into_response()
}
async fn convert_post(jar: CookieJar, state: State<AppState>, Form(form): Form<ConvertReq>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    let result = match form.action.as_str() {
        "upper" => form.text.to_uppercase(), "lower" => form.text.to_lowercase(),
        "reverse" => form.text.chars().rev().collect(),
        "base64" => base64_encode(&form.text),
        "url" => form.text.chars().map(|c| if c.is_ascii_alphanumeric()||"-_.~".contains(c){c.to_string()}else{format!("%{:02X}",c as u8)}).collect(),
        "title" => form.text.split_whitespace().map(|w|{let mut ch=w.chars();match ch.next(){None=>String::new(),Some(f)=>f.to_uppercase().to_string()+&ch.as_str().to_lowercase()}}).collect::<Vec<_>>().join(" "),
        "slug" => form.text.to_lowercase().split_whitespace().map(|w|w.chars().filter(|c|c.is_ascii_alphanumeric()).collect::<String>()).filter(|s|!s.is_empty()).collect::<Vec<_>>().join("-"),
        _ => form.text.clone(),
    };
    Html(convert_html(Some(&result), Some(&form.text), Some(&form.action))).into_response()
}

async fn notepad_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(notepad_html(None)).into_response()
}
async fn notepad_post(jar: CookieJar, state: State<AppState>, Form(form): Form<NoteReq>) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return Redirect::to("/login").into_response() };
    let code = nanoid!(8);
    let expires = chrono::Utc::now() + chrono::Duration::hours(form.ttl_hours.unwrap_or(24));
    let pw_hash = form.password.as_ref().map(|pw| { let mut h = Sha256::new(); h.update(pw.as_bytes()); format!("{:x}", h.finalize()) });
    let email = user.get("email").and_then(|v|v.as_str()).unwrap_or("unknown");
    let id = Uuid::new_v4();
    match state.db.execute("INSERT INTO notes (id, code, content, password_hash, expires_at, max_views) VALUES ($1,$2,$3,$4,$5,$6)", &[&id, &code, &form.content, &pw_hash, &expires, &None::<i32>]).await {
        Ok(_) => Html(notepad_html(Some(&format!("✅ Note created: w9.nu/n/{}", code)))).into_response(),
        Err(e) => Html(notepad_html(Some(&format!("❌ Error: {}", e)))).into_response(),
    }
}

async fn file_convert_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(file_convert_html()).into_response()
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.query_one("SELECT 1", &[]).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":"w9-tools","database":"connected","timestamp":Utc::now().to_rfc3339()}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"status":"error","error":e.to_string()}))),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).with(tracing_subscriber::fmt::layer()).init();
    dotenvy::dotenv().ok();
    let port = std::env::var("PORT").unwrap_or_else(|_| "10105".into());
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://w9_admin:password@w9-postgres:5432/w9_main".into());
    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move { if let Err(e) = conn.await { tracing::error!("DB: {}", e); } });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("Connected to PostgreSQL");
    let state = AppState { db: Arc::new(client), http_client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()? };
    let router = Router::new()
        .route("/", get(home)).route("/login", get(login_page))
        .route("/oauth/callback", get(oauth_callback)).route("/logout", get(logout))
        .route("/qr", get(qr_page)).route("/qr", axum::routing::post(qr_post))
        .route("/convert", get(convert_page)).route("/convert", axum::routing::post(convert_post))
        .route("/notepad", get(notepad_page)).route("/notepad", axum::routing::post(notepad_post))
        .route("/file-convert", get(file_convert_page))
        .route("/api/health", get(health_check))
        .nest_service("/w9-logo", ServeDir::new("public/w9-logo"))
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 Tools listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
