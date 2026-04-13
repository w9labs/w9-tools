use axum::{
    extract::{Form, Multipart, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use nanoid::nanoid;
use pulldown_cmark::{html, Options, Parser};
use qrcode::QrCode;
use qrcode::render::svg;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_postgres::{Client, NoTls};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer, services::ServeDir};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const CSS: &str = include_str!("../infra/templates/voxel.css");
const W9_DB_URL: &str = "https://db.w9.nu";
const UPLOADS_DIR: &str = "uploads";

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Client>,
    pub http_client: reqwest::Client,
}

// Layout helpers
fn layout(title: &str, body: &str, nav: &str) -> String {
    format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><link rel="icon" type="image/svg+xml" href="/w9-logo/favicon.svg"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>{title} — W9 Tools</title><style>{CSS}</style></head><body><div class="app"><nav class="nav"><div class="nav-inner"><a href="/" class="brand"><img src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><span class="brand-text">Tools</span></a><div class="nav-links">{nav}</div></div></nav>{body}<footer class="footer"><img class="footer-logo" src="/w9-logo/workmark-transparent.svg" alt="W9 Labs"/><p>W9 Tools — QR · Converter · Notepad · File Upload</p></footer></div></body></html>"#, title=title, CSS=CSS, nav=nav, body=body)
}
fn public_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/login">Login</a>"#) }
fn user_layout(title: &str, body: &str) -> String { layout(title, body, r#"<a href="/qr">QR</a><a href="/convert">Convert</a><a href="/notepad">Notepad</a><a href="/upload">Upload</a><a href="/logout">Logout</a>"#) }

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

fn html_escape(s: &str) -> String { s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;") }
fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}
fn base64_decode(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(input)?;
    Ok(String::from_utf8(decoded)?)
}

// Pages
fn home_html() -> String {
    public_layout("W9 Tools", r#"<div class="hero"><img class="hero-logo" src="/w9-logo/logo-landscape-transparent.svg" alt="W9 Labs"/><h1>🔧 W9 Tools</h1><p>Daily utilities for developers and teams</p><div class="flex mt-3" style="justify-content:center"><a href="/login" class="btn">Login with W9</a></div></div><div class="grid mt-3"><div class="card"><h3>📱 QR Code Generator</h3><p class="text-sm">Generate real QR codes for URLs and text. Download as SVG.</p></div><div class="card"><h3>🔄 Text Converter</h3><p class="text-sm">Base64, URL-encode, case conversion and more.</p></div><div class="card"><h3>📝 Markdown Notepad</h3><p class="text-sm">Create notes with KaTeX math and Mermaid diagrams.</p></div><div class="card"><h3>📁 File Upload</h3><p class="text-sm">Upload and share files with automatic previews.</p></div></div>"#)
}

fn login_html() -> String {
    public_layout("Login", r#"<div class="card" style="max-width:420px;margin:3rem auto;text-align:center"><h1>🔧 W9 Tools</h1><p class="text-sm text-muted mb-2">Sign in with your W9 DB account</p><a href="https://db.w9.nu/oauth/authorize?redirect_uri=https://tools.w9.nu/oauth/callback&response_type=code&client_id=w9-tools" class="btn" style="width:100%">Login with W9 DB</a><p class="text-xs text-muted mt-2">Don't have an account? <a href="https://db.w9.nu/register">Register at W9 DB</a></p></div>"#)
}

fn qr_html() -> String {
    user_layout("QR Code", r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>📱 QR Code Generator</h1><form method="POST" action="/qr"><label>Text or URL</label><input type="text" name="text" required placeholder="https://w9.se"/><button type="submit" class="btn mt-2" style="width:100%">Generate QR</button></form></div>"#)
}

fn convert_html(result: Option<&str>, orig: Option<&str>, action: Option<&str>) -> String {
    let result_html = match (result, orig, action) {
        (Some(r), Some(o), Some(a)) => format!(r#"<div class="card mt-2"><h3>Result ({})</h3><div class="code">{}</div><button onclick="navigator.clipboard.writeText(document.querySelector('.code').textContent.replace('Copy','').trim());this.textContent='Copied!'" class="btn btn--sm mt-1">Copy</button></div>"#, a, html_escape(r)),
        _ => String::new(),
    };
    user_layout("Text Converter", &format!(r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>🔄 Text Converter</h1><form method="POST" action="/convert"><label>Input Text</label><textarea name="text" rows="5" required placeholder="Enter text...">{}</textarea><label>Conversion</label><select name="action"><option value="upper" {}>UPPERCASE</option><option value="lower" {}>lowercase</option><option value="reverse" {}>Reverse</option><option value="base64" {}>Base64 Encode</option><option value="base64d" {}>Base64 Decode</option><option value="url" {}>URL Encode</option><option value="title" {}>Title Case</option><option value="slug" {}>Slug</option></select><button type="submit" class="btn mt-2" style="width:100%">Convert</button></form>{}</div>"#, orig.unwrap_or(""), if action==Some("upper") {"selected"} else {""}, if action==Some("lower") {"selected"} else {""}, if action==Some("reverse") {"selected"} else {""}, if action==Some("base64") {"selected"} else {""}, if action==Some("base64d") {"selected"} else {""}, if action==Some("url") {"selected"} else {""}, if action==Some("title") {"selected"} else {""}, if action==Some("slug") {"selected"} else {""}, result_html))
}

fn notepad_html(msg: Option<&str>) -> String {
    let alert = msg.map(|m| format!(r#"<div class="alert alert--ok">{}</div>"#, m)).unwrap_or_default();
    let placeholder = "Write your note here... Supports: bold, italic, code, lists, tables, math";
    user_layout("Notepad", &format!(r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>📝 Markdown Notepad</h1>{}<form method="POST" action="/notepad"><label>Note Title</label><input type="text" name="title" placeholder="My Note"/><label>Content (Markdown + KaTeX + Mermaid)</label><textarea name="content" rows="10" required placeholder="{}"></textarea><label>Password (optional)</label><input type="password" name="password" placeholder="Leave blank for public"/><label>Expires in (hours)</label><input type="number" name="ttl_hours" value="24" min="1"/><button type="submit" class="btn mt-2" style="width:100%">Save Note</button></form></div>"#, alert, placeholder))
}

fn notepad_view_html(code: &str, title: &str, rendered_md: &str) -> String {
    format!(
        r#"<div class="card" style="max-width:800px;margin:2rem auto"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem"><h1 style="margin:0">📝 {}</h1><a href="/notepad" class="btn btn--sm">+ New Note</a></div><div class="notepad-content">{}</div><hr style="border-color:#7f8aa8;margin:2rem 0"><p class="text-xs text-muted text-center">Generated by W9 Tools — <a href="https://w9.se">w9.se</a></p></div>
        <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css"/>
        <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
        <script>
        document.addEventListener('DOMContentLoaded', () => {{
            document.querySelectorAll('[data-math]').forEach(el => {{
                try {{ katex.render(el.dataset.tex, el, {{ throwOnError: false, displayMode: el.tagName === 'DIV' }}); }} catch(e) {{}}
            }});
            document.querySelectorAll('script[type="math/tex"]').forEach(el => {{
                const span = document.createElement('span');
                span.setAttribute('data-math',''); span.setAttribute('data-tex', el.textContent);
                el.parentNode.replaceChild(span, el);
                try {{ katex.render(span.dataset.tex, span, {{ throwOnError: false }}); }} catch(e) {{}}
            }});
            document.querySelectorAll('script[type="math/tex; mode=display"]').forEach(el => {{
                const div = document.createElement('div'); div.style.textAlign='center'; div.style.margin='1rem 0';
                div.setAttribute('data-math',''); div.setAttribute('data-tex', el.textContent);
                el.parentNode.replaceChild(div, el);
                try {{ katex.render(div.dataset.tex, div, {{ throwOnError: false, displayMode: true }}); }} catch(e) {{}}
            }});
            mermaid.initialize({{ startOnLoad: false, theme: 'dark' }});
            mermaid.run();
        }});
        </script>
        <style>
        .notepad-content h1,.notepad-content h2,.notepad-content h3{{color:#fce126;margin:1rem 0 0.5rem;font-family:'Press Start 2P',monospace}}
        .notepad-content h1{{font-size:1.2rem}} .notepad-content h2{{font-size:0.9rem}} .notepad-content h3{{font-size:0.7rem}}
        .notepad-content p{{margin:0.8rem 0;line-height:1.8}}
        .notepad-content code{{background:#0a0a0a;border:1px solid #7f8aa8;padding:2px 6px;font-size:0.9rem}}
        .notepad-content pre{{background:#0a0a0a;border:2px solid #7f8aa8;padding:1rem;overflow-x:auto;margin:1rem 0}}
        .notepad-content pre code{{background:none;border:none;padding:0}}
        .notepad-content blockquote{{border-left:4px solid #fce126;padding-left:1rem;margin:1rem 0;color:#987b9e}}
        .notepad-content table{{width:100%;border-collapse:collapse;margin:1rem 0}}
        .notepad-content th,.notepad-content td{{border:2px solid #7f8aa8;padding:0.5rem;text-align:left}}
        .notepad-content th{{background:#32305a;color:#fce126}}
        .notepad-content ul,.notepad-content ol{{padding-left:2rem;margin:0.8rem 0}}
        .notepad-content li{{margin:0.3rem 0}}
        .notepad-content a{{color:#fce126;text-decoration:underline}}
        .notepad-content hr{{border:none;border-top:2px solid #7f8aa8;margin:1.5rem 0}}
        .notepad-content img{{max-width:100%;height:auto}}
        </style>"#, title, rendered_md)
}

fn upload_html(msg: Option<&str>) -> String {
    let alert = msg.map(|m| format!(r#"<div class="alert alert--ok">{}</div>"#, m)).unwrap_or_default();
    user_layout("File Upload", &format!(r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>📁 File Upload</h1>{}<form method="POST" action="/upload" enctype="multipart/form-data"><label>Choose File</label><input type="file" name="file" required/><button type="submit" class="btn mt-2" style="width:100%">Upload</button></form><p class="text-xs text-muted mt-2">Supported: Images (PNG, JPG, GIF, WebP, SVG), Documents, Archives. Max 100MB.</p></div>"#, alert))
}

fn file_convert_html() -> String {
    user_layout("File Converter", r#"<div class="card" style="max-width:600px;margin:2rem auto"><h1>🔄 Image Converter</h1><p class="text-sm text-muted mb-2">Convert images between PNG, JPG, and WebP formats.</p><form method="POST" action="/file-convert" enctype="multipart/form-data"><label>Upload Image</label><input type="file" name="file" accept="image/*" required/><label>Convert to</label><select name="format"><option value="png">PNG</option><option value="jpg">JPG</option><option value="webp">WebP</option></select><button type="submit" class="btn mt-2" style="width:100%">Convert & Download</button></form></div>"#)
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

// QR Code Generator - Real QR codes using qrcode crate
async fn qr_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(qr_html()).into_response()
}
async fn qr_post(jar: CookieJar, state: State<AppState>, Form(form): Form<QrReq>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    let code = match QrCode::new(form.text.as_bytes()) {
        Ok(c) => c,
        Err(e) => return Html(user_layout("QR Error", &format!(r#"<div class="card" style="max-width:500px;margin:2rem auto;text-align:center"><h1>❌ Error</h1><p class="alert alert--err">{}</p><a href="/qr" class="btn mt-2">Try Again</a></div>"#, html_escape(&e.to_string())))).into_response(),
    };
    let svg = code.render::<svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(svg::Color("#160c13"))
        .light_color(svg::Color("#fce126"))
        .build();
    let body = format!(r#"<div class="card" style="max-width:500px;margin:2rem auto"><h1>📱 QR Code</h1><div class="card text-center" style="background:#fff;padding:1rem">{}</div><p class="text-sm text-muted mt-1 text-center">Input: <code class="text-xs">{}</code></p><a href="/qr" class="btn mt-2">Generate Another</a></div>"#, svg, html_escape(&form.text));
    Html(user_layout("QR Code", &body)).into_response()
}

// Text Converter
async fn convert_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(convert_html(None, None, None)).into_response()
}
async fn convert_post(jar: CookieJar, state: State<AppState>, Form(form): Form<ConvertReq>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    let result = match form.action.as_str() {
        "upper" => form.text.to_uppercase(),
        "lower" => form.text.to_lowercase(),
        "reverse" => form.text.chars().rev().collect(),
        "base64" => base64_encode(&form.text),
        "base64d" => match base64_decode(&form.text) { Ok(s) => s, Err(_) => return Html(convert_html(Some("❌ Invalid Base64 input"), Some(&form.text), Some(&form.action))).into_response() },
        "url" => form.text.chars().map(|c| if c.is_ascii_alphanumeric()||"-_.~".contains(c){c.to_string()}else{format!("%{:02X}",c as u8)}).collect(),
        "title" => form.text.split_whitespace().map(|w|{let mut ch=w.chars();match ch.next(){None=>String::new(),Some(f)=>f.to_uppercase().to_string()+&ch.as_str().to_lowercase()}}).collect::<Vec<_>>().join(" "),
        "slug" => form.text.to_lowercase().split_whitespace().map(|w|w.chars().filter(|c|c.is_ascii_alphanumeric()).collect::<String>()).filter(|s|!s.is_empty()).collect::<Vec<_>>().join("-"),
        _ => form.text.clone(),
    };
    Html(convert_html(Some(&result), Some(&form.text), Some(&form.action))).into_response()
}

// Markdown Notepad
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
        Ok(_) => Html(notepad_html(Some(&format!("✅ Note created! Access at: w9.nu/n/{}", code)))).into_response(),
        Err(e) => Html(notepad_html(Some(&format!("❌ Error: {}", e)))).into_response(),
    }
}

// View notepads at /n/:code (public, no auth required)
async fn view_notepad(State(state): State<AppState>, axum::extract::Path(code): axum::extract::Path<String>) -> impl IntoResponse {
    let row = match state.db.query_opt("SELECT content, password_hash, title FROM notes WHERE code=$1 AND expires_at>$2", &[&code, &Utc::now()]).await {
        Ok(Some(r)) => r,
        Ok(None) => return Html(layout("Not Found", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>404</h1><p>Note not found or expired.</p><a href="/notepad" class="btn mt-2">Create Note</a></div>"#, "")).into_response(),
        Err(_) => return Html(layout("Error", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>500</h1><p>Database error.</p></div>"#, "")).into_response(),
    };
    let content: String = row.get("content");
    let pw_hash: Option<String> = row.get("password_hash");
    let title: Option<String> = row.get("title");
    let display_title = title.unwrap_or_else(|| format!("Note: {}", code));

    // If password protected, show password form first
    if pw_hash.is_some() {
        let body = format!(r#"<div class="card" style="max-width:500px;margin:3rem auto"><h1>🔒 Protected Note</h1><p class="text-sm text-muted mb-2">This note requires a password to view.</p><form method="POST" action="/n/{}/unlock"><label>Password</label><input type="password" name="password" required/><button type="submit" class="btn mt-2" style="width:100%">Unlock</button></form></div>"#, code);
        return Html(layout("Protected Note", &body, "")).into_response();
    }

    // Render markdown
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let parser = Parser::new_ext(&content, opts);
    let mut rendered = String::new();
    html::push_html(&mut rendered, parser);

    // Add KaTeX data attributes for math
    let rendered = rendered.replace(r#"\["#, r#"<div data-math data-tex=""#)
        .replace(r#"\]"#, r#""></div>"#)
        .replace(r#"\("#, r#"<span data-math data-tex=""#)
        .replace(r#"\)"#, r#""></span>"#);

    Html(notepad_view_html(&code, &display_title, &rendered)).into_response()
}

#[derive(Debug, Deserialize)]
struct UnlockReq { password: String }
async fn unlock_notepad(State(state): State<AppState>, axum::extract::Path(code): axum::extract::Path<String>, Form(form): Form<UnlockReq>) -> impl IntoResponse {
    let row = match state.db.query_opt("SELECT content, password_hash, title FROM notes WHERE code=$1 AND expires_at>$2", &[&code, &Utc::now()]).await {
        Ok(Some(r)) => r,
        Ok(None) => return Html(layout("Not Found", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>404</h1><p>Note not found.</p></div>"#, "")).into_response(),
        Err(_) => return Html(layout("Error", r#"<div class="card" style="max-width:400px;margin:3rem auto;text-align:center"><h1>500</h1><p>Database error.</p></div>"#, "")).into_response(),
    };
    let content: String = row.get("content");
    let pw_hash: Option<String> = row.get("password_hash");
    let title: Option<String> = row.get("title");
    let display_title = title.unwrap_or_else(|| format!("Note: {}", code));

    let mut h = Sha256::new();
    h.update(form.password.as_bytes());
    let input_hash = format!("{:x}", h.finalize());

    if pw_hash.as_ref() != Some(&input_hash) {
        let body = format!(r#"<div class="card" style="max-width:500px;margin:3rem auto"><h1>❌ Wrong Password</h1><p class="alert alert--err">Incorrect password.</p><form method="POST" action="/n/{}/unlock"><label>Password</label><input type="password" name="password" required/><button type="submit" class="btn mt-2" style="width:100%">Try Again</button></form></div>"#, code);
        return Html(layout("Wrong Password", &body, "")).into_response();
    }

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    let parser = Parser::new_ext(&content, opts);
    let mut rendered = String::new();
    html::push_html(&mut rendered, parser);
    let rendered = rendered.replace(r#"\["#, r#"<div data-math data-tex=""#)
        .replace(r#"\]"#, r#""></div>"#)
        .replace(r#"\("#, r#"<span data-math data-tex=""#)
        .replace(r#"\)"#, r#""></span>"#);

    Html(notepad_view_html(&code, &display_title, &rendered)).into_response()
}

// File Upload
async fn upload_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(upload_html(None)).into_response()
}
async fn upload_post(jar: CookieJar, state: State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let user = match require_auth(&jar, &state).await { Some(u) => u, None => return Redirect::to("/login").into_response() };

    // Ensure uploads directory exists
    tokio::fs::create_dir_all(UPLOADS_DIR).await.unwrap_or(());

    let mut file_url = String::new();
    let mut file_name = String::new();
    let mut file_size = 0u64;

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            file_name = field.file_name().unwrap_or("upload").to_string();
            let data = field.bytes().await.unwrap_or_default();
            file_size = data.len() as u64;
            if file_size > 100 * 1024 * 1024 {
                return Html(upload_html(Some("❌ File too large (max 100MB)"))).into_response();
            }
            let ext = Path::new(&file_name).extension().and_then(|e| e.to_str()).unwrap_or("bin");
            let uuid = Uuid::new_v4();
            let filename = format!("{}.{}", uuid, ext);
            let path = format!("{}/{}", UPLOADS_DIR, filename);
            if let Err(e) = tokio::fs::write(&path, &data).await {
                return Html(upload_html(Some(&format!("❌ Save failed: {}", e)))).into_response();
            }
            file_url = format!("/uploads/{}", filename);

            // Store in database
            let id = Uuid::new_v4();
            let mime_type = mime_guess::from_path(&file_name).first_or_octet_stream().to_string();
            let email = user.get("email").and_then(|v|v.as_str()).unwrap_or("unknown");
            let _ = state.db.execute(
                "INSERT INTO uploads (id, code, filename, mime_type, file_size, original_name) VALUES ($1,$2,$3,$4,$5,$6)",
                &[&id, &filename, &filename, &mime_type, &(file_size as i64), &file_name]
            ).await;
        }
    }

    if file_url.is_empty() {
        return Html(upload_html(Some("❌ No file uploaded"))).into_response();
    }

    let body = format!(r#"<div class="card" style="max-width:500px;margin:2rem auto;text-align:center"><h1>✅ Upload Complete</h1><p class="text-sm mt-2">File: <strong>{}</strong> ({:.1} KB)</p><a href="{}" class="btn mt-2" target="_blank">View / Download</a><br/><a href="/upload" class="btn btn--ghost mt-1">Upload Another</a></div>"#, file_name, file_size as f64 / 1024.0, file_url);
    Html(user_layout("Upload Complete", &body)).into_response()
}

// File Converter (image format conversion)
async fn file_convert_page(jar: CookieJar, state: State<AppState>) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }
    Html(file_convert_html()).into_response()
}
async fn file_convert_post(jar: CookieJar, state: State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    if require_auth(&jar, &state).await.is_none() { return Redirect::to("/login").into_response(); }

    let mut format = String::from("png");
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name = String::from("image");

    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "format" => {
                let data = field.text().await.unwrap_or_default();
                format = data;
            }
            "file" => {
                file_name = field.file_name().unwrap_or("image").to_string();
                file_data = Some(field.bytes().await.unwrap_or_default().to_vec());
            }
            _ => {}
        }
    }

    let data = match file_data {
        Some(d) => d,
        None => return Html(file_convert_html()).into_response(),
    };

    // Convert image
    let img = match image::load_from_memory(&data) {
        Ok(i) => i,
        Err(e) => return Html(user_layout("Convert Error", &format!(r#"<div class="card" style="max-width:500px;margin:2rem auto;text-align:center"><h1>❌ Error</h1><p class="alert alert--err">Invalid image: {}</p><a href="/file-convert" class="btn mt-2">Try Again</a></div>"#, html_escape(&e.to_string())))).into_response(),
    };

    let mut buf = Vec::new();
    let ext = match format.as_str() {
        "jpg" | "jpeg" => { img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Jpeg).ok(); "jpg" }
        "webp" => { img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::WebP).ok(); "webp" }
        _ => { img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png).ok(); "png" }
    };

    if buf.is_empty() {
        return Html(user_layout("Convert Error", r#"<div class="card" style="max-width:500px;margin:2rem auto;text-align:center"><h1>❌ Error</h1><p class="alert alert--err">Conversion failed.</p><a href="/file-convert" class="btn mt-2">Try Again</a></div>"#)).into_response();
    }

    // Return as downloadable file
    let new_name = format!("converted.{}", ext);
    let mime = match ext {
        "jpg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "image/png",
    };
    (
        StatusCode::OK,
        [
            ("Content-Type", mime),
            ("Content-Disposition", &format!("attachment; filename=\"{}\"", new_name)),
        ],
        buf,
    ).into_response()
}

// Health check
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

    // Ensure uploads directory exists
    tokio::fs::create_dir_all(UPLOADS_DIR).await?;

    tracing::info!("Connecting to PostgreSQL...");
    let (client, conn) = tokio_postgres::connect(&db_url, NoTls).await?;
    tokio::spawn(async move { if let Err(e) = conn.await { tracing::error!("DB: {}", e); } });
    client.query_one("SELECT 1", &[]).await?;
    tracing::info!("Connected to PostgreSQL");

    // Create uploads table if not exists
    let _ = client.execute(
        "CREATE TABLE IF NOT EXISTS uploads (
            id UUID PRIMARY KEY,
            code TEXT NOT NULL UNIQUE,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            file_size BIGINT NOT NULL,
            original_name TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )",
        &[]
    ).await;

    let state = AppState { db: Arc::new(client), http_client: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()? };

    let router = Router::new()
        .route("/", get(home)).route("/login", get(login_page))
        .route("/oauth/callback", get(oauth_callback)).route("/logout", get(logout))
        .route("/qr", get(qr_page)).route("/qr", axum::routing::post(qr_post))
        .route("/convert", get(convert_page)).route("/convert", axum::routing::post(convert_post))
        .route("/notepad", get(notepad_page)).route("/notepad", axum::routing::post(notepad_post))
        .route("/n/:code", get(view_notepad))
        .route("/n/:code/unlock", axum::routing::post(unlock_notepad))
        .route("/upload", get(upload_page)).route("/upload", axum::routing::post(upload_post))
        .route("/file-convert", get(file_convert_page)).route("/file-convert", axum::routing::post(file_convert_post))
        .route("/api/health", get(health_check))
        .nest_service("/w9-logo", ServeDir::new("public/w9-logo"))
        .nest_service("/uploads", ServeDir::new(UPLOADS_DIR))
        .with_state(state)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()).layer(CorsLayer::permissive()));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("W9 Tools listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
