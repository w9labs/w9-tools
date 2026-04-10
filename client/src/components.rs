use leptos::*;

#[component] pub fn Header() -> impl IntoView {
    view! {
        <header class="voxel-header">
            <div class="header-content">
                <a href="/"><h1 class="logo-text">"W9 TOOLS"</h1></a>
                <nav class="header-nav">
                    <a href="/">"HOME"</a><a href="/files">"FILES"</a>
                    <a href="/short">"SHORT"</a><a href="/notes">"NOTES"</a>
                    <a href="/qr">"QR"</a><a href="/convert">"CONVERT"</a>
                </nav>
            </div>
        </header>
    }
}

#[component] pub fn Footer() -> impl IntoView {
    view! {
        <footer class="voxel-footer">
            <div class="footer-content">
                <div class="footer-section"><h3>"W9 TOOLS"</h3><p>"Developer utilities"</p></div>
                <div class="footer-section">
                    <h3>"NETWORK"</h3>
                    <a href="https://w9.se">"Homepage"</a><a href="https://db.w9.nu">"W9 DB"</a>
                    <a href="https://mail.w9.nu">"W9 Mail"</a>
                </div>
                <div class="footer-section"><p>"© 2026 W9 Labs"</p></div>
            </div>
        </footer>
    }
}
