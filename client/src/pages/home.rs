use leptos::*;
#[component] pub fn HomePage() -> impl IntoView {
    view! {
        <div class="page home-page">
            <section class="hero-section">
                <h2 class="hero-title">"W9 TOOLS"</h2>
                <p class="hero-subtitle">"DEVELOPER ARSENAL"</p>
                <div class="hero-actions">
                    <a href="/files" class="voxel-button">"FILES"</a>
                    <a href="/short" class="voxel-button">"SHORT URL"</a>
                    <a href="/notes" class="voxel-button">"NOTES"</a>
                </div>
            </section>
            <section class="features-section">
                <h2 class="section-title">"FEATURES"</h2>
                <div class="card-grid">
                    <div class="voxel-card"><h3 class="card-title">"FILE SHARING"</h3><p>"Upload and share files."</p></div>
                    <div class="voxel-card"><h3 class="card-title">"URL SHORTENER"</h3><p>"Create short links."</p></div>
                    <div class="voxel-card"><h3 class="card-title">"NOTE DROPS"</h3><p>"Self-destructing notes."</p></div>
                    <div class="voxel-card"><h3 class="card-title">"QR CODES"</h3><p>"Generate QR codes."</p></div>
                </div>
            </section>
        </div>
    }
}
