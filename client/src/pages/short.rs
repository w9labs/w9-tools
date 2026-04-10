use leptos::*;
#[component] pub fn ShortPage() -> impl IntoView {
    let title = match "short" {
        "files" => "FILES", "short" => "URL SHORTENER", "notes" => "NOTES",
        "qr" => "QR CODES", "convert" => "CONVERTERS", _ => "PAGE"
    };
    view! {
        <div class="page">
            <h2 class="page-title">{title}</h2>
            <div class="voxel-card"><p>"Coming soon."</p></div>
        </div>
    }
}
