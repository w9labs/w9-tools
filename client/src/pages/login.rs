use leptos::*;
use web_sys::window;
use crate::components::{Button, Input};

#[component]
pub fn LoginPage() -> impl IntoView {
    let oauth_url = "https://db.w9.nu/login";

    let handle_oauth_login = move |_| {
        if let Some(win) = window() {
            let _ = win.location().set_href(oauth_url);
        }
    };

    view! {
        <div class="page login-page">
            <div class="login-container">
                <h2 class="page-title">"LOGIN"</h2>

                <p class="card-content mb-3">
                    "W9 Tools uses the central W9 Database for authentication. "
                    "Click below to log in with your W9 account."
                </p>

                <div class="form-group">
                    <label>"W9 DATABASE OAUTH"</label>
                    <p class="oauth-description">
                        "You will be redirected to db.w9.nu to authenticate."
                    </p>
                </div>

                <div class="form-actions">
                    <Button
                        text="LOGIN VIA W9 DATABASE"
                        on_click=handle_oauth_login
                    />
                </div>

                <div class="login-footer">
                    <p>"Don't have a W9 account? " <a href="https://db.w9.nu/register">"Register at W9 Database"</a></p>
                </div>
            </div>
        </div>
    }
}
