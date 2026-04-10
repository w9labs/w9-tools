use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod components;
mod pages;

use components::{Header, Footer};
use pages::{HomePage, FilesPage, ShortPage, NotesPage, QrPage, ConvertPage};

#[component]
pub fn App() -> impl IntoView {
    view! {
        <Title text="W9 Tools"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1"/>
        <Stylesheet id="voxel" href="/pkg/w9-tools-client.css"/>
        <Router>
            <div class="app-container">
                <Header/>
                <main class="main-content">
                    <Routes>
                        <Route path="" view=HomePage/>
                        <Route path="/files" view=FilesPage/>
                        <Route path="/short" view=ShortPage/>
                        <Route path="/notes" view=NotesPage/>
                        <Route path="/qr" view=QrPage/>
                        <Route path="/convert" view=ConvertPage/>
                    </Routes>
                </main>
                <Footer/>
            </div>
        </Router>
    }
}
