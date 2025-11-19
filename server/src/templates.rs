use askama::Template;

// Simple monochrome templates (no external CSS/JS)

#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>w9</title>
    <style>
      body{font-family:Courier New,monospace;background:#fff;color:#000}
      main{max-width:560px;margin:4rem auto;text-align:center}
      label,input,button{display:block;margin:0.6rem auto}
    </style>
  </head>
  <body>
    <main>
      <h1>w9</h1>
      <form action="/submit" method="post" enctype="multipart/form-data">
        <label>URL:
          <input type="text" name="link">
        </label>
        <label>File:
          <input type="file" name="file">
        </label>
        <label>
          <input type="checkbox" name="qr"> Generate QR Code
        </label>
        <button type="submit">Create</button>
      </form>
    </main>
  </body>
 </html>"#, ext = "html")]
pub struct IndexTemplate;

#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>w9 result</title>
    <style>
      body{font-family:Courier New,monospace;background:#fff;color:#000}
      main{max-width:560px;margin:4rem auto;text-align:center}
      a{color:#000}
      .qr{margin-top:1rem}
    </style>
  </head>
  <body>
    <main>
      <h1>Short link created</h1>
      <p><strong>{{ code }}</strong></p>
      <p><a href="{{ short_link }}">{{ short_link }}</a></p>
      {% if qr_svg.is_some() %}
      <div class="qr">{{ qr_svg.as_ref().unwrap()|safe }}</div>
      {% endif %}
    </main>
  </body>
 </html>"#, ext = "html")]
pub struct ResultTemplate { pub code: String, pub short_link: String, pub qr_svg: Option<String> }

#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{{ title }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="canonical" href="{{ page_url }}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="w9.se">
    <meta property="og:title" content="{{ title }}">
    <meta property="og:description" content="{{ description }}">
    <meta property="og:url" content="{{ page_url }}">
    <meta property="og:image" content="{{ og_image_url }}">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{{ title }}">
    <meta name="twitter:description" content="{{ description }}">
    <meta name="twitter:image" content="{{ og_image_url }}">
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:Courier New,monospace;background:#000;color:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
      .img-container{max-width:95vw;max-height:85vh;position:relative}
      img{max-width:100%;max-height:85vh;height:auto;display:block;border:1px solid #333}
      .controls{margin-top:1rem;display:flex;gap:1rem;flex-wrap:wrap;justify-content:center}
      a,button{font-family:inherit;font-size:14px;padding:0.5rem 1rem;background:#fff;color:#000;border:1px solid #fff;text-decoration:none;cursor:pointer;transition:all 0.2s}
      a:hover,button:hover{background:#000;color:#fff}
      @media(prefers-color-scheme:light){body{background:#fff;color:#000}img{border-color:#ddd}a,button{background:#000;color:#fff}a:hover,button:hover{background:#fff;color:#000;border-color:#000}}
    </style>
  </head>
  <body>
    <div class="img-container">
      <img src="{{ full_image_url }}" alt="{{ title }}" loading="eager">
    </div>
    <div class="controls">
      <a href="{{ full_image_url }}" download>Download</a>
      <a href="/">← Home</a>
    </div>
  </body>
 </html>"#, ext = "html")]
pub struct ImageOgTemplate { pub og_image_url: String, pub full_image_url: String, pub page_url: String, pub title: String, pub description: String }

#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{{ filename }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="canonical" href="{{ page_url }}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="w9.se">
    <meta property="og:title" content="{{ filename }}">
    <meta property="og:description" content="{{ mime }}">
    <meta property="og:url" content="{{ page_url }}">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="{{ filename }}">
    <meta name="twitter:description" content="{{ mime }}">
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:Courier New,monospace;background:#f5f5f5;color:#000;min-height:100vh;padding:2rem}
      main{max-width:800px;margin:0 auto;background:#fff;padding:2rem;border:1px solid #ddd}
      h1{font-size:1.5rem;margin-bottom:1rem;word-break:break-all}
      .info{margin:1rem 0;padding:1rem;background:#f9f9f9;border-left:3px solid #000}
      .info div{margin:0.5rem 0}
      .actions{display:flex;gap:1rem;margin-top:1.5rem;flex-wrap:wrap}
      a,button{font-family:inherit;font-size:14px;padding:0.75rem 1.5rem;background:#000;color:#fff;border:1px solid #000;text-decoration:none;cursor:pointer;transition:all 0.2s;display:inline-block}
      a:hover,button:hover{background:#fff;color:#000}
      a.secondary{background:#fff;color:#000}
      a.secondary:hover{background:#000;color:#fff}
      @media(max-width:600px){body{padding:1rem}main{padding:1rem}.actions{flex-direction:column}a,button{text-align:center;width:100%}}
      @media(prefers-color-scheme:dark){body{background:#1a1a1a;color:#fff}main{background:#2a2a2a;border-color:#444}.info{background:#1f1f1f;border-color:#fff}a,button{background:#fff;color:#000;border-color:#fff}a:hover,button:hover{background:#000;color:#fff;border-color:#fff}a.secondary{background:#2a2a2a;color:#fff;border-color:#666}a.secondary:hover{background:#fff;color:#000}}
    </style>
  </head>
  <body>
    <main>
      <h1>📄 {{ filename }}</h1>
      <div class="info">
        <div><strong>Type:</strong> {{ mime }}</div>
      </div>
      <div class="actions">
        <a href="{{ file_url }}" download>⬇ Download</a>
        <a href="{{ file_url }}" target="_blank">👁 Open</a>
        <a href="/" class="secondary">← Home</a>
      </div>
    </main>
  </body>
</html>"#, ext = "html")]
pub struct FileInfoTemplate { pub filename: String, pub file_url: String, pub mime: String, pub page_url: String }

// PDF preview template with embedded viewer
#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{{ filename }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="canonical" href="{{ page_url }}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="w9.se">
    <meta property="og:title" content="{{ filename }}">
    <meta property="og:description" content="PDF Document">
    <meta property="og:url" content="{{ page_url }}">
    <meta name="twitter:card" content="summary">
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:Courier New,monospace;background:#333;color:#fff;height:100vh;display:flex;flex-direction:column}
      .header{padding:0.75rem 1rem;background:#000;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
      .title{font-size:14px;flex:1;min-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .actions{display:flex;gap:0.5rem}
      a,button{font-family:inherit;font-size:12px;padding:0.5rem 1rem;background:#fff;color:#000;border:none;text-decoration:none;cursor:pointer}
      a:hover,button:hover{background:#ddd}
      .viewer{flex:1;width:100%;border:none}
      @media(max-width:600px){.header{padding:0.5rem}.title{font-size:12px}.actions a,.actions button{padding:0.4rem 0.8rem;font-size:11px}}
    </style>
  </head>
  <body>
    <div class="header">
      <div class="title">📄 {{ filename }}</div>
      <div class="actions">
        <a href="{{ file_url }}" download>Download</a>
        <a href="/">Home</a>
      </div>
    </div>
    <embed class="viewer" src="{{ file_url }}" type="application/pdf">
  </body>
</html>"#, ext = "html")]
pub struct PdfTemplate { pub filename: String, pub file_url: String, pub page_url: String }

// Video preview template with HTML5 player
#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{{ filename }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="canonical" href="{{ page_url }}">
    <meta property="og:type" content="video.other">
    <meta property="og:site_name" content="w9.se">
    <meta property="og:title" content="{{ filename }}">
    <meta property="og:description" content="Shared Video">
    <meta property="og:url" content="{{ page_url }}">
    <meta property="og:video" content="{{ file_url }}">
    <meta property="og:video:type" content="{{ mime }}">
    <meta name="twitter:card" content="player">
    <meta name="twitter:title" content="{{ filename }}">
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:Courier New,monospace;background:#000;color:#fff;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:1rem}
      .container{max-width:1200px;width:100%}
      video{width:100%;max-height:80vh;background:#000;border:1px solid #333}
      .controls{margin-top:1rem;display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}
      a{font-family:inherit;font-size:14px;padding:0.5rem 1rem;background:#fff;color:#000;text-decoration:none}
      a:hover{background:#ddd}
      @media(max-width:600px){.controls{flex-direction:column}a{text-align:center}}
    </style>
  </head>
  <body>
    <div class="container">
      <video controls preload="metadata" controlsList="nodownload">
        <source src="{{ file_url }}" type="{{ mime }}">
        Your browser doesn't support video playback.
      </video>
      <div class="controls">
        <a href="{{ file_url }}" download>⬇ Download</a>
        <a href="/">← Home</a>
      </div>
    </div>
  </body>
</html>"#, ext = "html")]
pub struct VideoTemplate { pub filename: String, pub file_url: String, pub mime: String, pub page_url: String }

#[derive(Template)]
#[template(source = r#"<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Notepad</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="canonical" href="{{ page_url }}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="w9.se">
    <meta property="og:title" content="Notepad">
    <meta property="og:description" content="Shared Notepad">
    <meta property="og:url" content="{{ page_url }}">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css" integrity="sha384-n8MVd4RsNIU0tAv4ct0nTaAbDJwPJzDEaqSD1odI+WdtXRGWt2kTvGFasHpSy3SV" crossorigin="anonymous">
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js" integrity="sha384-XjKyOOlGwcjNTAIQHIpgOno0Hl1YQqzUOEleOLALmuqehneUG+vnGctmUb0ZY0l8" crossorigin="anonymous"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js" crossorigin="anonymous"></script>
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{font-family:Courier New,monospace;background:#fff;color:#000;min-height:100vh;padding:2rem}
      main{max-width:800px;margin:0 auto;background:#fff;padding:2rem;border:2px solid #000}
      .content{line-height:1.6;word-wrap:break-word;color:#000}
      .content h1,.content h2,.content h3,.content h4,.content h5,.content h6{margin-top:1.5rem;margin-bottom:0.5rem;color:#000}
      .content p{margin-bottom:1rem;color:#000}
      .content ul,.content ol{margin-left:1.5rem;margin-bottom:1rem}
      .content li{color:#000}
      .content code{background:#f5f5f5;padding:0.2rem 0.4rem;border:1px solid #ddd;color:#000}
      .content pre{background:#f5f5f5;padding:1rem;border:1px solid #ddd;overflow-x:auto;margin-bottom:1rem;border-radius:4px}
      .content pre code{background:transparent;padding:0;border:none;color:#000;white-space:pre}
      .content blockquote{border-left:3px solid #000;padding-left:1rem;margin-left:0;margin-bottom:1rem;color:#000}
      .content a{color:#000;text-decoration:underline}
      .content table{border-collapse:collapse;width:100%;margin-bottom:1rem}
      .content table th,.content table td{border:1px solid #000;padding:0.5rem;color:#000}
      .content table th{background:#f5f5f5}
      .math-fragment{display:inline-flex;align-items:center;justify-content:center}
      .math-inline{display:inline-flex}
      .math-block{width:100%;margin:1.5rem 0;text-align:center}
      .katex{font-size:1.1em}
      .katex-display{margin:1rem 0;text-align:center}
      .code-block{border:1px solid #ddd;background:#f8f8f8;margin-bottom:1.5rem;border-radius:4px;overflow:hidden}
      .code-block-header{display:flex;align-items:center;justify-content:space-between;background:#000;color:#fff;padding:0.4rem 0.8rem;font-size:0.75rem;letter-spacing:0.05em;text-transform:uppercase}
      .code-block-header button{font-family:inherit;font-size:0.7rem;background:transparent;color:inherit;border:1px solid rgba(255,255,255,0.5);padding:0.2rem 0.6rem;cursor:pointer;transition:opacity 0.2s}
      .code-block-header button:hover{opacity:0.8}
      .code-block pre{background:transparent;border:none;padding:1rem;margin:0;overflow:auto}
      .mermaid-diagram{margin:1.5rem 0;padding:1rem;border:1px solid #ddd;background:#f5f5f5;border-radius:4px;overflow:auto}
      .mermaid-diagram svg{width:100%;height:auto}
      @media(prefers-color-scheme:dark){
        .mermaid-diagram{background:#1f1f1f;border-color:#444}
      }
      .actions{margin-top:2rem;display:flex;gap:1rem}
      a{font-family:inherit;font-size:14px;padding:0.5rem 1rem;background:#000;color:#fff;text-decoration:none;border:2px solid #000}
      a:hover{background:#fff;color:#000}
      @media(prefers-color-scheme:dark){body{background:#000;color:#fff}main{background:#1a1a1a;border-color:#fff}.content{color:#fff}.content h1,.content h2,.content h3,.content h4,.content h5,.content h6{color:#fff}.content p{color:#fff}.content li{color:#fff}.content code,.content pre{background:#2a2a2a;border-color:#444;color:#fff}.content pre code{color:#fff}.content blockquote{border-color:#fff;color:#fff}.content a{color:#4a9eff}.content table th,.content table td{border-color:#fff;color:#fff}.content table th{background:#2a2a2a}.code-block{border-color:#444;background:#111}.code-block-header{background:#fff;color:#000}.code-block-header button{border-color:rgba(0,0,0,0.4)}.code-block pre{color:#fff}a{background:#fff;color:#000;border-color:#fff}a:hover{background:#000;color:#fff}}
    </style>
  </head>
  <body>
    <main>
      <div class="content">{{ content|safe }}</div>
      <div class="actions">
        <a href="/">← Home</a>
      </div>
    </main>
    <script>
      function bootstrapNotepadEnhancements() {
        const content = document.querySelector(".content");
        if (!content) {
          return;
        }

        function renderMathWhenReady() {
          if (!(window.katex && typeof window.katex.render === "function")) {
            setTimeout(renderMathWhenReady, 50);
            return;
          }

          const nodes = content.querySelectorAll("[data-math]");
          nodes.forEach(function(node) {
            const tex = node.getAttribute("data-tex") || "";
            const displayMode = node.getAttribute("data-math") === "block";
            try {
              window.katex.render(tex, node, { displayMode, throwOnError: false });
              node.classList.add(displayMode ? "katex-display" : "katex-inline");
            } catch (err) {
              console.error("KaTeX render error:", err);
              node.textContent = tex;
            }
          });
        }

        function convertMermaidBlocks() {
          const mermaidBlocks = content.querySelectorAll("pre code.language-mermaid, pre code.mermaid");
          if (mermaidBlocks.length === 0) {
            return;
          }

          mermaidBlocks.forEach(function(codeBlock) {
            const pre = codeBlock.parentElement;
            if (!pre) {
              return;
            }
            const container = document.createElement("div");
            container.className = "mermaid-diagram";
            container.dataset.source = "mermaid";
            container.textContent = codeBlock.textContent || "";
            pre.replaceWith(container);
          });

          const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
          if (window.mermaid) {
            try {
              window.mermaid.initialize({
                startOnLoad: false,
                securityLevel: "strict",
                theme: prefersDark ? "dark" : "default"
              });
              window.mermaid.run({ querySelector: ".mermaid-diagram" }).catch(function(err) {
                console.error("Mermaid rendering error:", err);
              });
            } catch (err) {
              console.error("Mermaid initialization failed:", err);
            }
          } else {
            console.warn("Mermaid script not available, diagrams left as code blocks.");
          }
        }

        function enhanceCodeBlocks() {
          const pres = content.querySelectorAll("pre");
          pres.forEach(function(pre) {
            if (pre.dataset.enhanced === "true") {
              return;
            }
            const code = pre.querySelector("code");
            if (!code) {
              return;
            }
            pre.dataset.enhanced = "true";
            const langClass = Array.from(code.classList || []).find(function(cls) {
              return cls.startsWith("language-");
            });
            const label = langClass ? langClass.replace("language-", "").toUpperCase() : "CODE";
            const wrapper = document.createElement("div");
            wrapper.className = "code-block";
            const header = document.createElement("div");
            header.className = "code-block-header";
            const title = document.createElement("span");
            title.textContent = label;
            const button = document.createElement("button");
            button.type = "button";
            button.textContent = "Copy";
            button.addEventListener("click", function() {
              const text = code.textContent || "";
              if (!(navigator.clipboard && navigator.clipboard.writeText)) {
                return;
              }
              navigator.clipboard.writeText(text).then(function() {
                button.textContent = "Copied";
                setTimeout(function() {
                  button.textContent = "Copy";
                }, 1500);
              }).catch(function(err) {
                console.error("Copy failed:", err);
              });
            });
            header.appendChild(title);
            header.appendChild(button);
            const parent = pre.parentNode;
            if (!parent) {
              return;
            }
            parent.insertBefore(wrapper, pre);
            wrapper.appendChild(header);
            wrapper.appendChild(pre);
          });
        }

        function initEnhancements() {
          convertMermaidBlocks();
          enhanceCodeBlocks();
          renderMathWhenReady();
        }

        if (document.readyState === "complete") {
          initEnhancements();
        } else {
          window.addEventListener("load", initEnhancements, { once: true });
        }
      }

      bootstrapNotepadEnhancements();
    </script>
  </body>
</html>"#, ext = "html")]
pub struct NotepadTemplate { pub content: String, pub page_url: String }

// Admin templates removed - frontend handles all admin UI
// Backend only provides JSON API endpoints
