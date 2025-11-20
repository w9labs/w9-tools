import { useState, useRef, FormEvent, useEffect } from 'react'
import { marked } from 'marked'

const API_BASE: string = import.meta.env?.VITE_API_BASE_URL || ''
const adminApi = (path: string) => {
  const suffix = path.startsWith('/') ? path : `/${path}`
  return joinUrl(API_BASE, `/api/admin${suffix}`)
}

type SuccessResult = {
  success: true
  short_url: string
  qr_code_data: string | null
}

type ErrorResult = {
  success: false
  error: string
}

type Result = SuccessResult | ErrorResult

type NotepadResult = {
  success: true
  short_url: string
} | {
  success: false
  error: string
}

// Simple router
function useRoute() {
  const path = window.location.pathname
  if (path === '/admin/login') return 'admin-login'
  if (path.startsWith('/admin')) return 'admin'
  if (path === '/short' || path.startsWith('/short/')) return 'shorts'
  if (path === '/note' || path.startsWith('/note')) return 'note'
  if (path === '/convert' || path.startsWith('/convert')) return 'convert'
  return 'home'
}

function Header() {
  const path = window.location.pathname
  return (
    <header className="header">
      <nav className="nav">
        <a href="/" className={path === '/' ? 'nav-link active' : 'nav-link'}>Home</a>
        <a href="/short" className={path.startsWith('/short') ? 'nav-link active' : 'nav-link'}>W9 Short Links</a>
        <a href="/note" className={path.startsWith('/note') ? 'nav-link active' : 'nav-link'}>W9 Notepad</a>
        <a href="/convert" className={path.startsWith('/convert') ? 'nav-link active' : 'nav-link'}>W9 Converter</a>
      </nav>
    </header>
  )
}

function AdminLogin() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleLogin(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const params = new URLSearchParams()
      params.append('username', username)
      params.append('password', password)
      const resp = await fetch(adminApi('/login'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
        credentials: 'include'
      })
      const text = await resp.text()
      if (resp.ok) {
        window.location.href = '/admin'
      } else {
        try {
          const data = JSON.parse(text)
          setError(data.error || `Error: ${resp.status}`)
        } catch {
          setError(text || `HTTP ${resp.status}`)
        }
      }
    } catch (err: any) {
      setError(err?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <main className="container">
        <h1>Admin Login</h1>
        <form onSubmit={handleLogin} className="form" style={{ maxWidth: '300px' }}>
          <label className="label">
            Username
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="input"
              required
            />
          </label>
          <label className="label">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input"
              required
            />
          </label>
          {error && <div className="error">{error}</div>}
          <button type="submit" className="button" disabled={loading}>
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </main>
    </div>
  )
}

function AdminPanel() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deletingCode, setDeletingCode] = useState<string | null>(null)

  const handleLogout = async () => {
    try {
      const resp = await fetch(adminApi('/logout'), { 
        method: 'POST', 
        credentials: 'include' 
      })
      if (resp.ok) {
        window.location.href = '/'
      }
    } catch (err) {
      console.error('Logout error:', err)
      window.location.href = '/'
    }
  }

  const handleDelete = async (code: string, kind: string) => {
    if (!confirm(`Delete ${kind} item ${code}?`)) return
    setDeletingCode(`${code}:${kind}`)
    try {
      const resp = await fetch(adminApi(`/items/${code}/${kind}`), {
        method: 'POST',
        credentials: 'include'
      })
      if (resp.status === 401) {
        window.location.href = '/admin/login'
        return
      }
      if (resp.ok) {
        setItems(items.filter((i: any) => !(i.code === code && i.kind === kind)))
      } else {
        throw new Error(`Failed to delete: HTTP ${resp.status}`)
      }
    } catch (err: any) {
      alert(err?.message || 'Delete failed')
    } finally {
      setDeletingCode(null)
    }
  }

  useEffect(() => {
    const fetchItems = async () => {
      try {
        const resp = await fetch(adminApi('/items'), { credentials: 'include' })
        
        if (resp.status === 401) {
          window.location.href = '/admin/login'
          return
        }
        
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`)
        }
        
        const data = await resp.json()
        setItems(Array.isArray(data) ? data : [])
      } catch (err: any) {
        setError(err?.message || 'Failed to load items')
      } finally {
        setLoading(false)
      }
    }
    fetchItems()
  }, [])

  return (
    <div className="app">
      <main className="container">
        <h1>Admin Panel</h1>
        <button onClick={handleLogout} className="button">Logout</button>
        {loading && <p>Loading items...</p>}
        {error && <p style={{ color: 'red' }}>Error: {error}</p>}
        {!loading && !error && (
          <table style={{ width: '100%', marginTop: '20px', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Code</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Type</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Value</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr><td colSpan={4} style={{ padding: '8px', textAlign: 'center' }}>No items</td></tr>
              ) : (
                items.map((item: any) => (
                  <tr key={`${item.code}:${item.kind}`}>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{item.code}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{item.kind}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.value}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                      <button
                        onClick={() => handleDelete(item.code, item.kind)}
                        className="button"
                        style={{ fontSize: '12px' }}
                        disabled={deletingCode === `${item.code}:${item.kind}`}
                      >
                        {deletingCode === `${item.code}:${item.kind}` ? 'Deleting...' : 'Delete'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </main>
    </div>
  )
}

function Homepage() {
  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>W9 Tools — Share Fast</h1>
        <p className="subtitle">
          Lightweight toolkit for instant short links, markdown notepads, and upcoming converters. Open-source, privacy-conscious, always ready.
        </p>
        <div style={{ marginTop: '2rem' }}>
          <a href="https://github.com/ShayNeeo/w9-tools" target="_blank" rel="noreferrer" className="button" style={{ display: 'inline-block' }}>
            View on GitHub
          </a>
        </div>
      </main>
    </div>
  )
}

function ShortsPage() {
  const [urlInput, setUrlInput] = useState('')
  const [fileInput, setFileInput] = useState<File | null>(null)
  const [generateQr, setGenerateQr] = useState(false)
  const [customCode, setCustomCode] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<SuccessResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [imagePreview, setImagePreview] = useState<string | null>(null)
  const [fileInfo, setFileInfo] = useState<{ name: string; type: string; sizeKB: number } | null>(null)
  const [copySuccess, setCopySuccess] = useState(false)

  const fileRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    return () => {
      if (imagePreview) {
        URL.revokeObjectURL(imagePreview)
      }
    }
  }, [imagePreview])

  function handleUrlChange(v: string) {
    setUrlInput(v)
    if (fileInput) {
      if (fileRef.current) fileRef.current.value = ''
      setFileInput(null)
    }
  }

  function handleFileChange(file: File | null) {
    if (imagePreview) {
      URL.revokeObjectURL(imagePreview)
    }
    
    setFileInput(file)
    if (file) {
      setUrlInput('')
      if (file.type.startsWith('image/')) {
        const url = URL.createObjectURL(file)
        setImagePreview(url)
        setFileInfo({ name: file.name, type: file.type || guessMimeFromName(file.name), sizeKB: Math.round(file.size / 1024 * 10) / 10 })
      } else {
        setImagePreview(null)
        setFileInfo({ name: file.name, type: file.type || guessMimeFromName(file.name), sizeKB: Math.round(file.size / 1024 * 10) / 10 })
      }
    } else {
      setImagePreview(null)
      setFileInfo(null)
    }
  }

  function handleCustomCodeChange(v: string) {
    const cleaned = v.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase()
    setCustomCode(cleaned)
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      const hasUrl = urlInput.trim().length > 0
      const hasFile = !!fileInput
      if (!hasUrl && !hasFile) {
        setError('Please provide a URL or choose a file.')
        return
      }
      if (hasUrl && hasFile) {
        setError('Provide only one: URL or File, not both.')
        return
      }

      const form = new FormData()
      form.set('qr_required', generateQr ? 'true' : 'false')
      const trimmedCode = customCode.trim()
      if (trimmedCode) {
        form.set('custom_code', trimmedCode)
      }

      if (hasUrl) {
        form.set('content', urlInput.trim())
      } else if (hasFile && fileInput) {
        form.set('content', fileInput)
      }

      const resp = await fetch(joinUrl(API_BASE, '/api/upload'), {
        method: 'POST',
        body: form,
      })

      const data = (await resp.json()) as Result
      if (!resp.ok || (data as ErrorResult).success === false) {
        const msg = (data as ErrorResult).error || `HTTP ${resp.status}`
        throw new Error(msg)
      }

      const ok = data as SuccessResult
      setResult(ok)
    } catch (err: any) {
      setError(err?.message || 'Unexpected error')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>W9 Short Links</h1>
        <p className="subtitle">Share a link or upload a file · get a short URL with QR code</p>

        <form onSubmit={handleSubmit} className="form">
          <div
            className={`dropzone ${dragOver ? 'dragover' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const f = e.dataTransfer.files?.[0]
              if (f) handleFileChange(f)
            }}
            onPaste={(e) => {
              const items = e.clipboardData?.items
              if (!items) return
              for (let i = 0; i < items.length; i++) {
                const it = items[i]
                if (it.kind === 'file') {
                  const f = it.getAsFile()
                  if (f) { handleFileChange(f); break }
                }
                if (it.kind === 'string') {
                  it.getAsString((text) => {
                    if (/^https?:\/\//i.test(text.trim())) handleUrlChange(text.trim())
                  })
                }
              }
            }}
          >
            <div>Drop a file here, or paste a file or URL</div>
          </div>

          <label className="label">
            URL
            <input
              type="text"
              placeholder="https://example.com"
              value={urlInput}
              onChange={(e) => handleUrlChange(e.target.value)}
              className="input"
            />
          </label>

          <div className="or">or</div>

          <label className="label">
            File
            <input
              ref={fileRef}
              type="file"
              onChange={(e) => handleFileChange(e.target.files?.[0] || null)}
              className="input"
            />
          </label>

          <label className="label">
            Custom short code (optional)
            <div className="custom-code-row">
              <span className="code-prefix">/s/</span>
              <input
                type="text"
                value={customCode}
                onChange={(e) => handleCustomCodeChange(e.target.value)}
                className="input"
                placeholder="my-link"
                maxLength={32}
              />
            </div>
            <span className="hint">Letters, numbers, '-' and '_'. Minimum 3 characters.</span>
          </label>

          {imagePreview && (
            <div className="preview">
              <img src={imagePreview} alt="preview" />
            </div>
          )}
          {!imagePreview && fileInfo && (
            <div className="file-preview">
              <div><strong>Name:</strong> {fileInfo.name}</div>
              <div><strong>Type:</strong> {fileInfo.type || 'unknown'}</div>
              <div><strong>Size:</strong> {fileInfo.sizeKB} KB</div>
            </div>
          )}

          <label className="checkbox">
            <input
              type="checkbox"
              checked={generateQr}
              onChange={(e) => setGenerateQr(e.target.checked)}
            />
            Generate QR Code
          </label>

          <button type="submit" className="button" disabled={isLoading}>
            {isLoading ? 'Submitting…' : 'Create'}
          </button>
        </form>

        {isLoading && <div className="status">Submitting…</div>}
        {error && <div className="error">{error}</div>}
        {result && (
          <div className="result">
            <div className="row">
              <span className="label-inline">Short URL</span>
              <a href={toAbsoluteUrl(result.short_url)} className="link" target="_blank" rel="noreferrer">
                {toAbsoluteUrl(result.short_url)}
              </a>
              <button
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(toAbsoluteUrl(result.short_url))
                    setCopySuccess(true)
                    setTimeout(() => setCopySuccess(false), 2000)
                  } catch (err) {
                    console.error('Copy failed:', err)
                  }
                }}
                className="button"
                style={{ marginLeft: '10px', fontSize: '14px', padding: '5px 10px' }}
              >
                {copySuccess ? '✓ Copied' : 'Copy'}
              </button>
            </div>
            {result.qr_code_data && (
              <div className="qr">
                <img src={result.qr_code_data} alt="QR code" />
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

function NotepadPage() {
  const [content, setContent] = useState('')
  const [customCode, setCustomCode] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<{ short_url: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copySuccess, setCopySuccess] = useState(false)

  function handleCustomCodeChange(v: string) {
    const cleaned = v.replace(/[^a-zA-Z0-9-_]/g, '').toLowerCase()
    setCustomCode(cleaned)
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      if (!content.trim()) {
        setError('Please enter some content.')
        return
      }

      const form = new FormData()
      form.set('content', content.trim())
      const trimmedCode = customCode.trim()
      if (trimmedCode) {
        form.set('custom_code', trimmedCode)
      }

      const resp = await fetch(joinUrl(API_BASE, '/api/notepad'), {
        method: 'POST',
        body: form,
      })

      const data = (await resp.json()) as NotepadResult
      if (!resp.ok || !data.success) {
        const msg = data.success === false ? data.error : `HTTP ${resp.status}`
        throw new Error(msg)
      }

      setResult({ short_url: data.short_url })
    } catch (err: any) {
      setError(err?.message || 'Unexpected error')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>W9 Notepad</h1>
        <p className="subtitle">Quickly paste something and create a short link</p>

        <form onSubmit={handleSubmit} className="form">
          <label className="label">
            Content (Markdown supported)
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="input"
              rows={10}
              placeholder="Paste your content here... Markdown is supported."
            />
          </label>

          <label className="label">
            Custom short code (optional)
            <div className="custom-code-row">
              <span className="code-prefix">/n/</span>
              <input
                type="text"
                value={customCode}
                onChange={(e) => handleCustomCodeChange(e.target.value)}
                className="input"
                placeholder="my-note"
                maxLength={32}
              />
            </div>
            <span className="hint">Letters, numbers, '-' and '_'. Minimum 3 characters.</span>
          </label>

          <button type="submit" className="button" disabled={isLoading}>
            {isLoading ? 'Creating…' : 'Create Notepad'}
          </button>
        </form>

        {isLoading && <div className="status">Creating…</div>}
        {error && <div className="error">{error}</div>}
        {result && (
          <div className="result">
            <div className="row">
              <span className="label-inline">Notepad URL</span>
              <a href={toAbsoluteUrl(result.short_url)} className="link" target="_blank" rel="noreferrer">
                {toAbsoluteUrl(result.short_url)}
              </a>
              <button
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(toAbsoluteUrl(result.short_url))
                    setCopySuccess(true)
                    setTimeout(() => setCopySuccess(false), 2000)
                  } catch (err) {
                    console.error('Copy failed:', err)
                  }
                }}
                className="button"
                style={{ marginLeft: '10px', fontSize: '14px', padding: '5px 10px' }}
              >
                {copySuccess ? '✓ Copied' : 'Copy'}
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function ConverterPage() {
  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>W9 Converter</h1>
        <p className="subtitle">In development</p>
      </main>
    </div>
  )
}

export default function App() {
  const route = useRoute()

  if (route === 'admin-login') {
    return <AdminLogin />
  }
  if (route === 'admin') {
    return <AdminPanel />
  }
  if (route === 'home') {
    return <Homepage />
  }
  if (route === 'shorts') {
    return <ShortsPage />
  }
  if (route === 'note') {
    return <NotepadPage />
  }
  if (route === 'convert') {
    return <ConverterPage />
  }
  return <Homepage />
}

function joinUrl(base: string, path: string) {
  if (!base) return path
  if (!path.startsWith('/')) path = '/' + path
  return base.replace(/\/+$/, '') + path
}

function toAbsoluteUrl(u: string) {
  try {
    return new URL(u, window.location.origin).href
  } catch {
    return u
  }
}

function guessMimeFromName(name: string) {
  const lower = name.toLowerCase()
  if (/(\.png)$/.test(lower)) return 'image/png'
  if (/(\.jpe?g)$/.test(lower)) return 'image/jpeg'
  if (/(\.gif)$/.test(lower)) return 'image/gif'
  if (/(\.webp)$/.test(lower)) return 'image/webp'
  if (/(\.svg)$/.test(lower)) return 'image/svg+xml'
  if (/(\.pdf)$/.test(lower)) return 'application/pdf'
  if (/(\.txt)$/.test(lower)) return 'text/plain'
  if (/(\.md)$/.test(lower)) return 'text/markdown'
  if (/(\.csv)$/.test(lower)) return 'text/csv'
  if (/(\.json)$/.test(lower)) return 'application/json'
  if (/(\.zip)$/.test(lower)) return 'application/zip'
  if (/(\.tar)$/.test(lower)) return 'application/x-tar'
  if (/(\.gz)$/.test(lower)) return 'application/gzip'
  if (/(\.rar)$/.test(lower)) return 'application/vnd.rar'
  if (/(\.7z)$/.test(lower)) return 'application/x-7z-compressed'
  if (/(\.mp3)$/.test(lower)) return 'audio/mpeg'
  if (/(\.wav)$/.test(lower)) return 'audio/wav'
  if (/(\.flac)$/.test(lower)) return 'audio/flac'
  if (/(\.ogg)$/.test(lower)) return 'audio/ogg'
  if (/(\.mp4)$/.test(lower)) return 'video/mp4'
  if (/(\.mov)$/.test(lower)) return 'video/quicktime'
  if (/(\.webm)$/.test(lower)) return 'video/webm'
  return ''
}
