import { useState, useRef, FormEvent, useEffect } from 'react'

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

// Simple router
function useRoute() {
  const path = window.location.pathname
  if (path === '/admin/login') return 'admin-login'
  if (path.startsWith('/admin')) return 'admin'
  return 'home'
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
      const form = new FormData()
      form.append('username', username)
      form.append('password', password)
      const resp = await fetch(adminApi('/login'), {
        method: 'POST',
        body: form,
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

  useEffect(() => {
    const fetchItems = async () => {
      try {
        const resp = await fetch(adminApi('/items'), { credentials: 'include' })
        console.log('admin/items response status:', resp.status)
        console.log('admin/items response headers:', resp.headers.get('content-type'))
        
        if (resp.status === 401) {
          console.log('Not authenticated, redirecting to login')
          window.location.href = '/admin/login'
          return
        }
        
        const text = await resp.text()
        console.log('admin/items response text:', text.substring(0, 200))
        
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}: ${text}`)
        }
        
        if (!text || text.trim() === '') {
          console.log('Empty response, setting empty items')
          setItems([])
          setLoading(false)
          return
        }
        
        try {
          const data = JSON.parse(text)
          console.log('Parsed items:', data)
          setItems(Array.isArray(data) ? data : [])
        } catch (parseErr) {
          console.error('JSON parse error:', parseErr, 'text was:', text.substring(0, 500))
          throw new Error(`JSON parse error: ${parseErr}`)
        }
      } catch (err: any) {
        console.error('admin/items error:', err)
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
                  <tr key={item.code}>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{item.code}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{item.kind}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.value}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                      <button
                        onClick={async () => {
                          const resp = await fetch(adminApi(`/items/${item.code}`), {
                            method: 'POST',
                            credentials: 'include'
                          })
                          if (resp.ok) {
                            setItems(items.filter((i: any) => i.code !== item.code))
                          }
                        }}
                        className="button"
                        style={{ fontSize: '12px' }}
                      >
                        Delete
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

export default function App() {
  const route = useRoute()

  if (route === 'admin-login') {
    return <AdminLogin />
  }
  if (route === 'admin') {
    return <AdminPanel />
  }
  const [urlInput, setUrlInput] = useState('')
  const [fileInput, setFileInput] = useState<File | null>(null)
  const [generateQr, setGenerateQr] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<SuccessResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [imagePreview, setImagePreview] = useState<string | null>(null)
  const [fileInfo, setFileInfo] = useState<{ name: string; type: string; sizeKB: number } | null>(null)

  const fileRef = useRef<HTMLInputElement | null>(null)

  function handleUrlChange(v: string) {
    setUrlInput(v)
    if (fileInput) {
      // Clear file if URL is being typed
      if (fileRef.current) fileRef.current.value = ''
      setFileInput(null)
    }
  }

  function handleFileChange(file: File | null) {
    setFileInput(file)
    if (file) {
      // Clear URL if a file is chosen
      setUrlInput('')
      if (file.type.startsWith('image/')) {
        const url = URL.createObjectURL(file)
        setImagePreview(url)
        setFileInfo({ name: file.name, type: file.type || guessMimeFromName(file.name), sizeKB: Math.round(file.size / 102.4) / 10 })
      } else {
        setImagePreview(null)
        setFileInfo({ name: file.name, type: file.type || guessMimeFromName(file.name), sizeKB: Math.round(file.size / 102.4) / 10 })
      }
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    setResult(null)

    try {
      // Validate inputs
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
      <main className="container">
        <h1>w9</h1>
        <p className="subtitle">Share a link or upload a file · get a short URL</p>

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
