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
  if (path === '/login') return 'login'
  if (path === '/register') return 'register'
  if (path === '/profile') return 'profile'
  if (path === '/short' || path.startsWith('/short/')) return 'shorts'
  if (path === '/note' || path.startsWith('/note')) return 'note'
  if (path === '/convert' || path.startsWith('/convert')) return 'convert'
  return 'home'
}

function Header() {
  const path = window.location.pathname
  const [token, setToken] = useState<string | null>(localStorage.getItem('w9_token'))
  
  useEffect(() => {
    const checkToken = () => {
      setToken(localStorage.getItem('w9_token'))
    }
    window.addEventListener('storage', checkToken)
    return () => window.removeEventListener('storage', checkToken)
  }, [])
  
  const handleLogout = () => {
    localStorage.removeItem('w9_token')
    setToken(null)
    window.location.href = '/'
  }
  
  return (
    <header className="header">
      <nav className="nav">
        <a href="/" className={path === '/' ? 'nav-link active' : 'nav-link'}>Home</a>
        <a href="/short" className={path.startsWith('/short') ? 'nav-link active' : 'nav-link'}>W9 Short Links</a>
        <a href="/note" className={path.startsWith('/note') ? 'nav-link active' : 'nav-link'}>W9 Notepad</a>
        <a href="/convert" className={path.startsWith('/convert') ? 'nav-link active' : 'nav-link'}>W9 Converter</a>
        {token ? (
          <>
            <a href="/profile" className={path === '/profile' ? 'nav-link active' : 'nav-link'}>Profile</a>
            <button onClick={handleLogout} className="button" style={{ marginLeft: 'auto' }}>Logout</button>
          </>
        ) : (
          <>
            <a href="/login" className={path === '/login' ? 'nav-link active' : 'nav-link'}>Login</a>
            <a href="/register" className={path === '/register' ? 'nav-link active' : 'nav-link'}>Register</a>
          </>
        )}
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
  const [activeTab, setActiveTab] = useState<string>('all')
  const [adminSection, setAdminSection] = useState<string>('items') // 'items' or 'users'
  
  // User management state
  const [users, setUsers] = useState<any[]>([])
  const [usersLoading, setUsersLoading] = useState(false)
  const [usersError, setUsersError] = useState<string | null>(null)
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [newUserEmail, setNewUserEmail] = useState('')
  const [newUserPassword, setNewUserPassword] = useState('')
  const [newUserRole, setNewUserRole] = useState('user')
  const [editingUser, setEditingUser] = useState<string | null>(null)
  const [editUserRole, setEditUserRole] = useState('user')
  const [editUserMustChangePass, setEditUserMustChangePass] = useState(false)
  
  const token = localStorage.getItem('w9_token')

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

  useEffect(() => {
    if (adminSection === 'users' && token) {
      fetchUsers()
    }
  }, [adminSection, token])

  const fetchUsers = async () => {
    setUsersLoading(true)
    setUsersError(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/admin/users'), {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (resp.status === 401) {
        setUsersError('Unauthorized - Admin access required')
        return
      }
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`)
      }
      const data = await resp.json()
      setUsers(Array.isArray(data) ? data : [])
    } catch (err: any) {
      setUsersError(err?.message || 'Failed to load users')
    } finally {
      setUsersLoading(false)
    }
  }

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault()
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/admin/users'), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: newUserEmail,
          password: newUserPassword,
          role: newUserRole
        })
      })
      if (resp.ok) {
        setShowCreateUser(false)
        setNewUserEmail('')
        setNewUserPassword('')
        setNewUserRole('user')
        fetchUsers()
      } else {
        const data = await resp.json()
        alert(data.error || 'Failed to create user')
      }
    } catch (err: any) {
      alert(err?.message || 'Failed to create user')
    }
  }

  const handleUpdateUser = async (userId: string) => {
    try {
      const resp = await fetch(joinUrl(API_BASE, `/api/admin/users/${userId}`), {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          role: editUserRole,
          must_change_password: editUserMustChangePass
        })
      })
      if (resp.ok) {
        setEditingUser(null)
        fetchUsers()
      } else {
        const data = await resp.json()
        alert(data.error || 'Failed to update user')
      }
    } catch (err: any) {
      alert(err?.message || 'Failed to update user')
    }
  }

  const handleDeleteUser = async (userId: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return
    try {
      const resp = await fetch(joinUrl(API_BASE, `/api/admin/users/${userId}`), {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (resp.ok) {
        fetchUsers()
      } else {
        const data = await resp.json()
        alert(data.error || 'Failed to delete user')
      }
    } catch (err: any) {
      alert(err?.message || 'Failed to delete user')
    }
  }

  const handleSendPasswordReset = async (email: string) => {
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/admin/users/send-reset'), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      })
      if (resp.ok) {
        const data = await resp.json()
        alert(data.message || 'Password reset link sent')
      } else {
        const data = await resp.json()
        alert(data.error || 'Failed to send reset link')
      }
    } catch (err: any) {
      alert(err?.message || 'Failed to send reset link')
    }
  }

  const filteredItems = activeTab === 'all' 
    ? items 
    : items.filter((item: any) => item.kind === activeTab)

  return (
    <div className="app">
      <main className="container">
        <h1>Admin Panel</h1>
        <button onClick={handleLogout} className="button">Logout</button>
        
        <div style={{ marginTop: '20px', borderBottom: '1px solid #ddd' }}>
          <button
            onClick={() => setAdminSection('items')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: adminSection === 'items' ? '#007bff' : 'transparent',
              color: adminSection === 'items' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: adminSection === 'items' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            Items
          </button>
          <button
            onClick={() => setAdminSection('users')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: adminSection === 'users' ? '#007bff' : 'transparent',
              color: adminSection === 'users' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: adminSection === 'users' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            Users
          </button>
        </div>

        {adminSection === 'items' && (
          <>
        <div style={{ marginTop: '20px', borderBottom: '1px solid #ddd' }}>
          <button
            onClick={() => setActiveTab('all')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: activeTab === 'all' ? '#007bff' : 'transparent',
              color: activeTab === 'all' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: activeTab === 'all' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            All
          </button>
          <button
            onClick={() => setActiveTab('url')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: activeTab === 'url' ? '#007bff' : 'transparent',
              color: activeTab === 'url' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: activeTab === 'url' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            URLs
          </button>
          <button
            onClick={() => setActiveTab('file')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: activeTab === 'file' ? '#007bff' : 'transparent',
              color: activeTab === 'file' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: activeTab === 'file' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            Files
          </button>
          <button
            onClick={() => setActiveTab('notepad')}
            style={{
              padding: '10px 20px',
              marginRight: '10px',
              border: 'none',
              background: activeTab === 'notepad' ? '#007bff' : 'transparent',
              color: activeTab === 'notepad' ? 'white' : '#007bff',
              cursor: 'pointer',
              borderBottom: activeTab === 'notepad' ? '2px solid #007bff' : '2px solid transparent'
            }}
          >
            Notepads
          </button>
        </div>

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
              {filteredItems.length === 0 ? (
                <tr><td colSpan={4} style={{ padding: '8px', textAlign: 'center' }}>No items</td></tr>
              ) : (
                filteredItems.map((item: any) => (
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
          </>
        )}

        {adminSection === 'users' && (
          <>
            {!token && (
              <p style={{ color: 'red', marginTop: '20px' }}>
                Please login with w9-mail account to manage users. <a href="/login">Login here</a>
              </p>
            )}
            {token && (
              <>
                <div style={{ marginTop: '20px', marginBottom: '20px' }}>
                  <button onClick={() => setShowCreateUser(!showCreateUser)} className="button">
                    {showCreateUser ? 'Cancel' : 'Add User'}
                  </button>
                </div>

                {showCreateUser && (
                  <form onSubmit={handleCreateUser} className="form" style={{ maxWidth: '400px', marginBottom: '20px', padding: '20px', border: '1px solid #ddd', borderRadius: '4px' }}>
                    <h2>Create User</h2>
                    <label className="label">
                      Email
                      <input
                        type="email"
                        value={newUserEmail}
                        onChange={(e) => setNewUserEmail(e.target.value)}
                        className="input"
                        required
                      />
                    </label>
                    <label className="label">
                      Password
                      <input
                        type="password"
                        value={newUserPassword}
                        onChange={(e) => setNewUserPassword(e.target.value)}
                        className="input"
                        required
                        minLength={8}
                      />
                    </label>
                    <label className="label">
                      Role
                      <select
                        value={newUserRole}
                        onChange={(e) => setNewUserRole(e.target.value)}
                        className="input"
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                      </select>
                    </label>
                    <button type="submit" className="button">Create User</button>
                  </form>
                )}

                {usersLoading && <p>Loading users...</p>}
                {usersError && <p style={{ color: 'red' }}>Error: {usersError}</p>}
                {!usersLoading && !usersError && (
                  <table style={{ width: '100%', marginTop: '20px', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr>
                        <th style={{ border: '1px solid #ddd', padding: '8px' }}>Email</th>
                        <th style={{ border: '1px solid #ddd', padding: '8px' }}>Role</th>
                        <th style={{ border: '1px solid #ddd', padding: '8px' }}>Must Change Password</th>
                        <th style={{ border: '1px solid #ddd', padding: '8px' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.length === 0 ? (
                        <tr><td colSpan={4} style={{ padding: '8px', textAlign: 'center' }}>No users</td></tr>
                      ) : (
                        users.map((user: any) => (
                          <tr key={user.id}>
                            <td style={{ border: '1px solid #ddd', padding: '8px' }}>{user.email}</td>
                            <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                              {editingUser === user.id ? (
                                <select
                                  value={editUserRole}
                                  onChange={(e) => setEditUserRole(e.target.value)}
                                  className="input"
                                  style={{ width: '100px' }}
                                >
                                  <option value="user">User</option>
                                  <option value="admin">Admin</option>
                                </select>
                              ) : (
                                user.role
                              )}
                            </td>
                            <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                              {editingUser === user.id ? (
                                <input
                                  type="checkbox"
                                  checked={editUserMustChangePass}
                                  onChange={(e) => setEditUserMustChangePass(e.target.checked)}
                                />
                              ) : (
                                user.must_change_password ? 'Yes' : 'No'
                              )}
                            </td>
                            <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                              {editingUser === user.id ? (
                                <>
                                  <button
                                    onClick={() => handleUpdateUser(user.id)}
                                    className="button"
                                    style={{ fontSize: '12px', marginRight: '5px' }}
                                  >
                                    Save
                                  </button>
                                  <button
                                    onClick={() => {
                                      setEditingUser(null)
                                      setEditUserRole('user')
                                      setEditUserMustChangePass(false)
                                    }}
                                    className="button"
                                    style={{ fontSize: '12px' }}
                                  >
                                    Cancel
                                  </button>
                                </>
                              ) : (
                                <>
                                  <button
                                    onClick={() => {
                                      setEditingUser(user.id)
                                      setEditUserRole(user.role)
                                      setEditUserMustChangePass(user.must_change_password)
                                    }}
                                    className="button"
                                    style={{ fontSize: '12px', marginRight: '5px' }}
                                    disabled={editingUser !== null}
                                  >
                                    Edit
                                  </button>
                                  <button
                                    onClick={() => handleSendPasswordReset(user.email)}
                                    className="button"
                                    style={{ fontSize: '12px', marginRight: '5px' }}
                                    disabled={editingUser !== null}
                                  >
                                    Send Reset
                                  </button>
                                  <button
                                    onClick={() => handleDeleteUser(user.id)}
                                    className="button"
                                    style={{ fontSize: '12px' }}
                                    disabled={editingUser !== null}
                                  >
                                    Delete
                                  </button>
                                </>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </>
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

      const token = localStorage.getItem('w9_token')
      const headers: HeadersInit = {}
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }
      const resp = await fetch(joinUrl(API_BASE, '/api/upload'), {
        method: 'POST',
        headers,
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

      const token = localStorage.getItem('w9_token')
      const headers: HeadersInit = {}
      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }
      const resp = await fetch(joinUrl(API_BASE, '/api/notepad'), {
        method: 'POST',
        headers,
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

function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [showReset, setShowReset] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetLoading, setResetLoading] = useState(false)
  const [resetMessage, setResetMessage] = useState<string | null>(null)

  async function handleLogin(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      const data = await resp.json()
      if (resp.ok && data.token) {
        localStorage.setItem('w9_token', data.token)
        window.location.href = '/profile'
      } else {
        setError(data.error || 'Login failed')
      }
    } catch (err: any) {
      setError(err?.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  async function handlePasswordReset(e: FormEvent) {
    e.preventDefault()
    setResetLoading(true)
    setResetMessage(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/password-reset'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail })
      })
      const data = await resp.json()
      if (resp.ok) {
        setResetMessage(data.message || 'If the email exists, a reset link was sent.')
      } else {
        setResetMessage(data.error || 'Failed to send reset link')
      }
    } catch (err: any) {
      setResetMessage(err?.message || 'Failed to send reset link')
    } finally {
      setResetLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>Login</h1>
        {!showReset ? (
          <form onSubmit={handleLogin} className="form" style={{ maxWidth: '400px' }}>
            <label className="label">
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
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
            <p style={{ marginTop: '10px' }}>
              <a href="#" onClick={(e) => { e.preventDefault(); setShowReset(true); setResetEmail(email); }}>Forgot password?</a>
            </p>
            <p style={{ marginTop: '10px' }}>
              Don't have an account? <a href="/register">Register here</a>
            </p>
          </form>
        ) : (
          <form onSubmit={handlePasswordReset} className="form" style={{ maxWidth: '400px' }}>
            <h2>Reset Password</h2>
            <label className="label">
              Email
              <input
                type="email"
                value={resetEmail}
                onChange={(e) => setResetEmail(e.target.value)}
                className="input"
                required
              />
            </label>
            {resetMessage && (
              <div style={{ color: resetMessage.includes('error') ? 'red' : 'green', marginBottom: '10px' }}>
                {resetMessage}
              </div>
            )}
            <button type="submit" className="button" disabled={resetLoading}>
              {resetLoading ? 'Sending...' : 'Send Reset Link'}
            </button>
            <p style={{ marginTop: '10px' }}>
              <a href="#" onClick={(e) => { e.preventDefault(); setShowReset(false); setResetMessage(null); }}>Back to login</a>
            </p>
          </form>
        )}
      </main>
    </div>
  )
}

function RegisterPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleRegister(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/register'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      const data = await resp.json()
      if (resp.ok) {
        setSuccess(data.message || 'Registration successful! Please check your email for verification link.')
      } else {
        setError(data.error || data.message || 'Registration failed')
      }
    } catch (err: any) {
      setError(err?.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>Register</h1>
        <form onSubmit={handleRegister} className="form" style={{ maxWidth: '400px' }}>
          <label className="label">
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
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
              minLength={8}
            />
          </label>
          {error && <div className="error">{error}</div>}
          {success && <div style={{ color: 'green', marginBottom: '10px' }}>{success}</div>}
          <button type="submit" className="button" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
          <p style={{ marginTop: '10px' }}>
            Already have an account? <a href="/login">Login here</a>
          </p>
        </form>
      </main>
    </div>
  )
}

function ProfilePage() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deletingCode, setDeletingCode] = useState<string | null>(null)
  const [editingCode, setEditingCode] = useState<string | null>(null)
  const [newCode, setNewCode] = useState('')
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null)
  const [passwordLoading, setPasswordLoading] = useState(false)

  const token = localStorage.getItem('w9_token')

  useEffect(() => {
    if (!token) {
      window.location.href = '/login'
      return
    }
    fetchItems()
  }, [token])

  const fetchItems = async () => {
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/user/items'), {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (resp.status === 401) {
        localStorage.removeItem('w9_token')
        window.location.href = '/login'
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

  const handleDelete = async (code: string, kind: string) => {
    if (!confirm(`Delete ${kind} item ${code}?`)) return
    setDeletingCode(`${code}:${kind}`)
    try {
      const resp = await fetch(joinUrl(API_BASE, `/api/user/items/${code}/${kind}`), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (resp.status === 401) {
        localStorage.removeItem('w9_token')
        window.location.href = '/login'
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

  const handleUpdate = async (code: string, kind: string) => {
    if (!newCode.trim()) {
      alert('Please enter a new code')
      return
    }
    try {
      const resp = await fetch(joinUrl(API_BASE, `/api/user/items/${code}/${kind}/update`), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ new_code: newCode.trim() })
      })
      if (resp.status === 401) {
        localStorage.removeItem('w9_token')
        window.location.href = '/login'
        return
      }
      if (resp.ok) {
        const data = await resp.json()
        setItems(items.map((i: any) => 
          i.code === code && i.kind === kind 
            ? { ...i, code: data.code, short_url: data.short_url }
            : i
        ))
        setEditingCode(null)
        setNewCode('')
      } else {
        const data = await resp.json()
        alert(data.error || 'Update failed')
      }
    } catch (err: any) {
      alert(err?.message || 'Update failed')
    }
  }

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault()
    setPasswordError(null)
    setPasswordSuccess(null)
    
    if (newPassword !== confirmPassword) {
      setPasswordError('New passwords do not match')
      return
    }
    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters')
      return
    }
    
    setPasswordLoading(true)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/change-password'), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
          confirm_password: confirmPassword
        })
      })
      const data = await resp.json()
      if (resp.ok) {
        setPasswordSuccess(data.message || 'Password changed successfully')
        setOldPassword('')
        setNewPassword('')
        setConfirmPassword('')
        setShowChangePassword(false)
      } else {
        setPasswordError(data.error || 'Failed to change password')
      }
    } catch (err: any) {
      setPasswordError(err?.message || 'Failed to change password')
    } finally {
      setPasswordLoading(false)
    }
  }

  if (!token) {
    return null
  }

  return (
    <div className="app">
      <Header />
      <main className="container">
        <h1>My Profile</h1>
        <p className="subtitle">Manage your short links</p>
        
        <div style={{ marginBottom: '20px' }}>
          <button
            onClick={() => setShowChangePassword(!showChangePassword)}
            className="button"
          >
            {showChangePassword ? 'Cancel' : 'Change Password'}
          </button>
        </div>

        {showChangePassword && (
          <form onSubmit={handleChangePassword} className="form" style={{ maxWidth: '400px', marginBottom: '20px', padding: '20px', border: '1px solid #ddd', borderRadius: '4px' }}>
            <h2>Change Password</h2>
            <label className="label">
              Old Password
              <input
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                className="input"
                required
              />
            </label>
            <label className="label">
              New Password
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="input"
                required
                minLength={8}
              />
            </label>
            <label className="label">
              Confirm New Password
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="input"
                required
                minLength={8}
              />
            </label>
            {passwordError && <div className="error">{passwordError}</div>}
            {passwordSuccess && <div style={{ color: 'green', marginBottom: '10px' }}>{passwordSuccess}</div>}
            <button type="submit" className="button" disabled={passwordLoading}>
              {passwordLoading ? 'Changing...' : 'Change Password'}
            </button>
          </form>
        )}

        {loading && <p>Loading items...</p>}
        {error && <p style={{ color: 'red' }}>Error: {error}</p>}
        {!loading && !error && (
          <table style={{ width: '100%', marginTop: '20px', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Type</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Short URL</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Value</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <tr><td colSpan={4} style={{ padding: '8px', textAlign: 'center' }}>No items yet. Create some short links!</td></tr>
              ) : (
                items.map((item: any) => (
                  <tr key={`${item.code}:${item.kind}`}>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>{item.kind}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                      {editingCode === `${item.code}:${item.kind}` ? (
                        <div>
                          <input
                            type="text"
                            value={newCode}
                            onChange={(e) => setNewCode(e.target.value)}
                            className="input"
                            style={{ width: '150px', marginRight: '5px' }}
                            placeholder="new-code"
                          />
                          <button
                            onClick={() => handleUpdate(item.code, item.kind)}
                            className="button"
                            style={{ fontSize: '12px', marginRight: '5px' }}
                          >
                            Save
                          </button>
                          <button
                            onClick={() => {
                              setEditingCode(null)
                              setNewCode('')
                            }}
                            className="button"
                            style={{ fontSize: '12px' }}
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <a href={item.short_url} target="_blank" rel="noreferrer">{item.short_url}</a>
                      )}
                    </td>
                    <td style={{ border: '1px solid #ddd', padding: '8px', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.value}</td>
                    <td style={{ border: '1px solid #ddd', padding: '8px' }}>
                      <button
                        onClick={() => {
                          setEditingCode(`${item.code}:${item.kind}`)
                          setNewCode(item.code)
                        }}
                        className="button"
                        style={{ fontSize: '12px', marginRight: '5px' }}
                        disabled={editingCode !== null}
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(item.code, item.kind)}
                        className="button"
                        style={{ fontSize: '12px' }}
                        disabled={deletingCode === `${item.code}:${item.kind}` || editingCode !== null}
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

export default function App() {
  const route = useRoute()

  if (route === 'admin-login') {
    return <AdminLogin />
  }
  if (route === 'admin') {
    return <AdminPanel />
  }
  if (route === 'login') {
    return <LoginPage />
  }
  if (route === 'register') {
    return <RegisterPage />
  }
  if (route === 'profile') {
    return <ProfilePage />
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
