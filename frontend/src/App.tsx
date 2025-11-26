import { useState, useRef, FormEvent, useEffect } from 'react'
import { marked } from 'marked'

const API_BASE: string = import.meta.env?.VITE_API_BASE_URL || ''
const TURNSTILE_SITE_KEY: string = import.meta.env?.VITE_TURNSTILE_SITE_KEY || ''

declare global {
  interface Window {
    turnstile?: {
      render: (element: string | HTMLElement, options: {
        sitekey: string
        callback?: (token: string) => void
        'error-callback'?: () => void
        'expired-callback'?: () => void
      }) => string
      reset: (widgetId?: string) => void
      remove: (widgetId?: string) => void
    }
  }
}

function TurnstileWidget({ onVerify, onError }: { onVerify: (token: string) => void; onError?: () => void }) {
  const widgetRef = useRef<HTMLDivElement>(null)
  const widgetIdRef = useRef<string | null>(null)
  const onVerifyRef = useRef(onVerify)
  const onErrorRef = useRef(onError)

  // Update refs when callbacks change
  useEffect(() => {
    onVerifyRef.current = onVerify
    onErrorRef.current = onError
  }, [onVerify, onError])

  useEffect(() => {
    if (!TURNSTILE_SITE_KEY || !widgetRef.current) return

    const checkTurnstile = () => {
      if (window.turnstile && widgetRef.current && !widgetIdRef.current) {
        widgetIdRef.current = window.turnstile.render(widgetRef.current, {
          sitekey: TURNSTILE_SITE_KEY,
          callback: (token: string) => {
            onVerifyRef.current(token)
          },
          'error-callback': () => {
            if (onErrorRef.current) onErrorRef.current()
          },
          'expired-callback': () => {
            if (widgetIdRef.current) {
              window.turnstile?.reset(widgetIdRef.current)
            }
          }
        })
      } else if (!window.turnstile) {
        setTimeout(checkTurnstile, 100)
      }
    }

    checkTurnstile()

    return () => {
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current)
        widgetIdRef.current = null
      }
    }
  }, []) // Empty dependency array - only run once

  if (!TURNSTILE_SITE_KEY) {
    return null
  }

  return <div ref={widgetRef} style={{ marginTop: '1rem' }}></div>
}
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
  qr_code_data: string | null
} | {
  success: false
  error: string
}

type EmailSenderOption = {
  sender_type: string
  sender_id: string
  email: string
  display_label: string
  via_display?: string
  is_active: boolean
}

type EmailSenderConfig = {
  sender_type?: string
  sender_id?: string
  email: string
  display_label?: string
  via_display?: string
} | null

// Simple router
const NETWORK_LINKS = [
  { id: 'tools', label: 'W9 Tools', description: 'w9.se · Links & drops', href: '/', external: false },
  { id: 'mail', label: 'W9 Mail', description: 'w9.nu · Transactional rail', href: 'https://w9.nu', external: true },
  { id: 'reminders', label: 'W9 Daily Reminders', description: 'reminder.w9.nu · Calendar digest', href: 'https://reminder.w9.nu', external: true },
] as const

type NetworkId = (typeof NETWORK_LINKS)[number]['id']

function NetworkBar({ active }: { active: NetworkId }) {
  return (
    <div className="network-bar">
      <div>
        <span className="network-label">W9 Labs Network</span>
        <span className="network-tagline">Open-source automation for independent teams</span>
      </div>
      <nav className="network-links">
        {NETWORK_LINKS.map((link) => {
          const className = `network-link ${active === link.id ? 'active' : ''}`
          return link.external ? (
            <a key={link.id} href={link.href} target="_blank" rel="noreferrer" className={className}>
              <span>{link.label}</span>
              <small>{link.description}</small>
            </a>
          ) : (
            <a key={link.id} href={link.href} className={className}>
              <span>{link.label}</span>
              <small>{link.description}</small>
            </a>
          )
        })}
      </nav>
    </div>
  )
}

function useRoute() {
  const path = window.location.pathname
  if (path.startsWith('/admin')) return 'admin'
  if (path === '/login') return 'login'
  if (path === '/register') return 'register'
  if (path === '/verify' || path === '/verify-email') return 'verify'
  if (path === '/reset-password') return 'reset-password'
  if (path === '/profile') return 'profile'
  if (path === '/short' || path.startsWith('/short/')) return 'shorts'
  if (path === '/note' || path.startsWith('/note')) return 'note'
  if (path === '/convert' || path.startsWith('/convert')) return 'convert'
  if (path === '/privacy') return 'privacy'
  if (path === '/terms') return 'terms'
  return 'home'
}

function Header() {
  const path = window.location.pathname
  const [token, setToken] = useState<string | null>(localStorage.getItem('w9_token'))
  const isHomepage = path === '/' || path === ''
  
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
      <NetworkBar active="tools" />
      <div className="brand">
        <div>
          <p className="eyebrow">Developed by W9 Labs</p>
          <h1>W9 Tools</h1>
          <span>Fast drops • Short links • Secure notes</span>
        </div>
        <div className="pill" style={{ borderColor: token ? '#00ffd0' : undefined, color: token ? '#00ffd0' : undefined }}>
          {token ? 'SIGNED IN' : 'GUEST'}
        </div>
      </div>
      <nav className="nav">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
          <a href="/" className={path === '/' ? 'nav-link active' : 'nav-link'}>Home</a>
          <a href="/short" className={path.startsWith('/short') ? 'nav-link active' : 'nav-link'}>Short Links</a>
          <a href="/note" className={path.startsWith('/note') ? 'nav-link active' : 'nav-link'}>Notepad</a>
          <a href="/convert" className={path.startsWith('/convert') ? 'nav-link active' : 'nav-link'}>Converter</a>
          <a href="/profile" className={path === '/profile' ? 'nav-link active' : 'nav-link'}>Profile</a>
          <a href="/admin" className={path.startsWith('/admin') ? 'nav-link active' : 'nav-link'}>Admin</a>
          <a href="/terms" className={path === '/terms' ? 'nav-link active' : 'nav-link'}>Terms</a>
          <a href="/privacy" className={path === '/privacy' ? 'nav-link active' : 'nav-link'}>Privacy</a>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {token ? (
            <button onClick={handleLogout} className="button secondary">Logout</button>
          ) : (
            <>
              <a href="/login" className={path === '/login' ? 'nav-link active' : 'nav-link'}>Login</a>
              <a href="/register" className={path === '/register' ? 'nav-link active' : 'nav-link'}>Register</a>
            </>
          )}
        </div>
      </nav>
    </header>
  )
}

function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-columns">
        <div>
          <div className="footer-title">Developed by W9 Labs</div>
          <p className="footer-copy">
            W9 Tools powers the public landing page for the W9 Labs network. Short links, note drops, and admin surfaces are open-source
            and community audited. Contact <a href="mailto:hi@w9.se">hi@w9.se</a>.
          </p>
        </div>
        <div>
          <div className="footer-title">Network</div>
          <ul className="footer-links">
            <li>
              <a href="https://w9.se" target="_blank" rel="noreferrer">
                W9 Tools · Links & drops
              </a>
            </li>
            <li>
              <a href="https://w9.nu" target="_blank" rel="noreferrer">
                W9 Mail · Transactional rail
              </a>
            </li>
            <li>
              <a href="https://reminder.w9.nu" target="_blank" rel="noreferrer">
                W9 Daily Reminders · Calendar digest
              </a>
            </li>
          </ul>
        </div>
        <div>
          <div className="footer-title">Legal</div>
          <ul className="footer-links">
            <li><a href="/terms">Terms of Service</a></li>
            <li><a href="/privacy">Privacy Notice</a></li>
          </ul>
        </div>
      </div>
      <div className="footer-bottom">© {new Date().getFullYear()} W9 Labs · Open infrastructure for independent teams.</div>
    </footer>
  )
}


function AdminPanel() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deletingCode, setDeletingCode] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<string>('all')
  const [expandedItem, setExpandedItem] = useState<any | null>(null)
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
  const [senderOptions, setSenderOptions] = useState<EmailSenderOption[]>([])
  const [currentSender, setCurrentSender] = useState<EmailSenderConfig>(null)
  const [senderLoading, setSenderLoading] = useState(false)
  const [senderError, setSenderError] = useState<string | null>(null)
  
  const [token, setToken] = useState<string | null>(localStorage.getItem('w9_token'))

  useEffect(() => {
    // Check token on mount and update state
    const currentToken = localStorage.getItem('w9_token')
    setToken(currentToken)
    
    if (!currentToken) {
      window.location.href = '/login?redirect=/admin'
      return
    }
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('w9_token')
    window.location.href = '/'
  }

  const handleDelete = async (code: string, kind: string) => {
    if (!token) return
    if (!confirm(`Delete ${kind} item ${code}?`)) return
    setDeletingCode(`${code}:${kind}`)
    try {
      const resp = await fetch(adminApi(`/items/${code}/${kind}`), {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (resp.status === 401) {
        // Token invalid or expired
        localStorage.removeItem('w9_token')
        window.location.href = '/login?redirect=/admin'
        return
      }
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          alert('Admin access required. You need to be logged in as an admin user.')
        })
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
    if (!token) return
    
    const fetchItems = async () => {
      try {
        const resp = await fetch(adminApi('/items'), {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })
        
        if (resp.status === 401) {
          // Token invalid or expired
          localStorage.removeItem('w9_token')
          window.location.href = '/login?redirect=/admin'
          return
        }
        if (resp.status === 403) {
          await handleForbiddenResponse(resp, () => {
            setError('Admin access required. You need to be logged in as an admin user.')
            setLoading(false)
          })
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
  }, [token])

  useEffect(() => {
    if (adminSection === 'users' && token) {
      fetchUsers()
    }
  }, [adminSection, token])

  useEffect(() => {
    if (adminSection === 'email' && token) {
      fetchSenderSettings()
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
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          setUsersError('Admin access required')
        })
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
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          alert('Admin access required')
        })
        return
      }
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
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          alert('Admin access required')
        })
        return
      }
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
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          alert('Admin access required')
        })
        return
      }
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

  const redirectToPasswordChange = () => {
    alert('Password update required. Please change your password before using admin tools.')
    window.location.href = '/profile?force=password'
  }

  const handleForbiddenResponse = async (resp: Response, onFallback: () => void) => {
    const text = await resp.text()
    if (text && text.includes('Password update required')) {
      redirectToPasswordChange()
    } else {
      onFallback()
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
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          alert('Admin access required')
        })
        return
      }
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

  const fetchSenderSettings = async () => {
    if (!token) return
    setSenderLoading(true)
    setSenderError(null)
    try {
      const [optionsResp, currentResp] = await Promise.all([
        fetch(joinUrl(API_BASE, '/api/admin/email/senders'), {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(joinUrl(API_BASE, '/api/admin/email/sender'), {
          headers: { 'Authorization': `Bearer ${token}` }
        })
      ])

      if (optionsResp.status === 403) {
        await handleForbiddenResponse(optionsResp, () => {
          setSenderError('Admin access required')
        })
        return
      }
      if (optionsResp.ok) {
        const data = await optionsResp.json()
        setSenderOptions(Array.isArray(data.options) ? data.options : [])
      } else {
        const data = await optionsResp.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to load sender options')
      }

      if (currentResp.status === 403) {
        await handleForbiddenResponse(currentResp, () => {
          setSenderError('Admin access required')
        })
        return
      }
      if (currentResp.ok) {
        const data = await currentResp.json()
        setCurrentSender(data.sender || null)
      } else {
        setCurrentSender(null)
      }
    } catch (err: any) {
      setSenderError(err?.message || 'Failed to load sender configuration')
    } finally {
      setSenderLoading(false)
    }
  }

  const handleSelectSender = async (option: EmailSenderOption) => {
    if (!token) return
    setSenderLoading(true)
    setSenderError(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/admin/email/sender'), {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sender_type: option.sender_type,
          sender_id: option.sender_id,
          email: option.email,
          display_label: option.display_label,
          via_display: option.via_display
        })
      })
      if (resp.status === 403) {
        await handleForbiddenResponse(resp, () => {
          setSenderError('Admin access required')
        })
        return
      }
      const data = await resp.json()
      if (!resp.ok) {
        throw new Error(data.error || 'Failed to update sender')
      }
      setCurrentSender(data.sender || null)
    } catch (err: any) {
      setSenderError(err?.message || 'Failed to update sender')
    } finally {
      setSenderLoading(false)
    }
  }

  const filteredItems = activeTab === 'all' 
    ? items 
    : items.filter((item: any) => item.kind === activeTab)

  const adminTabs = [
    { id: 'items', label: 'Items' },
    { id: 'users', label: 'Users' },
    { id: 'email', label: 'Email Sender' },
  ] as const

  const itemFilters = [
    { id: 'all', label: 'All' },
    { id: 'url', label: 'URLs' },
    { id: 'file', label: 'Files' },
    { id: 'notepad', label: 'Notepads' },
  ] as const

  return (
    <div className="app">
      <Header />
      <div className="page-shell">
      <main className="panel">
        <h1>Admin Panel</h1>
        
        <div className="admin-tabs">
          {adminTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setAdminSection(tab.id)}
              className={`admin-tab ${adminSection === tab.id ? 'active' : ''}`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {adminSection === 'items' && (
          <>
            <div className="admin-tabs" style={{ marginTop: '1rem' }}>
              {itemFilters.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`admin-tab ${activeTab === tab.id ? 'active' : ''}`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {loading && <p>Loading items...</p>}
            {error && <p style={{ color: 'red' }}>Error: {error}</p>}
            {!loading && !error && (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Code</th>
                      <th>Type</th>
                      <th>Value</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredItems.length === 0 ? (
                      <tr><td colSpan={4} style={{ textAlign: 'center' }}>No items</td></tr>
                    ) : (
                      filteredItems.map((item: any) => (
                        <tr key={`${item.code}:${item.kind}`}>
                          <td>{item.code}</td>
                          <td>{item.kind}</td>
                          <td className="table-cell-truncate">{item.value}</td>
                          <td>
                            <div className="table-actions">
                              <button
                                className="button ghost"
                                type="button"
                                onClick={() => setExpandedItem(item)}
                              >
                                View
                              </button>
                              <button
                                onClick={() => handleDelete(item.code, item.kind)}
                                className="button"
                                disabled={deletingCode === `${item.code}:${item.kind}`}
                              >
                                {deletingCode === `${item.code}:${item.kind}` ? 'Deleting...' : 'Delete'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
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
                  <div className="table-wrapper" style={{ marginTop: '1rem' }}>
                    <table>
                      <thead>
                        <tr>
                          <th>Email</th>
                          <th>Role</th>
                          <th>Must Change</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.length === 0 ? (
                          <tr><td colSpan={4} style={{ textAlign: 'center' }}>No users</td></tr>
                        ) : (
                          users.map((user: any) => (
                            <tr key={user.id}>
                              <td className="table-cell-truncate">{user.email}</td>
                              <td>
                                {editingUser === user.id ? (
                                  <select
                                    value={editUserRole}
                                    onChange={(e) => setEditUserRole(e.target.value)}
                                    className="input"
                                  >
                                    <option value="user">User</option>
                                    <option value="admin">Admin</option>
                                  </select>
                                ) : (
                                  user.role
                                )}
                              </td>
                              <td>
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
                              <td>
                                <div className="table-actions">
                                  {editingUser === user.id ? (
                                    <>
                                      <button
                                        onClick={() => handleUpdateUser(user.id)}
                                        className="button"
                                      >
                                        Save
                                      </button>
                                      <button
                                        onClick={() => {
                                          setEditingUser(null)
                                          setEditUserRole('user')
                                          setEditUserMustChangePass(false)
                                        }}
                                        className="button ghost"
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
                                        className="button ghost"
                                        disabled={editingUser !== null}
                                      >
                                        Edit
                                      </button>
                                      <button
                                        onClick={() => handleSendPasswordReset(user.email)}
                                        className="button ghost"
                                        disabled={editingUser !== null}
                                      >
                                        Send Reset
                                      </button>
                                      <button
                                        onClick={() => handleDeleteUser(user.id)}
                                        className="button"
                                        disabled={editingUser !== null}
                                      >
                                        Delete
                                      </button>
                                    </>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </>
        )}

        {adminSection === 'email' && (
          <section style={{ marginTop: '1.5rem' }}>
            <p className="subtitle">Choose which w9.mail account or alias should send verification + reset emails for w9-tools.</p>
            <div className="banner" style={{ marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', gap: '1rem', alignItems: 'center' }}>
              <div>
                <div style={{ fontSize: '0.85rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>Current sender</div>
                {currentSender ? (
                  <strong>{currentSender.display_label || currentSender.email}</strong>
                ) : (
                  <span>No sender configured</span>
                )}
              </div>
              <button className="button secondary" onClick={fetchSenderSettings} disabled={senderLoading}>
                {senderLoading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>
            {senderError && <p style={{ color: '#ff6b6b' }}>{senderError}</p>}
            {senderLoading && senderOptions.length === 0 && <p>Loading sender options...</p>}
            {!senderLoading && senderOptions.length === 0 && (
              <p style={{ color: 'var(--muted)' }}>No senders available from w9.mail. Add accounts or aliases there first.</p>
            )}
            {senderOptions.length > 0 && (
              <div className="sender-grid">
                {senderOptions.map((option) => {
                  const isCurrent = currentSender && currentSender.email === option.email
                  return (
                    <div key={`${option.sender_type}:${option.sender_id}`} className={`sender-card ${!option.is_active ? 'inactive' : ''}`}>
                      <div className={`tag ${option.sender_type}`}>
                        {option.sender_type === 'alias' ? 'Alias' : 'Account'}
                        {isCurrent && <span style={{ color: '#00ffd0' }}>• Current</span>}
                      </div>
                      <h4>{option.display_label}</h4>
                      <div className="sender-meta">{option.email}</div>
                      {option.via_display && (
                        <div className="sender-meta">via {option.via_display}</div>
                      )}
                      {!option.is_active && (
                        <div className="hint">Inactive sender in w9.mail</div>
                      )}
                      <div className="sender-actions">
                        <button
                          className="button"
                          disabled={isCurrent || senderLoading || !option.is_active}
                          onClick={() => handleSelectSender(option)}
                        >
                          {isCurrent ? 'Selected' : 'Use Sender'}
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </section>
        )}

        {expandedItem && (
          <div className="dialog-backdrop" onClick={() => setExpandedItem(null)}>
            <div className="dialog" onClick={(e) => e.stopPropagation()}>
              <h2 className="section-title">Item Details</h2>
              <p><strong>Code:</strong> {expandedItem.code}</p>
              <p><strong>Type:</strong> {expandedItem.kind}</p>
              {expandedItem.short_url && (
                <p>
                  <strong>Short URL:</strong>{' '}
                  <a href={toAbsoluteUrl(expandedItem.short_url)} target="_blank" rel="noreferrer" className="link">
                    {toAbsoluteUrl(expandedItem.short_url)}
                  </a>
                </p>
              )}
              <p><strong>Value:</strong></p>
              <pre className="value-block">{expandedItem.value}</pre>
              <div className="actions" style={{ marginTop: '1rem' }}>
                <button className="button" onClick={() => setExpandedItem(null)}>Close</button>
              </div>
            </div>
          </div>
        )}
      </main>
      </div>
      <Footer />
    </div>
  )
}

function Homepage() {
  return (
    <div className="app">
      <Header />
      <main className="page">
        <section className="box" style={{ textAlign: 'center' }}>
          <h1>W9 Labs</h1>
          <p className="subtitle" style={{ marginBottom: '1rem' }}>
            <strong>Open Source. Community Driven. Non-Profit.</strong>
          </p>
          <div className="actions" style={{ justifyContent: 'center', marginBottom: '1.5rem' }}>
            <a href="https://w9.se" className="button ghost" target="_blank" rel="noreferrer">HQ · w9.se</a>
            <a href="https://w9.nu" className="button ghost" target="_blank" rel="noreferrer">Hub · w9.nu</a>
          </div>
          <p style={{ marginBottom: '1.5rem' }}>
            <b>W9 Labs</b> is a non-profit collective dedicated to building accessible, transparent, and robust open-source software. We believe technology should be a commons, built by the community, for the community.
          </p>
        </section>

        <section className="box">
          <h2 className="section-title">Who We Are</h2>
          <p className="justify">
            We are a team of developers, designers, and enthusiasts working together to create tools that empower users. As a non-profit initiative, our primary stakeholders are our users and contributors, not shareholders.
          </p>
          <div style={{ marginTop: '1rem' }}>
            <p><strong>Our Domains</strong></p>
            <ul className="list">
              <li><a href="https://w9.se" target="_blank" rel="noreferrer">w9.se</a>: Our organizational home, governance, and long-term documentation.</li>
              <li><a href="https://w9.nu" target="_blank" rel="noreferrer">w9.nu</a>: Our release hub, community showcase, and "what's happening now."</li>
            </ul>
          </div>
        </section>

        <section className="box">
          <h2 className="section-title">Our Mission</h2>
          <ul className="list">
            <li><strong>Openness:</strong> Every line of code we produce is open source and auditable.</li>
            <li><strong>Community First:</strong> We prioritize user privacy, data sovereignty, and community feedback.</li>
            <li><strong>Sustainability:</strong> We build software designed to last, focusing on stability and performance.</li>
          </ul>
        </section>

        <section className="box">
          <h2 className="section-title">What We Build</h2>
          <p>We focus on developing solutions in the following areas:</p>
          <ul className="list">
            <li><strong>Core Infrastructure:</strong> Tools to help self-hosters and sysadmins.</li>
            <li><strong>Privacy Tools:</strong> Utilities that protect user identity on the modern web.</li>
            <li><strong>Community Utilities:</strong> Libraries and scripts to improve developer workflows.</li>
          </ul>
          <div className="actions" style={{ marginTop: '1rem' }}>
            <a href="/short" className="button">W9 Tools</a>
            <a href="https://w9.nu" className="button ghost" target="_blank" rel="noreferrer">W9 Mail</a>
            <a href="https://github.com/orgs/w9-labs/repositories" className="button ghost" target="_blank" rel="noreferrer">View Repositories</a>
          </div>
        </section>

        <section className="box">
          <h2 className="section-title">Contributing</h2>
          <p>
            We welcome contributors of all skill levels! Whether you are fixing a typo, refactoring code, or designing a logo, your help is appreciated.
          </p>
          <p style={{ marginTop: '0.5rem' }}>
            <strong>How to join the fun:</strong>
          </p>
          <ol style={{ listStyle: 'decimal', paddingLeft: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <li>Explore our repositories and look for the <code>good first issue</code> label.</li>
            <li>Fork the repo and create a branch.</li>
            <li>Submit a Pull Request (PR).</li>
          </ol>
        </section>

        <section className="box sponsorship">
          <h2 className="section-title">Sponsorship</h2>
          <p className="sponsor-intro">
            These organizations keep the lights on for the community build process. Their tooling and kindness help W9 Labs continue releasing open infrastructure.
          </p>
          <div className="sponsor-logos">
            <div className="sponsor-card">
              <div className="sponsor-logo" aria-label="1Password">
                <img src="/1password.svg" alt="1Password logo" />
              </div>
              <p className="sponsor-credit">Courtesy of 1Password · secure storage partner</p>
            </div>
            <div className="sponsor-card">
              <div className="sponsor-logo" aria-label="Core sponsor">
                <svg
                  className="css-lfbo6j e1igk8x04"
                  xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 222 66"
                  width="220"
                  height="66"
                >
                  <path
                    d="M29,2.26a4.67,4.67,0,0,0-8,0L14.42,13.53A32.21,32.21,0,0,1,32.17,40.19H27.55A27.68,27.68,0,0,0,12.09,17.47L6,28a15.92,15.92,0,0,1,9.23,12.17H4.62A.76.76,0,0,1,4,39.06l2.94-5a10.74,10.74,0,0,0-3.36-1.9l-2.91,5a4.54,4.54,0,0,0,1.69,6.24A4.66,4.66,0,0,0,4.62,44H19.15a19.4,19.4,0,0,0-8-17.31l2.31-4A23.87,23.87,0,0,1,23.76,44H36.07a35.88,35.88,0,0,0-16.41-31.8l4.67-8a.77.77,0,0,1,1.05-.27c.53.29,20.29,34.77,20.66,35.17a.76.76,0,0,1-.68,1.13H40.6q.09,1.91,0,3.81h4.78A4.59,4.59,0,0,0,50,39.43a4.49,4.49,0,0,0-.62-2.28Z M124.32,28.28,109.56,9.22h-3.68V34.77h3.73V15.19l15.18,19.58h3.26V9.22h-3.73ZM87.15,23.54h13.23V20.22H87.14V12.53h14.93V9.21H83.34V34.77h18.92V31.45H87.14ZM71.59,20.3h0C66.44,19.06,65,18.08,65,15.7c0-2.14,1.89-3.59,4.71-3.59a12.06,12.06,0,0,1,7.07,2.55l2-2.83a14.1,14.1,0,0,0-9-3c-5.06,0-8.59,3-8.59,7.27,0,4.6,3,6.19,8.46,7.52C74.51,24.74,76,25.78,76,28.11s-2,3.77-5.09,3.77a12.34,12.34,0,0,1-8.3-3.26l-2.25,2.69a15.94,15.94,0,0,0,10.42,3.85c5.48,0,9-2.95,9-7.51C79.75,23.79,77.47,21.72,71.59,20.3ZM195.7,9.22l-7.69,12-7.64-12h-4.46L186,24.67V34.78h3.84V24.55L200,9.22Zm-64.63,3.46h8.37v22.1h3.84V12.68h8.37V9.22H131.08ZM169.41,24.8c3.86-1.07,6-3.77,6-7.63,0-4.91-3.59-8-9.38-8H154.67V34.76h3.8V25.58h6.45l6.48,9.2h4.44l-7-9.82Zm-10.95-2.5V12.6h7.17c3.74,0,5.88,1.77,5.88,4.84s-2.29,4.86-5.84,4.86Z"
                    transform="translate(11, 11)"
                    fill="#ffffff"
                  ></path>
                </svg>
              </div>
              <p className="sponsor-credit">
                Sentry automatically detects and notifies you of critical performance issues so you can trace every slow transaction to a poor-performing API call or DB query.
              </p>
            </div>
            <div className="sponsor-card">
              <div className="sponsor-logo" aria-label="Algolia">
                <a href="https://www.algolia.com/?utm_medium=AOS-referral" target="_blank" rel="noreferrer">
                  <img src="/algolia.png" alt="Algolia logo" />
                </a>
              </div>
              <p className="sponsor-credit">Courtesy of Algolia · search infrastructure partner</p>
            </div>
            <div className="sponsor-card">
              <div className="sponsor-logo" aria-label="FOSSVPS">
                <a href="https://fossvps.org" target="_blank" rel="noreferrer">
                  <img src="/fossvps.png" alt="FOSSVPS logo" />
                </a>
              </div>
              <p className="sponsor-credit">FOSSVPS provide infrastructure for open-source developers.</p>
            </div>
          </div>
          <p className="sponsor-footnote">Credits curated by W9 Labs · reach out via hi@w9.se to be listed here.</p>
        </section>
      </main>
      <Footer />
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

  function resetAll() {
    setUrlInput('')
    setFileInput(null)
    setImagePreview(null)
    setFileInfo(null)
    setCustomCode('')
    setGenerateQr(false)
    setResult(null)
    setError(null)
    if (fileRef.current) fileRef.current.value = ''
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
      <main className="page">
        <section className="box">
          <h1>W9 Short Links</h1>
          <p className="subtitle">Drop a file or paste a URL · get a short code & QR in seconds.</p>

          <form onSubmit={handleSubmit} className="form">
            <div
              className={`dropzone ${dragOver ? 'dragover' : ''}`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragOver(false)
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
              <div>Drop / paste files or URLs here (1 GiB max)</div>
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
                <span className="code-prefix">w9.se/s/</span>
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
              <div className="status">
                <div>Name: {fileInfo.name}</div>
                <div>Type: {fileInfo.type || 'unknown'}</div>
                <div>Size: {fileInfo.sizeKB} KB</div>
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

            <div className="actions">
              <button type="submit" className="button" disabled={isLoading}>
                {isLoading ? 'Submitting…' : 'Create'}
              </button>
              <button type="button" className="button ghost" onClick={resetAll}>
                Reset
              </button>
            </div>
          </form>
        </section>

        {(isLoading || error || result) && (
          <section className="box">
            <h2 className="section-title">Output</h2>
            {isLoading && <div className="status">Submitting…</div>}
            {error && <div className="status error">{error}</div>}
            {result && (
              <div className="status">
                <div className="row" style={{ gap: '0.5rem', alignItems: 'center' }}>
                  <span className="label-inline">Short URL: </span>
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
                    className="button ghost"
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
          </section>
        )}
      </main>
      <Footer />
    </div>
  )
}

function NotepadPage() {
  const [content, setContent] = useState('')
  const [customCode, setCustomCode] = useState('')
  const [generateQr, setGenerateQr] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [result, setResult] = useState<{ short_url: string; qr_code_data: string | null } | null>(null)
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
      form.set('qr_required', generateQr ? 'true' : 'false')

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

      setResult({ short_url: data.short_url, qr_code_data: data.qr_code_data || null })
    } catch (err: any) {
      setError(err?.message || 'Unexpected error')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <div className="page-shell">
      <main className="panel">
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
              <span className="code-prefix">w9.se/n/</span>
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

          <label className="label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={generateQr}
              onChange={(e) => setGenerateQr(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            Generate QR Code
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
            {result.qr_code_data && (
              <div className="qr" style={{ marginTop: '1rem' }}>
                <img src={result.qr_code_data} alt="QR code" style={{ border: '2px solid #ffffff', maxWidth: '100%', height: 'auto' }} />
              </div>
            )}
          </div>
        )}
      </main>
      </div>
      <Footer />
    </div>
  )
}

function ConverterPage() {
  return (
    <div className="app">
      <Header />
      <div className="page-shell">
        <main className="panel">
          <h1>W9 Converter</h1>
          <p className="subtitle">In development</p>
        </main>
      </div>
      <Footer />
    </div>
  )
}

function TermsPage() {
  return (
    <div className="app">
      <Header />
      <main className="page">
        <section className="box">
          <h1>Terms of Service</h1>
          <p className="subtitle">W9 Tools is part of the W9 Labs umbrella. Using it means you agree to the network rules below.</p>
        </section>
        <section className="box">
          <h2 className="section-title">Allowed Use</h2>
          <ul className="list">
            <li>Host your own short links, file drops, note pads, and converters for legitimate personal or team workflows.</li>
            <li>Respect local laws, copyright, and platform policies. No spam, malware, phishing, or harassment.</li>
            <li>Rotate API keys and passwords regularly. Report security issues privately to hi@w9.se.</li>
          </ul>
        </section>
        <section className="box">
          <h2 className="section-title">Service Scope</h2>
          <p>
            This codebase is provided “as is,” without uptime guarantees. Integrations with W9 Mail or W9 Daily Reminders inherit their
            own limits. When you enable cross-project sharing, you allow those systems to call your W9 Tools deployment.
          </p>
        </section>
        <section className="box">
          <h2 className="section-title">Liability</h2>
          <p>
            W9 Labs is not responsible for lost revenue, corrupted files, or regulatory fines arising from improper use. Review content
            before distributing links, and avoid storing regulated data unless you run your own compliance wrappers.
          </p>
        </section>
        <section className="box">
          <h2 className="section-title">Termination & Changes</h2>
          <p>
            Self-hosted installs can be shut down at any time. Managed instances may be suspended if abuse, spam, or policy violations are
            detected. Terms evolve as EU/EEA regulations change—watch w9.se for changelog entries.
          </p>
        </section>
      </main>
      <Footer />
    </div>
  )
}

function PrivacyPage() {
  return (
    <div className="app">
      <Header />
      <main className="page">
        <section className="box">
          <h1>Privacy Notice</h1>
          <p className="subtitle">W9 Tools keeps data minimal and local. Here’s what we store when you use the service.</p>
        </section>
        <section className="box">
          <h2 className="section-title">Data We Collect</h2>
          <ul className="list">
            <li>Account email + password hashes for authentication.</li>
            <li>Uploaded files, URLs, and note contents so we can serve your drops and links.</li>
            <li>Optional Turnstile tokens for bot protection.</li>
            <li>Log metadata (IP, user agent, timestamps) for abuse mitigation.</li>
          </ul>
        </section>
        <section className="box">
          <h2 className="section-title">How It’s Used</h2>
          <p>
            Data is only used to render your drops, generate QR codes, and sync with other W9 Labs properties when you explicitly enable
            those integrations. We do not sell analytics or embed trackers.
          </p>
        </section>
        <section className="box">
          <h2 className="section-title">Storage & Deletion</h2>
          <p>
            Everything lives on the server you control. Delete a drop, notepad, or account to remove it permanently. Backups are encrypted
            and rotate within 30 days.
          </p>
        </section>
        <section className="box">
          <h2 className="section-title">Third Parties</h2>
          <p>
            Only Cloudflare Turnstile (if enabled) and the email provider you select (via W9 Mail) see limited metadata required to run
            the service. No ad networks or analytics beacons.
          </p>
        </section>
        <section className="box">
          <h2 className="section-title">Questions</h2>
          <p>
            Email <a href="mailto:hi@w9.se">hi@w9.se</a> for export/delete requests. W9 Labs is a non-profit collective based in the
            EU/EEA.
          </p>
        </section>
      </main>
      <Footer />
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
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null)
  const [resetTurnstileToken, setResetTurnstileToken] = useState<string | null>(null)

  // Get redirect parameter from URL
  const urlParams = new URLSearchParams(window.location.search)
  const redirectTo = urlParams.get('redirect') || '/profile'

  async function handleLogin(e: FormEvent) {
    e.preventDefault()
    if (TURNSTILE_SITE_KEY && !turnstileToken) {
      setError('Please complete the security check')
      return
    }
    setLoading(true)
    setError(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, turnstile_token: turnstileToken })
      })
      const data = await resp.json()
      if (resp.ok && data.token) {
        localStorage.setItem('w9_token', data.token)
        if (data.user?.must_change_password) {
          localStorage.setItem('w9_force_password_reset', '1')
        } else {
          localStorage.removeItem('w9_force_password_reset')
        }
        window.location.href = redirectTo
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
    if (TURNSTILE_SITE_KEY && !resetTurnstileToken) {
      setResetMessage('Please complete the security check')
      return
    }
    setResetLoading(true)
    setResetMessage(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/password-reset'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail, turnstile_token: resetTurnstileToken })
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
      <div className="page-shell">
      <main className="panel">
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
            <TurnstileWidget 
              onVerify={(token) => setTurnstileToken(token)}
              onError={() => setTurnstileToken(null)}
            />
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
            <TurnstileWidget 
              onVerify={(token) => setResetTurnstileToken(token)}
              onError={() => setResetTurnstileToken(null)}
            />
            <button type="submit" className="button" disabled={resetLoading}>
              {resetLoading ? 'Sending...' : 'Send Reset Link'}
            </button>
            <p style={{ marginTop: '10px' }}>
              <a href="#" onClick={(e) => { e.preventDefault(); setShowReset(false); setResetMessage(null); setResetTurnstileToken(null); }}>Back to login</a>
            </p>
          </form>
        )}
      </main>
      </div>
      <Footer />
    </div>
  )
}

function RegisterPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null)

  async function handleRegister(e: FormEvent) {
    e.preventDefault()
    if (TURNSTILE_SITE_KEY && !turnstileToken) {
      setError('Please complete the security check')
      return
    }
    setLoading(true)
    setError(null)
    setSuccess(null)
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/register'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, turnstile_token: turnstileToken })
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
      <div className="page-shell">
      <main className="panel">
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
          <TurnstileWidget 
            onVerify={(token) => setTurnstileToken(token)}
            onError={() => setTurnstileToken(null)}
          />
          <button type="submit" className="button" disabled={loading}>
            {loading ? 'Registering...' : 'Register'}
          </button>
          <p style={{ marginTop: '10px' }}>
            Already have an account? <a href="/login">Login here</a>
          </p>
        </form>
      </main>
      </div>
      <Footer />
    </div>
  )
}

function VerifyPage() {
  const [status, setStatus] = useState<'pending' | 'success' | 'error'>('pending')
  const [message, setMessage] = useState('Verifying your email...')

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get('token')
    if (!token) {
      setStatus('error')
      setMessage('Missing verification token.')
      return
    }

    let mounted = true
    async function verify() {
      try {
        const resp = await fetch(joinUrl(API_BASE, '/api/auth/verify-email'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        })
        const data = await resp.json()
        if (!mounted) return
        if (resp.ok && data.token) {
          localStorage.setItem('w9_token', data.token)
          setStatus('success')
          setMessage('Email verified! Redirecting to your dashboard...')
          setTimeout(() => {
            window.location.href = '/profile'
          }, 1500)
        } else {
          setStatus('error')
          setMessage(data.error || 'Verification failed.')
        }
      } catch (err: any) {
        if (!mounted) return
        setStatus('error')
        setMessage(err?.message || 'Verification failed.')
      }
    }

    verify()
    return () => {
      mounted = false
    }
  }, [])

  return (
    <div className="app">
      <Header />
      <div className="page-shell">
        <main className="panel" style={{ maxWidth: '480px' }}>
          <h1>Email Verification</h1>
          <p className="subtitle">{message}</p>
          {status === 'error' && (
            <a href="/login" className="button" style={{ marginTop: '1rem', display: 'inline-block' }}>
              Back to login
            </a>
          )}
        </main>
      </div>
      <Footer />
    </div>
  )
}

function ResetPasswordPage() {
  const [token, setToken] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null)

  useEffect(() => {
    const urlToken = new URLSearchParams(window.location.search).get('token')
    if (!urlToken) {
      setError('Missing reset token. Please use the link from your email.')
      return
    }
    setToken(urlToken)
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!token) {
      setError('Missing reset token.')
      return
    }
    
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    if (TURNSTILE_SITE_KEY && !turnstileToken) {
      setError('Please complete the security check')
      return
    }

    setLoading(true)
    setError(null)
    
    try {
      const resp = await fetch(joinUrl(API_BASE, '/api/auth/confirm-password-reset'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token,
          new_password: newPassword,
          confirm_password: confirmPassword,
          turnstile_token: turnstileToken
        })
      })
      const data = await resp.json()
      if (resp.ok) {
        setSuccess(true)
        setTimeout(() => {
          window.location.href = '/login'
        }, 2000)
      } else {
        setError(data.error || 'Failed to reset password')
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to reset password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <Header />
      <div className="page-shell">
        <main className="panel" style={{ maxWidth: '480px' }}>
          <h1>Reset Password</h1>
          {success ? (
            <>
              <p className="subtitle">Password reset successfully! Redirecting to login...</p>
            </>
          ) : !token ? (
            <>
              <p className="subtitle" style={{ color: 'var(--error)' }}>{error || 'Invalid reset link'}</p>
              <a href="/login" className="button" style={{ marginTop: '1rem', display: 'inline-block' }}>
                Back to login
              </a>
            </>
          ) : (
            <>
              <p className="subtitle">Enter your new password</p>
              <form onSubmit={handleSubmit} className="form">
                <label className="label">
                  New Password
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="input"
                    required
                    minLength={8}
                    placeholder="At least 8 characters"
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
                    placeholder="Re-enter your password"
                  />
                </label>
                {error && <div className="error">{error}</div>}
                <TurnstileWidget 
                  onVerify={(token) => setTurnstileToken(token)}
                  onError={() => setTurnstileToken(null)}
                />
                <button type="submit" className="button" disabled={loading}>
                  {loading ? 'Resetting...' : 'Reset Password'}
                </button>
              </form>
            </>
          )}
        </main>
      </div>
      <Footer />
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
  const [passwordRequiredBanner, setPasswordRequiredBanner] = useState(false)
  const [viewItem, setViewItem] = useState<any | null>(null)

  const token = localStorage.getItem('w9_token')

  useEffect(() => {
    if (!token) {
      window.location.href = '/login'
      return
    }
    const params = new URLSearchParams(window.location.search)
    const forceParam = params.get('force')
    if (forceParam === 'password' || localStorage.getItem('w9_force_password_reset') === '1') {
      setShowChangePassword(true)
      setPasswordRequiredBanner(true)
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
      if (resp.status === 403) {
        setPasswordError('Password update required before proceeding.')
        setShowChangePassword(true)
        setPasswordRequiredBanner(true)
        return
      }
      if (resp.status === 403) {
        setShowChangePassword(true)
        setPasswordRequiredBanner(true)
        alert('Password update required. Change your password to continue.')
        return
      }
      if (resp.status === 403) {
        setShowChangePassword(true)
        setPasswordRequiredBanner(true)
        alert('Password update required. Change your password to continue.')
        return
      }
      if (resp.status === 403) {
        setShowChangePassword(true)
        setPasswordRequiredBanner(true)
        setError('Password update required. Change your password to continue.')
        setLoading(false)
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
        setPasswordRequiredBanner(false)
        localStorage.removeItem('w9_force_password_reset')
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
      <div className="page-shell">
      <main className="panel">
        <h1>My Profile</h1>
        <p className="subtitle">Manage your short links</p>
        {passwordRequiredBanner && (
          <div className="banner" style={{ marginBottom: '1rem', borderColor: '#ff6b6b', color: '#ff6b6b' }}>
            You must update your password before continuing.
          </div>
        )}
        
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
          <div className="table-wrapper" style={{ marginTop: '1rem' }}>
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Short URL</th>
                  <th>Value</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr><td colSpan={4} style={{ textAlign: 'center' }}>No items yet. Create some short links!</td></tr>
                ) : (
                  items.map((item: any) => (
                    <tr key={`${item.code}:${item.kind}`}>
                      <td>{item.kind}</td>
                      <td>
                        {editingCode === `${item.code}:${item.kind}` ? (
                          <div className="table-actions">
                            <input
                              type="text"
                              value={newCode}
                              onChange={(e) => setNewCode(e.target.value)}
                              className="input"
                              placeholder="new-code"
                              style={{ width: '140px' }}
                            />
                            <button
                              onClick={() => handleUpdate(item.code, item.kind)}
                              className="button"
                            >
                              Save
                            </button>
                            <button
                              onClick={() => {
                                setEditingCode(null)
                                setNewCode('')
                              }}
                              className="button ghost"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <a href={item.short_url} target="_blank" rel="noreferrer">{item.short_url}</a>
                        )}
                      </td>
                      <td className="table-cell-truncate">{item.value}</td>
                      <td>
                        <div className="table-actions">
                          <button
                            className="button ghost"
                            type="button"
                            onClick={() => setViewItem(item)}
                          >
                            View
                          </button>
                          <button
                            onClick={() => {
                              setEditingCode(`${item.code}:${item.kind}`)
                              setNewCode(item.code)
                            }}
                            className="button ghost"
                            disabled={editingCode !== null}
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => handleDelete(item.code, item.kind)}
                            className="button"
                            disabled={deletingCode === `${item.code}:${item.kind}` || editingCode !== null}
                          >
                            {deletingCode === `${item.code}:${item.kind}` ? 'Deleting...' : 'Delete'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
        {viewItem && (
          <div className="dialog-backdrop" onClick={() => setViewItem(null)}>
            <div className="dialog" onClick={(e) => e.stopPropagation()}>
              <h2 className="section-title">Item Details</h2>
              <p><strong>Type:</strong> {viewItem.kind}</p>
              <p><strong>Code:</strong> {viewItem.code}</p>
              {viewItem.short_url && (
                <p>
                  <strong>Short URL:</strong>{' '}
                  <a href={toAbsoluteUrl(viewItem.short_url)} target="_blank" rel="noreferrer" className="link">
                    {toAbsoluteUrl(viewItem.short_url)}
                  </a>
                </p>
              )}
              <p><strong>Value:</strong></p>
              <pre className="value-block">{viewItem.value}</pre>
              <div className="actions" style={{ marginTop: '1rem' }}>
                <button className="button" onClick={() => setViewItem(null)}>Close</button>
              </div>
            </div>
          </div>
        )}
      </main>
      </div>
      <Footer />
    </div>
  )
}

export default function App() {
  const route = useRoute()

  if (route === 'admin') {
    return <AdminPanel />
  }
  if (route === 'login') {
    return <LoginPage />
  }
  if (route === 'register') {
    return <RegisterPage />
  }
  if (route === 'verify') {
    return <VerifyPage />
  }
  if (route === 'reset-password') {
    return <ResetPasswordPage />
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
  if (route === 'terms') {
    return <TermsPage />
  }
  if (route === 'privacy') {
    return <PrivacyPage />
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
