const TOKEN_KEY = 'misconfigly_token'
// Empty locally, where Vite proxies /api to the backend.
const API_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '')
const GENERIC_ERROR = 'Something went wrong. Please try again.'
const FIELD_ERRORS = {
  email: 'Please enter a valid email address.',
  password: 'Passwords must be between 8 and 200 characters.',
  new_password: 'Passwords must be between 8 and 200 characters.',
}

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token)
    else localStorage.removeItem(TOKEN_KEY)
  } catch {
    // Without storage the session just ends on reload.
  }
}

function messageFor(detail) {
  if (typeof detail === 'string') return detail
  const field = Array.isArray(detail) ? detail[0]?.loc?.at(-1) : null
  return FIELD_ERRORS[field] || GENERIC_ERROR
}

let onExpired = () => {}
export function whenSessionExpires(handler) {
  onExpired = handler
}

async function request(path, { method = 'GET', json } = {}) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (json) headers['Content-Type'] = 'application/json'
  let response
  try {
    response = await fetch(`${API_URL}/api${path}`, { method, headers, body: json ? JSON.stringify(json) : undefined })
  } catch {
    throw new Error("Can't reach the server. Check your connection and try again.")
  }
  if (response.status === 401 && token) onExpired()
  if (response.status === 204) return null
  const data = await response.json().catch(() => null)
  if (!response.ok) {
    const error = new Error(messageFor(data?.detail))
    error.status = response.status
    throw error
  }
  return data
}

export const api = {
  register: (email, password) => request('/auth/register', { method: 'POST', json: { email, password } }),
  login: (email, password) => request('/auth/login', { method: 'POST', json: { email, password } }),
  demo: () => request('/auth/demo', { method: 'POST' }),
  google: (credential) => request('/auth/google', { method: 'POST', json: { credential } }),
  authOptions: () => request('/auth/options'),
  forgotPassword: (email) => request('/password/forgot', { method: 'POST', json: { email } }),
  resetPassword: (token, new_password) => request('/password/reset', { method: 'POST', json: { token, new_password } }),
  me: () => request('/me'),
  changePassword: (current_password, new_password) =>
    request('/me/password', { method: 'POST', json: { current_password, new_password } }),
  scans: () => request('/scans'),
  scan: (id) => request(`/scans/${encodeURIComponent(id)}`),
  startScan: () => request('/scans', { method: 'POST' }),
  demoFix: (check_ids) => request('/demo/fixes', { method: 'POST', json: { check_ids } }),
  resetDemo: () => request('/demo/fixes', { method: 'DELETE' }),
  connection: () => request('/connection'),
  connect: (role_arn) => request('/connection', { method: 'POST', json: { role_arn } }),
  disconnect: () => request('/connection', { method: 'DELETE' }),
}
