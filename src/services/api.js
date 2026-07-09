import axios from 'axios'

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

// L'URL peut etre surchargee par VITE_API_BASE_URL en build, sinon par le
// champ "URL du Backend" des parametres (acces equipe), sinon localhost dev
function resolveApiBaseUrl() {
  if (import.meta.env?.VITE_API_BASE_URL) return import.meta.env.VITE_API_BASE_URL
  try {
    const stored = localStorage.getItem('phoenix_backend_url')
    if (stored) return stored.replace(/\/+$/, '') + '/api'
  } catch { /* localStorage indisponible (SSR/tests) */ }
  // Page servie par le backend lui-meme (mono-conteneur / acces equipe) :
  // utiliser la meme origine. Les ports Vite restent en localhost:5000.
  if (typeof window !== 'undefined' && window.location?.origin
      && !['5173', '5174', '3000'].includes(window.location.port)) {
    return `${window.location.origin}/api`
  }
  return 'http://localhost:5000/api'
}
const API_BASE_URL = resolveApiBaseUrl()

const STORAGE_ACCESS = 'phoenix_token'         // garde le nom legacy pour retro-compat
const STORAGE_REFRESH = 'phoenix_refresh_token'
const STORAGE_USER = 'phoenix_user'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
})

// ----------------------------------------------------------------------------
// Token helpers
// ----------------------------------------------------------------------------

export function setAuthTokens({ access, refresh } = {}) {
  if (access) localStorage.setItem(STORAGE_ACCESS, access)
  else localStorage.removeItem(STORAGE_ACCESS)
  if (refresh) localStorage.setItem(STORAGE_REFRESH, refresh)
  else if (refresh === null) localStorage.removeItem(STORAGE_REFRESH)
}

// Retro-compat avec l'ancien setter
export function setAuthToken(token) {
  if (token) localStorage.setItem(STORAGE_ACCESS, token)
  else localStorage.removeItem(STORAGE_ACCESS)
}

export function clearAuthToken() {
  localStorage.removeItem(STORAGE_ACCESS)
  localStorage.removeItem(STORAGE_REFRESH)
  localStorage.removeItem(STORAGE_USER)
}

function getAccessToken() { return localStorage.getItem(STORAGE_ACCESS) }
function getRefreshToken() { return localStorage.getItem(STORAGE_REFRESH) }

// ----------------------------------------------------------------------------
// Request interceptor : injecte le Bearer
// ----------------------------------------------------------------------------

api.interceptors.request.use((config) => {
  const token = getAccessToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ----------------------------------------------------------------------------
// Response interceptor : auto-refresh sur 401 avec dedup
// ----------------------------------------------------------------------------

// Promesse partagee : pendant qu'un refresh est en cours, toutes les autres
// requetes 401 attendent le meme refresh au lieu d'en lancer un par requete.
let refreshPromise = null

async function performTokenRefresh() {
  const refresh = getRefreshToken()
  if (!refresh) {
    throw new Error('no_refresh_token')
  }
  // Appel direct via axios.post (pas via 'api') pour bypass l'intercepteur
  const url = `${API_BASE_URL}/auth/refresh`
  const { data } = await axios.post(url, { refresh_token: refresh }, {
    timeout: 10000,
    headers: { 'Content-Type': 'application/json' },
  })
  if (!data?.access_token) throw new Error('refresh_no_access_token')
  setAuthTokens({
    access: data.access_token,
    refresh: data.refresh_token || refresh,  // garde l'ancien si rien renvoye
  })
  return data.access_token
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config
    const status = error?.response?.status

    // Auth endpoints : ne pas tenter de refresh, juste deconnecter en cas d'echec
    const isAuthEndpoint = originalRequest?.url?.includes('/auth/login')
                         || originalRequest?.url?.includes('/auth/register')
                         || originalRequest?.url?.includes('/auth/refresh')

    if (status === 401 && !originalRequest?._retried && !isAuthEndpoint && getRefreshToken()) {
      originalRequest._retried = true
      try {
        // Si un refresh est deja en cours, on attend
        if (!refreshPromise) {
          refreshPromise = performTokenRefresh().finally(() => { refreshPromise = null })
        }
        const newAccess = await refreshPromise
        originalRequest.headers.Authorization = `Bearer ${newAccess}`
        return api(originalRequest)
      } catch (refreshErr) {
        clearAuthToken()
        window.dispatchEvent(new CustomEvent('auth:logout'))
        return Promise.reject(refreshErr)
      }
    }

    // 401 sans refresh possible : on coupe la session
    if (status === 401 && !isAuthEndpoint) {
      clearAuthToken()
      window.dispatchEvent(new CustomEvent('auth:logout'))
    }

    if (status !== 401) {
      console.error('API Error:', error?.response?.data || error.message)
    }
    return Promise.reject(error)
  }
)

// ----------------------------------------------------------------------------
// API surface
// ----------------------------------------------------------------------------

export const apiService = {
  // ==================== AUTH ====================
  async login(username, password) {
    const response = await api.post('/auth/login', { username, password })
    return response.data
  },

  async register(username, password, display_name) {
    const response = await api.post('/auth/register', { username, password, display_name })
    return response.data
  },

  async logout() {
    const refresh_token = getRefreshToken()
    try {
      await api.post('/auth/logout', { refresh_token })
    } catch {
      // logout best-effort - on nettoie quand meme cote client
    }
  },

  async refresh() {
    return performTokenRefresh()
  },

  async changePassword(currentPassword, newPassword) {
    const response = await api.put('/auth/password', {
      current_password: currentPassword,
      new_password: newPassword,
    })
    return response.data
  },

  async getMe() {
    const response = await api.get('/auth/me')
    return response.data
  },

  async listUsers() {
    const response = await api.get('/auth/users')
    return response.data
  },

  // ==================== HEALTH / READINESS ====================
  async healthCheck() {
    const response = await api.get('/health')
    return response.data
  },

  // Sans /api prefix : direct sur le root
  async livenessCheck() {
    const base = API_BASE_URL.replace(/\/api\/?$/, '')
    const response = await axios.get(`${base}/livez`, { timeout: 3000 })
    return response.data
  },

  async readinessCheck() {
    const base = API_BASE_URL.replace(/\/api\/?$/, '')
    const response = await axios.get(`${base}/readyz`, { timeout: 5000 })
    return response.data
  },

  // ==================== INVESTIGATIONS ====================
  async getInvestigations(page = 1, perPage = 50) {
    const response = await api.get(`/investigations?page=${page}&per_page=${perPage}`)
    return response.data
  },

  async createInvestigation(name, description = '') {
    const response = await api.post('/investigations', { name, description })
    return response.data
  },

  async getInvestigation(id) {
    const response = await api.get(`/investigations/${id}`)
    return response.data
  },

  async deleteInvestigation(id) {
    const response = await api.delete(`/investigations/${id}`)
    return response.data
  },

  async updateInvestigation(id, data) {
    const response = await api.put(`/investigations/${id}`, data)
    return response.data
  },

  async updateInvestigationStatus(id, status) {
    const response = await api.put(`/investigations/${id}/status`, { status })
    return response.data
  },

  // ==================== UPLOAD ====================
  async uploadFile(file, investigationId, onProgress) {
    const formData = new FormData()
    formData.append('file', file)
    if (investigationId) {
      formData.append('investigation_id', investigationId)
    }
    const response = await api.post('/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          onProgress(Math.round((progressEvent.loaded * 100) / progressEvent.total))
        }
      }
    })
    return response.data
  },

  // ==================== ANALYZE ====================
  async analyzeFile(data) {
    const response = await api.post('/analyze', data)
    return response.data
  },

  // ==================== ENQUETEUR AUTONOME ====================
  async getAutonomousStatus() {
    const response = await api.get('/autonomous/status')
    return response.data
  },

  async startAutonomousInvestigation(investigationId, question) {
    const response = await api.post('/autonomous/investigate', {
      investigation_id: investigationId,
      question: question || undefined,
    })
    return response.data
  },

  async getAutonomousJob(jobId) {
    const response = await api.get(`/autonomous/jobs/${jobId}`)
    return response.data
  },

  async getAnalysisStatus(analysisId) {
    const response = await api.get(`/analysis/${analysisId}/status`)
    return response.data
  },

  // ==================== IOCS ====================
  async getIocs(investigationId, page = 1, perPage = 100) {
    const response = await api.get(`/investigations/${investigationId}/iocs?page=${page}&per_page=${perPage}`)
    return response.data
  },

  async addIoc(investigationId, ioc) {
    const response = await api.post(`/investigations/${investigationId}/iocs`, ioc)
    return response.data
  },

  async deleteIoc(investigationId, iocId) {
    const response = await api.delete(`/investigations/${investigationId}/iocs/${iocId}`)
    return response.data
  },

  async enrichIoc(type, value, iocId) {
    const response = await api.post('/iocs/enrich', { type, value, ioc_id: iocId })
    return response.data
  },

  // ==================== TIMELINE ====================
  async getTimeline(investigationId, page = 1, perPage = 100) {
    const response = await api.get(`/investigations/${investigationId}/timeline?page=${page}&per_page=${perPage}`)
    return response.data
  },

  async addTimelineEvent(investigationId, event) {
    const response = await api.post(`/investigations/${investigationId}/timeline`, event)
    return response.data
  },

  // ==================== ARTIFACTS ====================
  async getArtifacts(investigationId, page = 1, perPage = 50) {
    const response = await api.get(`/investigations/${investigationId}/artifacts?page=${page}&per_page=${perPage}`)
    return response.data
  },

  // ==================== REPORTS ====================
  async generateReport(data) {
    const response = await api.post('/reports/generate', data)
    return response.data
  },

  async downloadReport(reportId) {
    const response = await api.get(`/reports/${reportId}/download`, { responseType: 'blob' })
    return response.data
  },

  // ==================== TOOLS ====================
  async calculateHash(file) {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/tools/hash', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    })
    return response.data
  },

  // ==================== STATS ====================
  async getStats() {
    const response = await api.get('/stats')
    return response.data
  },

  // ==================== AUDIT ====================
  async getAuditLog(page = 1, perPage = 50) {
    const response = await api.get(`/audit?page=${page}&per_page=${perPage}`)
    return response.data
  },

  // ==================== STIX EXPORT ====================
  async exportStix(investigationId) {
    const response = await api.get(`/investigations/${investigationId}/export/stix`)
    return response.data
  },

  // ==================== BULK IOC IMPORT ====================
  async bulkImportIocs(investigationId, data) {
    const response = await api.post(`/investigations/${investigationId}/iocs/bulk`, data)
    return response.data
  },

  // ==================== IOC CSV EXPORT ====================
  async exportIocsCsv(investigationId) {
    const response = await api.get(`/investigations/${investigationId}/iocs/export`, { responseType: 'blob' })
    return response.data
  },

  // ==================== MITRE ATT&CK ====================
  async getMitreMapping(investigationId) {
    const response = await api.get(`/investigations/${investigationId}/mitre`)
    return response.data
  },

  // ==================== SEARCH ====================
  async searchInvestigations(params = {}) {
    const query = new URLSearchParams(params).toString()
    const response = await api.get(`/investigations?${query}`)
    return response.data
  },

  // ==================== INTEGRATIONS ====================
  async listIntegrations() {
    const response = await api.get('/integrations')
    return response.data
  },

  async getIntegration(connectorId) {
    const response = await api.get(`/integrations/${connectorId}`)
    return response.data
  },

  async updateIntegration(connectorId, data) {
    const response = await api.put(`/integrations/${connectorId}`, data)
    return response.data
  },

  async testIntegration(connectorId) {
    const response = await api.post(`/integrations/${connectorId}/test`)
    return response.data
  },

  async enrichViaIntegration(connectorId, type, value) {
    const response = await api.post(`/integrations/${connectorId}/enrich`, { type, value })
    return response.data
  },

  async pushToIntegration(connectorId, investigationId) {
    const response = await api.post(`/integrations/${connectorId}/push`, { investigation_id: investigationId })
    return response.data
  },

  async pullFromIntegration(connectorId, investigationId, query = '') {
    const response = await api.post(`/integrations/${connectorId}/pull`, { investigation_id: investigationId, query })
    return response.data
  },
}

export default apiService
