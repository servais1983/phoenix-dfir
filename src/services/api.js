/**
 * Phoenix DFIR - API Service
 * Client HTTP avec refresh token automatique et URL dynamique
 *
 * URL de l'API configuree via variable d'environnement Vite:
 *   VITE_API_URL=http://mon-serveur/api (dans .env ou .env.production)
 * Fallback: /api (relatif, fonctionne derriere nginx)
 */

import axios from 'axios'

// URL de base: variable d'env Vite ou chemin relatif (recommande derriere nginx)
const API_BASE_URL = import.meta.env.VITE_API_URL || '/api'

// Indicateur pour eviter les boucles de refresh
let _isRefreshing = false
let _refreshSubscribers = []

function _onRefreshed(token) {
  _refreshSubscribers.forEach(cb => cb(token))
  _refreshSubscribers = []
}

function _addRefreshSubscriber(cb) {
  _refreshSubscribers.push(cb)
}

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: false,
})

// ============================================================================
// INTERCEPTEUR REQUETE: ajouter le token d'authentification
// ============================================================================
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phoenix_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ============================================================================
// INTERCEPTEUR REPONSE: refresh token automatique sur 401
// ============================================================================
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Si 401 et qu'on n'a pas deja tente un refresh pour cette requete
    if (error?.response?.status === 401 && !originalRequest._retry) {
      const refreshToken = localStorage.getItem('phoenix_refresh_token')

      if (!refreshToken) {
        // Pas de refresh token: deconnecter
        _forceLogout()
        return Promise.reject(error)
      }

      if (_isRefreshing) {
        // Un refresh est deja en cours: mettre en file d'attente
        return new Promise((resolve, reject) => {
          _addRefreshSubscriber((newToken) => {
            if (newToken) {
              originalRequest.headers.Authorization = `Bearer ${newToken}`
              resolve(api(originalRequest))
            } else {
              reject(error)
            }
          })
        })
      }

      originalRequest._retry = true
      _isRefreshing = true

      try {
        const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
          refresh_token: refreshToken
        })

        const { token: newToken, refresh_token: newRefresh } = response.data
        localStorage.setItem('phoenix_token', newToken)
        if (newRefresh) {
          localStorage.setItem('phoenix_refresh_token', newRefresh)
        }

        _onRefreshed(newToken)
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)

      } catch (refreshError) {
        _onRefreshed(null)
        _forceLogout()
        return Promise.reject(refreshError)
      } finally {
        _isRefreshing = false
      }
    }

    // Pour les autres erreurs, logger sans exposer de details sensibles
    if (error?.response?.status !== 401) {
      console.error('API Error:', error?.response?.status, error?.response?.data?.error || error.message)
    }
    return Promise.reject(error)
  }
)

function _forceLogout() {
  localStorage.removeItem('phoenix_token')
  localStorage.removeItem('phoenix_refresh_token')
  localStorage.removeItem('phoenix_user')
  window.dispatchEvent(new CustomEvent('auth:logout'))
}

// ============================================================================
// GESTION DU TOKEN
// ============================================================================

export function setAuthToken(token, refreshToken) {
  if (token) {
    localStorage.setItem('phoenix_token', token)
  } else {
    localStorage.removeItem('phoenix_token')
  }
  if (refreshToken) {
    localStorage.setItem('phoenix_refresh_token', refreshToken)
  } else if (!token) {
    localStorage.removeItem('phoenix_refresh_token')
  }
}

export function clearAuthToken() {
  localStorage.removeItem('phoenix_token')
  localStorage.removeItem('phoenix_refresh_token')
  localStorage.removeItem('phoenix_user')
}

// ============================================================================
// API SERVICE
// ============================================================================

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

  async logout(refreshToken) {
    try {
      await api.post('/auth/logout', { refresh_token: refreshToken })
    } catch (_) {
      // Ignorer les erreurs de logout (token deja expire, etc.)
    }
  },

  async getMe() {
    const response = await api.get('/auth/me')
    return response.data
  },

  async listUsers() {
    const response = await api.get('/auth/users')
    return response.data
  },

  async unlockUser(userId) {
    const response = await api.post(`/auth/users/${userId}/unlock`)
    return response.data
  },

  async updateUserRole(userId, role) {
    const response = await api.put(`/auth/users/${userId}/role`, { role })
    return response.data
  },

  // ==================== HEALTH ====================
  async healthCheck() {
    const response = await api.get('/health')
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
      timeout: 300000,  // 5 minutes pour les gros fichiers
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
    const response = await api.get(`/reports/${reportId}/download`, {
      responseType: 'blob'
    })
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
    const response = await api.get(`/investigations/${investigationId}/iocs/export`, {
      responseType: 'blob'
    })
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
