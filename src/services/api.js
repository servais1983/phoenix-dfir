import axios from 'axios'

const API_BASE_URL = 'http://localhost:5000/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  }
})

// Intercepteur requete: ajouter le token d'authentification
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('phoenix_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Intercepteur reponse: gestion automatique du 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) {
      localStorage.removeItem('phoenix_token')
      localStorage.removeItem('phoenix_user')
      window.dispatchEvent(new CustomEvent('auth:logout'))
    }
    console.error('API Error:', error?.response?.data || error.message)
    return Promise.reject(error)
  }
)

export function setAuthToken(token) {
  if (token) {
    localStorage.setItem('phoenix_token', token)
  } else {
    localStorage.removeItem('phoenix_token')
  }
}

export function clearAuthToken() {
  localStorage.removeItem('phoenix_token')
  localStorage.removeItem('phoenix_user')
}

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

  async getMe() {
    const response = await api.get('/auth/me')
    return response.data
  },

  async listUsers() {
    const response = await api.get('/auth/users')
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
}

export default apiService
