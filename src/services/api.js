import axios from 'axios'

const API_BASE_URL = 'http://localhost:5000/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  }
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error?.response?.data || error.message)
    return Promise.reject(error)
  }
)

export const apiService = {
  async healthCheck() {
    const response = await api.get('/health')
    return response.data
  },

  async getInvestigations() {
    const response = await api.get('/investigations')
    return response.data
  },

  async createInvestigation(name) {
    const response = await api.post('/investigations', { name })
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

  async uploadFile(file, onProgress) {
    const formData = new FormData()
    formData.append('file', file)
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

  async analyzeFile(data) {
    const response = await api.post('/analyze', data)
    return response.data
  },

  async getAnalysisStatus(analysisId) {
    const response = await api.get(`/analysis/${analysisId}/status`)
    return response.data
  },

  async getIocs(investigationId) {
    const response = await api.get(`/investigations/${investigationId}/iocs`)
    return response.data
  },

  async addIoc(investigationId, ioc) {
    const response = await api.post(`/investigations/${investigationId}/iocs`, ioc)
    return response.data
  },

  async deleteIoc(investigationId, iocType, iocIndex) {
    const response = await api.delete(`/investigations/${investigationId}/iocs/${iocType}/${iocIndex}`)
    return response.data
  },

  async enrichIoc(type, value) {
    const response = await api.post('/iocs/enrich', { type, value })
    return response.data
  },

  async getTimeline(investigationId) {
    const response = await api.get(`/investigations/${investigationId}/timeline`)
    return response.data
  },

  async addTimelineEvent(investigationId, event) {
    const response = await api.post(`/investigations/${investigationId}/timeline`, event)
    return response.data
  },

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

  async calculateHash(file) {
    const formData = new FormData()
    formData.append('file', file)
    const response = await api.post('/tools/hash', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120000,
    })
    return response.data
  },

  async getStats() {
    const response = await api.get('/stats')
    return response.data
  },
}

export default apiService
