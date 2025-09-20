// Service API pour Phoenix DFIR
import axios from 'axios'

const API_BASE_URL = 'http://localhost:5000/api'

// Configuration axios
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
})

// Intercepteur pour gérer les erreurs
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('Erreur API:', error)
    return Promise.reject(error)
  }
)

// Services API
export const apiService = {
  // Health check
  async healthCheck() {
    const response = await api.get('/health')
    return response.data
  },

  // Enquêtes
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

  // Upload de fichiers
  async uploadFile(file, onProgress) {
    const formData = new FormData()
    formData.append('file', file)

    const response = await api.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress) {
          const progress = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          )
          onProgress(progress)
        }
      }
    })

    return response.data
  },

  // Analyse de fichiers
  async analyzeFile(data) {
    const response = await api.post('/analyze', data)
    return response.data
  },

  async getAnalysisStatus(analysisId) {
    const response = await api.get(`/analysis/${analysisId}/status`)
    return response.data
  },

  // Rapports
  async generateReport(data) {
    const response = await api.post('/reports/generate', data)
    return response.data
  },

  async downloadReport(reportId) {
    const response = await api.get(`/reports/${reportId}/download`, {
      responseType: 'blob'
    })
    return response.data
  }
}

export default apiService
