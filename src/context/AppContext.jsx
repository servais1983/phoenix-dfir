import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  // Backend status
  const [backendStatus, setBackendStatus] = useState('connecting') // connecting | online | offline
  const [phoenixAvailable, setPhoenixAvailable] = useState(false)

  // Investigations
  const [investigations, setInvestigations] = useState([])
  const [currentInvestigation, setCurrentInvestigation] = useState(null)

  // Analysis
  const [analysisResults, setAnalysisResults] = useState([])
  const [activeAnalysis, setActiveAnalysis] = useState(null)

  // Notifications
  const [notifications, setNotifications] = useState([])

  // Health check
  const checkHealth = useCallback(async () => {
    try {
      const data = await apiService.healthCheck()
      setBackendStatus('online')
      setPhoenixAvailable(data.phoenix_available)
      return data
    } catch {
      setBackendStatus('offline')
      return null
    }
  }, [])

  // Load investigations (gere la reponse paginee)
  const loadInvestigations = useCallback(async () => {
    try {
      const data = await apiService.getInvestigations()
      // Support de la reponse paginee {items, total} ou tableau
      setInvestigations(data.items || data)
      return data.items || data
    } catch {
      return []
    }
  }, [])

  // Create investigation
  const createInvestigation = useCallback(async (name) => {
    const result = await apiService.createInvestigation(name)
    await loadInvestigations()
    return result
  }, [loadInvestigations])

  // Delete investigation
  const deleteInvestigation = useCallback(async (id) => {
    await apiService.deleteInvestigation(id)
    await loadInvestigations()
    if (currentInvestigation?.id === id) {
      setCurrentInvestigation(null)
    }
  }, [loadInvestigations, currentInvestigation])

  // Upload file
  const uploadFile = useCallback(async (file, onProgress) => {
    return await apiService.uploadFile(file, onProgress)
  }, [])

  // Analyze file
  const analyzeFile = useCallback(async (data) => {
    const result = await apiService.analyzeFile(data)
    setActiveAnalysis(result)
    return result
  }, [])

  // Add notification
  const addNotification = useCallback((notification) => {
    const id = Date.now()
    setNotifications(prev => [...prev, { id, timestamp: new Date().toISOString(), ...notification }])
    return id
  }, [])

  const dismissNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id))
  }, [])

  // Initialize
  useEffect(() => {
    checkHealth()
    loadInvestigations()

    // Periodic health check
    const interval = setInterval(checkHealth, 30000)

    // WebSocket connection
    try {
      websocketService.connect()

      const unsubProgress = websocketService.onAnalysisProgress((data) => {
        setActiveAnalysis(prev => prev ? { ...prev, ...data } : data)
        if (data.status === 'Analyse terminee' || data.status === 'completed') {
          if (data.result) {
            setAnalysisResults(prev => [
              { id: data.analysis_id, result: data.result, timestamp: new Date().toISOString() },
              ...prev
            ])
          }
          loadInvestigations()
        }
      })

      const unsubNotif = websocketService.onNotification((data) => {
        addNotification(data)
      })

      return () => {
        clearInterval(interval)
        unsubProgress()
        unsubNotif()
        websocketService.disconnect()
      }
    } catch {
      // WebSocket not available - that's OK
      return () => clearInterval(interval)
    }
  }, [checkHealth, loadInvestigations, addNotification])

  const value = {
    // State
    backendStatus,
    phoenixAvailable,
    investigations,
    currentInvestigation,
    analysisResults,
    activeAnalysis,
    notifications,

    // Actions
    setCurrentInvestigation,
    setActiveAnalysis,
    checkHealth,
    loadInvestigations,
    createInvestigation,
    deleteInvestigation,
    uploadFile,
    analyzeFile,
    addNotification,
    dismissNotification,
  }

  return (
    <AppContext.Provider value={value}>
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const context = useContext(AppContext)
  if (!context) {
    throw new Error('useApp must be used within AppProvider')
  }
  return context
}
