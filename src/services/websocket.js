// Service WebSocket pour Phoenix DFIR
import { io } from 'socket.io-client'

class WebSocketService {
  constructor() {
    this.socket = null
    this.listeners = new Map()
  }

  connect() {
    if (this.socket?.connected) {
      return this.socket
    }

    this.socket = io('http://localhost:5000', {
      transports: ['websocket', 'polling'],
      timeout: 20000,
    })

    this.socket.on('connect', () => {
      console.log('✅ WebSocket connecté à Phoenix DFIR')
    })

    this.socket.on('disconnect', () => {
      console.log('❌ WebSocket déconnecté')
    })

    this.socket.on('connect_error', (error) => {
      console.error('Erreur de connexion WebSocket:', error)
    })

    // Gestionnaire générique pour tous les événements
    this.socket.onAny((eventName, data) => {
      if (this.listeners.has(eventName)) {
        this.listeners.get(eventName).forEach(callback => callback(data))
      }
    })

    return this.socket
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect()
      this.socket = null
    }
  }

  // Écouter un événement
  on(eventName, callback) {
    if (!this.listeners.has(eventName)) {
      this.listeners.set(eventName, new Set())
    }
    this.listeners.get(eventName).add(callback)

    // Retourner une fonction pour supprimer l'écouteur
    return () => {
      const eventListeners = this.listeners.get(eventName)
      if (eventListeners) {
        eventListeners.delete(callback)
        if (eventListeners.size === 0) {
          this.listeners.delete(eventName)
        }
      }
    }
  }

  // Émettre un événement
  emit(eventName, data) {
    if (this.socket?.connected) {
      this.socket.emit(eventName, data)
    } else {
      console.warn('WebSocket non connecté, impossible d\'émettre:', eventName)
    }
  }

  // Rejoindre une enquête
  joinInvestigation(investigationId) {
    this.emit('join_investigation', { investigation_id: investigationId })
  }

  // Écouter les mises à jour d'analyse
  onAnalysisProgress(callback) {
    return this.on('analysis_progress', callback)
  }

  // Écouter les notifications
  onNotification(callback) {
    return this.on('notification', callback)
  }

  // Écouter la progression de l'enquêteur autonome
  onAutonomousProgress(callback) {
    return this.on('autonomous_progress', callback)
  }
}

// Instance singleton
const websocketService = new WebSocketService()

export default websocketService
