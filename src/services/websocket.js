// Service WebSocket pour Phoenix DFIR
import { io } from 'socket.io-client'
import { getAccessToken, refreshSession } from '@/services/api'

class WebSocketService {
  constructor() {
    this.socket = null
    this.listeners = new Map()
  }

  connect() {
    if (this.socket?.connected) {
      return this.socket
    }

    // Meme logique que l'API : VITE_API_BASE_URL en build, sinon l'URL backend
    // configuree dans les parametres, sinon la propre origine de la page
    // (mono-conteneur / acces equipe), sinon localhost (dev Vite)
    const apiBase = import.meta.env?.VITE_API_BASE_URL
    const sameOrigin = (typeof window !== 'undefined' && window.location?.origin
      && !['5173', '5174', '3000'].includes(window.location.port))
      ? window.location.origin
      : null
    const backendUrl = (apiBase && apiBase.replace(/\/api\/?$/, ''))
      || localStorage.getItem('phoenix_backend_url')
      || sameOrigin
      || 'http://localhost:5000'

    // Le serveur refuse toute connexion sans jeton d'acces : le jeton (en
    // memoire, jamais en query string) est lu a chaque (re)connexion pour
    // suivre les rafraichissements.
    this.socket = io(backendUrl, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      auth: (cb) => cb({ token: getAccessToken() || '' }),
    })

    this.socket.on('connect', () => {
      console.log('✅ WebSocket connecté à Phoenix DFIR')
    })

    this.socket.on('disconnect', (reason) => {
      console.log('❌ WebSocket déconnecté')
      // Deconnexion par le serveur (jeton expire ou revoque) : renouveler le
      // jeton puis se reconnecter (pas de reconnexion automatique dans ce cas).
      if (reason === 'io server disconnect') {
        this.scheduleReconnect(this.socket)
      }
    })

    this.socket.on('connect_error', (error) => {
      console.error('Erreur de connexion WebSocket:', error)
      // Refus serveur (jeton expire) : pas de reconnexion automatique cote
      // client, on retente apres le rafraichissement du jeton.
      const socket = this.socket
      if (socket && !socket.active) {
        this.scheduleReconnect(socket)
      }
    })

    // Gestionnaire générique pour tous les événements
    this.socket.onAny((eventName, data) => {
      if (this.listeners.has(eventName)) {
        this.listeners.get(eventName).forEach(callback => callback(data))
      }
    })

    return this.socket
  }

  scheduleReconnect(socket) {
    if (!socket) return
    clearTimeout(this.retryTimer)
    this.retryTimer = setTimeout(async () => {
      if (this.socket !== socket) return
      try {
        await refreshSession()
      } catch {
        // Session terminee : l'API declenchera auth:logout
        return
      }
      if (this.socket === socket && !socket.connected) socket.connect()
    }, 2000)
  }

  disconnect() {
    clearTimeout(this.retryTimer)
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

  // Console Enqueteur DFIR : etapes des agents scellees dans la chaine de preuve
  onAgentStep(callback) {
    return this.on('agent_step', callback)
  }

  // Validation humaine (Human-in-the-Loop) des remediations
  onHitlRequired(callback) {
    return this.on('hitl_required', callback)
  }

  onHitlResolved(callback) {
    return this.on('hitl_resolved', callback)
  }
}

// Instance singleton
const websocketService = new WebSocketService()

export default websocketService
