import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { apiService, setAuthTokens, clearAuthToken } from '@/services/api'

const AuthContext = createContext(null)

// L'access token reste en memoire (jamais dans localStorage) ; le refresh
// token est un cookie HttpOnly gere par le navigateur.
function keepAccessToken(data) {
  setAuthTokens({ access: data.access_token || data.token })
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const isAuthenticated = !!user

  // Au chargement de la page : restaurer la session via le cookie de refresh
  useEffect(() => {
    let cancelled = false
    apiService.restoreSession()
      .then((data) => {
        if (!cancelled) setUser(data.user || null)
      })
      .catch(() => {
        clearAuthToken()
        if (!cancelled) setUser(null)
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [])

  // Ecouter les deconnexions forcees (401 sans refresh possible)
  useEffect(() => {
    const handler = () => {
      setUser(null)
      clearAuthToken()
    }
    window.addEventListener('auth:logout', handler)
    return () => window.removeEventListener('auth:logout', handler)
  }, [])

  const login = useCallback(async (username, password) => {
    const data = await apiService.login(username, password)
    keepAccessToken(data)
    setUser(data.user)
    return data
  }, [])

  const register = useCallback(async (username, password, displayName, setupToken) => {
    const data = await apiService.register(username, password, displayName, setupToken)
    keepAccessToken(data)
    setUser(data.user)
    return data
  }, [])

  const logout = useCallback(async () => {
    // Best-effort cote serveur (revoque les jetons, efface le cookie), puis nettoyage local
    await apiService.logout()
    clearAuthToken()
    setUser(null)
  }, [])

  const changePassword = useCallback(async (currentPassword, newPassword) => {
    await apiService.changePassword(currentPassword, newPassword)
    // Le backend revoque toutes les sessions -> on force la deconnexion locale
    clearAuthToken()
    setUser(null)
  }, [])

  const value = {
    user,
    loading,
    isAuthenticated,
    login,
    register,
    logout,
    changePassword,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
