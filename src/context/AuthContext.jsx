import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { apiService, setAuthTokens, clearAuthToken } from '@/services/api'

const AuthContext = createContext(null)

function persistTokensFromResponse(data) {
  setAuthTokens({
    // L'API renvoie access_token + token (alias retro-compat) ainsi que refresh_token
    access: data.access_token || data.token,
    refresh: data.refresh_token || null,
  })
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const isAuthenticated = !!user

  // Verifier le token au demarrage
  useEffect(() => {
    const token = localStorage.getItem('phoenix_token')
    if (token) {
      apiService.getMe()
        .then((userData) => setUser(userData))
        .catch(() => {
          clearAuthToken()
          setUser(null)
        })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
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
    persistTokensFromResponse(data)
    setUser(data.user)
    return data
  }, [])

  const register = useCallback(async (username, password, displayName) => {
    const data = await apiService.register(username, password, displayName)
    persistTokensFromResponse(data)
    setUser(data.user)
    return data
  }, [])

  const logout = useCallback(async () => {
    // Best-effort cote serveur (revoque le token), puis nettoyage local
    await apiService.logout()
    clearAuthToken()
    setUser(null)
  }, [])

  const changePassword = useCallback(async (currentPassword, newPassword) => {
    await apiService.changePassword(currentPassword, newPassword)
    // Le backend revoque le token courant -> on force la deconnexion locale
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
