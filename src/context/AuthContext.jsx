import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { apiService, setAuthToken, clearAuthToken } from '@/services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const isAuthenticated = !!user

  // Verifier le token au demarrage
  useEffect(() => {
    const token = localStorage.getItem('phoenix_token')
    if (token) {
      apiService.getMe()
        .then((userData) => {
          setUser(userData)
        })
        .catch(() => {
          clearAuthToken()
          setUser(null)
        })
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  // Ecouter les deconnexions forcees (401)
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
    setAuthToken(data.token)
    setUser(data.user)
    return data
  }, [])

  const register = useCallback(async (username, password, displayName) => {
    const data = await apiService.register(username, password, displayName)
    setAuthToken(data.token)
    setUser(data.user)
    return data
  }, [])

  const logout = useCallback(() => {
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
