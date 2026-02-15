import { useState } from 'react'
import { useAuth } from '@/context/AuthContext'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Shield, Loader2, AlertCircle } from 'lucide-react'

export default function LoginPage() {
  const { login, register } = useAuth()
  const [mode, setMode] = useState('login') // login | register
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // Champs formulaire
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (mode === 'register') {
        if (password !== confirmPassword) {
          setError('Les mots de passe ne correspondent pas')
          setLoading(false)
          return
        }
        if (password.length < 6) {
          setError('Le mot de passe doit contenir au moins 6 caracteres')
          setLoading(false)
          return
        }
        await register(username, password, displayName || username)
      } else {
        await login(username, password)
      }
    } catch (err) {
      const message = err?.response?.data?.error || err.message || 'Erreur de connexion'
      setError(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-orange-600/20 mb-4">
            <Shield className="h-8 w-8 text-orange-500" />
          </div>
          <h1 className="text-2xl font-bold text-white">Phoenix DFIR</h1>
          <p className="text-sm text-gray-400 mt-1">Plateforme d'Investigation Forensique</p>
        </div>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="pb-4">
            {/* Onglets Connexion / Inscription */}
            <div className="flex gap-1 bg-gray-800 rounded-lg p-1">
              <button
                onClick={() => { setMode('login'); setError('') }}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  mode === 'login'
                    ? 'bg-gray-700 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Connexion
              </button>
              <button
                onClick={() => { setMode('register'); setError('') }}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  mode === 'register'
                    ? 'bg-gray-700 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                Inscription
              </button>
            </div>
          </CardHeader>

          <CardContent>
            {/* Erreur */}
            {error && (
              <div className="flex items-center gap-2 p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
                <p className="text-sm text-red-400">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-gray-300">Nom d'utilisateur</Label>
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyste"
                  required
                  minLength={3}
                  className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500 focus:border-orange-500 focus:ring-orange-500/20"
                />
              </div>

              {mode === 'register' && (
                <div className="space-y-2">
                  <Label htmlFor="displayName" className="text-gray-300">Nom complet</Label>
                  <Input
                    id="displayName"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Jean Dupont"
                    className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500 focus:border-orange-500 focus:ring-orange-500/20"
                  />
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="password" className="text-gray-300">Mot de passe</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  minLength={6}
                  className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500 focus:border-orange-500 focus:ring-orange-500/20"
                />
              </div>

              {mode === 'register' && (
                <div className="space-y-2">
                  <Label htmlFor="confirmPassword" className="text-gray-300">Confirmer le mot de passe</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••"
                    required
                    minLength={6}
                    className="bg-gray-800 border-gray-700 text-white placeholder:text-gray-500 focus:border-orange-500 focus:ring-orange-500/20"
                  />
                </div>
              )}

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-orange-600 hover:bg-orange-700 text-white font-medium"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                ) : null}
                {mode === 'login' ? 'Se connecter' : "S'inscrire"}
              </Button>
            </form>

            {mode === 'login' && (
              <p className="text-xs text-gray-500 text-center mt-4">
                Premier utilisateur inscrit = administrateur
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
