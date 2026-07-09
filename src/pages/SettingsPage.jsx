import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Separator } from '@/components/ui/separator.jsx'
import { useApp } from '@/context/AppContext'
import { useAuth } from '@/context/AuthContext'
import { apiService } from '@/services/api'
import { Settings, Wifi, WifiOff, CheckCircle, XCircle, Save, Loader2, Download, User, Key } from 'lucide-react'
import { toast } from 'sonner'

export default function SettingsPage() {
  const { backendStatus, phoenixAvailable, checkHealth, currentInvestigation } = useApp()
  const { user, changePassword } = useAuth()
  const [testing, setTesting] = useState(false)
  const [saved, setSaved] = useState(false)
  const [exportingStix, setExportingStix] = useState(false)

  // Changement de mot de passe
  const [currentPwd, setCurrentPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [changingPwd, setChangingPwd] = useState(false)

  const [vtKey, setVtKey] = useState(() => localStorage.getItem('phoenix_vt_key') || '')
  const [githubToken, setGithubToken] = useState(() => localStorage.getItem('phoenix_github_token') || '')
  const [githubModel, setGithubModel] = useState(() => localStorage.getItem('phoenix_github_model') || 'openai/gpt-4o-mini')
  const [googleKey, setGoogleKey] = useState(() => localStorage.getItem('phoenix_google_key') || '')
  const [ollamaModel, setOllamaModel] = useState(() => localStorage.getItem('phoenix_ollama_model') || 'phi3:mini')
  const [backendUrl, setBackendUrl] = useState(() => localStorage.getItem('phoenix_backend_url') || 'http://localhost:5000')

  const handleChangePassword = async () => {
    if (newPwd !== confirmPwd) {
      toast.error('Le nouveau mot de passe et la confirmation ne correspondent pas')
      return
    }
    if (!currentPwd || !newPwd) {
      toast.error('Tous les champs sont requis')
      return
    }
    setChangingPwd(true)
    try {
      await changePassword(currentPwd, newPwd)
      toast.success('Mot de passe modifie. Reconnectez-vous.')
      // changePassword vide deja les tokens locaux et user
    } catch (e) {
      const msg = e?.response?.data?.error || 'Erreur lors du changement de mot de passe'
      toast.error(msg)
    } finally {
      setChangingPwd(false)
      setCurrentPwd('')
      setNewPwd('')
      setConfirmPwd('')
    }
  }

  const handleTest = async () => {
    setTesting(true)
    await checkHealth()
    setTesting(false)
  }

  const handleSave = () => {
    localStorage.setItem('phoenix_vt_key', vtKey)
    localStorage.setItem('phoenix_github_token', githubToken)
    localStorage.setItem('phoenix_github_model', githubModel)
    localStorage.setItem('phoenix_google_key', googleKey)
    localStorage.setItem('phoenix_ollama_model', ollamaModel)
    localStorage.setItem('phoenix_backend_url', backendUrl)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
    toast.success('Parametres sauvegardes')
  }

  const handleExportStix = async () => {
    if (!currentInvestigation?.id) {
      toast.error('Aucune enquete selectionnee pour l\'export STIX')
      return
    }
    setExportingStix(true)
    try {
      const data = await apiService.exportStix(currentInvestigation.id)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `stix_export_${currentInvestigation.name || currentInvestigation.id}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Export STIX telecharge')
    } catch (e) {
      console.error(e)
      toast.error('Erreur lors de l\'export STIX')
    } finally {
      setExportingStix(false)
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Backend */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Connexion Backend</CardTitle>
          <CardDescription className="text-gray-400">Configuration du serveur Phoenix DFIR</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-gray-300">URL du Backend</Label>
            <Input
              value={backendUrl}
              onChange={(e) => setBackendUrl(e.target.value)}
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
          </div>
          <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
            <div className="flex items-center gap-3">
              {backendStatus === 'online' ? (
                <Wifi className="h-5 w-5 text-emerald-500" />
              ) : (
                <WifiOff className="h-5 w-5 text-red-400" />
              )}
              <div>
                <p className="text-sm text-white">
                  {backendStatus === 'online' ? 'Connecte' : backendStatus === 'connecting' ? 'Connexion...' : 'Deconnecte'}
                </p>
                <p className="text-xs text-gray-500">{backendUrl}</p>
              </div>
            </div>
            <Badge variant={backendStatus === 'online' ? 'default' : 'destructive'}
              className={backendStatus === 'online' ? 'bg-emerald-600/20 text-emerald-400 border-emerald-600/30' : ''}>
              {backendStatus === 'online' ? 'En ligne' : 'Hors ligne'}
            </Badge>
          </div>
          <Button variant="outline" onClick={handleTest} disabled={testing} className="border-gray-700 text-gray-300">
            {testing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Wifi className="h-4 w-4 mr-2" />}
            Tester la connexion
          </Button>
        </CardContent>
      </Card>

      {/* API Keys */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Cles API</CardTitle>
          <CardDescription className="text-gray-400">Configurez vos cles API pour les services externes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-gray-300">VirusTotal API Key</Label>
            <Input
              type="password"
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="Votre cle API VirusTotal"
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">Requis pour l&apos;enrichissement des IoCs</p>
          </div>
          <Separator className="bg-gray-800" />
          <div>
            <Label className="text-gray-300">GitHub Copilot Token</Label>
            <Input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="Jeton GitHub (permission Models: read)"
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">
              Fournisseur IA principal (API GitHub Models). Cote serveur, definissez la variable
              d&apos;environnement GITHUB_TOKEN ou PHOENIX_GITHUB_TOKEN.
            </p>
          </div>
          <div>
            <Label className="text-gray-300">Modele GitHub Copilot</Label>
            <Input
              value={githubModel}
              onChange={(e) => setGithubModel(e.target.value)}
              placeholder="openai/gpt-4o-mini"
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">Modele du catalogue GitHub Models (ex: openai/gpt-4o, meta/llama-3.3-70b-instruct)</p>
          </div>
          <Separator className="bg-gray-800" />
          <div>
            <Label className="text-gray-300">Google AI API Key</Label>
            <Input
              type="password"
              value={googleKey}
              onChange={(e) => setGoogleKey(e.target.value)}
              placeholder="Votre cle API Google AI Studio"
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">Repli pour l&apos;analyse IA avec Gemini (si GitHub Copilot n&apos;est pas configure)</p>
          </div>
          <Separator className="bg-gray-800" />
          <div>
            <Label className="text-gray-300">Modele Ollama</Label>
            <Input
              value={ollamaModel}
              onChange={(e) => setOllamaModel(e.target.value)}
              placeholder="phi3:mini"
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
            />
            <p className="text-xs text-gray-500 mt-1">Repli local pour l&apos;analyse offline (si GitHub Copilot n&apos;est pas configure)</p>
          </div>
          <Button onClick={handleSave} className="bg-orange-600 hover:bg-orange-700">
            {saved ? <CheckCircle className="h-4 w-4 mr-2" /> : <Save className="h-4 w-4 mr-2" />}
            {saved ? 'Sauvegarde !' : 'Sauvegarder'}
          </Button>
        </CardContent>
      </Card>

      {/* User Info + change password */}
      {user && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Utilisateur Connecte</CardTitle>
            <CardDescription className="text-gray-400">Informations de votre compte et securite</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-3 p-3 bg-gray-800 rounded-lg">
              <User className="h-5 w-5 text-orange-400" />
              <div>
                <p className="text-sm text-white font-medium">{user.display_name || user.username}</p>
                <p className="text-xs text-gray-400">@{user.username}{user.role ? ` - ${user.role}` : ''}</p>
              </div>
            </div>

            <Separator className="bg-gray-800" />

            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm text-gray-300">
                <Key className="h-4 w-4 text-orange-400" />
                Changer mon mot de passe
              </div>
              <p className="text-xs text-gray-500">
                Politique : 12 caracteres minimum, au moins 3 types
                (majuscule, minuscule, chiffre, special). La session courante sera revoquee.
              </p>
              <div>
                <Label className="text-gray-300 text-xs">Mot de passe actuel</Label>
                <Input
                  type="password"
                  value={currentPwd}
                  onChange={(e) => setCurrentPwd(e.target.value)}
                  autoComplete="current-password"
                  className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                />
              </div>
              <div>
                <Label className="text-gray-300 text-xs">Nouveau mot de passe</Label>
                <Input
                  type="password"
                  value={newPwd}
                  onChange={(e) => setNewPwd(e.target.value)}
                  autoComplete="new-password"
                  className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                />
              </div>
              <div>
                <Label className="text-gray-300 text-xs">Confirmer</Label>
                <Input
                  type="password"
                  value={confirmPwd}
                  onChange={(e) => setConfirmPwd(e.target.value)}
                  autoComplete="new-password"
                  className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                />
              </div>
              <Button
                onClick={handleChangePassword}
                disabled={changingPwd || !currentPwd || !newPwd || !confirmPwd}
                className="bg-orange-600 hover:bg-orange-700"
              >
                {changingPwd ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Key className="h-4 w-4 mr-2" />}
                {changingPwd ? 'Modification...' : 'Changer'}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* STIX Export */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Export STIX</CardTitle>
          <CardDescription className="text-gray-400">Exportez les IoCs de l&apos;enquete courante au format STIX 2.1</CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={handleExportStix} disabled={exportingStix || !currentInvestigation} className="bg-orange-600 hover:bg-orange-700">
            {exportingStix ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
            {exportingStix ? 'Export en cours...' : 'Exporter en STIX'}
          </Button>
          {!currentInvestigation && (
            <p className="text-xs text-gray-500 mt-2">Selectionnez une enquete pour activer l&apos;export.</p>
          )}
        </CardContent>
      </Card>

      {/* System Info */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Informations Systeme</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
              <span className="text-sm text-gray-300">Phoenix Core</span>
              <div className="flex items-center gap-2">
                {phoenixAvailable ? (
                  <><CheckCircle className="h-4 w-4 text-emerald-500" /><span className="text-sm text-emerald-400">Disponible</span></>
                ) : (
                  <><XCircle className="h-4 w-4 text-gray-500" /><span className="text-sm text-gray-500">Non disponible</span></>
                )}
              </div>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
              <span className="text-sm text-gray-300">Version</span>
              <span className="text-sm text-gray-400 font-mono">4.0.0</span>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
              <span className="text-sm text-gray-300">Backend API</span>
              <span className={`text-sm ${backendStatus === 'online' ? 'text-emerald-400' : 'text-red-400'}`}>
                {backendStatus === 'online' ? 'Operationnel' : 'Inactif'}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
