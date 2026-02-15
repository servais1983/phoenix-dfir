import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Separator } from '@/components/ui/separator.jsx'
import { useAuth } from '@/context/AuthContext'
import { apiService } from '@/services/api'
import {
  Plug, ShieldAlert, Brain, ShieldCheck, Globe, Radar, Users, FileSearch, FileCode,
  CheckCircle, XCircle, Loader2, Save, Wifi, ArrowUpRight, ArrowDownLeft, Settings,
  ChevronDown, ChevronUp
} from 'lucide-react'
import { toast } from 'sonner'

const ICON_MAP = {
  'shield-alert': ShieldAlert,
  'brain': Brain,
  'shield-check': ShieldCheck,
  'globe': Globe,
  'radar': Radar,
  'users': Users,
  'file-search': FileSearch,
  'file-code': FileCode,
  'plug': Plug,
}

const CATEGORY_LABELS = {
  'threat_intel': 'Threat Intelligence',
  'sandbox': 'Analyse / Sandbox',
  'rule_engine': 'Moteurs de Regles',
  'siem': 'SIEM',
  'ticketing': 'Ticketing',
  'other': 'Autre',
}

function ConnectorCard({ connector, onUpdate }) {
  const [expanded, setExpanded] = useState(false)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [config, setConfig] = useState({})
  const [enabled, setEnabled] = useState(connector.enabled || false)
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const Icon = ICON_MAP[connector.icon] || Plug

  useEffect(() => {
    if (expanded && connector.id) {
      apiService.getIntegration(connector.id).then(data => {
        setConfig(data.config || {})
        setEnabled(data.enabled || false)
      }).catch(() => {})
    }
  }, [expanded, connector.id])

  const handleTest = async () => {
    setTesting(true)
    try {
      const result = await apiService.testIntegration(connector.id)
      if (result.success) {
        toast.success(result.message)
      } else {
        toast.error(result.message)
      }
      onUpdate?.()
    } catch (e) {
      toast.error('Erreur lors du test')
    } finally {
      setTesting(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      await apiService.updateIntegration(connector.id, { config, enabled })
      toast.success(`${connector.name} configure`)
      onUpdate?.()
    } catch (e) {
      toast.error('Erreur lors de la sauvegarde')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card className="bg-gray-900 border-gray-800">
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-800/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${enabled ? 'bg-orange-600/20' : 'bg-gray-800'}`}>
            <Icon className={`h-5 w-5 ${enabled ? 'text-orange-500' : 'text-gray-500'}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-medium text-white">{connector.name}</h3>
              <Badge variant="outline" className="text-[10px] border-gray-700 text-gray-500">
                {CATEGORY_LABELS[connector.category] || connector.category}
              </Badge>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{connector.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {connector.last_test_status === 'success' && (
            <CheckCircle className="h-4 w-4 text-emerald-500" />
          )}
          {connector.last_test_status === 'error' && (
            <XCircle className="h-4 w-4 text-red-500" />
          )}
          <Badge className={enabled
            ? 'bg-emerald-600/20 text-emerald-400 border-emerald-600/30'
            : 'bg-gray-800 text-gray-500 border-gray-700'
          }>
            {enabled ? 'Active' : 'Inactif'}
          </Badge>
          {expanded ? <ChevronUp className="h-4 w-4 text-gray-500" /> : <ChevronDown className="h-4 w-4 text-gray-500" />}
        </div>
      </div>

      {expanded && (
        <CardContent className="pt-0 space-y-4">
          <Separator className="bg-gray-800" />

          {/* Capabilities */}
          <div className="flex gap-2 flex-wrap">
            {connector.capabilities?.includes('push_iocs') && (
              <Badge variant="outline" className="text-[10px] border-blue-800 text-blue-400">
                <ArrowUpRight className="h-3 w-3 mr-1" /> Push IoCs
              </Badge>
            )}
            {connector.capabilities?.includes('pull_iocs') && (
              <Badge variant="outline" className="text-[10px] border-green-800 text-green-400">
                <ArrowDownLeft className="h-3 w-3 mr-1" /> Pull IoCs
              </Badge>
            )}
            {connector.capabilities?.includes('enrich_ioc') && (
              <Badge variant="outline" className="text-[10px] border-purple-800 text-purple-400">
                <ShieldCheck className="h-3 w-3 mr-1" /> Enrichissement
              </Badge>
            )}
            {connector.capabilities?.includes('search') && (
              <Badge variant="outline" className="text-[10px] border-yellow-800 text-yellow-400">
                <Radar className="h-3 w-3 mr-1" /> Recherche
              </Badge>
            )}
          </div>

          {/* Config fields */}
          {isAdmin && connector.config_schema?.map(field => (
            <div key={field.key}>
              <Label className="text-gray-300 text-xs">{field.label}</Label>
              <Input
                type={field.type === 'password' ? 'password' : 'text'}
                value={config[field.key] || ''}
                onChange={e => setConfig(prev => ({ ...prev, [field.key]: e.target.value }))}
                placeholder={field.placeholder}
                className="bg-gray-800 border-gray-700 text-white mt-1 font-mono text-xs"
              />
            </div>
          ))}

          {/* Enable toggle + actions */}
          {isAdmin && (
            <div className="flex items-center gap-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={(e) => { e.stopPropagation(); setEnabled(!enabled) }}
                className={`text-xs ${enabled ? 'border-emerald-700 text-emerald-400' : 'border-gray-700 text-gray-400'}`}
              >
                {enabled ? 'Desactiver' : 'Activer'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={(e) => { e.stopPropagation(); handleTest() }}
                disabled={testing}
                className="border-gray-700 text-gray-300 text-xs"
              >
                {testing ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Wifi className="h-3 w-3 mr-1" />}
                Tester
              </Button>
              <Button
                size="sm"
                onClick={(e) => { e.stopPropagation(); handleSave() }}
                disabled={saving}
                className="bg-orange-600 hover:bg-orange-700 text-xs"
              >
                {saving ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Save className="h-3 w-3 mr-1" />}
                Sauvegarder
              </Button>
            </div>
          )}

          {!isAdmin && (
            <p className="text-xs text-gray-500">Seuls les administrateurs peuvent configurer les integrations.</p>
          )}

          {connector.last_test_message && (
            <p className={`text-xs ${connector.last_test_status === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
              Dernier test: {connector.last_test_message}
            </p>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState([])
  const [loading, setLoading] = useState(true)

  const loadIntegrations = async () => {
    try {
      const data = await apiService.listIntegrations()
      setIntegrations(data.integrations || [])
    } catch (e) {
      console.error('Erreur chargement integrations:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { loadIntegrations() }, [])

  // Grouper par categorie
  const grouped = {}
  for (const c of integrations) {
    const cat = c.category || 'other'
    if (!grouped[cat]) grouped[cat] = []
    grouped[cat].push(c)
  }

  const activeCount = integrations.filter(c => c.enabled).length

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-orange-500" />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-lg bg-orange-600/20 flex items-center justify-center">
            <Plug className="h-5 w-5 text-orange-500" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">Integrations</h2>
            <p className="text-sm text-gray-400">{integrations.length} connecteurs disponibles, {activeCount} actifs</p>
          </div>
        </div>
      </div>

      {/* Connectors by category */}
      {Object.entries(grouped).map(([category, connectors]) => (
        <div key={category} className="space-y-3">
          <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wider">
            {CATEGORY_LABELS[category] || category}
          </h3>
          {connectors.map(connector => (
            <ConnectorCard
              key={connector.id}
              connector={connector}
              onUpdate={loadIntegrations}
            />
          ))}
        </div>
      ))}
    </div>
  )
}
