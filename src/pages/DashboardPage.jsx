import { useState, useEffect, useCallback, useMemo } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { useApp } from '@/context/AppContext'
import { apiService } from '@/services/api'
import { toast } from 'sonner'
import {
  Database,
  AlertTriangle,
  FileText,
  Activity,
  Plus,
  Upload,
  Clock,
  CheckCircle,
  XCircle,
  Zap,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

export default function DashboardPage() {
  const {
    investigations,
    currentInvestigation,
    backendStatus,
    analysisResults,
  } = useApp()

  const [stats, setStats] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [loadingTimeline, setLoadingTimeline] = useState(false)

  const loadTimeline = useCallback(async () => {
    if (!currentInvestigation?.id) return
    setLoadingTimeline(true)
    try {
      const data = await apiService.getTimeline(currentInvestigation.id)
      setTimeline(Array.isArray(data) ? data : data.events || [])
    } catch {
      setTimeline([])
    } finally {
      setLoadingTimeline(false)
    }
  }, [currentInvestigation?.id])

  const loadStats = useCallback(async () => {
    try {
      const data = await apiService.getStats()
      setStats(data)
    } catch (err) {
      setStats(null)
      if (err?.response?.status !== 401) {
        toast.error('Impossible de charger les statistiques')
      }
    }
  }, [])

  useEffect(() => {
    loadStats()
  }, [loadStats])

  useEffect(() => {
    loadTimeline()
  }, [loadTimeline])

  const activeCount = investigations.filter(
    (inv) => inv.status === 'active' || inv.status === 'en_cours'
  ).length || investigations.length

  const totalIocs = stats?.total_iocs ?? investigations.reduce(
    (sum, inv) => sum + (inv.iocs_count || inv.iocs || 0),
    0
  )

  const totalArtifacts = stats?.total_artifacts ?? investigations.reduce(
    (sum, inv) => sum + (inv.artifacts_count || inv.artifacts || 0),
    0
  )

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-500'
      case 'high': return 'bg-orange-500'
      case 'medium': return 'bg-yellow-500'
      case 'low': return 'bg-blue-500'
      default: return 'bg-gray-500'
    }
  }

  const recentEvents = timeline.length > 0
    ? timeline.slice(0, 5)
    : [
        { timestamp: '--', event: 'Aucun evenement recent', severity: 'low' },
      ]

  // Construire les donnees du graphique a partir des series temporelles reelles
  const activityData = useMemo(() => {
    const ts = stats?.timeseries
    if (!ts) return []

    const dateMap = {}
    const dayNames = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam']

    // Generer les 7 derniers jours
    for (let i = 6; i >= 0; i--) {
      const d = new Date()
      d.setDate(d.getDate() - i)
      const key = d.toISOString().split('T')[0]
      dateMap[key] = { jour: dayNames[d.getDay()], analyses: 0, iocs: 0, events: 0 }
    }

    for (const entry of (ts.artifacts || [])) {
      if (dateMap[entry.date]) dateMap[entry.date].analyses = entry.count
    }
    for (const entry of (ts.iocs || [])) {
      if (dateMap[entry.date]) dateMap[entry.date].iocs = entry.count
    }
    for (const entry of (ts.investigations || [])) {
      if (dateMap[entry.date]) dateMap[entry.date].events = entry.count
    }

    return Object.values(dateMap)
  }, [stats])

  return (
    <div className="space-y-6">
      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">
              Enquetes Actives
            </CardTitle>
            <Database className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{activeCount}</div>
            <p className="text-xs text-gray-400">
              {investigations.length} total
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">
              IoCs Detectes
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{totalIocs}</div>
            <p className="text-xs text-gray-400">
              Indicateurs de compromission
            </p>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">
              Artefacts Analyses
            </CardTitle>
            <FileText className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-white">{totalArtifacts}</div>
            <p className="text-xs text-gray-400">Fichiers traites</p>
          </CardContent>
        </Card>

        <Card className="bg-gray-900 border-gray-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-gray-300">
              Statut Backend
            </CardTitle>
            {backendStatus === 'online' ? (
              <CheckCircle className="h-4 w-4 text-green-500" />
            ) : (
              <XCircle className="h-4 w-4 text-red-500" />
            )}
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div
                className={`h-2 w-2 rounded-full ${
                  backendStatus === 'online'
                    ? 'bg-green-500'
                    : backendStatus === 'connecting'
                    ? 'bg-yellow-500 animate-pulse'
                    : 'bg-red-500'
                }`}
              />
              <span className="text-2xl font-bold text-white capitalize">
                {backendStatus === 'online'
                  ? 'En ligne'
                  : backendStatus === 'connecting'
                  ? 'Connexion...'
                  : 'Hors ligne'}
              </span>
            </div>
            <p className="text-xs text-gray-400">Phoenix DFIR Core</p>
          </CardContent>
        </Card>
      </div>

      {/* Chart and Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Chart */}
        <Card className="bg-gray-900 border-gray-800 lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-white">Activite sur 7 jours</CardTitle>
            <CardDescription className="text-gray-400">
              Analyses, IoCs et evenements detectes
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData}>
                  <defs>
                    <linearGradient id="colorAnalyses" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorIocs" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="jour" stroke="#9ca3af" fontSize={12} />
                  <YAxis stroke="#9ca3af" fontSize={12} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: '1px solid #374151',
                      borderRadius: '8px',
                      color: '#f3f4f6',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="analyses"
                    stroke="#f97316"
                    fillOpacity={1}
                    fill="url(#colorAnalyses)"
                    name="Analyses"
                  />
                  <Area
                    type="monotone"
                    dataKey="iocs"
                    stroke="#ef4444"
                    fillOpacity={1}
                    fill="url(#colorIocs)"
                    name="IoCs"
                  />
                  <Area
                    type="monotone"
                    dataKey="events"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorEvents)"
                    name="Evenements"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity Feed */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Activite Recente</CardTitle>
            <CardDescription className="text-gray-400">
              {currentInvestigation
                ? currentInvestigation.name
                : 'Derniers evenements'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loadingTimeline ? (
              <div className="space-y-3">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-12 bg-gray-800 rounded animate-pulse" />
                ))}
              </div>
            ) : (
              <div className="space-y-3">
                {recentEvents.map((event, index) => (
                  <div
                    key={index}
                    className="flex items-start space-x-3 p-2 rounded-lg hover:bg-gray-800/50 transition-colors"
                  >
                    <div
                      className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${getSeverityColor(
                        event.severity
                      )}`}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-white font-medium truncate">
                        {event.event || event.description || 'Evenement'}
                      </p>
                      <p className="text-xs text-gray-400 font-mono">
                        {event.timestamp}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Actions Rapides</CardTitle>
          <CardDescription className="text-gray-400">
            Operations courantes
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              className="h-20 bg-orange-600 hover:bg-orange-700 flex flex-col gap-2"
              onClick={() => {
                window.dispatchEvent(
                  new CustomEvent('navigate', { detail: 'investigations' })
                )
              }}
            >
              <Plus className="h-6 w-6" />
              <span>Nouvelle Enquete</span>
            </Button>
            <Button
              variant="outline"
              className="h-20 border-gray-700 hover:bg-gray-800 flex flex-col gap-2 text-gray-300"
              onClick={() => {
                window.dispatchEvent(
                  new CustomEvent('navigate', { detail: 'analyzer' })
                )
              }}
            >
              <Upload className="h-6 w-6" />
              <span>Uploader des Preuves</span>
            </Button>
            <Button
              variant="outline"
              className="h-20 border-gray-700 hover:bg-gray-800 flex flex-col gap-2 text-gray-300"
              onClick={() => {
                window.dispatchEvent(
                  new CustomEvent('navigate', { detail: 'reports' })
                )
              }}
            >
              <FileText className="h-6 w-6" />
              <span>Generer un Rapport</span>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
