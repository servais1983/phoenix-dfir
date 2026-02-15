import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog.jsx'
import { ScrollArea } from '@/components/ui/scroll-area.jsx'
import { useApp } from '@/context/AppContext'
import { apiService } from '@/services/api'
import { Plus, Download, Clock, AlertTriangle, Loader2, Filter } from 'lucide-react'

const SEVERITY_CONFIG = {
  critical: { color: 'bg-red-500', text: 'text-red-400', border: 'border-red-500/30', label: 'Critique' },
  high: { color: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500/30', label: 'Elevee' },
  medium: { color: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'Moyenne' },
  low: { color: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500/30', label: 'Basse' },
  info: { color: 'bg-gray-500', text: 'text-gray-400', border: 'border-gray-500/30', label: 'Info' },
}

export default function TimelinePage() {
  const { currentInvestigation } = useApp()
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(false)
  const [filter, setFilter] = useState('all')
  const [addOpen, setAddOpen] = useState(false)
  const [adding, setAdding] = useState(false)
  const [newEvent, setNewEvent] = useState({ timestamp: '', event: '', severity: 'medium' })

  const loadTimeline = useCallback(async () => {
    if (!currentInvestigation?.id) return
    setLoading(true)
    try {
      const data = await apiService.getTimeline(currentInvestigation.id)
      setEvents(Array.isArray(data) ? data : data.events || [])
    } catch {
      setEvents([])
    } finally {
      setLoading(false)
    }
  }, [currentInvestigation?.id])

  useEffect(() => { loadTimeline() }, [loadTimeline])

  const handleAdd = async () => {
    if (!newEvent.timestamp || !newEvent.event || !currentInvestigation?.id) return
    setAdding(true)
    try {
      await apiService.addTimelineEvent(currentInvestigation.id, newEvent)
      setNewEvent({ timestamp: '', event: '', severity: 'medium' })
      setAddOpen(false)
      loadTimeline()
    } catch (e) {
      console.error(e)
    } finally {
      setAdding(false)
    }
  }

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `timeline_${currentInvestigation?.name || 'export'}_${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const filteredEvents = filter === 'all' ? events : events.filter(e => e.severity === filter)
  const sortedEvents = [...filteredEvents].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''))

  if (!currentInvestigation) {
    return (
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="flex flex-col items-center justify-center py-16 text-gray-400">
          <Clock className="h-12 w-12 mb-4 text-gray-600" />
          <p className="text-lg font-medium">Aucune enquete selectionnee</p>
          <p className="text-sm">Selectionnez une enquete dans l&apos;onglet Enquetes pour voir la timeline.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Timeline des Evenements</h2>
          <p className="text-sm text-gray-400">{events.length} evenement{events.length !== 1 ? 's' : ''}</p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={filter} onValueChange={setFilter}>
            <SelectTrigger className="w-40 bg-gray-800 border-gray-700 text-white">
              <Filter className="h-3.5 w-3.5 mr-2" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-gray-800 border-gray-700">
              <SelectItem value="all">Toutes</SelectItem>
              <SelectItem value="critical">Critique</SelectItem>
              <SelectItem value="high">Elevee</SelectItem>
              <SelectItem value="medium">Moyenne</SelectItem>
              <SelectItem value="low">Basse</SelectItem>
              <SelectItem value="info">Info</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={handleExport} disabled={events.length === 0} className="border-gray-700 text-gray-300">
            <Download className="h-4 w-4 mr-2" /> Exporter
          </Button>
          <Dialog open={addOpen} onOpenChange={setAddOpen}>
            <DialogTrigger asChild>
              <Button className="bg-orange-600 hover:bg-orange-700">
                <Plus className="h-4 w-4 mr-2" /> Ajouter
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-gray-900 border-gray-700">
              <DialogHeader>
                <DialogTitle className="text-white">Ajouter un evenement</DialogTitle>
                <DialogDescription className="text-gray-400">Ajoutez un evenement a la timeline de l&apos;enquete.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label className="text-gray-300">Horodatage</Label>
                  <Input
                    type="datetime-local"
                    value={newEvent.timestamp}
                    onChange={(e) => setNewEvent(prev => ({ ...prev, timestamp: e.target.value }))}
                    className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                  />
                </div>
                <div>
                  <Label className="text-gray-300">Description</Label>
                  <Textarea
                    value={newEvent.event}
                    onChange={(e) => setNewEvent(prev => ({ ...prev, event: e.target.value }))}
                    placeholder="Description de l'evenement..."
                    className="bg-gray-800 border-gray-700 text-white mt-1"
                  />
                </div>
                <div>
                  <Label className="text-gray-300">Severite</Label>
                  <Select value={newEvent.severity} onValueChange={(v) => setNewEvent(prev => ({ ...prev, severity: v }))}>
                    <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-gray-800 border-gray-700">
                      <SelectItem value="critical">Critique</SelectItem>
                      <SelectItem value="high">Elevee</SelectItem>
                      <SelectItem value="medium">Moyenne</SelectItem>
                      <SelectItem value="low">Basse</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setAddOpen(false)} className="border-gray-700 text-gray-300">Annuler</Button>
                <Button onClick={handleAdd} disabled={adding || !newEvent.timestamp || !newEvent.event} className="bg-orange-600 hover:bg-orange-700">
                  {adding && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Ajouter
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Timeline */}
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-orange-500 mr-3" />
              <span className="text-gray-400">Chargement de la timeline...</span>
            </div>
          ) : sortedEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-gray-500">
              <Clock className="h-10 w-10 mb-3 text-gray-600" />
              <p className="text-sm">Aucun evenement dans la timeline</p>
            </div>
          ) : (
            <ScrollArea className="h-[600px]">
              <div className="relative pl-8">
                <div className="absolute left-3 top-0 bottom-0 w-px bg-gray-800" />
                {sortedEvents.map((event, index) => {
                  const config = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.info
                  return (
                    <div key={event.id || index} className="relative mb-6 last:mb-0">
                      <div className={`absolute left-[-22px] top-1.5 w-3 h-3 rounded-full ${config.color} ring-4 ring-gray-900`} />
                      <div className={`p-4 rounded-lg border bg-gray-800/40 ${config.border}`}>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-xs font-mono text-gray-400">{event.timestamp}</span>
                          <Badge variant="outline" className={`text-xs ${config.text} border-current`}>
                            {config.label}
                          </Badge>
                        </div>
                        <p className="text-sm text-gray-200">{event.event || event.description}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
