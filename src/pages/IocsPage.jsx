import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog.jsx'
import { useApp } from '@/context/AppContext'
import { apiService } from '@/services/api'
import { Plus, Trash2, Search, Globe, Hash, AlertTriangle, Loader2, Shield } from 'lucide-react'

const TYPE_CONFIG = {
  ips: { icon: Globe, color: 'text-blue-400', bg: 'bg-blue-500/10', label: 'IP' },
  domaines: { icon: Globe, color: 'text-green-400', bg: 'bg-green-500/10', label: 'Domaine' },
  hashes: { icon: Hash, color: 'text-purple-400', bg: 'bg-purple-500/10', label: 'Hash' },
}

export default function IocsPage() {
  const { currentInvestigation } = useApp()
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const [adding, setAdding] = useState(false)
  const [enriching, setEnriching] = useState(null)
  const [newIoc, setNewIoc] = useState({ type: 'ips', value: '', source: '' })

  const loadIocs = useCallback(async () => {
    if (!currentInvestigation?.id) return
    setLoading(true)
    try {
      const data = await apiService.getIocs(currentInvestigation.id)
      setIocs(data.iocs || [])
    } catch {
      setIocs([])
    } finally {
      setLoading(false)
    }
  }, [currentInvestigation?.id])

  useEffect(() => { loadIocs() }, [loadIocs])

  const handleAdd = async () => {
    if (!newIoc.value || !currentInvestigation?.id) return
    setAdding(true)
    try {
      await apiService.addIoc(currentInvestigation.id, newIoc)
      setNewIoc({ type: 'ips', value: '', source: '' })
      setAddOpen(false)
      loadIocs()
    } catch (e) {
      console.error(e)
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async (ioc) => {
    if (!currentInvestigation?.id) return
    try {
      await apiService.deleteIoc(currentInvestigation.id, ioc.type, ioc.index)
      loadIocs()
    } catch (e) {
      console.error(e)
    }
  }

  const handleEnrich = async (ioc) => {
    setEnriching(ioc.value)
    try {
      const result = await apiService.enrichIoc(ioc.type, ioc.value)
      setIocs(prev => prev.map(i =>
        i.value === ioc.value && i.type === ioc.type
          ? { ...i, enrichment: result.enrichment }
          : i
      ))
    } catch (e) {
      console.error(e)
    } finally {
      setEnriching(null)
    }
  }

  const ipsCount = iocs.filter(i => i.type === 'ips').length
  const domainsCount = iocs.filter(i => i.type === 'domaines').length
  const hashesCount = iocs.filter(i => i.type === 'hashes').length

  if (!currentInvestigation) {
    return (
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="flex flex-col items-center justify-center py-16 text-gray-400">
          <AlertTriangle className="h-12 w-12 mb-4 text-gray-600" />
          <p className="text-lg font-medium">Aucune enquete selectionnee</p>
          <p className="text-sm">Selectionnez une enquete pour gerer les IoCs.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Globe className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{ipsCount}</p>
              <p className="text-xs text-gray-400">Adresses IP</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 bg-green-500/10 rounded-lg">
              <Globe className="h-5 w-5 text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{domainsCount}</p>
              <p className="text-xs text-gray-400">Domaines</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="p-4 flex items-center gap-3">
            <div className="p-2 bg-purple-500/10 rounded-lg">
              <Hash className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-white">{hashesCount}</p>
              <p className="text-xs text-gray-400">Hashes</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-white">Indicateurs de Compromission</h2>
        <Dialog open={addOpen} onOpenChange={setAddOpen}>
          <DialogTrigger asChild>
            <Button className="bg-orange-600 hover:bg-orange-700">
              <Plus className="h-4 w-4 mr-2" /> Ajouter un IoC
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-gray-900 border-gray-700">
            <DialogHeader>
              <DialogTitle className="text-white">Ajouter un IoC</DialogTitle>
              <DialogDescription className="text-gray-400">Ajoutez un indicateur de compromission.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-gray-300">Type</Label>
                <Select value={newIoc.type} onValueChange={(v) => setNewIoc(prev => ({ ...prev, type: v }))}>
                  <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-gray-800 border-gray-700">
                    <SelectItem value="ips">Adresse IP</SelectItem>
                    <SelectItem value="domaines">Domaine</SelectItem>
                    <SelectItem value="hashes">Hash (MD5/SHA)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-gray-300">Valeur</Label>
                <Input
                  value={newIoc.value}
                  onChange={(e) => setNewIoc(prev => ({ ...prev, value: e.target.value }))}
                  placeholder={newIoc.type === 'ips' ? '192.168.1.1' : newIoc.type === 'domaines' ? 'malware.example.com' : 'a1b2c3d4e5f6...'}
                  className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                />
              </div>
              <div>
                <Label className="text-gray-300">Source</Label>
                <Input
                  value={newIoc.source}
                  onChange={(e) => setNewIoc(prev => ({ ...prev, source: e.target.value }))}
                  placeholder="Ex: auth.log, analyse manuelle..."
                  className="bg-gray-800 border-gray-700 text-white mt-1"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setAddOpen(false)} className="border-gray-700 text-gray-300">Annuler</Button>
              <Button onClick={handleAdd} disabled={adding || !newIoc.value} className="bg-orange-600 hover:bg-orange-700">
                {adding && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Ajouter
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* IoC Table */}
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="p-0">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-orange-500 mr-3" />
              <span className="text-gray-400">Chargement...</span>
            </div>
          ) : iocs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-500">
              <Shield className="h-10 w-10 mb-3 text-gray-600" />
              <p className="text-sm">Aucun IoC detecte</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-gray-800 hover:bg-transparent">
                  <TableHead className="text-gray-400">Type</TableHead>
                  <TableHead className="text-gray-400">Valeur</TableHead>
                  <TableHead className="text-gray-400">Source</TableHead>
                  <TableHead className="text-gray-400">Enrichissement VT</TableHead>
                  <TableHead className="text-gray-400 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {iocs.map((ioc, index) => {
                  const config = TYPE_CONFIG[ioc.type] || TYPE_CONFIG.ips
                  const Icon = config.icon
                  return (
                    <TableRow key={`${ioc.type}-${index}`} className="border-gray-800 hover:bg-gray-800/50">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className={`p-1 rounded ${config.bg}`}>
                            <Icon className={`h-3.5 w-3.5 ${config.color}`} />
                          </div>
                          <span className="text-gray-300 text-sm">{config.label}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm text-white">{ioc.value}</TableCell>
                      <TableCell className="text-sm text-gray-400">{ioc.source || '-'}</TableCell>
                      <TableCell>
                        {ioc.enrichment ? (
                          <Badge variant="outline" className="text-xs border-gray-700 text-gray-300">
                            {typeof ioc.enrichment === 'object'
                              ? `M:${ioc.enrichment.malicious || 0} S:${ioc.enrichment.suspicious || 0}`
                              : ioc.enrichment}
                          </Badge>
                        ) : (
                          <span className="text-xs text-gray-600">Non enrichi</span>
                        )}
                      </TableCell>
                      <TableCell className="text-right space-x-1">
                        <Button
                          variant="ghost" size="sm"
                          onClick={() => handleEnrich(ioc)}
                          disabled={enriching === ioc.value}
                          className="text-gray-400 hover:text-orange-400"
                        >
                          {enriching === ioc.value ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => handleDelete(ioc)} className="text-gray-400 hover:text-red-400">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
