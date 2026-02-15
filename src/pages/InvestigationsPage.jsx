import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table.jsx'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog.jsx'
import { useApp } from '@/context/AppContext'
import { apiService } from '@/services/api'
import { Plus, Trash2, Eye, FolderSearch, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

export default function InvestigationsPage() {
  const { investigations, loadInvestigations, createInvestigation, deleteInvestigation, currentInvestigation, setCurrentInvestigation } = useApp()
  const [newName, setNewName] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [details, setDetails] = useState(null)
  const [loadingDetails, setLoadingDetails] = useState(false)

  const handleCreate = async () => {
    if (!newName.trim()) return
    setCreating(true)
    try {
      await createInvestigation(newName.trim())
      setNewName('')
      setCreateOpen(false)
      toast.success('Enquete creee avec succes')
    } catch (e) {
      console.error(e)
      toast.error('Erreur lors de la creation de l\'enquete')
    } finally {
      setCreating(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    setDeleting(true)
    try {
      await deleteInvestigation(deleteTarget.id)
      setDeleteOpen(false)
      setDeleteTarget(null)
      if (details?.id === deleteTarget.id) setDetails(null)
      toast.success('Enquete supprimee')
    } catch (e) {
      console.error(e)
      toast.error('Erreur lors de la suppression')
    } finally {
      setDeleting(false)
    }
  }

  const handleView = async (inv) => {
    setCurrentInvestigation(inv)
    setLoadingDetails(true)
    try {
      const data = await apiService.getInvestigation(inv.id)
      setDetails({ ...data, id: inv.id })
    } catch {
      setDetails(null)
      toast.error('Erreur lors du chargement des details')
    } finally {
      setLoadingDetails(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-white">Gestion des Enquetes</h2>
          <p className="text-sm text-gray-400">{investigations.length} enquete{investigations.length !== 1 ? 's' : ''} enregistree{investigations.length !== 1 ? 's' : ''}</p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button className="bg-orange-600 hover:bg-orange-700">
              <Plus className="h-4 w-4 mr-2" />
              Nouvelle Enquete
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-gray-900 border-gray-700">
            <DialogHeader>
              <DialogTitle className="text-white">Creer une Enquete</DialogTitle>
              <DialogDescription className="text-gray-400">
                Donnez un nom a votre nouvelle investigation forensique.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-gray-300">Nom de l&apos;enquete</Label>
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Ex: Incident-2026-001"
                  className="bg-gray-800 border-gray-700 text-white mt-1"
                  onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)} className="border-gray-700 text-gray-300">
                Annuler
              </Button>
              <Button onClick={handleCreate} disabled={creating || !newName.trim()} className="bg-orange-600 hover:bg-orange-700">
                {creating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Creer
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Investigations Table */}
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="p-0">
          {investigations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-400">
              <FolderSearch className="h-12 w-12 mb-4 text-gray-600" />
              <p className="text-lg font-medium">Aucune enquete</p>
              <p className="text-sm">Creez votre premiere investigation pour commencer.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="border-gray-800 hover:bg-transparent">
                  <TableHead className="text-gray-400">Nom</TableHead>
                  <TableHead className="text-gray-400">Statut</TableHead>
                  <TableHead className="text-gray-400">Date</TableHead>
                  <TableHead className="text-gray-400 text-center">Artefacts</TableHead>
                  <TableHead className="text-gray-400 text-center">IoCs</TableHead>
                  <TableHead className="text-gray-400 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {investigations.map((inv) => (
                  <TableRow key={inv.id} className={`border-gray-800 hover:bg-gray-800/50 ${currentInvestigation?.id === inv.id ? 'bg-orange-600/5' : ''}`}>
                    <TableCell className="text-white font-medium">{inv.name}</TableCell>
                    <TableCell>
                      <Badge variant={inv.status === 'active' ? 'default' : 'secondary'} className={inv.status === 'active' ? 'bg-green-600/20 text-green-400 border-green-600/30' : 'bg-gray-700 text-gray-400'}>
                        {inv.status === 'active' ? 'Active' : 'Inactive'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-gray-400 text-sm font-mono">{inv.created}</TableCell>
                    <TableCell className="text-gray-300 text-center">{inv.artifacts}</TableCell>
                    <TableCell className="text-gray-300 text-center">{inv.iocs}</TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button variant="ghost" size="sm" onClick={() => handleView(inv)} className="text-gray-400 hover:text-white hover:bg-gray-800">
                        <Eye className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => { setDeleteTarget(inv); setDeleteOpen(true) }}
                        className="text-gray-400 hover:text-red-400 hover:bg-red-900/20"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent className="bg-gray-900 border-gray-700">
          <DialogHeader>
            <DialogTitle className="text-white">Confirmer la suppression</DialogTitle>
            <DialogDescription className="text-gray-400">
              Supprimer l&apos;enquete &quot;{deleteTarget?.name}&quot; ? Cette action est irreversible.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)} className="border-gray-700 text-gray-300">Annuler</Button>
            <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
              {deleting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Supprimer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Details Panel */}
      {loadingDetails && (
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="py-8 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-orange-500 mr-3" />
            <span className="text-gray-400">Chargement des details...</span>
          </CardContent>
        </Card>
      )}

      {details && !loadingDetails && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">{details.nom_du_cas}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-500 uppercase">Cree le</p>
                <p className="text-sm text-white font-mono">{details.date_creation}</p>
              </div>
              <div className="p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-500 uppercase">Derniere activite</p>
                <p className="text-sm text-white font-mono">{details.derniere_activite}</p>
              </div>
              <div className="p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-500 uppercase">Artefacts</p>
                <p className="text-sm text-white">{details.artefacts_analyses?.length || 0} fichier(s)</p>
              </div>
              <div className="p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-500 uppercase">IoCs</p>
                <p className="text-sm text-white">
                  {(details.iocs?.ips?.length || 0) + (details.iocs?.hashes?.length || 0) + (details.iocs?.domaines?.length || 0)} detecte(s)
                </p>
              </div>
            </div>
            {details.artefacts_analyses?.length > 0 && (
              <div>
                <h4 className="text-sm text-gray-400 mb-2">Artefacts analyses</h4>
                <div className="flex flex-wrap gap-2">
                  {details.artefacts_analyses.map((a, i) => (
                    <Badge key={i} variant="outline" className="border-gray-700 text-gray-300 font-mono text-xs">{typeof a === 'string' ? a : a.name || a.filename || JSON.stringify(a)}</Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
