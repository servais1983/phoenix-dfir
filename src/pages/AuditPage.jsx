import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { useAuth } from '@/context/AuthContext'
import { apiService } from '@/services/api'
import { toast } from 'sonner'
import {
  ScrollText,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Loader2,
} from 'lucide-react'

const ACTION_LABELS = {
  'login': 'Connexion',
  'register': 'Inscription',
  'create_investigation': 'Nouvelle enquete',
  'update_investigation': 'Modification enquete',
  'update_investigation_status': 'Changement statut',
  'delete_investigation': 'Suppression enquete',
  'add_ioc': 'Ajout IoC',
  'delete_ioc': 'Suppression IoC',
  'add_timeline_event': 'Ajout evenement',
  'upload_artifact': 'Upload artefact',
  'analyze_file': 'Analyse fichier',
  'generate_report': 'Generation rapport',
}

const ACTION_COLORS = {
  'login': 'text-green-400',
  'register': 'text-blue-400',
  'delete_investigation': 'text-red-400',
  'delete_ioc': 'text-red-400',
  'create_investigation': 'text-orange-400',
  'upload_artifact': 'text-cyan-400',
  'analyze_file': 'text-purple-400',
}

export default function AuditPage() {
  const { user } = useAuth()
  const [auditLog, setAuditLog] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const perPage = 30

  const loadAudit = useCallback(async () => {
    setLoading(true)
    try {
      const data = await apiService.getAuditLog(page, perPage)
      setAuditLog(data.items || [])
      setTotal(data.total || 0)
    } catch {
      toast.error('Erreur chargement du journal d\'audit')
      setAuditLog([])
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    if (user?.role === 'admin') {
      loadAudit()
    } else {
      setLoading(false)
    }
  }, [user?.role, loadAudit])

  if (user?.role !== 'admin') {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-center">
        <ShieldAlert className="h-16 w-16 text-gray-600 mb-4" />
        <h2 className="text-xl font-semibold text-gray-300 mb-2">Acces reserve aux administrateurs</h2>
        <p className="text-gray-500">Vous devez avoir le role administrateur pour consulter le journal d'audit.</p>
      </div>
    )
  }

  const totalPages = Math.ceil(total / perPage)

  return (
    <div className="space-y-6">
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white flex items-center gap-2">
                <ScrollText className="h-5 w-5 text-orange-500" />
                Journal d'Audit
              </CardTitle>
              <CardDescription className="text-gray-400">
                {total} action{total !== 1 ? 's' : ''} enregistree{total !== 1 ? 's' : ''}
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-orange-500" />
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800">
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">Date</th>
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">Utilisateur</th>
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">Action</th>
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">Cible</th>
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">Details</th>
                      <th className="text-left py-3 px-3 text-gray-400 font-medium">IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLog.map((entry) => (
                      <tr key={entry.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                          {entry.created_at ? new Date(entry.created_at).toLocaleString('fr-FR') : '--'}
                        </td>
                        <td className="py-2.5 px-3 text-gray-200">
                          {entry.username || '--'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={ACTION_COLORS[entry.action] || 'text-gray-300'}>
                            {ACTION_LABELS[entry.action] || entry.action}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-gray-400 text-xs">
                          {entry.target_type ? (
                            <Badge variant="outline" className="border-gray-700 text-gray-400 text-xs">
                              {entry.target_type}
                            </Badge>
                          ) : '--'}
                        </td>
                        <td className="py-2.5 px-3 text-gray-500 text-xs max-w-xs truncate">
                          {typeof entry.details === 'object'
                            ? JSON.stringify(entry.details).substring(0, 80)
                            : (entry.details || '--').substring(0, 80)
                          }
                        </td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-500">
                          {entry.ip_address || '--'}
                        </td>
                      </tr>
                    ))}
                    {auditLog.length === 0 && (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-gray-500">
                          Aucune action enregistree
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-800">
                  <span className="text-xs text-gray-500">
                    Page {page} sur {totalPages}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page <= 1}
                      onClick={() => setPage(p => Math.max(1, p - 1))}
                      className="border-gray-700 text-gray-300"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={page >= totalPages}
                      onClick={() => setPage(p => p + 1)}
                      className="border-gray-700 text-gray-300"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
