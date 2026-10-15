import { useCallback, useEffect, useState } from 'react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import { Loader2, UserPlus, X } from 'lucide-react'
import { toast } from 'sonner'

// Membres d'une enquete : seuls les membres (et les admins) y ont acces.
// L'admin et le createur de l'enquete peuvent ajouter / retirer des membres.
export default function InvestigationMembers({ investigationId }) {
  const [members, setMembers] = useState([])
  const [canManage, setCanManage] = useState(false)
  const [loading, setLoading] = useState(true)
  const [username, setUsername] = useState('')
  const [adding, setAdding] = useState(false)

  const load = useCallback(async () => {
    if (!investigationId) return
    setLoading(true)
    try {
      const data = await apiService.getInvestigationMembers(investigationId)
      setMembers(data.items || [])
      setCanManage(!!data.can_manage)
    } catch {
      setMembers([])
    } finally {
      setLoading(false)
    }
  }, [investigationId])

  useEffect(() => { load() }, [load])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!username.trim()) return
    setAdding(true)
    try {
      const data = await apiService.addInvestigationMember(investigationId, username.trim())
      setMembers(data.items || [])
      setUsername('')
      toast.success('Membre ajoute')
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Ajout impossible')
    } finally {
      setAdding(false)
    }
  }

  const handleRemove = async (member) => {
    try {
      const data = await apiService.removeInvestigationMember(investigationId, member.user_id)
      setMembers(data.items || [])
      toast.success(`${member.username} retire de l'enquete`)
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Retrait impossible')
    }
  }

  if (loading) return <Loader2 className="h-4 w-4 animate-spin text-gray-400" />

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        {members.map((m) => (
          <div key={m.user_id} className="flex items-center justify-between p-2 bg-gray-800 rounded-md">
            <span className="text-sm text-gray-200">
              {m.display_name || m.username}{' '}
              <span className="text-gray-500 font-mono">@{m.username}</span>
            </span>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className="border-gray-600 text-gray-300">{m.role}</Badge>
              {m.is_creator && <Badge className="bg-orange-600/20 text-orange-300">createur</Badge>}
              {canManage && !m.is_creator && (
                <Button variant="ghost" size="sm" onClick={() => handleRemove(m)}
                  aria-label={`Retirer ${m.username}`} className="text-gray-400 hover:text-red-400">
                  <X className="h-4 w-4" />
                </Button>
              )}
            </div>
          </div>
        ))}
      </div>
      {canManage && (
        <form onSubmit={handleAdd} className="flex gap-2">
          <Input value={username} onChange={(e) => setUsername(e.target.value)}
            placeholder="Nom d'utilisateur a ajouter"
            className="bg-gray-800 border-gray-700 text-white" />
          <Button type="submit" disabled={adding || !username.trim()} className="bg-orange-600 hover:bg-orange-700">
            {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />}
          </Button>
        </form>
      )}
    </div>
  )
}
