import { useCallback, useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import { Users, UserPlus, Loader2 } from 'lucide-react'
import { toast } from 'sonner'

const ROLES = [
  { value: 'admin', label: 'Administrateur' },
  { value: 'analyst', label: 'Analyste' },
  { value: 'viewer', label: 'Lecteur (viewer)' },
]

const selectClass = 'bg-gray-800 border border-gray-700 text-white rounded-md px-2 py-1 text-sm'

// Administration des comptes (admin uniquement) : liste, creation, roles,
// desactivation. Toute modification de role ou desactivation revoque les
// sessions de l'utilisateur concerne cote serveur.
export default function UserManagement({ currentUserId }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ username: '', display_name: '', password: '', role: 'analyst' })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setUsers(await apiService.listUsers())
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Impossible de charger les utilisateurs')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleCreate = async (e) => {
    e.preventDefault()
    setCreating(true)
    try {
      await apiService.createUser(form)
      toast.success(`Compte ${form.username} cree`)
      setForm({ username: '', display_name: '', password: '', role: 'analyst' })
      await load()
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Creation impossible')
    } finally {
      setCreating(false)
    }
  }

  const handleRole = async (u, role) => {
    try {
      await apiService.setUserRole(u.id, role)
      toast.success(`Role de ${u.username} : ${role}`)
      await load()
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Changement de role impossible')
    }
  }

  const handleDisabled = async (u) => {
    try {
      await apiService.setUserDisabled(u.id, !u.disabled)
      toast.success(u.disabled ? `${u.username} reactive` : `${u.username} desactive`)
      await load()
    } catch (err) {
      toast.error(err?.response?.data?.error || 'Operation impossible')
    }
  }

  return (
    <Card className="bg-gray-900 border-gray-800">
      <CardHeader>
        <CardTitle className="text-white flex items-center gap-2">
          <Users className="h-5 w-5 text-orange-500" />
          Utilisateurs
        </CardTitle>
        <CardDescription className="text-gray-400">
          Les inscriptions publiques sont fermees par defaut : creez ici les comptes de l'equipe.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading ? (
          <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
        ) : (
          <div className="space-y-2">
            {users.map((u) => (
              <div key={u.id} className="flex flex-wrap items-center justify-between gap-2 p-3 bg-gray-800 rounded-lg">
                <div className="min-w-0">
                  <p className="text-sm text-white truncate">
                    {u.display_name || u.username}{' '}
                    <span className="text-gray-500 font-mono">@{u.username}</span>
                  </p>
                  {u.disabled ? <Badge variant="destructive" className="mt-1">Desactive</Badge> : null}
                </div>
                <div className="flex items-center gap-2">
                  <select
                    aria-label={`Role de ${u.username}`}
                    value={u.role}
                    disabled={u.id === currentUserId}
                    onChange={(e) => handleRole(u, e.target.value)}
                    className={selectClass}
                  >
                    {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                  </select>
                  {u.id !== currentUserId && (
                    <Button variant="outline" size="sm" onClick={() => handleDisabled(u)}
                      className="border-gray-700 text-gray-300">
                      {u.disabled ? 'Reactiver' : 'Desactiver'}
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <form onSubmit={handleCreate} className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-gray-800">
          <div>
            <Label className="text-gray-300">Nom d'utilisateur</Label>
            <Input value={form.username} required minLength={3}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              className="bg-gray-800 border-gray-700 text-white mt-1" />
          </div>
          <div>
            <Label className="text-gray-300">Nom complet</Label>
            <Input value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              className="bg-gray-800 border-gray-700 text-white mt-1" />
          </div>
          <div>
            <Label className="text-gray-300">Mot de passe initial</Label>
            <Input type="password" value={form.password} required minLength={12} autoComplete="new-password"
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="bg-gray-800 border-gray-700 text-white mt-1" />
          </div>
          <div>
            <Label className="text-gray-300">Role</Label>
            <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}
              className={`${selectClass} w-full mt-1 py-2`}>
              {ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
            </select>
          </div>
          <div className="md:col-span-2">
            <Button type="submit" disabled={creating} className="bg-orange-600 hover:bg-orange-700">
              {creating ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <UserPlus className="h-4 w-4 mr-2" />}
              Creer le compte
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
