import { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'
import { useAuth } from '@/context/AuthContext'
import {
  BookOpenCheck, CheckCircle2, XCircle, Copy, Download, Eye, EyeOff, Loader2, Send, ShieldAlert,
} from 'lucide-react'
import { toast } from 'sonner'

const STATUS_STYLES = {
  WAITING_APPROVAL: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  APPROVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  REJECTED: 'bg-gray-500/10 text-gray-400 border-gray-600/40',
}
const STATUS_LABELS = { WAITING_APPROVAL: 'En attente', APPROVED: 'Approuve', REJECTED: 'Rejete' }
const PARTS = [['script', 'Script'], ['prechecks', 'Pre-verifications'], ['rollback', 'Rollback']]
const EXT = { bash: 'sh', powershell: 'ps1', csv: 'csv' }

function saveBlob(blob, name) {
  const url = URL.createObjectURL(new Blob([blob]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

function ScriptViewer({ item }) {
  const [part, setPart] = useState('script')
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap gap-1">
        {PARTS.map(([key, label]) => (
          <button key={key} type="button" onClick={() => setPart(key)}
            className={`px-2 py-0.5 rounded text-[11px] border ${part === key
              ? 'border-orange-500/60 text-orange-300 bg-orange-500/10' : 'border-gray-700 text-gray-400'}`}>
            {label}
          </button>
        ))}
        {item.script_language && (
          <span className="ml-auto text-[10px] font-mono text-gray-500 self-center">{item.script_language}</span>
        )}
      </div>
      <pre className="max-h-72 overflow-auto p-2 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-gray-300 whitespace-pre">
        {item[part] || '—'}
      </pre>
    </div>
  )
}

/**
 * Playbooks de remediation : proposition (analyste / admin), apercu, validation
 * humaine en un clic et recuperation du script approuve. Phoenix n'execute
 * jamais ces scripts.
 */
export default function PlaybookPanel({ investigationId, jobId, title = 'Playbooks de remediation' }) {
  const { user } = useAuth()
  const canWrite = user?.role === 'admin' || user?.role === 'analyst'
  const [templates, setTemplates] = useState([])
  const [actions, setActions] = useState([])
  const [templateId, setTemplateId] = useState('')
  const [params, setParams] = useState({})
  const [reason, setReason] = useState('')
  const [severity, setSeverity] = useState('high')
  const [preview, setPreview] = useState(null)
  const [fieldErrors, setFieldErrors] = useState({})
  const [busy, setBusy] = useState(false)
  const [notes, setNotes] = useState({})
  const [deciding, setDeciding] = useState(null)
  const [expanded, setExpanded] = useState({})

  useEffect(() => {
    apiService.getPlaybookTemplates().then((d) => setTemplates(d.items || [])).catch(() => setTemplates([]))
  }, [])

  const loadActions = useCallback(async () => {
    try {
      const data = await apiService.getRemediations(undefined, investigationId || undefined)
      setActions((data.items || []).filter((a) => a.playbook_id))
    } catch {
      setActions([])
    }
  }, [investigationId])

  useEffect(() => { loadActions() }, [loadActions])

  useEffect(() => {
    const offReq = websocketService.onHitlRequired((a) => {
      if (!a.playbook_id || (investigationId && a.investigation_id !== investigationId)) return
      setActions((prev) => [a, ...prev.filter((x) => x.id !== a.id)])
    })
    const offRes = websocketService.onHitlResolved((a) => {
      setActions((prev) => prev.map((x) => (x.id === a.id ? { ...x, ...a } : x)))
    })
    return () => { offReq(); offRes() }
  }, [investigationId])

  const template = useMemo(() => templates.find((t) => t.id === templateId), [templates, templateId])

  const chooseTemplate = (id) => {
    setTemplateId(id)
    const t = templates.find((x) => x.id === id)
    const defaults = {}
    ;(t?.params || []).forEach((p) => { if (p.default !== null && p.default !== undefined) defaults[p.name] = p.default })
    setParams(defaults)
    setPreview(null)
    setFieldErrors({})
  }

  const runPreview = async () => {
    if (!templateId) return
    setBusy(true)
    try {
      setPreview(await apiService.renderPlaybook(templateId, params))
      setFieldErrors({})
    } catch (e) {
      setPreview(null)
      setFieldErrors(e?.response?.data?.fields || {})
      toast.error(e?.response?.data?.error || 'Apercu impossible')
    } finally {
      setBusy(false)
    }
  }

  const propose = async () => {
    if (!templateId || !investigationId) return
    setBusy(true)
    try {
      const action = await apiService.proposePlaybook(investigationId, templateId, params, reason, severity, jobId)
      setActions((prev) => [action, ...prev.filter((x) => x.id !== action.id)])
      setPreview(null)
      setReason('')
      toast.success(`Playbook ${action.id} propose : en attente de validation humaine`)
    } catch (e) {
      setFieldErrors(e?.response?.data?.fields || {})
      toast.error(e?.response?.data?.error || 'Proposition impossible')
    } finally {
      setBusy(false)
    }
  }

  const decide = async (action, decision) => {
    setDeciding(action.id)
    try {
      const updated = await apiService.decideRemediation(action.id, decision, notes[action.id] || '')
      setActions((prev) => prev.map((a) => (a.id === updated.id ? { ...a, ...updated } : a)))
      toast.success(decision === 'approve'
        ? `${action.id} approuve : a executer par l'equipe (Phoenix ne l'execute pas)`
        : `${action.id} rejete`)
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Decision impossible')
    } finally {
      setDeciding(null)
    }
  }

  const copyScript = async (action) => {
    try {
      await navigator.clipboard.writeText(action.script || '')
      toast.success('Script copie dans le presse-papiers')
    } catch {
      toast.error('Copie impossible')
    }
  }

  const download = async (action, part) => {
    try {
      const blob = await apiService.downloadRemediationScript(action.id, part)
      saveBlob(blob, `${action.id}_${action.playbook_id}_${part}.${EXT[action.script_language] || 'txt'}`)
    } catch (e) {
      toast.error(e?.response?.status === 409 ? 'Script disponible apres approbation' : 'Telechargement impossible')
    }
  }

  return (
    <Card className="bg-gray-900 border-gray-800">
      <CardHeader className="pb-3">
        <CardTitle className="text-white text-sm flex items-center gap-2">
          <BookOpenCheck className="h-4 w-4 text-orange-500" /> {title}
          {actions.filter((a) => a.status === 'WAITING_APPROVAL').length > 0 && (
            <Badge className={STATUS_STYLES.WAITING_APPROVAL}>
              {actions.filter((a) => a.status === 'WAITING_APPROVAL').length} en attente
            </Badge>
          )}
        </CardTitle>
        <CardDescription className="text-[11px] text-amber-300/90 flex items-start gap-1.5">
          <ShieldAlert className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          Phoenix n&apos;execute JAMAIS ces scripts : ils sont generes pour revue, scelles (SHA-256)
          dans la chaine de preuve, puis joues par votre equipe avec ses propres outils apres approbation.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {canWrite && investigationId && (
          <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 space-y-2">
            <div className="grid gap-2 sm:grid-cols-3">
              <select value={templateId} onChange={(e) => chooseTemplate(e.target.value)}
                className="h-9 rounded-md border border-gray-700 bg-gray-900 px-2 text-sm text-gray-200 sm:col-span-2"
                aria-label="Modele de playbook">
                <option value="">Choisir un playbook...</option>
                {['firewall', 'account', 'isolation', 'persistence'].map((cat) => (
                  <optgroup key={cat} label={cat}>
                    {templates.filter((t) => t.category === cat).map((t) => (
                      <option key={t.id} value={t.id}>{t.title}</option>
                    ))}
                  </optgroup>
                ))}
              </select>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}
                className="h-9 rounded-md border border-gray-700 bg-gray-900 px-2 text-sm text-gray-200" aria-label="Severite">
                {['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            {template && (
              <>
                <p className="text-[11px] text-gray-500">{template.description}</p>
                <div className="grid gap-2 sm:grid-cols-2">
                  {template.params.map((p) => (
                    <label key={p.name} className="text-[11px] text-gray-400 space-y-1">
                      <span>{p.label}{p.required && p.default === null ? ' *' : ''}</span>
                      {p.type === 'choice' ? (
                        <select value={params[p.name] ?? ''} onChange={(e) => setParams((v) => ({ ...v, [p.name]: e.target.value }))}
                          className="w-full h-8 rounded-md border border-gray-700 bg-gray-900 px-2 text-xs text-gray-200">
                          {(p.options || []).map((o) => <option key={o} value={o}>{o}</option>)}
                        </select>
                      ) : p.type === 'bool' ? (
                        <input type="checkbox" checked={Boolean(params[p.name])} className="block accent-orange-500"
                          onChange={(e) => setParams((v) => ({ ...v, [p.name]: e.target.checked }))} />
                      ) : (
                        <input value={params[p.name] ?? ''} placeholder={p.type_help || ''}
                          onChange={(e) => setParams((v) => ({ ...v, [p.name]: e.target.value }))}
                          className={`w-full h-8 rounded-md border bg-gray-900 px-2 font-mono text-xs text-gray-200 ${fieldErrors[p.name] ? 'border-red-500' : 'border-gray-700'}`} />
                      )}
                      {fieldErrors[p.name] && <span className="text-red-400">{fieldErrors[p.name]}</span>}
                    </label>
                  ))}
                </div>
                <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Justification (constat, IoC...)"
                  className="w-full h-8 rounded-md border border-gray-700 bg-gray-900 px-2 text-xs text-gray-200" />
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={runPreview} disabled={busy} className="border-gray-700 text-gray-300">
                    {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />} Apercu
                  </Button>
                  <Button size="sm" onClick={propose} disabled={busy} className="bg-orange-600 hover:bg-orange-500 text-white">
                    <Send className="h-3.5 w-3.5" /> Proposer pour validation
                  </Button>
                </div>
                {preview && <ScriptViewer item={preview} />}
              </>
            )}
          </div>
        )}

        {actions.length === 0 && <p className="text-xs text-gray-500">Aucun playbook propose.</p>}
        {actions.map((a) => (
          <div key={a.id} className={`p-3 rounded-lg border space-y-2 ${a.status === 'WAITING_APPROVAL'
            ? 'bg-amber-950/10 border-amber-500/30' : 'bg-gray-950 border-gray-800'}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono font-semibold text-gray-200">{a.id}</span>
              <Badge className="bg-gray-800 text-gray-300 border-gray-700 font-mono text-[10px]">{a.playbook_id}</Badge>
              <Badge className={STATUS_STYLES[a.status]}>{STATUS_LABELS[a.status]}</Badge>
              <span className="text-xs text-gray-400 truncate">→ {a.target_host}</span>
              <button type="button" onClick={() => setExpanded((v) => ({ ...v, [a.id]: !v[a.id] }))}
                className="ml-auto text-gray-400 hover:text-gray-200" aria-label="Apercu du script">
                {expanded[a.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-xs text-gray-400">{a.reason}</p>
            <p className="text-[10px] font-mono text-gray-500 break-all">sha256 {a.script_sha256}</p>
            {a.decided_by && (
              <p className="text-[11px] text-gray-500">
                Decision : {a.decided_by}{a.decision_note ? ` — ${a.decision_note}` : ''}
              </p>
            )}
            {(expanded[a.id] || a.status === 'WAITING_APPROVAL') && <ScriptViewer item={a} />}
            {a.status === 'WAITING_APPROVAL' && (canWrite ? (
              <div className="flex flex-wrap gap-2">
                <input value={notes[a.id] || ''} onChange={(e) => setNotes((v) => ({ ...v, [a.id]: e.target.value }))}
                  placeholder="Note de decision (optionnel)"
                  className="flex-1 min-w-[10rem] h-8 rounded-md border border-gray-700 bg-gray-950 px-2 text-xs text-gray-200" />
                <Button size="sm" disabled={deciding === a.id} onClick={() => decide(a, 'approve')}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Approuver
                </Button>
                <Button size="sm" variant="outline" disabled={deciding === a.id} onClick={() => decide(a, 'reject')}
                  className="border-gray-700 text-gray-300 text-xs">
                  <XCircle className="h-3.5 w-3.5" /> Rejeter
                </Button>
              </div>
            ) : <p className="text-[11px] text-gray-500">Role analyste ou admin requis pour decider.</p>)}
            {a.status === 'APPROVED' && (
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={() => copyScript(a)} className="border-gray-700 text-gray-300 text-xs">
                  <Copy className="h-3.5 w-3.5" /> Copier
                </Button>
                <Button size="sm" variant="outline" onClick={() => download(a, 'script')} className="border-gray-700 text-gray-300 text-xs">
                  <Download className="h-3.5 w-3.5" /> Script
                </Button>
                <Button size="sm" variant="outline" onClick={() => download(a, 'rollback')} className="border-gray-700 text-gray-300 text-xs">
                  <Download className="h-3.5 w-3.5" /> Rollback
                </Button>
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
