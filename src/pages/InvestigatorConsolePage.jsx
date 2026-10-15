import { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'
import { useApp } from '@/context/AppContext'
import { useAuth } from '@/context/AuthContext'
import {
  ShieldCheck, ShieldAlert, Cpu, Activity, Lock, Hash, Terminal, AlertTriangle,
  CheckCircle2, XCircle, RefreshCw, Loader2, HardDrive, Link2, Import, Bot,
} from 'lucide-react'
import { toast } from 'sonner'

const SEVERITY_STYLES = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  low: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
  info: 'bg-gray-500/10 text-gray-400 border-gray-600/40',
}

const STATUS_STYLES = {
  WAITING_APPROVAL: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  APPROVED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  REJECTED: 'bg-gray-500/10 text-gray-400 border-gray-600/40',
}

const STATUS_LABELS = {
  WAITING_APPROVAL: 'En attente',
  APPROVED: 'Approuvee',
  REJECTED: 'Rejetee',
}

function formatSize(bytes) {
  if (!bytes) return '0 o'
  const units = ['o', 'Ko', 'Mo', 'Go', 'To']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`
}

function formatTs(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString('fr-FR')
}

function HashLine({ label, value, tone = 'text-emerald-400' }) {
  return (
    <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
      <div className="text-[11px] uppercase tracking-wider text-gray-500 flex items-center gap-1">
        <Hash className="h-3.5 w-3.5" /> {label}
      </div>
      <div className={`font-mono text-xs break-all ${tone}`}>{value || '—'}</div>
    </div>
  )
}

export default function InvestigatorConsolePage() {
  const { investigations } = useApp()
  const { user } = useAuth()
  const investigationList = useMemo(() => investigations?.items || investigations || [], [investigations])
  const canDecide = user?.role === 'admin' || user?.role === 'analyst'

  const [status, setStatus] = useState(null)
  const [filterInv, setFilterInv] = useState('')
  const [entries, setEntries] = useState([])
  const [selected, setSelected] = useState(null)
  const [integrity, setIntegrity] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [remediations, setRemediations] = useState([])
  const [deciding, setDeciding] = useState(null)
  const [notes, setNotes] = useState({})
  const [vault, setVault] = useState(null)
  const [vaultSelection, setVaultSelection] = useState(new Set())
  const [vaultTarget, setVaultTarget] = useState('')
  const [importing, setImporting] = useState(false)
  const [loading, setLoading] = useState(true)
  const [chainHead, setChainHead] = useState({ entries: 0, head_hash: '' })
  const [launching, setLaunching] = useState(false)

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [st, custody, rem, vlt] = await Promise.all([
        apiService.getConsoleStatus().catch(() => null),
        apiService.getCustody(filterInv || undefined).catch(() => ({ items: [] })),
        apiService.getRemediations(undefined, filterInv || undefined).catch(() => ({ items: [] })),
        apiService.getEvidenceVault().catch(() => null),
      ])
      setStatus(st)
      if (st?.custody) setChainHead(st.custody)
      setEntries(custody.items || [])
      setSelected((prev) => prev || (custody.items || []).at(-1) || null)
      setRemediations(rem.items || [])
      setVault(vlt)
    } finally {
      setLoading(false)
    }
  }, [filterInv])

  useEffect(() => { loadAll() }, [loadAll])

  // Flux temps reel : etapes d'agents et demandes de validation humaine
  useEffect(() => {
    const offStep = websocketService.onAgentStep((entry) => {
      // La tete de chaine est globale : a jour quel que soit le filtre
      setChainHead((prev) => (entry.seq > prev.entries
        ? { entries: entry.seq, head_hash: entry.entry_hash } : prev))
      if (filterInv && entry.investigation_id !== filterInv) return
      setEntries((prev) => (prev.some((e) => e.seq === entry.seq) ? prev : [...prev, entry]))
      setSelected(entry)
      setIntegrity(null)
    })
    const offRequired = websocketService.onHitlRequired((action) => {
      if (filterInv && action.investigation_id !== filterInv) return
      setRemediations((prev) => [action, ...prev.filter((a) => a.id !== action.id)])
      toast.warning(`Validation humaine requise : ${action.id} (${action.target_host})`)
    })
    const offResolved = websocketService.onHitlResolved((action) => {
      setRemediations((prev) => prev.map((a) => (a.id === action.id ? { ...a, ...action } : a)))
    })
    return () => { offStep(); offRequired(); offResolved() }
  }, [filterInv])

  const verify = async () => {
    setVerifying(true)
    try {
      const result = await apiService.verifyCustody()
      setIntegrity(result)
      if (result.valid) toast.success(`Chaine de preuve intacte (${result.entries} maillons)`)
      else toast.error(`Chaine rompue au maillon #${result.broken_at} : ${result.reason}`)
    } catch {
      toast.error('Verification impossible')
    } finally {
      setVerifying(false)
    }
  }

  const decide = async (action, decision) => {
    setDeciding(action.id)
    try {
      const updated = await apiService.decideRemediation(action.id, decision, notes[action.id] || '')
      setRemediations((prev) => prev.map((a) => (a.id === updated.id ? { ...a, ...updated } : a)))
      toast.success(decision === 'approve'
        ? `${action.id} approuvee : a executer par l'equipe (non execute par Phoenix)`
        : `${action.id} rejetee`)
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Decision impossible')
    } finally {
      setDeciding(null)
    }
  }

  const launchInvestigator = async () => {
    if (!filterInv) return
    setLaunching(true)
    try {
      await apiService.startAutonomousInvestigation(filterInv, '')
      toast.success("Enqueteur IA lance : suivez les agents dans la chronologie")
    } catch (e) {
      toast.error(e?.response?.data?.error || "Impossible de lancer l'Enqueteur IA")
    } finally {
      setLaunching(false)
    }
  }

  const toggleVaultFile = (path) => {
    setVaultSelection((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }

  const importVault = async () => {
    if (!vaultTarget || !vaultSelection.size) return
    setImporting(true)
    try {
      const res = await apiService.importFromVault(vaultTarget, [...vaultSelection])
      if (res.imported?.length) toast.success(`${res.imported.length} evidence(s) rattachee(s) et scellee(s)`)
      res.rejected?.forEach((r) => toast.error(`${r.path} : ${r.error}`))
      setVaultSelection(new Set())
      loadAll()
    } catch (e) {
      toast.error(e?.response?.data?.error || 'Import impossible')
    } finally {
      setImporting(false)
    }
  }

  const pending = remediations.filter((a) => a.status === 'WAITING_APPROVAL')
  const decided = remediations.filter((a) => a.status !== 'WAITING_APPROVAL').slice(0, 5)
  const chainTotal = chainHead.entries

  return (
    <div className="space-y-4">
      {/* En-tete */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="text-white flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-orange-500" />
                Console Enqueteur DFIR — Chain of Custody
              </CardTitle>
              <CardDescription className="text-gray-400">
                Chaque evidence acquise et chaque outil execute par l&apos;essaim d&apos;agents est
                scelle dans une chaine SHA-256 inalterable ; les actions de confinement attendent
                une validation humaine.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={filterInv}
                onChange={(e) => { setFilterInv(e.target.value); setSelected(null); setIntegrity(null) }}
                className="h-9 rounded-md border border-gray-700 bg-gray-950 px-2 text-sm text-gray-200"
                aria-label="Filtrer par enquete"
              >
                <option value="">Toutes les enquetes</option>
                {investigationList.map((inv) => (
                  <option key={inv.id} value={inv.id}>{inv.name}</option>
                ))}
              </select>
              <Button variant="outline" size="sm" onClick={loadAll} disabled={loading}
                className="border-gray-700 text-gray-300">
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
              <Button size="sm" variant="outline" onClick={launchInvestigator}
                disabled={!filterInv || launching || !status?.llm?.configured}
                title={filterInv ? "Investigation autonome sur l'enquete selectionnee" : 'Selectionnez une enquete'}
                className="border-gray-700 text-gray-200">
                {launching ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bot className="h-4 w-4" />}
                Lancer l&apos;Enqueteur IA
              </Button>
              <Button size="sm" onClick={verify} disabled={verifying}
                className="bg-orange-600 hover:bg-orange-500 text-white">
                {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
                Verifier l&apos;integrite
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Badge className="bg-gray-800 text-gray-300 border-gray-700 font-mono">
              {chainTotal} maillon{chainTotal !== 1 ? 's' : ''}
            </Badge>
            {integrity && (
              <Badge className={integrity.valid ? STATUS_STYLES.APPROVED : SEVERITY_STYLES.critical}>
                {integrity.valid ? 'Chaine intacte' : `Chaine rompue (#${integrity.broken_at})`}
              </Badge>
            )}
            {chainTotal > 0 && (
              <span className="font-mono text-[11px] text-gray-500 truncate max-w-full">
                tete : {chainHead.head_hash}
              </span>
            )}
          </div>
        </CardHeader>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Colonne gauche : agents + HITL */}
        <div className="lg:col-span-3 space-y-4 min-w-0">
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-xs uppercase tracking-wider text-gray-400 flex items-center gap-2">
                <Cpu className="h-4 w-4 text-orange-500" /> Essaim d&apos;agents (MCP)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {(status?.agents || []).map((agent) => (
                <div key={agent.id} className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm text-gray-200 truncate">{agent.name}</div>
                    <div className="text-[11px] font-mono text-gray-500 truncate" title={agent.tool}>{agent.tool}</div>
                  </div>
                  <span className={`text-[10px] font-mono font-semibold shrink-0 ${agent.ready ? 'text-emerald-400' : 'text-gray-500'}`}>
                    {agent.ready ? 'PRET' : 'INDISPO'}
                  </span>
                </div>
              ))}
              {!status && <p className="text-xs text-gray-500">Statut indisponible.</p>}
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-gray-800">
            <CardHeader className="pb-3">
              <CardTitle className="text-xs uppercase tracking-wider text-gray-400 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" /> Validation humaine
                {pending.length > 0 && (
                  <Badge className={STATUS_STYLES.WAITING_APPROVAL}>{pending.length}</Badge>
                )}
              </CardTitle>
              <CardDescription className="text-[11px] text-gray-500">
                Phoenix n&apos;execute jamais l&apos;action : l&apos;approbation autorise l&apos;equipe a la
                jouer avec ses outils de reponse et est scellee dans la chaine.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {pending.length === 0 && <p className="text-xs text-gray-500">Aucune action en attente.</p>}
              {pending.map((action) => (
                <div key={action.id} className="p-3 rounded-lg bg-red-950/20 border border-red-500/30 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-semibold text-red-300">{action.id}</span>
                    <Badge className={SEVERITY_STYLES[action.severity] || SEVERITY_STYLES.info}>{action.severity}</Badge>
                  </div>
                  <div className="text-xs text-gray-300">
                    <span className="text-gray-500">Hote : </span>{action.target_host}
                  </div>
                  <p className="text-xs text-gray-400">{action.reason}</p>
                  <pre className="p-2 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-red-300 whitespace-pre-wrap break-all">$ {action.command}</pre>
                  {canDecide ? (
                    <>
                      <input
                        value={notes[action.id] || ''}
                        onChange={(e) => setNotes((prev) => ({ ...prev, [action.id]: e.target.value }))}
                        placeholder="Note de decision (optionnel)"
                        className="w-full h-8 rounded-md border border-gray-700 bg-gray-950 px-2 text-xs text-gray-200"
                      />
                      <div className="grid grid-cols-2 gap-2">
                        <Button size="sm" disabled={deciding === action.id} onClick={() => decide(action, 'approve')}
                          className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs">
                          <CheckCircle2 className="h-3.5 w-3.5" /> Approuver
                        </Button>
                        <Button size="sm" variant="outline" disabled={deciding === action.id}
                          onClick={() => decide(action, 'reject')}
                          className="border-gray-700 text-gray-300 text-xs">
                          <XCircle className="h-3.5 w-3.5" /> Rejeter
                        </Button>
                      </div>
                    </>
                  ) : (
                    <p className="text-[11px] text-gray-500">Role analyste ou admin requis pour decider.</p>
                  )}
                </div>
              ))}
              {decided.map((action) => (
                <div key={action.id} className="p-2 rounded-lg bg-gray-950 border border-gray-800 text-xs flex items-center justify-between gap-2">
                  <span className="font-mono text-gray-400 truncate">{action.id} · {action.target_host}</span>
                  <Badge className={STATUS_STYLES[action.status]}>{STATUS_LABELS[action.status]}</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Colonne centrale : chronologie */}
        <Card className="lg:col-span-5 bg-gray-900 border-gray-800 min-w-0">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs uppercase tracking-wider text-gray-400 flex items-center gap-2">
              <Activity className="h-4 w-4 text-orange-500" /> Chronologie temps reel (WebSocket)
            </CardTitle>
          </CardHeader>
          <CardContent>
            {entries.length === 0 ? (
              <div className="py-16 text-center text-sm text-gray-500">
                Aucune entree. Uploadez des evidences ou lancez l&apos;Enqueteur IA : chaque etape
                apparaitra ici en direct.
              </div>
            ) : (
              <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
                {[...entries].reverse().map((entry) => (
                  <button
                    type="button"
                    key={entry.seq}
                    onClick={() => setSelected(entry)}
                    className={`w-full text-left p-3 rounded-lg border transition-colors ${
                      selected?.seq === entry.seq
                        ? 'bg-gray-800/60 border-orange-500/50'
                        : 'bg-gray-950/60 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-xs font-semibold text-orange-400 truncate">
                        #{entry.seq} · {entry.agent || entry.actor}
                      </span>
                      <div className="flex items-center gap-1 shrink-0">
                        {entry.mitre && (
                          <Badge className="bg-purple-500/10 text-purple-300 border-purple-500/30 font-mono text-[10px]">
                            {entry.mitre}
                          </Badge>
                        )}
                        <Badge className={`${SEVERITY_STYLES[entry.severity] || SEVERITY_STYLES.info} text-[10px]`}>
                          {entry.severity}
                        </Badge>
                      </div>
                    </div>
                    {entry.summary && <p className="text-sm text-gray-200 mb-1.5">{entry.summary}</p>}
                    <div className="px-2 py-1 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-gray-400 truncate">
                      $ {entry.action}
                    </div>
                    <div className="mt-1 text-[10px] text-gray-500">{formatTs(entry.ts)}</div>
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Colonne droite : inspecteur */}
        <Card className="lg:col-span-4 bg-gray-900 border-gray-800 min-w-0">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs uppercase tracking-wider text-gray-400 flex items-center gap-2">
              <Lock className="h-4 w-4 text-emerald-400" /> Inspecteur forensique
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selected ? (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
                  <div className="text-[11px] uppercase tracking-wider text-gray-500">Artefact reference</div>
                  <div className="text-amber-400 font-semibold text-sm break-all">{selected.artifact_ref || '—'}</div>
                  <div className="text-gray-500">
                    {selected.actor} · {formatTs(selected.ts)}
                  </div>
                </div>
                <HashLine label="Empreinte du maillon (entry_hash)" value={selected.entry_hash} />
                <HashLine label="Maillon precedent (prev_hash)" value={selected.prev_hash} tone="text-gray-400" />
                <HashLine label="Empreinte de la preuve / sortie (payload)" value={selected.payload_sha256} tone="text-sky-400" />
                <div className="p-3 rounded-lg bg-gray-950 border border-gray-800 space-y-1">
                  <div className="text-[11px] uppercase tracking-wider text-gray-500 flex items-center gap-1">
                    <Terminal className="h-3.5 w-3.5" /> Action executee
                  </div>
                  <pre className="font-mono text-orange-300 whitespace-pre-wrap break-all">{selected.action}</pre>
                </div>
                {selected.details && Object.keys(selected.details).length > 0 && (
                  <pre className="p-3 rounded-lg bg-gray-950 border border-gray-800 font-mono text-[11px] text-gray-400 whitespace-pre-wrap break-all">
                    {JSON.stringify(selected.details, null, 2)}
                  </pre>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-xs text-gray-500">
                Selectionnez une etape pour inspecter sa preuve SHA-256.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Coffre de preuves */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="text-white text-sm flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-orange-500" /> Coffre de preuves
                {vault?.read_only && (
                  <Badge className={STATUS_STYLES.APPROVED}>Lecture seule</Badge>
                )}
                {vault && vault.exists && !vault.read_only && (
                  <Badge className={SEVERITY_STYLES.medium}>Ecriture possible</Badge>
                )}
              </CardTitle>
              <CardDescription className="text-xs text-gray-500 font-mono break-all">
                {vault?.vault_dir || '—'}
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={vaultTarget}
                onChange={(e) => setVaultTarget(e.target.value)}
                className="h-9 rounded-md border border-gray-700 bg-gray-950 px-2 text-sm text-gray-200"
                aria-label="Enquete cible"
              >
                <option value="">Enquete cible...</option>
                {investigationList.map((inv) => (
                  <option key={inv.id} value={inv.id}>{inv.name}</option>
                ))}
              </select>
              <Button size="sm" onClick={importVault}
                disabled={!canDecide || importing || !vaultTarget || !vaultSelection.size}
                className="bg-orange-600 hover:bg-orange-500 text-white">
                {importing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Import className="h-4 w-4" />}
                Rattacher ({vaultSelection.size})
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {!vault?.exists ? (
            <p className="text-xs text-gray-500">
              Coffre absent. En Docker, montez le dossier des evidences en lecture seule
              (./evidence_vault:/mnt/evidence:ro) — voir docs/WINDOWS_DOCKER.md.
            </p>
          ) : vault.files.length === 0 ? (
            <p className="text-xs text-gray-500">Coffre vide : deposez vos .evtx, $MFT, dumps RAM sur l&apos;hote.</p>
          ) : (
            <div className="max-h-64 overflow-y-auto divide-y divide-gray-800 rounded-lg border border-gray-800">
              {vault.files.map((f) => (
                <label key={f.path} className="flex items-center gap-3 px-3 py-2 text-xs hover:bg-gray-800/40 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={vaultSelection.has(f.path)}
                    onChange={() => toggleVaultFile(f.path)}
                    className="accent-orange-500"
                  />
                  <span className="font-mono text-gray-200 truncate flex-1 min-w-0">{f.path}</span>
                  <span className="text-gray-500 shrink-0">{formatSize(f.size)}</span>
                </label>
              ))}
            </div>
          )}
          {vault?.truncated && <p className="mt-2 text-[11px] text-gray-500">Liste tronquee.</p>}
          {status && !status.llm?.configured && (
            <p className="mt-3 text-xs text-amber-400 flex items-center gap-1">
              <ShieldAlert className="h-3.5 w-3.5" />
              LLM non configure : definissez GITHUB_TOKEN, OPENAI_API_KEY ou PHOENIX_LLM_PROVIDER=ollama pour l&apos;Enqueteur IA.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
