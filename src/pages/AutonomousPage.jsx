import { useCallback, useEffect, useRef, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'
import { useApp } from '@/context/AppContext'
import PlaybookPanel from '@/components/PlaybookPanel'
import VerificationPanel from '@/components/VerificationPanel'
import { Bot, UploadCloud, FolderOpen, Loader2, CheckCircle, XCircle, FileText, Download, Play, Network, Ban, ListChecks, RefreshCw, Clock } from 'lucide-react'
import { toast } from 'sonner'

const ACCEPTED = '.evtx,.csv,.json,.log,.txt,.xml,.pcap,.pcapng,.pf,.lnk,.sqlite,.db,.ps1,.bat,.sh,.hve,.dat,.raw,.mem,.vmem,.dmp,.lime,.e01,.ex01,.dd,.img,.001,.vmdk,.vhd,.vhdx,.md'

// Statuts historiques de l'API (file durable : queued/running/done/failed/cancelled)
const JOB_STATUS = {
  queued: { label: 'En file', className: 'bg-sky-600/20 text-sky-300 border-sky-600/30' },
  running: { label: 'En cours', className: 'bg-orange-600/20 text-orange-300 border-orange-600/30' },
  completed: { label: 'Termine', className: 'bg-emerald-600/20 text-emerald-400 border-emerald-600/30' },
  error: { label: 'Echec', className: 'bg-red-600/20 text-red-400 border-red-600/30' },
  cancelled: { label: 'Annule', className: 'bg-gray-600/20 text-gray-300 border-gray-600/30' },
}

const isActiveJob = (job) => job?.status === 'queued' || job?.status === 'running'

function progressLabel(job) {
  const p = job?.progress || {}
  const parts = []
  if (job?.status === 'queued') parts.push("En attente d'un worker")
  if (p.tools_executed) parts.push(`${p.tools_executed} outil(s)`)
  if (p.messages_count) parts.push(`${p.messages_count} etape(s)`)
  if (job?.cancel_requested && isActiveJob(job)) parts.push('annulation demandee')
  return parts.join(' · ')
}

function formatTime(value) {
  if (!value) return ''
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('fr-FR')
}

function JobBadge({ status }) {
  const meta = JOB_STATUS[status] || { label: status, className: 'bg-gray-700 text-gray-300' }
  return <Badge className={meta.className}>{meta.label}</Badge>
}


const ROLE_LABELS = {
  investigator: 'Enqueteur',
  reviewer: 'Revue',
  extractor: 'Extracteur',
  analyst: 'Analyse',
}

export default function AutonomousPage() {
  const [status, setStatus] = useState(null)
  const [files, setFiles] = useState([])
  const [caseName, setCaseName] = useState('')
  const [question, setQuestion] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [phase, setPhase] = useState('idle') // idle | uploading | investigating | done | error
  const [uploadProgress, setUploadProgress] = useState('')
  const [logs, setLogs] = useState([])
  const [result, setResult] = useState(null)
  const [investigationId, setInvestigationId] = useState(null)
  const [jobId, setJobId] = useState(null)
  const [jobs, setJobs] = useState([])
  const [jobsLoading, setJobsLoading] = useState(false)
  const [cancelling, setCancelling] = useState({})
  const { setCurrentInvestigation } = useApp()
  const jobIdRef = useRef(null)
  const logsEndRef = useRef(null)
  const fileInputRef = useRef(null)
  const refreshTimer = useRef(null)

  useEffect(() => {
    apiService.getAutonomousStatus().then(setStatus).catch(() => setStatus(null))
  }, [])

  // Jobs persistes (file durable SQLite) : survivent a un redemarrage du serveur
  const refreshJobs = useCallback(async () => {
    setJobsLoading(true)
    try {
      const data = await apiService.listAutonomousJobs({ limit: 20 })
      setJobs(Array.isArray(data?.items) ? data.items : [])
    } catch {
      // liste indisponible : la page reste utilisable
    } finally {
      setJobsLoading(false)
    }
  }, [])

  // Rafraichissement groupe (un evenement temps reel par etape)
  const scheduleRefresh = useCallback(() => {
    if (refreshTimer.current) return
    refreshTimer.current = setTimeout(() => {
      refreshTimer.current = null
      refreshJobs()
    }, 1500)
  }, [refreshJobs])

  useEffect(() => {
    refreshJobs()
    const unsub = websocketService.on('job_status', scheduleRefresh)
    return () => {
      unsub()
      if (refreshTimer.current) clearTimeout(refreshTimer.current)
      refreshTimer.current = null
    }
  }, [refreshJobs, scheduleRefresh])

  // Filet de securite si le WebSocket est coupe : sondage tant qu'un job est actif
  const hasActiveJob = jobs.some(isActiveJob)
  useEffect(() => {
    if (!hasActiveJob) return undefined
    const timer = setInterval(refreshJobs, 10000)
    return () => clearInterval(timer)
  }, [hasActiveJob, refreshJobs])

  // Progression temps reel de l'enqueteur
  useEffect(() => {
    const unsub = websocketService.onAutonomousProgress((data) => {
      scheduleRefresh()
      if (jobIdRef.current && data.job_id !== jobIdRef.current) return
      if (data.message) {
        setLogs((prev) => [...prev, data.message])
      }
      if (data.status === 'completed') {
        setResult(data)
        setPhase('done')
        toast.success('Enquete close : rapport genere')
      } else if (data.status === 'error') {
        setPhase('error')
        toast.error(data.error || "Erreur de l'enqueteur autonome")
      } else if (data.status === 'cancelled') {
        setPhase('cancelled')
        toast.info('Investigation annulee')
      }
    })
    return unsub
  }, [scheduleRefresh])

  const cancelJob = async (id) => {
    if (!id) return
    setCancelling((prev) => ({ ...prev, [id]: true }))
    try {
      const res = await apiService.cancelAutonomousJob(id)
      if (res?.status === 'cancelled') {
        toast.success('Job annule')
        if (id === jobIdRef.current) setPhase('cancelled')
      } else {
        toast.info('Annulation demandee : arret au prochain point de controle')
      }
    } catch (e) {
      toast.error(e?.response?.data?.error || "Annulation impossible")
    } finally {
      setCancelling((prev) => {
        const next = { ...prev }
        delete next[id]
        return next
      })
      refreshJobs()
    }
  }

  // Reprendre le suivi d'un job persiste (en cours ou termine)
  const openJob = async (id) => {
    try {
      const job = await apiService.getAutonomousJob(id)
      jobIdRef.current = job.job_id
      setJobId(job.job_id)
      setInvestigationId(job.investigation_id)
      setLogs(Array.isArray(job.messages) ? job.messages : [])
      if (job.status === 'completed') {
        setResult(job)
        setPhase('done')
      } else {
        setResult(null)
        setPhase(isActiveJob(job) ? 'investigating' : job.status === 'cancelled' ? 'cancelled' : 'error')
      }
    } catch {
      toast.error('Job introuvable')
    }
  }

  const currentJob = jobs.find((j) => j.job_id === jobId)

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const addFiles = useCallback((list) => {
    const incoming = Array.from(list || [])
    if (!incoming.length) return
    setFiles((prev) => {
      const known = new Set(prev.map((f) => `${f.name}:${f.size}`))
      return [...prev, ...incoming.filter((f) => !known.has(`${f.name}:${f.size}`))]
    })
  }, [])

  const handleDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    addFiles(e.dataTransfer.files)
  }

  const launch = async () => {
    if (!files.length) {
      toast.error('Deposez au moins une evidence')
      return
    }
    setPhase('uploading')
    setLogs([])
    setResult(null)
    setInvestigationId(null)
    setJobId(null)
    jobIdRef.current = null
    try {
      const name = caseName.trim() || `Enquete autonome du ${new Date().toLocaleString('fr-FR')}`
      const inv = await apiService.createInvestigation(name, 'Enquete lancee depuis la page Enqueteur IA.')
      const invId = inv.id || inv.investigation?.id
      setInvestigationId(invId)
      for (let i = 0; i < files.length; i++) {
        setUploadProgress(`Upload ${i + 1}/${files.length} : ${files[i].name}`)
        await apiService.uploadFile(files[i], invId)
      }
      setUploadProgress('')
      setPhase('investigating')
      setLogs([`Enquete '${name}' creee, ${files.length} evidence(s) uploadee(s).`])
      const job = await apiService.startAutonomousInvestigation(invId, question.trim())
      jobIdRef.current = job.job_id
      setJobId(job.job_id)
      setLogs((prev) => [...prev, "Investigation en file d'attente : un worker la prend en main des que possible..."])
      refreshJobs()
    } catch (e) {
      setPhase('error')
      const msg = e?.response?.data?.error || "Impossible de lancer l'investigation"
      toast.error(msg)
      setLogs((prev) => [...prev, `Erreur : ${msg}`])
    }
  }

  const downloadFile = async (fileId) => {
    if (!fileId) return
    try {
      const blob = await apiService.downloadReport(fileId)
      const url = URL.createObjectURL(new Blob([blob]))
      const a = document.createElement('a')
      a.href = url
      a.download = fileId
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      toast.error('Telechargement impossible')
    }
  }
  const downloadReport = () => downloadFile(result?.report_id)

  const reset = () => {
    setFiles([])
    setCaseName('')
    setQuestion('')
    setPhase('idle')
    setLogs([])
    setResult(null)
    setInvestigationId(null)
    setJobId(null)
    jobIdRef.current = null
  }

  const openGraph = () => {
    if (!investigationId) return
    setCurrentInvestigation?.({ id: investigationId, name: caseName.trim() || investigationId })
    window.dispatchEvent(new CustomEvent('navigate', { detail: 'attack-graph' }))
  }

  const busy = phase === 'uploading' || phase === 'investigating'
  const copilotReady = status?.copilot_configured

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Statut */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white flex items-center gap-2">
                <Bot className="h-5 w-5 text-orange-500" />
                Enqueteur DFIR autonome
              </CardTitle>
              <CardDescription className="text-gray-400">
                Deposez vos evidences : le LLM local mene l&apos;enquete seul (parsing, Sigma,
                IoCs, timeline, MITRE) et redige le rapport.
              </CardDescription>
            </div>
            {status && (
              <Badge className={copilotReady
                ? 'bg-emerald-600/20 text-emerald-400 border-emerald-600/30'
                : 'bg-red-600/20 text-red-400 border-red-600/30'}>
                {copilotReady
                  ? `${status.llm_label || 'LLM'} pret (${status.model})`
                  : 'LLM non configure'}
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {!copilotReady && status && (
            <p className="text-xs text-red-400">
              Demarrez un LLM local (Ollama, llama.cpp, LM Studio ou Jan) et definissez
              PHOENIX_LLM_PROVIDER (ollama, llamacpp, lmstudio ou jan), puis redemarrez le backend.
              Sans LLM, le triage deterministe reste disponible.
            </p>
          )}
          {copilotReady && status?.llm_roles && (
            <div className="flex flex-wrap gap-2" data-testid="llm-roles">
              {Object.entries(status.llm_roles).map(([role, model]) => (
                <Badge key={role} className="bg-gray-800 text-gray-300 border-gray-700 font-mono text-[11px]">
                  {ROLE_LABELS[role] || role} : {model}
                </Badge>
              ))}
            </div>
          )}
          {status?.inbox_dir && (
            <div className="flex items-start gap-2 p-3 bg-gray-800 rounded-lg">
              <FolderOpen className="h-4 w-4 text-orange-400 mt-0.5 shrink-0" />
              <p className="text-xs text-gray-400">
                <span className="text-gray-300">Mode 100% automatique :</span> deposez simplement vos
                fichiers ou un dossier dans{' '}
                <code className="text-orange-300 font-mono break-all">{status.inbox_dir}</code>{' '}
                — l&apos;enquete se cree et se resout toute seule
                {status.inbox_watcher_active ? ' (surveillance active).' : ' (surveillance inactive).'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Upload + lancement */}
      {phase !== 'done' && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white text-base">1. Deposer les evidences</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`flex flex-col items-center justify-center gap-2 border-2 border-dashed rounded-xl p-10 cursor-pointer transition-colors ${
                dragOver ? 'border-orange-500 bg-orange-600/10' : 'border-gray-700 hover:border-gray-500'
              }`}
            >
              <UploadCloud className="h-10 w-10 text-orange-500" />
              <p className="text-sm text-gray-300">Glissez-deposez vos evidences ici, ou cliquez pour parcourir</p>
              <p className="text-xs text-gray-500">EVTX, CSV, JSON, logs, Prefetch, LNK, SQLite, registre... (500 Mo max/fichier)</p>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept={ACCEPTED}
                className="hidden"
                onChange={(e) => { addFiles(e.target.files); e.target.value = '' }}
              />
            </div>

            {files.length > 0 && (
              <div className="space-y-1">
                {files.map((f, i) => (
                  <div key={`${f.name}-${i}`} className="flex items-center justify-between text-xs bg-gray-800 rounded px-3 py-1.5">
                    <span className="text-gray-300 font-mono truncate">{f.name}</span>
                    <span className="text-gray-500 shrink-0 ml-3">{(f.size / 1024).toFixed(1)} Ko</span>
                  </div>
                ))}
              </div>
            )}

            <div className="grid gap-3 sm:grid-cols-2">
              <Input
                value={caseName}
                onChange={(e) => setCaseName(e.target.value)}
                placeholder="Nom du cas (optionnel)"
                className="bg-gray-800 border-gray-700 text-white font-mono"
              />
              <Input
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Contexte / question (optionnel)"
                className="bg-gray-800 border-gray-700 text-white font-mono"
              />
            </div>

            <Button
              onClick={launch}
              disabled={busy || !files.length || !copilotReady}
              className="bg-orange-600 hover:bg-orange-700 w-full"
            >
              {busy ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
              {phase === 'uploading' ? (uploadProgress || 'Upload en cours...')
                : phase === 'investigating' ? 'Investigation en cours...'
                : "2. Lancer l'investigation autonome"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Journal en direct */}
      {logs.length > 0 && phase !== 'done' && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <div className="flex items-center justify-between gap-3">
              <CardTitle className="text-white text-base flex items-center gap-2">
                {phase === 'investigating' && <Loader2 className="h-4 w-4 animate-spin text-orange-500" />}
                {phase === 'error' && <XCircle className="h-4 w-4 text-red-400" />}
                {phase === 'cancelled' && <Ban className="h-4 w-4 text-gray-400" />}
                Journal de l&apos;enqueteur
                {currentJob && <JobBadge status={currentJob.status} />}
              </CardTitle>
              {jobId && phase === 'investigating' && (!currentJob || isActiveJob(currentJob)) && (
                <Button variant="outline" size="sm" onClick={() => cancelJob(jobId)}
                  disabled={!!cancelling[jobId] || !!currentJob?.cancel_requested}
                  className="border-red-700/60 text-red-300 hover:bg-red-900/30">
                  <Ban className="h-3.5 w-3.5 mr-1.5" />
                  {currentJob?.cancel_requested ? 'Annulation demandee' : 'Annuler'}
                </Button>
              )}
            </div>
            {currentJob && progressLabel(currentJob) && (
              <CardDescription className="text-gray-500 text-xs">{progressLabel(currentJob)}</CardDescription>
            )}
          </CardHeader>
          <CardContent>
            <div className="bg-gray-950 rounded-lg p-3 max-h-64 overflow-auto font-mono text-xs space-y-1">
              {logs.map((line, i) => (
                <p key={i} className="text-gray-400 break-all">{line}</p>
              ))}
              <div ref={logsEndRef} />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Rapport final */}
      {phase === 'done' && result && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-white text-base flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-emerald-500" />
                Rapport d&apos;enquete
              </CardTitle>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={downloadReport} className="border-gray-700 text-gray-300">
                  <Download className="h-3.5 w-3.5 mr-1.5" /> Telecharger
                </Button>
                {result.exports?.navigator_layer && (
                  <Button variant="outline" size="sm" onClick={() => downloadFile(result.exports.navigator_layer)}
                    className="border-gray-700 text-gray-300" title="Calque importable dans MITRE ATT&CK Navigator">
                    <Download className="h-3.5 w-3.5 mr-1.5" /> ATT&amp;CK Navigator
                  </Button>
                )}
                {result.exports?.iocs_csv && (
                  <Button variant="outline" size="sm" onClick={() => downloadFile(result.exports.iocs_csv)}
                    className="border-gray-700 text-gray-300">
                    <Download className="h-3.5 w-3.5 mr-1.5" /> IoCs (CSV)
                  </Button>
                )}
                <Button size="sm" onClick={reset} className="bg-orange-600 hover:bg-orange-700">
                  <Bot className="h-3.5 w-3.5 mr-1.5" /> Nouveau cas
                </Button>
              </div>
            </div>
            {(result.steps || result.tools_executed) && (
              <CardDescription className="text-gray-500 text-xs">
                {result.tools_executed} outil(s) execute(s) en {result.steps} tour(s) — IoCs et
                timeline ajoutes a l&apos;enquete.
              </CardDescription>
            )}
          </CardHeader>
          <CardContent>
            {result.metrics && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
                {[
                  ['Constats', result.metrics.findings],
                  ['Verifies', result.metrics.findings_verified],
                  ['Critiques/Hauts', result.metrics.findings_critical_or_high],
                  ['Tokens', result.metrics.total_tokens],
                ].map(([label, value]) => (
                  <div key={label} className="bg-gray-800 rounded-lg p-2.5 text-center">
                    <p className="text-lg font-semibold text-orange-400">{value ?? 0}</p>
                    <p className="text-[10px] text-gray-500 uppercase tracking-wide">{label}</p>
                  </div>
                ))}
              </div>
            )}
            {Array.isArray(result.metrics?.phases) && (
              <div className="mb-4 grid grid-cols-1 sm:grid-cols-5 gap-2">
                {result.metrics.phases.map((p) => (
                  <div key={p.phase} title={(p.gaps || []).join('\n')}
                    className={`rounded-lg p-2 text-xs border ${p.passed
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                      : 'bg-amber-500/10 border-amber-500/30 text-amber-300'}`}>
                    <p className="font-semibold capitalize">{p.phase.replace('_', '-')}</p>
                    <p className="text-[10px] opacity-80">
                      {p.passed ? 'Porte franchie' : `${(p.gaps || []).length} lacune(s)`}
                      {p.attempts > 1 ? ` · ${p.attempts} essais` : ''}
                    </p>
                  </div>
                ))}
              </div>
            )}
            <VerificationPanel metrics={result.metrics} />
            {result.metrics?.adviser_verdict && (
              <div className="mb-4 flex items-start gap-2 p-3 bg-gray-800 rounded-lg">
                <CheckCircle className="h-4 w-4 text-emerald-400 mt-0.5 shrink-0" />
                <p className="text-xs text-gray-300">
                  <span className="text-gray-400">Revue qualite : </span>
                  {result.metrics.adviser_verdict}
                </p>
              </div>
            )}
            <div className="bg-gray-950 rounded-lg p-4 max-h-[32rem] overflow-auto">
              <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">
                {result.report_content || result.summary}
              </pre>
            </div>
            {result.summary && result.report_content && result.summary !== result.report_content && (
              <div className="mt-3 flex items-start gap-2 p-3 bg-gray-800 rounded-lg">
                <FileText className="h-4 w-4 text-orange-400 mt-0.5 shrink-0" />
                <p className="text-xs text-gray-300 whitespace-pre-wrap">{result.summary}</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {investigationId && (phase === 'investigating' || phase === 'done') && (
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={openGraph} className="border-gray-700 text-gray-300">
            <Network className="h-3.5 w-3.5 mr-1.5" /> Graphe d&apos;attaque du cas
          </Button>
        </div>
      )}

      {investigationId && (phase === 'investigating' || phase === 'done') && (
        <PlaybookPanel investigationId={investigationId} jobId={jobId}
          title="Remediation : playbooks a valider" />
      )}

      {/* Jobs persistes : file d'attente, en cours, termines (survivent a un redemarrage) */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-white text-base flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-orange-500" />
              Investigations autonomes
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={refreshJobs} disabled={jobsLoading}
              className="text-gray-400" aria-label="Rafraichir la liste des jobs">
              <RefreshCw className={`h-3.5 w-3.5 ${jobsLoading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
          {status?.max_jobs_per_user && (
            <CardDescription className="text-gray-500 text-xs">
              {status.max_jobs_per_user} investigation(s) simultanee(s) maximum par utilisateur ;
              les suivantes attendent en file.
            </CardDescription>
          )}
        </CardHeader>
        <CardContent>
          {jobs.length === 0 ? (
            <p className="text-xs text-gray-500">Aucune investigation autonome pour le moment.</p>
          ) : (
            <ul className="space-y-2" data-testid="autonomous-jobs">
              {jobs.map((job) => (
                <li key={job.job_id}
                  className="flex flex-wrap items-center justify-between gap-2 bg-gray-800 rounded-lg px-3 py-2">
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex items-center gap-2">
                      <JobBadge status={job.status} />
                      <span className="text-xs text-gray-300 font-mono truncate" title={job.job_id}>
                        {job.job_id.slice(0, 8)}
                      </span>
                      {job.username && <span className="text-[11px] text-gray-500">{job.username}</span>}
                    </div>
                    <p className="text-[11px] text-gray-500 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatTime(job.finished_at || job.started_at || job.queued_at)}
                      {progressLabel(job) && <span> · {progressLabel(job)}</span>}
                      {job.status === 'error' && job.error && (
                        <span className="text-red-400 truncate max-w-[16rem]" title={job.error}> · {job.error}</span>
                      )}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    {job.job_id !== jobId && (
                      <Button variant="outline" size="sm" onClick={() => openJob(job.job_id)}
                        className="border-gray-700 text-gray-300">
                        {isActiveJob(job) ? 'Suivre' : 'Ouvrir'}
                      </Button>
                    )}
                    {isActiveJob(job) && (
                      <Button variant="outline" size="sm" onClick={() => cancelJob(job.job_id)}
                        disabled={!!cancelling[job.job_id] || job.cancel_requested}
                        className="border-red-700/60 text-red-300 hover:bg-red-900/30">
                        <Ban className="h-3.5 w-3.5 mr-1.5" />
                        {job.cancel_requested ? 'Annulation...' : 'Annuler'}
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
