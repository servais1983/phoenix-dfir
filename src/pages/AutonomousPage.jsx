import { useCallback, useEffect, useRef, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'
import { Bot, UploadCloud, FolderOpen, Loader2, CheckCircle, XCircle, FileText, Download, Play } from 'lucide-react'
import { toast } from 'sonner'

const ACCEPTED = '.evtx,.csv,.json,.log,.txt,.xml,.pcap,.pcapng,.pf,.lnk,.sqlite,.db,.ps1,.bat,.sh,.hve,.dat'

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
  const jobIdRef = useRef(null)
  const logsEndRef = useRef(null)
  const fileInputRef = useRef(null)

  useEffect(() => {
    apiService.getAutonomousStatus().then(setStatus).catch(() => setStatus(null))
  }, [])

  // Progression temps reel de l'enqueteur
  useEffect(() => {
    const unsub = websocketService.onAutonomousProgress((data) => {
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
      }
    })
    return unsub
  }, [])

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
    jobIdRef.current = null
    try {
      const name = caseName.trim() || `Enquete autonome du ${new Date().toLocaleString('fr-FR')}`
      const inv = await apiService.createInvestigation(name, 'Enquete lancee depuis la page Enqueteur IA.')
      const invId = inv.id || inv.investigation?.id
      for (let i = 0; i < files.length; i++) {
        setUploadProgress(`Upload ${i + 1}/${files.length} : ${files[i].name}`)
        await apiService.uploadFile(files[i], invId)
      }
      setUploadProgress('')
      setPhase('investigating')
      setLogs([`Enquete '${name}' creee, ${files.length} evidence(s) uploadee(s).`])
      const job = await apiService.startAutonomousInvestigation(invId, question.trim())
      jobIdRef.current = job.job_id
      setLogs((prev) => [...prev, 'GitHub Copilot prend le cas en main...'])
    } catch (e) {
      setPhase('error')
      const msg = e?.response?.data?.error || "Impossible de lancer l'investigation"
      toast.error(msg)
      setLogs((prev) => [...prev, `Erreur : ${msg}`])
    }
  }

  const downloadReport = async () => {
    if (!result?.report_id) return
    try {
      const blob = await apiService.downloadReport(result.report_id)
      const url = URL.createObjectURL(new Blob([blob]))
      const a = document.createElement('a')
      a.href = url
      a.download = result.report_id
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      toast.error('Telechargement du rapport impossible')
    }
  }

  const reset = () => {
    setFiles([])
    setCaseName('')
    setQuestion('')
    setPhase('idle')
    setLogs([])
    setResult(null)
    jobIdRef.current = null
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
                Deposez vos evidences : GitHub Copilot mene l&apos;enquete seul (parsing, Sigma,
                IoCs, timeline, MITRE) et redige le rapport.
              </CardDescription>
            </div>
            {status && (
              <Badge className={copilotReady
                ? 'bg-emerald-600/20 text-emerald-400 border-emerald-600/30'
                : 'bg-red-600/20 text-red-400 border-red-600/30'}>
                {copilotReady ? `Copilot pret (${status.model})` : 'GITHUB_TOKEN manquant'}
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {!copilotReady && status && (
            <p className="text-xs text-red-400">
              Definissez la variable d&apos;environnement GITHUB_TOKEN (jeton GitHub, permission
              Models: read) puis redemarrez le backend.
            </p>
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
            <CardTitle className="text-white text-base flex items-center gap-2">
              {phase === 'investigating' && <Loader2 className="h-4 w-4 animate-spin text-orange-500" />}
              {phase === 'error' && <XCircle className="h-4 w-4 text-red-400" />}
              Journal de l&apos;enqueteur
            </CardTitle>
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
    </div>
  )
}
