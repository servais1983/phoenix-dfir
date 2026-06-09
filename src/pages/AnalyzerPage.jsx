import { useState, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Textarea } from '@/components/ui/textarea.jsx'
import { Progress } from '@/components/ui/progress.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { ScrollArea } from '@/components/ui/scroll-area.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { useApp } from '@/context/AppContext'
import { Upload, FileUp, Search, Loader2, CheckCircle, AlertTriangle, File, Link as LinkIcon, Globe, PlayCircle } from 'lucide-react'
import { toast } from 'sonner'

// Affiche les champs specifiques aux parsers v4.0 (Prefetch / LNK / Browser history).
// Le backend renvoie un payload structure ; on detecte les cles caracteristiques.
function StructuredArtifactDetails({ payload }) {
  if (!payload || typeof payload !== 'object') return null

  // Prefetch
  if (payload.executable !== undefined || payload.run_count !== undefined) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1 text-orange-400 col-span-2">
          <PlayCircle className="h-3 w-3" /> Prefetch
        </div>
        <div className="text-gray-400">Executable</div>
        <div className="text-gray-200 font-mono truncate" title={payload.executable}>{payload.executable || '-'}</div>
        <div className="text-gray-400">Executions</div>
        <div className="text-gray-200">{payload.run_count ?? '-'}</div>
        {payload.last_run && (<>
          <div className="text-gray-400">Derniere execution</div>
          <div className="text-gray-200">{payload.last_run}</div>
        </>)}
        {Array.isArray(payload.referenced_files) && payload.referenced_files.length > 0 && (
          <div className="col-span-2 text-gray-400 mt-2">
            Fichiers references : <span className="text-gray-200">{payload.referenced_files.length}</span>
          </div>
        )}
      </div>
    )
  }

  // LNK
  if (payload.target_path !== undefined || payload.icon_location !== undefined) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1 text-orange-400 col-span-2">
          <LinkIcon className="h-3 w-3" /> Raccourci Windows (LNK)
        </div>
        <div className="text-gray-400">Cible</div>
        <div className="text-gray-200 font-mono truncate col-span-1" title={payload.target_path}>{payload.target_path || '-'}</div>
        {payload.arguments && (<>
          <div className="text-gray-400">Arguments</div>
          <div className="text-gray-200 font-mono break-all" title={payload.arguments}>{payload.arguments}</div>
        </>)}
        {payload.working_dir && (<>
          <div className="text-gray-400">Working dir</div>
          <div className="text-gray-200 font-mono truncate" title={payload.working_dir}>{payload.working_dir}</div>
        </>)}
        {payload.severity && (<>
          <div className="text-gray-400">Severite</div>
          <div>
            <Badge className={
              payload.severity === 'high' || payload.severity === 'critical'
                ? 'bg-red-600/20 text-red-400 border-red-600/30'
                : 'bg-gray-800 text-gray-400 border-gray-700'
            }>
              {payload.severity}
            </Badge>
          </div>
        </>)}
      </div>
    )
  }

  // Browser history
  if (payload.browser !== undefined || payload.total_visits !== undefined) {
    return (
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-1 text-orange-400 col-span-2">
          <Globe className="h-3 w-3" /> Historique navigateur ({payload.browser})
        </div>
        <div className="text-gray-400">Visites analysees</div>
        <div className="text-gray-200">{payload.total_visits ?? '-'}</div>
        {Array.isArray(payload.events) && payload.events.length > 0 && (
          <div className="col-span-2 mt-2">
            <div className="text-gray-400 mb-1">5 dernieres URLs</div>
            <ul className="text-gray-200 space-y-0.5 font-mono text-[10px]">
              {payload.events.slice(0, 5).map((e, i) => (
                <li key={i} className="truncate" title={e.url}>{e.url}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    )
  }

  return null
}

export default function AnalyzerPage() {
  const { investigations, currentInvestigation, uploadFile, analyzeFile, activeAnalysis, analysisResults, setCurrentInvestigation } = useApp()

  const fileInputRef = useRef(null)
  const [dragActive, setDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadedFile, setUploadedFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)

  const [fileType, setFileType] = useState('auto')
  const [eventIdFilter, setEventIdFilter] = useState('')
  const [query, setQuery] = useState('')
  const [selectedInvestigation, setSelectedInvestigation] = useState(currentInvestigation?.id || '')

  const handleDragOver = (e) => { e.preventDefault(); e.stopPropagation(); setDragActive(true) }
  const handleDragLeave = (e) => { e.preventDefault(); e.stopPropagation(); setDragActive(false) }
  const handleDrop = (e) => {
    e.preventDefault(); e.stopPropagation(); setDragActive(false)
    if (e.dataTransfer.files?.[0]) {
      setSelectedFile(e.dataTransfer.files[0])
      setUploadedFile(null)
    }
  }
  const handleFileSelect = (e) => {
    if (e.target.files?.[0]) {
      setSelectedFile(e.target.files[0])
      setUploadedFile(null)
    }
  }

  const handleUpload = async () => {
    if (!selectedFile) return
    setUploading(true)
    setUploadProgress(0)
    try {
      const result = await uploadFile(selectedFile, (p) => setUploadProgress(p))
      setUploadedFile(result)
      toast.success('Fichier uploade avec succes')
    } catch (e) {
      console.error('Upload error:', e)
      toast.error('Erreur lors de l\'upload du fichier')
    } finally {
      setUploading(false)
    }
  }

  const handleAnalyze = async () => {
    if (!uploadedFile) return
    setAnalyzing(true)
    try {
      await analyzeFile({
        filename: uploadedFile.filename,
        query: query || 'Analyse complete du fichier',
        investigation_id: selectedInvestigation || undefined,
        event_id_filter: eventIdFilter || undefined,
      })
      toast.success('Analyse lancee avec succes')
    } catch (e) {
      console.error('Analysis error:', e)
      toast.error('Erreur lors du lancement de l\'analyse')
    } finally {
      setAnalyzing(false)
    }
  }

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1048576).toFixed(1)} MB`
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left Panel - Upload & Config */}
      <div className="space-y-6">
        {/* Drop Zone */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Upload de Fichier</CardTitle>
            <CardDescription className="text-gray-400">Glissez un fichier ou cliquez pour selectionner</CardDescription>
          </CardHeader>
          <CardContent>
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
                dragActive ? 'border-orange-500 bg-orange-500/5' : 'border-gray-700 hover:border-gray-600 hover:bg-gray-800/30'
              }`}
            >
              <input ref={fileInputRef} type="file" className="hidden" onChange={handleFileSelect} accept=".evtx,.csv,.json,.log,.txt,.xml,.pcap,.pcapng,.pf,.lnk,.sqlite,.db" />
              <Upload className={`h-10 w-10 mx-auto mb-3 ${dragActive ? 'text-orange-500' : 'text-gray-500'}`} />
              <p className="text-sm text-gray-300">
                {selectedFile ? selectedFile.name : 'EVTX, CSV, JSON, LOG, XML, PCAP, Prefetch (.pf), LNK, SQLite (browser history)'}
              </p>
              {selectedFile && (
                <p className="text-xs text-gray-500 mt-1">{formatSize(selectedFile.size)}</p>
              )}
            </div>

            {selectedFile && !uploadedFile && (
              <div className="mt-4 space-y-2">
                {uploading && <Progress value={uploadProgress} className="h-2" />}
                <Button onClick={handleUpload} disabled={uploading} className="w-full bg-orange-600 hover:bg-orange-700">
                  {uploading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <FileUp className="h-4 w-4 mr-2" />}
                  {uploading ? `Upload... ${uploadProgress}%` : 'Uploader'}
                </Button>
              </div>
            )}

            {uploadedFile && (
              <div className="mt-4 flex items-center gap-2 p-3 bg-green-900/20 border border-green-800/30 rounded-lg">
                <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm text-green-300 truncate">{uploadedFile.original_filename}</p>
                  <p className="text-xs text-green-500">{formatSize(uploadedFile.size)}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Analysis Config */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-gray-300">Type de fichier</Label>
              <Select value={fileType} onValueChange={setFileType}>
                <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-gray-800 border-gray-700">
                  <SelectItem value="auto">Auto-detection</SelectItem>
                  <SelectItem value="evtx">EVTX (Windows Event Log)</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="log">LOG / TXT</SelectItem>
                  <SelectItem value="prefetch">Prefetch (.pf)</SelectItem>
                  <SelectItem value="lnk">Raccourci Windows (.lnk)</SelectItem>
                  <SelectItem value="browser_history">Historique navigateur (SQLite)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {(fileType === 'evtx' || fileType === 'auto') && (
              <div>
                <Label className="text-gray-300">Filtre Event ID (optionnel)</Label>
                <Input
                  value={eventIdFilter}
                  onChange={(e) => setEventIdFilter(e.target.value)}
                  placeholder="Ex: 4624, 4625, 4688"
                  className="bg-gray-800 border-gray-700 text-white mt-1 font-mono"
                />
              </div>
            )}

            <div>
              <Label className="text-gray-300">Enquete associee</Label>
              <Select value={selectedInvestigation} onValueChange={(v) => {
                setSelectedInvestigation(v)
                const inv = investigations.find(i => i.id === v)
                if (inv) setCurrentInvestigation(inv)
              }}>
                <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                  <SelectValue placeholder="Aucune enquete" />
                </SelectTrigger>
                <SelectContent className="bg-gray-800 border-gray-700">
                  {investigations.map(inv => (
                    <SelectItem key={inv.id} value={inv.id}>{inv.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-gray-300">Question d&apos;analyse</Label>
              <Textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Decrivez ce que vous recherchez dans ce fichier..."
                className="bg-gray-800 border-gray-700 text-white mt-1 min-h-[80px]"
              />
            </div>

            <Button onClick={handleAnalyze} disabled={!uploadedFile || analyzing} className="w-full bg-orange-600 hover:bg-orange-700">
              {analyzing ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
              {analyzing ? 'Analyse en cours...' : 'Lancer l\'analyse'}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Right Panel - Results */}
      <div className="space-y-6">
        {/* Active Analysis Progress */}
        {activeAnalysis && activeAnalysis.progress < 100 && (
          <Card className="bg-gray-900 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Analyse en cours</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Progress value={activeAnalysis.progress || 0} className="h-2" />
              <p className="text-sm text-gray-400">{activeAnalysis.status}</p>
            </CardContent>
          </Card>
        )}

        {/* Results */}
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Resultats d&apos;Analyse</CardTitle>
            <CardDescription className="text-gray-400">
              {analysisResults.length} analyse(s) disponible(s)
            </CardDescription>
          </CardHeader>
          <CardContent>
            {analysisResults.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-gray-500">
                <File className="h-10 w-10 mb-3 text-gray-600" />
                <p className="text-sm">Aucun resultat d&apos;analyse</p>
                <p className="text-xs text-gray-600">Uploadez et analysez un fichier pour voir les resultats</p>
              </div>
            ) : (
              <ScrollArea className="h-[500px]">
                <div className="space-y-4">
                  {analysisResults.map((result, index) => (
                    <div key={result.id || index} className="border border-gray-800 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <Badge variant="outline" className="text-xs border-gray-700 text-gray-400 font-mono">
                          {result.timestamp ? new Date(result.timestamp).toLocaleString('fr-FR') : 'Analyse'}
                        </Badge>
                      </div>
                      <pre className="text-xs text-gray-300 bg-gray-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap font-mono max-h-[300px] overflow-y-auto">
                        {typeof result.result === 'string'
                          ? result.result
                          : (result.result?.summary || JSON.stringify(result.result, null, 2))}
                      </pre>
                      <StructuredArtifactDetails payload={typeof result.result === 'object' ? result.result : null} />
                    </div>
                  ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
