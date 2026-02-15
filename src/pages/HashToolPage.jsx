import { useState, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Separator } from '@/components/ui/separator.jsx'
import { apiService } from '@/services/api'
import { Hash, Upload, Copy, Check, Loader2, FileDigit } from 'lucide-react'

export default function HashToolPage() {
  const fileInputRef = useRef(null)
  const [dragActive, setDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [calculating, setCalculating] = useState(false)
  const [hashes, setHashes] = useState(null)
  const [copied, setCopied] = useState('')
  const [compareHash, setCompareHash] = useState('')
  const [matchResult, setMatchResult] = useState(null)

  const handleDragOver = (e) => { e.preventDefault(); setDragActive(true) }
  const handleDragLeave = (e) => { e.preventDefault(); setDragActive(false) }
  const handleDrop = (e) => {
    e.preventDefault(); setDragActive(false)
    if (e.dataTransfer.files?.[0]) processFile(e.dataTransfer.files[0])
  }
  const handleFileSelect = (e) => {
    if (e.target.files?.[0]) processFile(e.target.files[0])
  }

  const processFile = async (file) => {
    setSelectedFile(file)
    setHashes(null)
    setMatchResult(null)
    setCalculating(true)
    try {
      const result = await apiService.calculateHash(file)
      setHashes(result.hashes)
      if (compareHash) checkMatch(result.hashes, compareHash)
    } catch (e) {
      console.error(e)
    } finally {
      setCalculating(false)
    }
  }

  const copyToClipboard = (value, label) => {
    navigator.clipboard.writeText(value)
    setCopied(label)
    setTimeout(() => setCopied(''), 1500)
  }

  const checkMatch = (hashesObj, compare) => {
    if (!hashesObj || !compare) { setMatchResult(null); return }
    const trimmed = compare.trim().toLowerCase()
    if (hashesObj.md5 === trimmed) setMatchResult({ match: true, type: 'MD5' })
    else if (hashesObj.sha1 === trimmed) setMatchResult({ match: true, type: 'SHA1' })
    else if (hashesObj.sha256 === trimmed) setMatchResult({ match: true, type: 'SHA256' })
    else setMatchResult({ match: false })
  }

  const formatSize = (bytes) => {
    if (!bytes) return ''
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / 1048576).toFixed(1)} MB`
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* File Upload */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Calculateur de Hash</CardTitle>
          <CardDescription className="text-gray-400">Calculez les empreintes MD5, SHA1 et SHA256 d&apos;un fichier</CardDescription>
        </CardHeader>
        <CardContent>
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
              dragActive ? 'border-orange-500 bg-orange-500/5' : 'border-gray-700 hover:border-gray-600'
            }`}
          >
            <input ref={fileInputRef} type="file" className="hidden" onChange={handleFileSelect} />
            {calculating ? (
              <Loader2 className="h-10 w-10 mx-auto mb-3 text-orange-500 animate-spin" />
            ) : (
              <Upload className={`h-10 w-10 mx-auto mb-3 ${dragActive ? 'text-orange-500' : 'text-gray-500'}`} />
            )}
            <p className="text-sm text-gray-300">
              {calculating ? 'Calcul en cours...' : selectedFile ? selectedFile.name : 'Deposez un fichier ou cliquez pour selectionner'}
            </p>
            {selectedFile && <p className="text-xs text-gray-500 mt-1">{formatSize(selectedFile.size)}</p>}
          </div>
        </CardContent>
      </Card>

      {/* Hash Results */}
      {hashes && (
        <Card className="bg-gray-900 border-gray-800">
          <CardHeader>
            <CardTitle className="text-white">Empreintes</CardTitle>
            <CardDescription className="text-gray-400">{selectedFile?.name}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { label: 'MD5', value: hashes.md5 },
              { label: 'SHA1', value: hashes.sha1 },
              { label: 'SHA256', value: hashes.sha256 },
            ].map(({ label, value }) => (
              <div key={label}>
                <div className="flex items-center justify-between mb-1">
                  <Label className="text-gray-400 text-xs">{label}</Label>
                  <Button
                    variant="ghost" size="sm"
                    onClick={() => copyToClipboard(value, label)}
                    className="h-6 px-2 text-gray-500 hover:text-white"
                  >
                    {copied === label ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                  </Button>
                </div>
                <div className="p-2.5 bg-gray-800 rounded-md">
                  <code className="text-sm text-gray-200 font-mono break-all">{value}</code>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Hash Comparison */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Comparaison de Hash</CardTitle>
          <CardDescription className="text-gray-400">Verifiez un hash connu contre le fichier uploade</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label className="text-gray-300">Hash a comparer</Label>
            <Input
              value={compareHash}
              onChange={(e) => {
                setCompareHash(e.target.value)
                if (hashes) checkMatch(hashes, e.target.value)
              }}
              placeholder="Collez un hash MD5, SHA1 ou SHA256..."
              className="bg-gray-800 border-gray-700 text-white mt-1 font-mono text-sm"
            />
          </div>
          {matchResult && (
            <div className={`p-3 rounded-lg border ${matchResult.match ? 'bg-emerald-900/20 border-emerald-700/30' : 'bg-red-900/20 border-red-700/30'}`}>
              {matchResult.match ? (
                <div className="flex items-center gap-2">
                  <Check className="h-4 w-4 text-emerald-500" />
                  <span className="text-sm text-emerald-300">Correspondance {matchResult.type} trouvee</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <FileDigit className="h-4 w-4 text-red-400" />
                  <span className="text-sm text-red-300">Aucune correspondance</span>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
