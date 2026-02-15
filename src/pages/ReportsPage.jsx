import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Label } from '@/components/ui/label.jsx'
import { Checkbox } from '@/components/ui/checkbox.jsx'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select.jsx'
import { ScrollArea } from '@/components/ui/scroll-area.jsx'
import { useApp } from '@/context/AppContext'
import { apiService } from '@/services/api'
import { FileText, Download, Loader2 } from 'lucide-react'

const TEMPLATES = [
  { value: 'executive', label: 'Resume Executif' },
  { value: 'technical', label: 'Rapport Technique' },
  { value: 'forensic', label: 'Analyse Forensique' },
  { value: 'incident', label: "Rapport d'Incident" },
]

const SECTIONS = [
  { id: 'summary', label: 'Resume executif' },
  { id: 'timeline', label: 'Timeline des evenements' },
  { id: 'iocs', label: 'Indicateurs de compromission' },
  { id: 'artifacts', label: 'Artefacts analyses' },
  { id: 'recommendations', label: 'Recommandations' },
]

export default function ReportsPage() {
  const { currentInvestigation } = useApp()
  const [title, setTitle] = useState(currentInvestigation?.name || currentInvestigation?.nom_du_cas || '')
  const [template, setTemplate] = useState('executive')
  const [format, setFormat] = useState('markdown')
  const [selectedSections, setSelectedSections] = useState(['summary', 'timeline', 'iocs', 'artifacts', 'recommendations'])
  const [generating, setGenerating] = useState(false)
  const [reportResult, setReportResult] = useState(null)
  const [reportContent, setReportContent] = useState('')

  const toggleSection = (id) => {
    setSelectedSections(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    )
  }

  const handleGenerate = async () => {
    if (!currentInvestigation?.id) return
    setGenerating(true)
    setReportContent('')
    try {
      const result = await apiService.generateReport({
        investigation_id: currentInvestigation.id,
        title: title || currentInvestigation.name,
        template,
        format,
        sections: selectedSections,
      })
      setReportResult(result)
      // Try downloading the report content for preview
      if (result.report_id) {
        try {
          const blob = await apiService.downloadReport(result.report_id)
          const text = await blob.text()
          setReportContent(text)
        } catch {
          setReportContent('Rapport genere avec succes. Utilisez le bouton Telecharger.')
        }
      }
    } catch (e) {
      console.error(e)
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = async () => {
    if (!reportResult?.report_id) return
    try {
      const blob = await apiService.downloadReport(reportResult.report_id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = reportResult.report_id
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error(e)
    }
  }

  if (!currentInvestigation) {
    return (
      <Card className="bg-gray-900 border-gray-800">
        <CardContent className="flex flex-col items-center justify-center py-16 text-gray-400">
          <FileText className="h-12 w-12 mb-4 text-gray-600" />
          <p className="text-lg font-medium">Aucune enquete selectionnee</p>
          <p className="text-sm">Selectionnez une enquete pour generer un rapport.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Left - Configuration */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Configuration du Rapport</CardTitle>
          <CardDescription className="text-gray-400">Parametrez et generez votre rapport d&apos;investigation.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div>
            <Label className="text-gray-300">Titre du rapport</Label>
            <Input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Titre du rapport"
              className="bg-gray-800 border-gray-700 text-white mt-1"
            />
          </div>

          <div>
            <Label className="text-gray-300">Template</Label>
            <Select value={template} onValueChange={setTemplate}>
              <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-gray-800 border-gray-700">
                {TEMPLATES.map(t => (
                  <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label className="text-gray-300">Format</Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger className="bg-gray-800 border-gray-700 text-white mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-gray-800 border-gray-700">
                <SelectItem value="markdown">Markdown</SelectItem>
                <SelectItem value="html">HTML</SelectItem>
                <SelectItem value="pdf">PDF</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <Label className="text-gray-300 mb-3 block">Sections</Label>
            <div className="space-y-3">
              {SECTIONS.map(section => (
                <div key={section.id} className="flex items-center gap-3">
                  <Checkbox
                    id={section.id}
                    checked={selectedSections.includes(section.id)}
                    onCheckedChange={() => toggleSection(section.id)}
                    className="border-gray-600 data-[state=checked]:bg-orange-600 data-[state=checked]:border-orange-600"
                  />
                  <label htmlFor={section.id} className="text-sm text-gray-300 cursor-pointer">
                    {section.label}
                  </label>
                </div>
              ))}
            </div>
          </div>

          <Button onClick={handleGenerate} disabled={generating} className="w-full bg-orange-600 hover:bg-orange-700">
            {generating ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <FileText className="h-4 w-4 mr-2" />}
            {generating ? 'Generation en cours...' : 'Generer le Rapport'}
          </Button>
        </CardContent>
      </Card>

      {/* Right - Preview */}
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-white">Apercu du Rapport</CardTitle>
              <CardDescription className="text-gray-400">
                {reportResult ? `Rapport genere: ${reportResult.report_id}` : 'Generez un rapport pour voir l\'apercu'}
              </CardDescription>
            </div>
            {reportResult && (
              <Button variant="outline" onClick={handleDownload} className="border-gray-700 text-gray-300">
                <Download className="h-4 w-4 mr-2" /> Telecharger
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {reportContent ? (
            <ScrollArea className="h-[500px]">
              <pre className="text-sm text-gray-300 bg-gray-800 rounded-lg p-4 whitespace-pre-wrap font-mono">
                {reportContent}
              </pre>
            </ScrollArea>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 text-gray-500">
              <FileText className="h-10 w-10 mb-3 text-gray-600" />
              <p className="text-sm">Aucun rapport genere</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
