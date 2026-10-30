import { useMemo, useState } from 'react'
import { Clock } from 'lucide-react'

const SEVERITY_CLASS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-300',
  low: 'text-sky-300',
  info: 'text-gray-400',
}

function techniquesOf(item) {
  return (String(item.mitre || '').toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) || [])
}

function artifactName(ref) {
  return String(ref.artifact || '').split(/[\\/]/).pop()
}

// Chronologie des constats verifies (console enqueteur DFIR)
export default function FindingsTimeline({ items }) {
  const [technique, setTechnique] = useState('')
  const [artifact, setArtifact] = useState('')
  const list = useMemo(() => (Array.isArray(items) ? items : []), [items])
  const techniques = useMemo(() => [...new Set(list.flatMap(techniquesOf))].sort(), [list])
  const artifacts = useMemo(
    () => [...new Set(list.flatMap((i) => (i.refs || []).map(artifactName)))].filter(Boolean).sort(), [list])
  if (!list.length) return null

  const shown = list.filter((i) => (!technique || techniquesOf(i).includes(technique))
    && (!artifact || (i.refs || []).some((r) => artifactName(r) === artifact)))

  return (
    <div className="mb-4 bg-gray-800 rounded-lg p-3" data-testid="findings-timeline">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <p className="text-xs text-gray-400 flex items-center gap-1.5">
          <Clock className="h-3.5 w-3.5 text-orange-400" /> Chronologie des constats verifies
        </p>
        <div className="flex gap-2">
          <select aria-label="Filtrer par technique" value={technique} onChange={(e) => setTechnique(e.target.value)}
            className="bg-gray-900 border border-gray-700 rounded text-[11px] text-gray-300 px-1.5 py-0.5">
            <option value="">Toutes les techniques</option>
            {techniques.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select aria-label="Filtrer par artefact" value={artifact} onChange={(e) => setArtifact(e.target.value)}
            className="bg-gray-900 border border-gray-700 rounded text-[11px] text-gray-300 px-1.5 py-0.5">
            <option value="">Tous les artefacts</option>
            {artifacts.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
      </div>
      <ol className="space-y-1.5">
        {shown.map((item) => (
          <li key={item.id} className="text-[11px] border-l-2 border-gray-600 pl-2" data-testid="timeline-item">
            <span className="text-gray-500 font-mono">{item.timestamp || 'sans horodatage'}</span>{' '}
            <span className={`uppercase font-semibold ${SEVERITY_CLASS[item.severity] || 'text-gray-300'}`}>
              {item.severity}
            </span>{' '}
            <span className="text-gray-200">[F{item.id}] {item.title}</span>
            {item.mitre && <span className="text-orange-300"> · {item.mitre}</span>}
            <span className="block text-gray-500">
              {(item.refs || []).map((r) => `${artifactName(r)} ${r.kind}=${r.value}`).join(' · ')}
            </span>
          </li>
        ))}
      </ol>
    </div>
  )
}
