import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card.jsx'
import { Button } from '@/components/ui/button.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { apiService } from '@/services/api'
import websocketService from '@/services/websocket'
import { useApp } from '@/context/AppContext'
import {
  layoutGraph, filterByTime, timeSteps, collectTechniques, pathEdgeIds, nodeStyle, shapePoints, NODE_STYLES,
} from '@/lib/graphLayout'
import {
  Network, RefreshCw, Loader2, ZoomIn, ZoomOut, Maximize2, Play, Pause, Radar, Crosshair, Radio,
} from 'lucide-react'

const POLL_MS = 10000
const NODE_R = 18

function formatTs(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString('fr-FR')
}

function NodeShape({ shape, color, r, strokeColor, strokeWidth }) {
  const common = { fill: `${color}33`, stroke: strokeColor || color, strokeWidth }
  if (shape === 'rect') return <rect x={-r} y={-r * 0.75} width={r * 2} height={r * 1.5} rx={3} {...common} />
  if (shape === 'roundrect') return <rect x={-r} y={-r * 0.75} width={r * 2} height={r * 1.5} rx={r * 0.5} {...common} />
  if (shape === 'document') {
    return <path d={`M${-r * 0.75},${-r} H${r * 0.35} L${r * 0.75},${-r * 0.6} V${r} H${-r * 0.75} Z`} {...common} />
  }
  if (shape === 'diamond' || shape === 'hexagon') return <polygon points={shapePoints(shape, r * 1.1)} {...common} />
  return <circle r={r * 0.9} {...common} />
}

function Chip({ children, active, onClick, title }) {
  return (
    <button type="button" onClick={onClick} title={title}
      className={`px-2 py-0.5 rounded-full border font-mono text-[11px] transition-colors ${active
        ? 'bg-purple-500/30 border-purple-400 text-purple-100'
        : 'bg-purple-500/10 border-purple-500/30 text-purple-300 hover:border-purple-400'}`}>
      {children}
    </button>
  )
}

export default function AttackGraphPage() {
  const { investigations, currentInvestigation } = useApp()
  const investigationList = useMemo(() => investigations?.items || investigations || [], [investigations])
  const [invId, setInvId] = useState(currentInvestigation?.id || '')
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(null) // { kind: 'node'|'edge', id }
  const [showBlast, setShowBlast] = useState(false)
  const [technique, setTechnique] = useState(null)
  const [stepIndex, setStepIndex] = useState(null) // null = graphe complet
  const [playing, setPlaying] = useState(false)
  const [jobRunning, setJobRunning] = useState(false)
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const svgRef = useRef(null)
  const dragRef = useRef(null)

  const effectiveInv = invId || investigationList[0]?.id || ''

  const load = useCallback(async (quiet = false) => {
    if (!effectiveInv) return
    if (!quiet) setLoading(true)
    try {
      const data = await apiService.getInvestigationGraph(effectiveInv)
      setGraph(data)
      setError(null)
    } catch (e) {
      setGraph(null)
      setError(e?.response?.data?.error || "Graphe d'attaque indisponible")
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [effectiveInv])

  useEffect(() => {
    setSelected(null)
    setStepIndex(null)
    setTechnique(null)
    setJobRunning(false)
    load()
  }, [load])

  // Temps reel : evenement graph_updated + suivi des jobs autonomes de l'enquete
  useEffect(() => {
    const offGraph = websocketService.onGraphUpdated((evt) => {
      if (evt?.investigation_id === effectiveInv) load(true)
    })
    const offProgress = websocketService.onAutonomousProgress((evt) => {
      if (evt?.investigation_id !== effectiveInv) return
      if (evt.status === 'completed' || evt.status === 'error') {
        setJobRunning(false)
        load(true)
      } else {
        setJobRunning(true)
      }
    })
    return () => { offGraph(); offProgress() }
  }, [effectiveInv, load])

  // Repli : interrogation toutes les 10 s tant qu'un job tourne
  useEffect(() => {
    if (!jobRunning) return undefined
    const timer = setInterval(() => load(true), POLL_MS)
    return () => clearInterval(timer)
  }, [jobRunning, load])

  const layout = useMemo(() => layoutGraph(graph || { nodes: [], edges: [] }), [graph])
  const steps = useMemo(() => timeSteps(graph), [graph])
  const cutoff = stepIndex === null || stepIndex >= steps.length ? null : steps[stepIndex]
  const visible = useMemo(() => filterByTime(graph, cutoff), [graph, cutoff])
  const techniques = useMemo(() => collectTechniques(graph), [graph])
  const pzEdges = useMemo(() => pathEdgeIds(graph), [graph])
  const blast = useMemo(() => new Set(graph?.blast_radius?.nodes || []), [graph])
  const nodeById = useMemo(() => new Map((graph?.nodes || []).map((n) => [n.id, n])), [graph])
  const presentTypes = useMemo(() => [...new Set((graph?.nodes || []).map((n) => n.type))].sort(), [graph])

  // Rejeu automatique
  useEffect(() => {
    if (!playing) return undefined
    const timer = setInterval(() => {
      setStepIndex((prev) => {
        const next = prev === null ? 0 : prev + 1
        if (next >= steps.length) {
          setPlaying(false)
          return null
        }
        return next
      })
    }, 900)
    return () => clearInterval(timer)
  }, [playing, steps.length])

  // Zoom molette (listener non passif pour bloquer le defilement de la page)
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return undefined
    const onWheel = (e) => {
      e.preventDefault()
      const rect = svg.getBoundingClientRect()
      const px = e.clientX - rect.left
      const py = e.clientY - rect.top
      setView((v) => {
        const k = Math.min(4, Math.max(0.2, v.k * (e.deltaY < 0 ? 1.15 : 1 / 1.15)))
        return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k }
      })
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [graph])

  const zoom = (factor) => setView((v) => ({ ...v, k: Math.min(4, Math.max(0.2, v.k * factor)) }))
  const resetView = () => setView({ x: 0, y: 0, k: 1 })

  const onPointerDown = (e) => {
    if (e.target.closest('[data-graph-item]')) return
    dragRef.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }
  const onPointerMove = (e) => {
    const d = dragRef.current
    if (!d) return
    setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }))
  }
  const onPointerUp = () => { dragRef.current = null }

  const highlightTech = (item) => technique && (item.technique_ids || []).includes(technique)
  const selectedItem = selected
    ? (selected.kind === 'node' ? nodeById.get(selected.id) : (graph?.edges || []).find((e) => e.id === selected.id))
    : null
  const pz = graph?.patient_zero

  return (
    <div className="space-y-4">
      <Card className="bg-gray-900 border-gray-800">
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="text-white flex items-center gap-2">
                <Network className="h-5 w-5 text-orange-500" /> Graphe d&apos;attaque
              </CardTitle>
              <CardDescription className="text-gray-400">
                Entites (hotes, comptes, IP, processus, fichiers) et relations reconstruites par
                l&apos;Enqueteur IA, avec patient zero, rayon d&apos;impact et rejeu chronologique.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={effectiveInv}
                onChange={(e) => setInvId(e.target.value)}
                className="h-9 max-w-[16rem] rounded-md border border-gray-700 bg-gray-950 px-2 text-sm text-gray-200"
                aria-label="Enquete"
              >
                {investigationList.length === 0 && <option value="">Aucune enquete</option>}
                {investigationList.map((inv) => (
                  <option key={inv.id} value={inv.id}>{inv.name}</option>
                ))}
              </select>
              <Button variant="outline" size="sm" onClick={() => load()} disabled={loading || !effectiveInv}
                className="border-gray-700 text-gray-300" aria-label="Rafraichir">
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
              {jobRunning && (
                <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                  <Radio className="h-3 w-3 mr-1 animate-pulse" /> Job en cours : mise a jour en direct
                </Badge>
              )}
            </div>
          </div>
          {graph && (
            <div className="flex flex-wrap items-center gap-2 pt-2 text-xs text-gray-400">
              <Badge className="bg-gray-800 text-gray-300 border-gray-700">{graph.nodes.length} entites</Badge>
              <Badge className="bg-gray-800 text-gray-300 border-gray-700">{graph.edges.length} relations</Badge>
              <Badge className="bg-red-500/10 text-red-400 border-red-500/30">
                {graph.nodes.filter((n) => n.malicious).length} malveillante(s)
              </Badge>
              {pz?.node && (
                <Badge className="bg-orange-500/10 text-orange-300 border-orange-500/40">
                  <Crosshair className="h-3 w-3 mr-1" /> Patient zero : {nodeById.get(pz.node)?.label || pz.node}
                  {pz.timestamp ? ` (${formatTs(pz.timestamp)})` : ''}
                </Badge>
              )}
              {(graph.truncated?.nodes || graph.truncated?.edges) && (
                <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/30">Graphe tronque</Badge>
              )}
              {graph.generated_at && <span>Genere le {formatTs(graph.generated_at)}</span>}
            </div>
          )}
        </CardHeader>
      </Card>

      {!graph && (
        <Card className="bg-gray-900 border-gray-800">
          <CardContent className="py-16 text-center text-sm text-gray-500">
            {loading ? <Loader2 className="h-6 w-6 animate-spin text-orange-500 mx-auto" />
              : (error || 'Selectionnez une enquete.')}
          </CardContent>
        </Card>
      )}

      {graph && (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
          <Card className="xl:col-span-8 bg-gray-900 border-gray-800 min-w-0">
            <CardContent className="p-3 space-y-3">
              {/* Barre d'outils */}
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="outline" className="border-gray-700 text-gray-300" onClick={() => zoom(1.2)} aria-label="Zoom avant">
                  <ZoomIn className="h-4 w-4" />
                </Button>
                <Button size="sm" variant="outline" className="border-gray-700 text-gray-300" onClick={() => zoom(1 / 1.2)} aria-label="Zoom arriere">
                  <ZoomOut className="h-4 w-4" />
                </Button>
                <Button size="sm" variant="outline" className="border-gray-700 text-gray-300" onClick={resetView} aria-label="Recentrer">
                  <Maximize2 className="h-4 w-4" />
                </Button>
                <Button size="sm" variant="outline" onClick={() => setShowBlast((s) => !s)}
                  disabled={!blast.size}
                  className={showBlast ? 'border-amber-500 text-amber-300 bg-amber-500/10' : 'border-gray-700 text-gray-300'}>
                  <Radar className="h-4 w-4" /> Rayon d&apos;impact ({blast.size})
                </Button>
              </div>

              {/* Curseur temporel (rejeu de la chaine d'attaque) */}
              {steps.length > 0 && (
                <div className="flex flex-wrap items-center gap-3 p-2 rounded-lg bg-gray-950 border border-gray-800">
                  <Button size="sm" variant="outline" className="border-gray-700 text-gray-300"
                    onClick={() => {
                      if (!playing && stepIndex === null) setStepIndex(0)
                      setPlaying((p) => !p)
                    }}
                    aria-label={playing ? 'Pause' : 'Rejouer'}>
                    {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  </Button>
                  <input
                    type="range" min={0} max={steps.length} step={1}
                    value={stepIndex === null ? steps.length : stepIndex}
                    onChange={(e) => {
                      const v = Number(e.target.value)
                      setPlaying(false)
                      setStepIndex(v >= steps.length ? null : v)
                    }}
                    className="flex-1 min-w-[10rem] accent-orange-500"
                    aria-label="Rejeu chronologique"
                  />
                  <span className="text-xs font-mono text-gray-400 min-w-[11rem] text-right">
                    {cutoff === null ? 'Graphe complet' : `Jusqu'au ${formatTs(new Date(cutoff).toISOString())}`}
                  </span>
                </div>
              )}

              {/* Graphe SVG */}
              <div className="relative rounded-lg border border-gray-800 bg-gray-950 overflow-hidden h-[55vh] min-h-[320px]">
                <svg
                  ref={svgRef}
                  className="w-full h-full touch-none select-none cursor-grab active:cursor-grabbing"
                  onPointerDown={onPointerDown}
                  onPointerMove={onPointerMove}
                  onPointerUp={onPointerUp}
                  onPointerLeave={onPointerUp}
                  onClick={(e) => { if (!e.target.closest('[data-graph-item]')) setSelected(null) }}
                  role="img"
                  aria-label="Graphe d'attaque"
                >
                  <defs>
                    <marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280" />
                    </marker>
                    <marker id="arrow-hot" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#f97316" />
                    </marker>
                  </defs>
                  <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                    {graph.edges.filter((e) => visible.edges.has(e.id)).map((e) => {
                      const a = layout.positions[e.source]
                      const b = layout.positions[e.target]
                      if (!a || !b) return null
                      const dx = b.x - a.x
                      const dy = b.y - a.y
                      const len = Math.hypot(dx, dy) || 1
                      const ux = dx / len
                      const uy = dy / len
                      const hot = pzEdges.has(e.id) || highlightTech(e)
                      const isSel = selected?.kind === 'edge' && selected.id === e.id
                      const dim = showBlast && !(blast.has(e.source) && blast.has(e.target))
                      const self = e.source === e.target
                      return (
                        <g key={e.id} data-graph-item onClick={() => setSelected({ kind: 'edge', id: e.id })}
                          className="cursor-pointer" opacity={dim ? 0.15 : 1}>
                          {self ? (
                            <circle cx={a.x} cy={a.y - NODE_R - 10} r={10} fill="none" stroke="#6b7280" />
                          ) : (
                            <>
                              <line x1={a.x + ux * NODE_R} y1={a.y + uy * NODE_R} x2={b.x - ux * (NODE_R + 2)} y2={b.y - uy * (NODE_R + 2)}
                                stroke="transparent" strokeWidth={12} />
                              <line x1={a.x + ux * NODE_R} y1={a.y + uy * NODE_R} x2={b.x - ux * (NODE_R + 2)} y2={b.y - uy * (NODE_R + 2)}
                                stroke={isSel ? '#fde68a' : hot ? '#f97316' : '#4b5563'}
                                strokeWidth={isSel || hot ? 2.5 : 1.4}
                                markerEnd={hot ? 'url(#arrow-hot)' : 'url(#arrow)'} />
                            </>
                          )}
                          {(isSel || view.k > 1.3) && (
                            <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 6} textAnchor="middle"
                              className="fill-gray-400" fontSize={10}>{e.type}</text>
                          )}
                        </g>
                      )
                    })}
                    {graph.nodes.filter((n) => visible.nodes.has(n.id)).map((n) => {
                      const p = layout.positions[n.id]
                      if (!p) return null
                      const st = nodeStyle(n.type)
                      const isSel = selected?.kind === 'node' && selected.id === n.id
                      const inBlast = blast.has(n.id)
                      const dim = showBlast && !inBlast
                      const isPz = pz?.node === n.id
                      return (
                        <g key={n.id} transform={`translate(${p.x},${p.y})`} data-graph-item
                          onClick={() => setSelected({ kind: 'node', id: n.id })}
                          className="cursor-pointer" opacity={dim ? 0.2 : 1}>
                          <title>{`${n.label} (${st.label})`}</title>
                          {showBlast && inBlast && <circle r={NODE_R + 9} fill="#f59e0b22" stroke="#f59e0b" strokeDasharray="3 3" />}
                          {n.malicious && <circle r={NODE_R + 5} fill="#ef444422" stroke="#ef4444" strokeWidth={1.5} />}
                          {highlightTech(n) && <circle r={NODE_R + 7} fill="none" stroke="#c084fc" strokeWidth={2} />}
                          <NodeShape shape={st.shape} color={st.color} r={NODE_R}
                            strokeColor={isSel ? '#fde68a' : n.malicious ? '#ef4444' : undefined}
                            strokeWidth={isSel ? 3 : 1.5} />
                          {isPz && (
                            <g transform={`translate(${NODE_R - 2},${-NODE_R - 2})`}>
                              <rect x={-11} y={-8} width={22} height={14} rx={7} fill="#f97316" />
                              <text textAnchor="middle" y={3} fontSize={9} fontWeight="700" fill="#111827">P0</text>
                            </g>
                          )}
                          <text y={NODE_R + 14} textAnchor="middle" fontSize={11}
                            className={n.malicious ? 'fill-red-300' : 'fill-gray-300'}>
                            {n.label.length > 24 ? `${n.label.slice(0, 22)}...` : n.label}
                          </text>
                        </g>
                      )
                    })}
                  </g>
                </svg>
              </div>

              {/* Legende */}
              <div className="flex flex-wrap gap-3 text-[11px] text-gray-400">
                {(presentTypes.length ? presentTypes : Object.keys(NODE_STYLES)).map((t) => {
                  const st = nodeStyle(t)
                  return (
                    <span key={t} className="flex items-center gap-1">
                      <svg width="16" height="16" viewBox="-12 -12 24 24" aria-hidden="true">
                        <NodeShape shape={st.shape} color={st.color} r={9} strokeWidth={1.5} />
                      </svg>
                      {st.label}
                    </span>
                  )
                })}
                <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full border-2 border-red-500" /> Malveillant</span>
                <span className="flex items-center gap-1"><span className="px-1 rounded bg-orange-500 text-gray-900 font-bold text-[9px]">P0</span> Patient zero</span>
                <span className="flex items-center gap-1"><span className="h-0.5 w-4 bg-orange-500" /> Chemin d&apos;attaque</span>
                <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-full border border-dashed border-amber-400" /> Rayon d&apos;impact</span>
              </div>
            </CardContent>
          </Card>

          {/* Panneau lateral : techniques + inspecteur */}
          <div className="xl:col-span-4 space-y-4 min-w-0">
            <Card className="bg-gray-900 border-gray-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-gray-400">Techniques ATT&amp;CK</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-1.5">
                {techniques.length === 0 && <p className="text-xs text-gray-500">Aucune technique rattachee.</p>}
                {techniques.map((t) => (
                  <Chip key={t} active={technique === t} onClick={() => setTechnique((cur) => (cur === t ? null : t))}
                    title="Surligner les entites et relations">
                    {t}
                  </Chip>
                ))}
              </CardContent>
            </Card>

            <Card className="bg-gray-900 border-gray-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-gray-400">
                  {selected?.kind === 'edge' ? 'Relation' : 'Entite'}
                </CardTitle>
              </CardHeader>
              <CardContent className="text-xs space-y-3">
                {!selectedItem && <p className="text-gray-500">Cliquez une entite ou une relation pour voir ses preuves.</p>}
                {selectedItem && selected.kind === 'node' && (
                  <>
                    <div>
                      <p className={`text-sm font-semibold break-all ${selectedItem.malicious ? 'text-red-300' : 'text-gray-100'}`}>
                        {selectedItem.label}
                      </p>
                      <p className="font-mono text-gray-500 break-all">{selectedItem.id}</p>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <Badge className="bg-gray-800 text-gray-300 border-gray-700">{nodeStyle(selectedItem.type).label}</Badge>
                      {selectedItem.malicious && <Badge className="bg-red-500/10 text-red-400 border-red-500/30">Malveillant</Badge>}
                      {pz?.node === selectedItem.id && <Badge className="bg-orange-500/10 text-orange-300 border-orange-500/40">Patient zero</Badge>}
                      {blast.has(selectedItem.id) && <Badge className="bg-amber-500/10 text-amber-300 border-amber-500/30">Rayon d&apos;impact</Badge>}
                    </div>
                    <p className="text-gray-400">Vu de {formatTs(selectedItem.first_seen)} a {formatTs(selectedItem.last_seen)}</p>
                  </>
                )}
                {selectedItem && selected.kind === 'edge' && (
                  <>
                    <p className="text-sm text-gray-100 break-all">
                      {nodeById.get(selectedItem.source)?.label || selectedItem.source}
                      <span className="text-orange-400 font-mono"> —{selectedItem.type}→ </span>
                      {nodeById.get(selectedItem.target)?.label || selectedItem.target}
                    </p>
                    <p className="text-gray-400">Vu de {formatTs(selectedItem.first_seen)} a {formatTs(selectedItem.last_seen)}</p>
                    <div>
                      <p className="text-[11px] uppercase tracking-wider text-gray-500 mb-1">Preuves ({(selectedItem.refs || []).length})</p>
                      {(selectedItem.refs || []).length === 0 && <p className="text-gray-500">Aucune reference.</p>}
                      <div className="space-y-1">
                        {(selectedItem.refs || []).map((r, i) => (
                          <div key={i} className="p-2 rounded bg-gray-950 border border-gray-800 font-mono break-all">
                            <span className="text-amber-300">{r.artifact}</span>
                            <span className="text-gray-500"> · {r.kind} = </span>
                            <span className="text-gray-200">{r.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}
                {selectedItem && (
                  <>
                    {(selectedItem.technique_ids || []).length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedItem.technique_ids.map((t) => (
                          <Chip key={t} active={technique === t} onClick={() => setTechnique((cur) => (cur === t ? null : t))}>{t}</Chip>
                        ))}
                      </div>
                    )}
                    <p className="text-gray-400">
                      Constats : {(selectedItem.finding_ids || []).length
                        ? selectedItem.finding_ids.map((f) => `#${f}`).join(', ') : 'aucun'}
                    </p>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}
