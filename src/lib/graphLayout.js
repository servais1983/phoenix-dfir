// Graphe d'attaque : mise en page en couches deterministe et filtre temporel.
// Fonctions pures (aucune dependance), testees par vitest.

export const NODE_STYLES = {
  host: { color: '#38bdf8', shape: 'rect', label: 'Hote' },
  user: { color: '#a78bfa', shape: 'circle', label: 'Utilisateur' },
  account: { color: '#c084fc', shape: 'circle', label: 'Compte' },
  ip: { color: '#f59e0b', shape: 'diamond', label: 'Adresse IP' },
  domain: { color: '#fb923c', shape: 'hexagon', label: 'Domaine' },
  url: { color: '#fdba74', shape: 'hexagon', label: 'URL' },
  process: { color: '#34d399', shape: 'roundrect', label: 'Processus' },
  file: { color: '#94a3b8', shape: 'document', label: 'Fichier' },
  hash: { color: '#cbd5e1', shape: 'document', label: 'Empreinte' },
  registry: { color: '#2dd4bf', shape: 'roundrect', label: 'Registre' },
  service: { color: '#4ade80', shape: 'roundrect', label: 'Service' },
  task: { color: '#86efac', shape: 'roundrect', label: 'Tache planifiee' },
  other: { color: '#9ca3af', shape: 'circle', label: 'Autre' },
}

export function nodeStyle(type) {
  return NODE_STYLES[type] || NODE_STYLES.other
}

export function parseTs(value) {
  if (!value) return null
  const t = Date.parse(value)
  return Number.isNaN(t) ? null : t
}

const byTimeThenId = (a, b) => {
  const ta = parseTs(a.first_seen)
  const tb = parseTs(b.first_seen)
  if (ta !== tb) {
    if (ta === null) return 1
    if (tb === null) return -1
    return ta - tb
  }
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

/**
 * Mise en page en couches (gauche -> droite) :
 * - couche 0 : patient zero, puis les sources (sans arete entrante) par first_seen ;
 * - parcours en largeur sur les aretes sortantes (couche = profondeur) ;
 * - noeuds isoles / non atteints : nouvelles racines, par first_seen ;
 * - ordre vertical : barycentre des parents dans la couche precedente, puis first_seen/id.
 * Deterministe : memes donnees => memes positions, quel que soit l'ordre d'entree.
 */
export function layoutGraph(graph, options = {}) {
  const layerGap = options.layerGap ?? 180
  const rowGap = options.rowGap ?? 80
  const margin = options.margin ?? 60
  const nodes = [...(graph?.nodes || [])].sort(byTimeThenId)
  const ids = new Set(nodes.map((n) => n.id))
  const edges = (graph?.edges || []).filter((e) => ids.has(e.source) && ids.has(e.target))

  const out = new Map()
  const incoming = new Map()
  nodes.forEach((n) => { out.set(n.id, []); incoming.set(n.id, 0) })
  const sortedEdges = [...edges].sort(byTimeThenId)
  sortedEdges.forEach((e) => {
    if (e.source === e.target) return
    out.get(e.source).push(e.target)
    incoming.set(e.target, incoming.get(e.target) + 1)
  })

  const rank = new Map()
  const bfs = (start, base) => {
    if (rank.has(start)) return
    const queue = [start]
    rank.set(start, base)
    while (queue.length) {
      const id = queue.shift()
      for (const next of out.get(id)) {
        if (!rank.has(next)) {
          rank.set(next, rank.get(id) + 1)
          queue.push(next)
        }
      }
    }
  }

  const pz = graph?.patient_zero?.node
  if (pz && ids.has(pz)) bfs(pz, 0)
  nodes.filter((n) => incoming.get(n.id) === 0).forEach((n) => bfs(n.id, 0))
  nodes.forEach((n) => bfs(n.id, 0))

  const layers = []
  nodes.forEach((n) => {
    const r = rank.get(n.id)
    if (!layers[r]) layers[r] = []
    layers[r].push(n)
  })

  const parents = new Map()
  nodes.forEach((n) => parents.set(n.id, []))
  sortedEdges.forEach((e) => { if (e.source !== e.target) parents.get(e.target).push(e.source) })

  const positions = {}
  const rowIndex = new Map()
  const maxRows = Math.max(1, ...layers.filter(Boolean).map((l) => l.length))
  layers.forEach((layer, r) => {
    if (!layer) return
    const keyed = layer.map((n, i) => {
      const ps = parents.get(n.id).filter((p) => rank.get(p) === r - 1 && rowIndex.has(p))
      const bary = ps.length ? ps.reduce((s, p) => s + rowIndex.get(p), 0) / ps.length : Infinity
      return { n, bary, i }
    })
    keyed.sort((a, b) => (a.bary === b.bary ? a.i - b.i : a.bary - b.bary))
    const offset = ((maxRows - keyed.length) * rowGap) / 2
    keyed.forEach(({ n }, i) => {
      rowIndex.set(n.id, i)
      positions[n.id] = { x: margin + r * layerGap, y: margin + offset + i * rowGap }
    })
  })

  const width = margin * 2 + Math.max(0, layers.length - 1) * layerGap
  const height = margin * 2 + (maxRows - 1) * rowGap
  return { positions, width: Math.max(width, 200), height: Math.max(height, 160), layers: layers.length }
}

/** Bornes temporelles (ms) des first_seen des noeuds et aretes, ou null. */
export function timeBounds(graph) {
  const times = []
  ;(graph?.nodes || []).forEach((n) => { const t = parseTs(n.first_seen); if (t !== null) times.push(t) })
  ;(graph?.edges || []).forEach((e) => { const t = parseTs(e.first_seen); if (t !== null) times.push(t) })
  if (!times.length) return null
  return { min: Math.min(...times), max: Math.max(...times) }
}

/** Instants distincts (ms, tries) : pas du curseur de rejeu. */
export function timeSteps(graph) {
  const set = new Set()
  ;(graph?.edges || []).forEach((e) => { const t = parseTs(e.first_seen); if (t !== null) set.add(t) })
  ;(graph?.nodes || []).forEach((n) => { const t = parseTs(n.first_seen); if (t !== null) set.add(t) })
  return [...set].sort((a, b) => a - b)
}

/**
 * Filtre de rejeu : aretes dont first_seen <= cutoff (les aretes sans date
 * restent visibles si includeUndated) ; noeuds dont first_seen <= cutoff, sans
 * date, ou extremite d'une arete visible. cutoff null = tout le graphe.
 */
export function filterByTime(graph, cutoff, { includeUndated = true } = {}) {
  const nodes = graph?.nodes || []
  const edges = graph?.edges || []
  if (cutoff === null || cutoff === undefined) {
    return { nodes: new Set(nodes.map((n) => n.id)), edges: new Set(edges.map((e) => e.id)) }
  }
  const visibleEdges = new Set()
  const visibleNodes = new Set()
  // 1. Aretes datees deja survenues : leurs extremites sont donc connues
  edges.forEach((e) => {
    const t = parseTs(e.first_seen)
    if (t !== null && t <= cutoff) {
      visibleEdges.add(e.id)
      visibleNodes.add(e.source)
      visibleNodes.add(e.target)
    }
  })
  // 2. Noeuds selon leur propre date
  nodes.forEach((n) => {
    const t = parseTs(n.first_seen)
    if ((t === null && includeUndated) || (t !== null && t <= cutoff)) visibleNodes.add(n.id)
  })
  // 3. Aretes sans date : seulement entre deux noeuds deja visibles
  if (includeUndated) {
    edges.forEach((e) => {
      if (parseTs(e.first_seen) === null && visibleNodes.has(e.source) && visibleNodes.has(e.target)) {
        visibleEdges.add(e.id)
      }
    })
  }
  return { nodes: visibleNodes, edges: visibleEdges }
}

/** Techniques ATT&CK distinctes (triees) des noeuds et aretes. */
export function collectTechniques(graph) {
  const set = new Set()
  ;(graph?.nodes || []).forEach((n) => (n.technique_ids || []).forEach((t) => set.add(t)))
  ;(graph?.edges || []).forEach((e) => (e.technique_ids || []).forEach((t) => set.add(t)))
  return [...set].sort()
}

/** Aretes du chemin du patient zero (paires consecutives de path). */
export function pathEdgeIds(graph) {
  const path = graph?.patient_zero?.path || []
  const pairs = new Set()
  for (let i = 0; i + 1 < path.length; i++) pairs.add(`${path[i]}->${path[i + 1]}`)
  return new Set((graph?.edges || []).filter((e) => pairs.has(`${e.source}->${e.target}`)).map((e) => e.id))
}

/** Polygone SVG (points) d'une forme centree en (0,0) de rayon r. */
export function shapePoints(shape, r) {
  if (shape === 'diamond') return `0,${-r} ${r},0 0,${r} ${-r},0`
  if (shape === 'hexagon') {
    const pts = []
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i
      pts.push(`${(r * Math.cos(a)).toFixed(2)},${(r * Math.sin(a)).toFixed(2)}`)
    }
    return pts.join(' ')
  }
  return ''
}
