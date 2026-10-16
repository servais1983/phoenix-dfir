import { describe, it, expect } from 'vitest'
import {
  layoutGraph, filterByTime, timeBounds, timeSteps, collectTechniques, pathEdgeIds, nodeStyle, shapePoints,
} from './graphLayout'

const GRAPH = {
  version: 1,
  nodes: [
    { id: 'ip:203.0.113.9', type: 'ip', first_seen: '2026-03-01T08:30:00Z', technique_ids: [] },
    { id: 'user:jdoe', type: 'user', first_seen: '2026-03-01T08:00:00Z', technique_ids: ['T1078'] },
    { id: 'host:SRV-01', type: 'host', first_seen: '2026-03-01T08:05:00Z', technique_ids: ['T1059.001'] },
    { id: 'host:WS-02', type: 'host', first_seen: null, technique_ids: [] },
    { id: 'file:evil.exe', type: 'file', first_seen: '2026-03-01T08:10:00Z', technique_ids: [] },
  ],
  edges: [
    { id: 'e1', source: 'user:jdoe', target: 'host:SRV-01', first_seen: '2026-03-01T08:05:00Z' },
    { id: 'e2', source: 'host:SRV-01', target: 'file:evil.exe', first_seen: '2026-03-01T08:10:00Z',
      technique_ids: ['T1105'] },
    { id: 'e3', source: 'host:SRV-01', target: 'ip:203.0.113.9', first_seen: '2026-03-01T08:30:00Z' },
    { id: 'e4', source: 'file:evil.exe', target: 'host:WS-02', first_seen: null },
  ],
  patient_zero: { node: 'user:jdoe', timestamp: '2026-03-01T08:00:00Z', path: ['user:jdoe', 'host:SRV-01', 'file:evil.exe'] },
  blast_radius: { seed: 'host:SRV-01', nodes: ['host:SRV-01', 'file:evil.exe'] },
}

describe('layoutGraph', () => {
  it('places nodes in layers from patient zero', () => {
    const { positions, layers } = layoutGraph(GRAPH)
    expect(layers).toBe(4)
    expect(positions['user:jdoe'].x).toBeLessThan(positions['host:SRV-01'].x)
    expect(positions['host:SRV-01'].x).toBeLessThan(positions['file:evil.exe'].x)
    expect(positions['file:evil.exe'].x).toBe(positions['ip:203.0.113.9'].x)
    expect(positions['host:WS-02'].x).toBeGreaterThan(positions['file:evil.exe'].x)
  })

  it('is deterministic regardless of input order', () => {
    const a = layoutGraph(GRAPH)
    const b = layoutGraph({ ...GRAPH, nodes: [...GRAPH.nodes].reverse(), edges: [...GRAPH.edges].reverse() })
    expect(b.positions).toEqual(a.positions)
    expect(layoutGraph(GRAPH)).toEqual(a)
  })

  it('handles cycles, self loops, dangling edges and empty graphs', () => {
    const cyc = {
      nodes: [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
      edges: [{ id: '1', source: 'a', target: 'b' }, { id: '2', source: 'b', target: 'a' },
        { id: '3', source: 'c', target: 'c' }, { id: '4', source: 'a', target: 'zz' }],
    }
    const { positions } = layoutGraph(cyc)
    expect(Object.keys(positions).sort()).toEqual(['a', 'b', 'c'])
    Object.values(positions).forEach((p) => {
      expect(Number.isFinite(p.x)).toBe(true)
      expect(Number.isFinite(p.y)).toBe(true)
    })
    const empty = layoutGraph({ nodes: [], edges: [] })
    expect(empty.positions).toEqual({})
    expect(empty.width).toBeGreaterThan(0)
  })

  it('never overlaps two nodes', () => {
    const { positions } = layoutGraph(GRAPH)
    const keys = Object.values(positions).map((p) => `${p.x}:${p.y}`)
    expect(new Set(keys).size).toBe(keys.length)
  })
})

describe('time filter', () => {
  it('computes bounds and steps', () => {
    expect(timeBounds(GRAPH)).toEqual({ min: Date.parse('2026-03-01T08:00:00Z'), max: Date.parse('2026-03-01T08:30:00Z') })
    expect(timeSteps(GRAPH)).toHaveLength(4)
    expect(timeBounds({ nodes: [{ id: 'x' }], edges: [] })).toBeNull()
  })

  it('replays the attack chain', () => {
    const at = (iso, opts) => filterByTime(GRAPH, Date.parse(iso), opts)
    const t0 = at('2026-03-01T08:06:00Z')
    expect([...t0.edges]).toEqual(['e1'])
    expect(t0.nodes.has('user:jdoe')).toBe(true)
    expect(t0.nodes.has('host:SRV-01')).toBe(true)
    expect(t0.nodes.has('ip:203.0.113.9')).toBe(false)
    // e4 is undated but its source (evil.exe, 08:10) is not visible yet
    expect(t0.edges.has('e4')).toBe(false)

    const t1 = at('2026-03-01T08:10:00Z')
    expect(t1.edges.has('e2')).toBe(true)
    expect(t1.edges.has('e4')).toBe(true)
    expect(t1.edges.has('e3')).toBe(false)

    const strict = at('2026-03-01T08:10:00Z', { includeUndated: false })
    expect(strict.edges.has('e4')).toBe(false)
    expect(strict.nodes.has('host:WS-02')).toBe(false)

    const all = filterByTime(GRAPH, null)
    expect(all.edges.size).toBe(4)
    expect(all.nodes.size).toBe(5)
  })
})

describe('helpers', () => {
  it('collects techniques and patient zero path edges', () => {
    expect(collectTechniques(GRAPH)).toEqual(['T1059.001', 'T1078', 'T1105'])
    expect([...pathEdgeIds(GRAPH)].sort()).toEqual(['e1', 'e2'])
  })

  it('provides styles and shapes', () => {
    expect(nodeStyle('host').shape).toBe('rect')
    expect(nodeStyle('nope')).toEqual(nodeStyle('other'))
    expect(shapePoints('diamond', 10)).toBe('0,-10 10,0 0,10 -10,0')
    expect(shapePoints('hexagon', 10).split(' ')).toHaveLength(6)
  })
})
