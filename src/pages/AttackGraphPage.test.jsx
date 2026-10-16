import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { createRoot } from 'react-dom/client'

const GRAPH = {
  version: 1,
  generated_at: '2026-03-01T10:00:00Z',
  nodes: [
    { id: 'user:jdoe', type: 'user', label: 'jdoe', first_seen: '2026-03-01T08:00:00Z', malicious: false, technique_ids: [], finding_ids: [] },
    { id: 'host:SRV-01', type: 'host', label: 'SRV-01', first_seen: '2026-03-01T08:05:00Z', malicious: true, technique_ids: ['T1059.001'], finding_ids: [1] },
  ],
  edges: [
    { id: 'e1', source: 'user:jdoe', target: 'host:SRV-01', type: 'authenticated_to', first_seen: '2026-03-01T08:05:00Z',
      refs: [{ artifact: 'Security.evtx', kind: 'record_id', value: '4624' }], technique_ids: [], finding_ids: [] },
  ],
  patient_zero: { node: 'user:jdoe', timestamp: '2026-03-01T08:00:00Z', path: ['user:jdoe', 'host:SRV-01'] },
  blast_radius: { seed: 'host:SRV-01', nodes: ['host:SRV-01'] },
  truncated: { nodes: false, edges: false },
}

const listeners = {}
vi.mock('@/services/api', () => ({
  apiService: { getInvestigationGraph: vi.fn() },
}))
vi.mock('@/services/websocket', () => ({
  default: {
    onGraphUpdated: (cb) => { listeners.graph = cb; return () => {} },
    onAutonomousProgress: (cb) => { listeners.progress = cb; return () => {} },
  },
}))
vi.mock('@/context/AppContext', () => ({
  useApp: () => ({ investigations: [{ id: 'inv-1', name: 'Case 1' }], currentInvestigation: null }),
}))

import { apiService } from '@/services/api'
import AttackGraphPage from './AttackGraphPage'

globalThis.IS_REACT_ACT_ENVIRONMENT = true

async function render() {
  const el = document.createElement('div')
  document.body.appendChild(el)
  const root = createRoot(el)
  await act(async () => { root.render(<AttackGraphPage />) })
  await act(async () => { await Promise.resolve() })
  return { el, root }
}

describe('AttackGraphPage', () => {
  beforeEach(() => { apiService.getInvestigationGraph.mockReset() })

  it('renders nodes, patient zero badge and refs on edge click', async () => {
    apiService.getInvestigationGraph.mockResolvedValue(GRAPH)
    const { el, root } = await render()
    expect(apiService.getInvestigationGraph).toHaveBeenCalledWith('inv-1')
    expect(el.textContent).toContain('Patient zero')
    expect(el.textContent).toContain('T1059.001')
    expect(el.querySelectorAll('svg[role="img"] [data-graph-item]').length).toBe(3)
    const edge = el.querySelector('svg[role="img"] g[data-graph-item] line')
    await act(async () => { edge.parentElement.dispatchEvent(new MouseEvent('click', { bubbles: true })) })
    expect(el.textContent).toContain('Security.evtx')

    // Live update refreshes the graph
    await act(async () => { listeners.graph({ investigation_id: 'inv-1' }) })
    expect(apiService.getInvestigationGraph).toHaveBeenCalledTimes(2)
    act(() => root.unmount())
  })

  it('shows the not-built message', async () => {
    apiService.getInvestigationGraph.mockRejectedValue({ response: { status: 404, data: { error: 'pas encore construit' } } })
    const { el, root } = await render()
    expect(el.textContent).toContain('pas encore construit')
    act(() => root.unmount())
  })
})
