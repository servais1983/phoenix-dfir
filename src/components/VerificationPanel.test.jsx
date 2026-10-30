import { describe, it, expect } from 'vitest'
import { act } from 'react'
import { createRoot } from 'react-dom/client'

import VerificationPanel from './VerificationPanel'

globalThis.IS_REACT_ACT_ENVIRONMENT = true

function render(metrics) {
  const el = document.createElement('div')
  document.body.appendChild(el)
  const root = createRoot(el)
  act(() => { root.render(<VerificationPanel metrics={metrics} />) })
  return { el, root }
}

describe('VerificationPanel', () => {
  it('shows the citation coverage, the unlinked sentences and the cost per agent', () => {
    const { el, root } = render({
      findings_verified: 2,
      findings_unverified: 1,
      citations: {
        factual_sentences: 3, linked: 2, coverage: 0.6667,
        unlinked: [{ sentence: 'Exfiltration to 8.8.4.4 [F1].', cited: [1],
          reason: "entities not in the cited findings' events: 8.8.4.4" }],
      },
      agents: {
        usage: { attack: { calls: 4, total_tokens: 1200 }, writer: { calls: 1, total_tokens: 300 } },
        tool_calls: { logs: 3, network: 2 },
      },
    })
    expect(el.querySelector('[data-testid="citation-coverage"]').textContent).toBe('2/3 (67 %)')
    expect(el.querySelector('[data-testid="unlinked-sentences"]').textContent).toContain('8.8.4.4')
    const usage = el.querySelector('[data-testid="agent-usage"]').textContent
    expect(usage).toContain('ATT&CK et correlation')
    expect(usage).toContain('1200 tokens')
    expect(el.querySelector('[data-testid="agent-tool-calls"]').textContent).toContain('Reseau 2')
    act(() => root.unmount())
  })

  it('renders nothing without verification or agent data', () => {
    const { el, root } = render({ findings: 1 })
    expect(el.querySelector('[data-testid="verification-panel"]')).toBeNull()
    act(() => root.unmount())
  })

  it('marks a fully linked report', () => {
    const { el, root } = render({ citations: { factual_sentences: 4, linked: 4, coverage: 1 } })
    expect(el.querySelector('[data-testid="citation-coverage"]').textContent).toBe('4/4 (100 %)')
    expect(el.querySelector('[data-testid="unlinked-sentences"]')).toBeNull()
    act(() => root.unmount())
  })
})
