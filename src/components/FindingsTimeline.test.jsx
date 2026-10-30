import { describe, it, expect } from 'vitest'
import { act } from 'react'
import { createRoot } from 'react-dom/client'

import FindingsTimeline from './FindingsTimeline'

globalThis.IS_REACT_ACT_ENVIRONMENT = true

const ITEMS = [
  { id: 1, title: 'Brute force SSH depuis 185.220.101.44', severity: 'high', mitre: 'T1110',
    timestamp: '2026-10-10T03:12:00Z', refs: [{ artifact: 'auth.log', kind: 'line', value: 1 }] },
  { id: 2, title: 'Connexion apres brute force', severity: 'high', mitre: 'T1078',
    timestamp: '2026-10-10T03:19:02Z', refs: [{ artifact: 'auth.log', kind: 'line', value: 37 }] },
  { id: 3, title: 'Beaconing vers 91.215.85.14:443', severity: 'high', mitre: 'T1071.001',
    timestamp: '2026-10-12T14:00:05Z', refs: [{ artifact: 'exports/firewall_export.csv', kind: 'row', value: 1 }] },
]

function render(items) {
  const el = document.createElement('div')
  document.body.appendChild(el)
  const root = createRoot(el)
  act(() => { root.render(<FindingsTimeline items={items} />) })
  return { el, root }
}

function choose(select, value) {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set
    setter.call(select, value)
    select.dispatchEvent(new Event('change', { bubbles: true }))
  })
}

describe('FindingsTimeline', () => {
  it('lists the verified findings with their references', () => {
    const { el, root } = render(ITEMS)
    const items = el.querySelectorAll('[data-testid="timeline-item"]')
    expect(items).toHaveLength(3)
    expect(items[0].textContent).toContain('[F1] Brute force SSH')
    expect(items[2].textContent).toContain('firewall_export.csv row=1')
    act(() => root.unmount())
  })

  it('filters by technique and by artifact', () => {
    const { el, root } = render(ITEMS)
    choose(el.querySelector('select[aria-label="Filtrer par technique"]'), 'T1078')
    expect(el.querySelectorAll('[data-testid="timeline-item"]')).toHaveLength(1)
    choose(el.querySelector('select[aria-label="Filtrer par technique"]'), '')
    choose(el.querySelector('select[aria-label="Filtrer par artefact"]'), 'firewall_export.csv')
    const items = el.querySelectorAll('[data-testid="timeline-item"]')
    expect(items).toHaveLength(1)
    expect(items[0].textContent).toContain('Beaconing')
    act(() => root.unmount())
  })

  it('renders nothing without verified findings', () => {
    const { el, root } = render([])
    expect(el.querySelector('[data-testid="findings-timeline"]')).toBeNull()
    act(() => root.unmount())
  })
})
