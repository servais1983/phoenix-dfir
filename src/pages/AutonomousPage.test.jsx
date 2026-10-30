import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from 'react'
import { createRoot } from 'react-dom/client'

vi.mock('@/services/api', () => ({
  apiService: {
    getAutonomousStatus: vi.fn(),
    listAutonomousJobs: vi.fn(),
    getPlaybookTemplates: vi.fn(),
    getRemediations: vi.fn(),
  },
}))
vi.mock('@/services/websocket', () => ({
  default: {
    on: () => () => {},
    onAutonomousProgress: () => () => {},
    onHitlRequired: () => () => {},
    onHitlResolved: () => () => {},
  },
}))
vi.mock('@/context/AppContext', () => ({
  useApp: () => ({ investigations: [], currentInvestigation: null, refreshInvestigations: () => {} }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

import { apiService } from '@/services/api'
import AutonomousPage from './AutonomousPage'

globalThis.IS_REACT_ACT_ENVIRONMENT = true

async function render() {
  const el = document.createElement('div')
  document.body.appendChild(el)
  const root = createRoot(el)
  await act(async () => { root.render(<AutonomousPage />) })
  await act(async () => { await Promise.resolve() })
  return { el, root }
}

describe('AutonomousPage LLM status', () => {
  beforeEach(() => {
    apiService.listAutonomousJobs.mockResolvedValue({ jobs: [] })
    apiService.getPlaybookTemplates.mockResolvedValue({ templates: [] })
    apiService.getRemediations.mockResolvedValue({ remediations: [] })
  })

  it('shows the local provider and the model chosen for each role', async () => {
    apiService.getAutonomousStatus.mockResolvedValue({
      copilot_configured: true,
      llm_provider: 'lmstudio',
      llm_label: 'LM Studio (local LLM)',
      model: 'openai/gpt-oss-20b',
      llm_roles: { investigator: 'openai/gpt-oss-20b', extractor: 'qwen/qwen3-14b' },
    })
    const { el, root } = await render()
    expect(el.textContent).toContain('LM Studio (local LLM) pret (openai/gpt-oss-20b)')
    const roles = el.querySelector('[data-testid="llm-roles"]')
    expect(roles.textContent).toContain('Enqueteur : openai/gpt-oss-20b')
    expect(roles.textContent).toContain('Extracteur : qwen/qwen3-14b')
    expect(el.textContent).not.toContain('GITHUB_TOKEN')
    act(() => root.unmount())
  })

  it('explains how to start a local LLM when none is configured', async () => {
    apiService.getAutonomousStatus.mockResolvedValue({ copilot_configured: false, llm_label: 'Ollama (local LLM)' })
    const { el, root } = await render()
    expect(el.textContent).toContain('LLM non configure')
    expect(el.textContent).toContain('LM Studio ou Jan')
    expect(el.querySelector('[data-testid="llm-roles"]')).toBeNull()
    act(() => root.unmount())
  })
})
