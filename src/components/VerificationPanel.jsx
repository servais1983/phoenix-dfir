import { ShieldCheck, AlertTriangle, Cpu } from 'lucide-react'

const AGENT_LABELS = {
  orchestrator: 'Orchestrateur',
  triage: 'Triage et collecte',
  logs: 'Journaux (EVTX, Sigma)',
  memory: 'Memoire',
  disk: 'Disque et timeline',
  network: 'Reseau',
  cloud: 'Cloud et identite',
  ioc: 'Enrichissement IoC',
  attack: 'ATT&CK et correlation',
  verifier: 'Verificateur',
  writer: 'Redacteur',
}

function agentLabel(name) {
  return AGENT_LABELS[name] || name
}

function percent(value) {
  return typeof value === 'number' ? `${Math.round(value * 100)} %` : '-'
}

// Verification deterministe du rapport et cout par agent (console enqueteur DFIR)
export default function VerificationPanel({ metrics }) {
  if (!metrics) return null
  const citations = metrics.citations
  const usage = metrics.agents?.usage || {}
  const toolCalls = metrics.agents?.tool_calls || {}
  const unlinked = Array.isArray(citations?.unlinked) ? citations.unlinked : []
  const complete = citations && citations.linked === citations.factual_sentences
  if (!citations && !Object.keys(usage).length) return null

  return (
    <div className="mb-4 grid grid-cols-1 lg:grid-cols-2 gap-3" data-testid="verification-panel">
      {citations && (
        <div className="bg-gray-800 rounded-lg p-3">
          <p className="text-xs text-gray-400 flex items-center gap-1.5 mb-2">
            {complete
              ? <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
              : <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />}
            Phrases factuelles liees a un constat verifie
          </p>
          <p className={`text-lg font-semibold ${complete ? 'text-emerald-300' : 'text-amber-300'}`}
            data-testid="citation-coverage">
            {citations.linked}/{citations.factual_sentences} ({percent(citations.coverage)})
          </p>
          <p className="text-[10px] text-gray-500 mt-1">
            Constats verifies : {metrics.findings_verified ?? 0} · non verifies : {metrics.findings_unverified ?? 0}
          </p>
          {unlinked.length > 0 && (
            <ul className="mt-2 space-y-1.5" data-testid="unlinked-sentences">
              {unlinked.map((u, i) => (
                <li key={i} className="text-[11px] text-gray-300 border-l-2 border-amber-500/50 pl-2">
                  <span className="text-amber-300">{u.reason}</span>
                  <span className="block text-gray-400 break-words">{u.sentence}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {Object.keys(usage).length > 0 && (
        <div className="bg-gray-800 rounded-lg p-3">
          <p className="text-xs text-gray-400 flex items-center gap-1.5 mb-2">
            <Cpu className="h-3.5 w-3.5 text-orange-400" /> Agents : tokens et appels d&apos;outils
          </p>
          <table className="w-full text-[11px] text-gray-300" data-testid="agent-usage">
            <tbody>
              {Object.entries(usage).map(([name, row]) => (
                <tr key={name} className="border-b border-gray-700/50 last:border-0">
                  <td className="py-1">{agentLabel(name)}</td>
                  <td className="py-1 text-right">{row.total_tokens ?? 0} tokens</td>
                  <td className="py-1 text-right text-gray-500">{row.calls ?? 0} appel(s) LLM</td>
                </tr>
              ))}
            </tbody>
          </table>
          {Object.keys(toolCalls).length > 0 && (
            <p className="text-[10px] text-gray-500 mt-2" data-testid="agent-tool-calls">
              Outils par specialiste : {Object.entries(toolCalls)
                .map(([name, n]) => `${agentLabel(name)} ${n}`).join(' · ')}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
