"""Specialized agents: model role, tool allowlist, budget and contract.

An agent is a mandate, not a process: the phase engine runs one LLM session
per phase, led by the phase's lead agent, with the tools of the phase's team.
A tool outside the team's allowlists is never offered and is refused if the
LLM calls it anyway. Each call is attributed to the specialist that owns the
tool, and the tokens of each session are logged under its lead agent.

Budgets: ``max_turns`` per session comes from the phase; ``max_tokens``
(``PHOENIX_AGENT_MAX_TOKENS``, default 300000) stops a session that would
exceed it. The global turn budget of the investigation still applies.
"""

import os
from dataclasses import dataclass
from typing import Optional

DEFAULT_MAX_TOKENS = 300000


def default_max_tokens():
    try:
        return max(1000, int(os.environ.get('PHOENIX_AGENT_MAX_TOKENS', DEFAULT_MAX_TOKENS)))
    except ValueError:
        return DEFAULT_MAX_TOKENS


@dataclass(frozen=True)
class Agent:
    name: str
    title: str
    role: str  # model role (models.ROLES)
    mission: str
    tools: tuple = ()
    prefixes: tuple = ()  # tool families, e.g. 'net_' for every network tool
    contract: str = ''  # contracts.CONTRACTS key of the structured output it writes
    token_limit: Optional[int] = None  # None: PHOENIX_AGENT_MAX_TOKENS

    @property
    def max_tokens(self):
        return self.token_limit or default_max_tokens()

    def allows(self, tool):
        return tool in self.tools or any(tool.startswith(p) for p in self.prefixes)

    def allowlist(self, available):
        """Tools of ``available`` this agent may call (stable order)."""
        return tuple(t for t in available if self.allows(t))


_STATUS = ('zimmermann_status', 'hayabusa_status', 'volatility_status', 'disk_status')
_QUERY = ('search_evidence', 'get_timeline', 'get_case_state')

AGENTS = {a.name: a for a in (
    Agent('orchestrator', 'Orchestrator', 'investigator',
          'Plans the investigation, tracks the plan and the tool coverage.',
          ('list_artifacts', 'set_investigation_plan', 'get_case_state', 'complete_plan_step', 'list_sources',
           'audit_tool_coverage', 'phase_gate') + _STATUS),
    Agent('triage', 'Triage and collection', 'investigator',
          'Inventories the artifacts and identifies their formats.',
          ('list_artifacts', 'analyze_artifact', 'extract_iocs', 'disk_status', 'disk_image_info',
           'macos_detect_artifact', 'cloud_detect_format')),
    Agent('logs', 'Logs (EVTX and Sigma)', 'investigator',
          'Parses event logs and text logs, runs the Sigma and Hayabusa detections.',
          ('parse_evtx', 'parse_log_file', 'parse_csv', 'parse_json_file', 'sigma_scan', 'run_hayabusa',
           'hayabusa_status', 'run_zimmermann', 'zimmermann_status') + _QUERY,
          ('linux_', 'analytics_')),
    Agent('memory', 'Memory', 'investigator',
          'Analyzes memory dumps with Volatility 3.',
          ('run_volatility', 'volatility_status') + _QUERY),
    Agent('disk', 'Disk and timeline', 'investigator',
          'Reads disk images and file system artifacts, builds the file system timeline.',
          ('disk_status', 'disk_image_info', 'disk_list_files', 'disk_timeline', 'disk_extract_artifacts',
           'parse_prefetch', 'parse_lnk', 'parse_browser_history', 'run_zimmermann') + _QUERY,
          ('macos_',)),
    Agent('network', 'Network', 'investigator',
          'Reads packet captures: flows, DNS, HTTP, TLS and network detections.',
          _QUERY, ('net_',)),
    Agent('cloud', 'Cloud and identity', 'investigator',
          'Reads cloud and identity provider logs.',
          _QUERY, ('cloud_',)),
    Agent('ioc', 'IoC enrichment', 'investigator',
          'Extracts and enriches indicators (opt-in online lookups send IoCs only).',
          ('extract_iocs', 'virustotal_lookup', 'casemem_similar_cases') + _QUERY, ('deobfuscate_',)),
    Agent('attack', 'ATT&CK and correlation', 'investigator',
          'Records findings with their references and ATT&CK techniques, weighs competing hypotheses.',
          ('record_finding', 'mitre_map_events', 'add_hypothesis', 'set_hypothesis', 'weigh_evidence',
           'rank_hypotheses', 'declare_no_incident', 'propose_remediation') + _QUERY,
          ('graph_',), contract='finding'),
    Agent('verifier', 'Verifier', 'investigator',
          'Challenges every retained finding, audits coverage, writes detection rules.',
          ('challenge_finding', 'audit_tool_coverage', 'audit_evidence_coverage', 'verify_finding',
           'record_finding', 'add_hypothesis', 'set_hypothesis', 'weigh_evidence', 'rank_hypotheses',
           'declare_no_incident') + _QUERY,
          ('detect_', 'graph_'), contract='verdict'),
    Agent('writer', 'Writer', 'investigator',
          'Writes the report: only verified findings, each factual sentence cites [F<id>].',
          ('save_report', 'list_sources', 'casemem_index_case', 'rank_hypotheses') + _QUERY,
          ('detect_', 'graph_')),
)}

SPECIALISTS = ('logs', 'memory', 'disk', 'network', 'cloud', 'ioc', 'triage')

# Lead agent first, then the specialists whose tools the phase offers
PHASE_TEAMS = {
    'inventaire': ('triage', 'orchestrator', 'disk'),
    'extraction': ('triage', 'orchestrator', 'logs', 'memory', 'disk', 'network', 'cloud', 'ioc'),
    'correlation': ('attack', 'orchestrator', 'triage', 'logs', 'memory', 'disk', 'network', 'cloud', 'ioc'),
    'contre_analyse': ('verifier', 'orchestrator', 'triage', 'logs', 'memory', 'disk', 'network', 'cloud',
                       'ioc'),
    'rapport': ('writer', 'orchestrator'),
}


def team(phase_key):
    return tuple(AGENTS[n] for n in PHASE_TEAMS[phase_key])


def lead(phase_key):
    return team(phase_key)[0]


def team_allowlist(phase_key, available):
    """Tools of ``available`` that at least one agent of the phase's team may call."""
    members = team(phase_key)
    return tuple(t for t in available if any(a.allows(t) for a in members))


def owner(phase_key, tool):
    """Name of the agent of the team that operates a tool (lead agent first, then specialists)."""
    members = team(phase_key)
    ordered = members[:1] + tuple(sorted(members[1:], key=lambda a: a.name == 'orchestrator'))
    return next((a.name for a in ordered if a.allows(tool)), None)


class Budget:
    """Token budget of one agent session."""

    def __init__(self, agent, usage):
        self.agent = agent
        self.start = int((usage or {}).get('total_tokens') or 0)
        self.used = 0

    def charge(self, usage):
        self.used = max(0, int((usage or {}).get('total_tokens') or 0) - self.start)
        return self.used

    @property
    def exhausted(self):
        return self.used >= self.agent.max_tokens


def describe():
    """Agents with their role, contract and tool families (CLI, docs)."""
    return [{'name': a.name, 'title': a.title, 'role': a.role, 'mission': a.mission, 'contract': a.contract,
             'tools': list(a.tools), 'tool_families': [p + '*' for p in a.prefixes], 'max_tokens': a.max_tokens,
             'phases': [k for k, names in PHASE_TEAMS.items() if a.name in names]}
            for a in AGENTS.values()]
