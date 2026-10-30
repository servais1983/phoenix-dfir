"""Live check against the real local LLM server (LM Studio, Jan, Ollama, llama.cpp).

Skipped unless PHOENIX_LLM_LIVE=1. Run it on the analyst workstation, with the
local server started and PHOENIX_LLM_PROVIDER set:

    PHOENIX_LLM_LIVE=1 PHOENIX_LLM_PROVIDER=lmstudio python -m pytest tests/test_local_llm_live.py -v
"""

import os
from pathlib import Path

import pytest

from phoenix_dfir_mcp import copilot, models, triage

pytestmark = pytest.mark.skipif(os.environ.get('PHOENIX_LLM_LIVE') != '1',
                                reason='set PHOENIX_LLM_LIVE=1 with a local LLM server running')
SUITE = Path(__file__).resolve().parents[2] / 'eval' / 'suite'


def test_server_answers_and_lists_models():
    provider = copilot.provider_name()
    assert provider in copilot.LOCAL_PROVIDERS, 'the live check only targets local servers'
    assert copilot.llm_reachable(provider), f'{copilot.provider_label(provider)} is not reachable'
    assert models.list_models(provider, refresh=True), 'the server lists no model: load one first'


@pytest.mark.parametrize('role', ['investigator', 'extractor'])
def test_chosen_model_calls_tools(role):
    provider = copilot.provider_name()
    model = models.select(provider, role)
    result = models.probe_tool_calling(provider, model)
    assert result['ok'], f'{model} ({role}): {result["detail"]}'


def test_reviewer_answers_in_text():
    provider = copilot.provider_name()
    client = copilot.CopilotClient(provider=provider, role='reviewer')
    msg = client.chat([{'role': 'user', 'content': 'Reply with the single word APPROVED.'}])
    assert 'APPROVED' in (msg.get('content') or '').upper()
    assert client.usage['calls'] == 1


def test_triage_stays_deterministic_with_the_llm_running():
    first = triage.to_json(triage.run_triage(SUITE / 'net_c2_beacon_pcap'))
    assert first == triage.to_json(triage.run_triage(SUITE / 'net_c2_beacon_pcap'))
