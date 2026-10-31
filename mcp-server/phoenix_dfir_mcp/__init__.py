"""Phoenix DFIR: MCP server, deterministic triage and autonomous DFIR investigator.

Exposes the Phoenix forensic toolkit (native EVTX, CSV, JSON, log, Prefetch,
LNK and browser parsers, IoC extraction, Sigma rules, MITRE ATT&CK mapping,
Eric Zimmermann tools, Volatility, Hayabusa, The Sleuth Kit):

- as a stdio MCP server for any MCP client;
- as an autonomous investigator driven by a local LLM (Ollama or llama.cpp
  by default, cloud providers only on explicit opt-in);
- as a deterministic triage engine that needs no LLM at all.
"""

__version__ = "4.17.0"
