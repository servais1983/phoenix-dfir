#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du fournisseur IA GitHub Copilot (API GitHub Models), fournisseur
unique du CLI legacy.

Ces tests sont ignores si les dependances optionnelles du CLI (typer, pandas)
ne sont pas installees, comme le reste de la plateforme qui bascule alors en
mode standalone.
"""

import importlib
import os
import sys

import pytest

pytest.importorskip('typer')
pytest.importorskip('pandas')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'legacy'))


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _load_phoenix(monkeypatch, token='github_pat_test'):
    if token is None:
        monkeypatch.delenv('GITHUB_TOKEN', raising=False)
        monkeypatch.delenv('PHOENIX_GITHUB_TOKEN', raising=False)
    else:
        monkeypatch.setenv('GITHUB_TOKEN', token)
    import phoenix
    return importlib.reload(phoenix)


def test_github_copilot_actif_avec_jeton(monkeypatch):
    phoenix = _load_phoenix(monkeypatch)
    assert phoenix.github_copilot_disponible() is True


def test_github_copilot_inactif_sans_jeton(monkeypatch):
    phoenix = _load_phoenix(monkeypatch, token=None)
    assert phoenix.github_copilot_disponible() is False


def test_query_github_appelle_api_models(monkeypatch):
    phoenix = _load_phoenix(monkeypatch)
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured['url'] = url
        captured['headers'] = headers
        captured['json'] = json
        return FakeResponse({'choices': [{'message': {'content': 'Analyse DFIR terminee.'}}]})

    monkeypatch.setattr(phoenix.requests, 'post', fake_post)
    result = phoenix.query_github('Analyse ce log')

    assert result == 'Analyse DFIR terminee.'
    assert captured['url'] == 'https://models.github.ai/inference/chat/completions'
    assert captured['headers']['Authorization'] == 'Bearer github_pat_test'
    assert captured['json']['model'] == phoenix.MODEL_GITHUB
    assert captured['json']['messages'][-1] == {'role': 'user', 'content': 'Analyse ce log'}


def test_query_local_et_remote_sont_github_copilot(monkeypatch):
    """query_local/query_remote (retro-compat) pointent sur GitHub Copilot."""
    phoenix = _load_phoenix(monkeypatch)
    assert phoenix.query_local is phoenix.query_github
    assert phoenix.query_remote is phoenix.query_github


def test_modele_github_configurable(monkeypatch):
    monkeypatch.setenv('PHOENIX_GITHUB_MODEL', 'openai/gpt-4o')
    phoenix = _load_phoenix(monkeypatch)
    assert phoenix.MODEL_GITHUB == 'openai/gpt-4o'


def test_sans_jeton_message_erreur_explicite(monkeypatch):
    phoenix = _load_phoenix(monkeypatch, token=None)
    result = phoenix.query_github('prompt')
    assert result.startswith('Erreur:') and 'GITHUB_TOKEN' in result


def test_erreur_http_retourne_message_erreur(monkeypatch):
    phoenix = _load_phoenix(monkeypatch)
    monkeypatch.setattr(phoenix.requests, 'post', lambda *a, **k: FakeResponse({}, status=401))
    result = phoenix.query_github('prompt')
    assert result.startswith('Erreur:') and 'GitHub Copilot' in result
