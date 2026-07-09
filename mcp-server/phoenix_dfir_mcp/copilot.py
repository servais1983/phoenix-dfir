"""Client GitHub Copilot : chat completions avec function calling.

Utilise l'API GitHub Models (https://docs.github.com/en/github-models),
la meme integration que le reste de Phoenix : un jeton GitHub avec la
permission "Models: read" suffit (GITHUB_TOKEN ou PHOENIX_GITHUB_TOKEN).
"""

import os

import requests

DEFAULT_MODEL = 'openai/gpt-4o-mini'
DEFAULT_URL = 'https://models.github.ai/inference/chat/completions'


class CopilotError(RuntimeError):
    """Erreur d'appel a GitHub Copilot (configuration ou reseau)."""


class CopilotClient:
    """Client minimal de l'API GitHub Models (format OpenAI chat completions)."""

    def __init__(self, model=None, token=None, url=None, timeout=180):
        self.token = token or os.environ.get('PHOENIX_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN', '')
        self.model = model or os.environ.get('PHOENIX_GITHUB_MODEL', DEFAULT_MODEL)
        self.url = url or os.environ.get('PHOENIX_GITHUB_MODELS_URL', DEFAULT_URL)
        self.timeout = timeout

    def chat(self, messages, tools=None):
        """Envoyer une conversation, retourner le message assistant (dict).

        Le message retourne peut contenir 'content' et/ou 'tool_calls'
        (format OpenAI function calling).
        """
        if not self.token:
            raise CopilotError(
                "GitHub Copilot non configure : definissez un jeton GitHub via GITHUB_TOKEN "
                "ou PHOENIX_GITHUB_TOKEN (fine-grained PAT avec la permission Models: read)."
            )
        payload = {'model': self.model, 'messages': messages}
        if tools:
            payload['tools'] = tools
        try:
            resp = requests.post(
                self.url,
                headers={
                    'Authorization': f'Bearer {self.token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()['choices'][0]['message']
        except requests.RequestException as e:
            raise CopilotError(f'Appel GitHub Copilot echoue: {e}') from e
        except (KeyError, IndexError, ValueError) as e:
            raise CopilotError(f'Reponse GitHub Copilot inattendue: {e}') from e
