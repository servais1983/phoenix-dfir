"""A local HTTP server speaking the LM Studio / Jan API (OpenAI compatible).

It answers like a model would, from a fixed script, so the tests exercise the
real network path (HTTP, JSON, tool calls) of every LLM driven process. It
never produces forensic content: the investigation script only lists the
artifacts and saves a report built from tool output.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class LocalLLMServer:
    def __init__(self, models, script):
        self.models = list(models)
        self.script = script            # callable(payload) -> assistant message
        self.requests = []              # (path, payload or None)
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                server.requests.append((self.path, None))
                if self.path.rstrip('/') == '/v1/models':
                    self._send(200, {'object': 'list',
                                     'data': [{'id': m, 'object': 'model'} for m in server.models]})
                else:
                    self._send(404, {'error': 'not found'})

            def do_POST(self):
                length = int(self.headers.get('Content-Length') or 0)
                payload = json.loads(self.rfile.read(length) or b'{}')
                server.requests.append((self.path, payload))
                if self.path.rstrip('/') != '/v1/chat/completions':
                    self._send(404, {'error': 'not found'})
                    return
                message = server.script(payload)
                self._send(200, {'id': 'cmpl-local', 'object': 'chat.completion', 'model': payload.get('model'),
                                 'choices': [{'index': 0, 'message': message, 'finish_reason': 'stop'}],
                                 'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}})

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.httpd.server_address[1]}/v1'
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def chats(self):
        return [p for path, p in self.requests if p is not None and path.endswith('/chat/completions')]


def tool_call(call_id, name, args):
    return {'role': 'assistant', 'content': None, 'tool_calls': [
        {'id': call_id, 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}]}
