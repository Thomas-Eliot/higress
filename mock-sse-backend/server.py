#!/usr/bin/env python3
"""
Mock LLM backend (OpenAI-compatible).

POST /v1/chat/completions
  - X-Mock-Tokens: <N>  -> return exactly N completion tokens (default 50)
  - stream: true        -> SSE chunks; usage in final chunk
  Response content echoes/repeats words from the user prompt.

GET /health -> ok
"""

import json
import uuid
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

FILLER = ("the quick brown fox jumps over the lazy dog "
          "mock response token test language model ai chat ").split()


def fill_to_tokens(prompt: str, n: int) -> str:
    words = prompt.split() or FILLER
    result = []
    while len(result) < n:
        result.extend(words)
    return " ".join(result[:n])


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path not in ("/v1/chat/completions", "/chat/completions"):
            self.send_response(404)
            self.end_headers()
            return

        cl = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(cl) if cl > 0 else b"{}")

        mock_tokens = int(self.headers.get("X-Mock-Tokens", "50"))
        stream = body.get("stream", False)

        messages = body.get("messages", [])
        prompt = next(
            (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
            "mock response",
        )
        prompt_tokens = max(1, len(prompt.split()))
        content = fill_to_tokens(prompt, mock_tokens)
        model = body.get("model", "mock-llm")

        print(f"[mock] prompt_tokens={prompt_tokens} completion_tokens={mock_tokens} stream={stream}", flush=True)

        if stream:
            self._stream(content, mock_tokens, prompt_tokens, model)
        else:
            self._json(content, mock_tokens, prompt_tokens, model)

    def _json(self, content, completion_tokens, prompt_tokens, model):
        resp = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {"index": 0,
                 "message": {"role": "assistant", "content": content},
                 "finish_reason": "stop"}
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, content, completion_tokens, prompt_tokens, model):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        words = content.split()
        chunk_size = max(1, len(words) // 10)
        cid = uuid.uuid4().hex[:8]

        for i in range(0, len(words), chunk_size):
            piece = " ".join(words[i:i + chunk_size]) + " "
            chunk = {
                "id": f"chatcmpl-{cid}",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}],
            }
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()

        # stop chunk + usage (higress ai-statistics reads usage here)
        stop = {
            "id": f"chatcmpl-{cid}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
        self.wfile.write(f"data: {json.dumps(stop)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = 8080
    print(f"Mock LLM server on :{port}", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
