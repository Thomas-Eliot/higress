#!/usr/bin/env python3
"""
Mock backend to simulate:
1. POST /chat/completions -> returns messageId
2. GET /messages/{messageId} -> waits for "kafka message", returns JSON (non-streaming)
"""

import json
import uuid
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# In-memory store simulating Kafka
message_store = {}
store_lock = threading.Lock()


def simulate_kafka_produce(message_id, prompt):
    """Simulate async Kafka produce: after a delay, store the response."""
    def produce():
        time.sleep(5)  # Simulate LLM processing + Kafka latency
        response = {
            "id": f"chatcmpl-{message_id[:8]}",
            "object": "chat.completion",
            "model": "mock-model",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"This is a mock response for: {prompt}"
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
        }
        with store_lock:
            message_store[message_id] = response
        print(f"[Kafka] Message {message_id} produced")

    t = threading.Thread(target=produce, daemon=True)
    t.start()


class MockHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path == "/chat/completions" or self.path == "/v1/chat/completions":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                data = json.loads(body)
                prompt = data.get("messages", [{}])[-1].get("content", "hello")
            except Exception:
                prompt = "hello"

            message_id = str(uuid.uuid4())
            simulate_kafka_produce(message_id, prompt)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = json.dumps({"messageId": message_id, "status": "processing"})
            self.wfile.write(resp.encode())
            print(f"[POST] Created message {message_id}")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        # Match /messages/{messageId}
        if self.path.startswith("/messages/"):
            message_id = self.path.split("/messages/")[1].strip("/")
            print(f"[GET] Waiting for message {message_id}")

            # Block and wait for Kafka message (up to 30s)
            waited = 0
            while waited < 30:
                with store_lock:
                    if message_id in message_store:
                        response = message_store.pop(message_id)
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(response).encode())
                        print(f"[GET] Returned message {message_id}")
                        return
                time.sleep(0.5)
                waited += 0.5

            # Timeout
            self.send_response(408)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "timeout waiting for message"}).encode())

        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[HTTP] {args[0]}")


if __name__ == "__main__":
    port = 8080
    server = HTTPServer(("0.0.0.0", port), MockHandler)
    print(f"Mock backend listening on :{port}")
    server.serve_forever()
