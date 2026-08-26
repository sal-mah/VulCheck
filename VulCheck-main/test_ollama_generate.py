import json
import requests

MODEL = "qwen3.5:4b"
URL = "http://127.0.0.1:11434/api/generate"

payload = {
    "model": MODEL,
    "prompt": "Reply with exactly: VulCheck Ollama integration works.",
    "stream": False,
    "think": False,
}

r = requests.post(URL, json=payload, timeout=120)
print("HTTP:", r.status_code)
data = r.json()
print("Response keys:", list(data.keys()))
print("Generated text:")
print(data.get("response") or data.get("message", {}).get("content") or data.get("thinking") or "(empty)")
