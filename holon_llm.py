# -*- coding: utf-8 -*-
"""
holon_llm.py — Klient LLM, trzy backendy w kolejności:

  1. Ollama lokalnie (pkg install ollama w Termux)
  2. Groq API (GROQ_API_KEY=gsk_...)
  3. DeepSeek API (DEEPSEEK_API_KEY=...)

Zmiana backendu = tylko zmienna środowiskowa.
"""

import os
import requests
from typing import List, Dict, Optional


class OpenAIClient:
    """
    Działa z każdym OpenAI-compatible endpointem:
      - Ollama:   base_url=http://localhost:11434/v1, api_key="ollama"
      - Groq:     base_url=https://api.groq.com/openai/v1
      - DeepSeek: base_url=https://api.deepseek.com/v1
    """

    def __init__(self, api_key: str,
                 base_url: str = "http://localhost:11434/v1",
                 model: str    = "qwen2.5:3b"):
        self.api_key  = api_key
        self.base_url = base_url.rstrip('/')
        self.model    = model

    def chat_completion(self, messages: List[Dict[str, str]],
                        temperature: float = 0.7,
                        max_tokens: int    = 1024) -> str:
        filtered = [m for m in messages if m.get("content", "").strip()]
        if not filtered:
            return "[Błąd: brak wiadomości do wysłania]"
        url     = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        payload = {"model": self.model, "messages": filtered,
                   "temperature": temperature, "max_tokens": max_tokens}
        try:
            resp = requests.post(url, headers=headers,
                                 json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except requests.exceptions.HTTPError as e:
            print(f"[LLM] HTTP {e.response.status_code}")
            try:    print(f"[LLM] {e.response.json()}")
            except: print(f"[LLM] {e.response.text}")
            return f"[Błąd LLM: {e}]"
        except Exception as e:
            print(f"[LLM] Błąd: {e}")
            return f"[Błąd LLM: {e}]"


def _ollama_running() -> bool:
    try:
        r = requests.get("http://localhost:11434", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def build_llm_client(api_key: Optional[str] = None,
                     model: Optional[str]   = None) -> Optional[OpenAIClient]:
    """
    Auto-detect backendu:
      1. Ollama lokalnie (sprawdza localhost:11434)
      2. GROQ_API_KEY
      3. DEEPSEEK_API_KEY
      4. None → mock
    """
    # 1. Ollama
    if _ollama_running():
        m = model or os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
        print(f"[LLM] Backend: Ollama lokalnie → {m}")
        return OpenAIClient(api_key="ollama",
                            base_url="http://localhost:11434/v1",
                            model=m)

    # 2. Groq
    groq_key = api_key or os.environ.get("GROQ_API_KEY", "")
    if groq_key.startswith("gsk_"):
        m = model or "llama-3.3-70b-versatile"
        print(f"[LLM] Backend: Groq → {m}")
        return OpenAIClient(api_key=groq_key,
                            base_url="https://api.groq.com/openai/v1",
                            model=m)

    # 3. DeepSeek
    ds_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if ds_key:
        m = model or "deepseek-chat"
        print(f"[LLM] Backend: DeepSeek → {m}")
        return OpenAIClient(api_key=ds_key,
                            base_url="https://api.deepseek.com/v1",
                            model=m)

    # 4. Mock
    print("[LLM] Brak backendu. Uruchom: ollama serve  "
          "lub ustaw GROQ_API_KEY.")
    return None
