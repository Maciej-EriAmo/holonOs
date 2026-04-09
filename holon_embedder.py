# -*- coding: utf-8 -*-
"""holon/embedder.py — Embedder + kodowanie czasowe"""

import os
import math
import time
import numpy as np
from typing import Optional

# ── Epoch ──────────────────────────────────────────────────────────────────
_HOLON_EPOCH: float = float(os.environ.get("HOLON_EPOCH", str(time.time())))


def time_embed(timestamp: float, time_dim: int = 8) -> np.ndarray:
    if time_dim <= 0:
        return np.zeros(0, dtype=np.float32)
    delta_days = (timestamp - _HOLON_EPOCH) / 86400.0
    vec = np.zeros(time_dim, dtype=np.float32)
    n_sincos = (time_dim - 1) // 2
    scales   = [1.0 / 24.0, 1.0, 7.0, 30.0, 365.0][:n_sincos]
    for i, scale in enumerate(scales):
        angle = 2.0 * math.pi * delta_days / (scale + 1e-8)
        vec[i * 2]     = math.sin(angle)
        vec[i * 2 + 1] = math.cos(angle)
    vec[-1] = float(np.clip(delta_days / 365.0, -10.0, 10.0))
    return vec


# ── KuRz fallback ──────────────────────────────────────────────────────────
try:
    from kurz import KuRz as _KuRz
except ImportError:
    class _KuRz:
        def __init__(self, dim=256, dict_path=None):
            self.dim        = dim
            self.dict_path  = dict_path
            self.vocab_size = 10000
            self.calls      = 0

        def encode(self, text):
            self.calls += 1
            return np.random.randn(self.dim).astype(np.float32)

        def save_dict(self):
            pass


# ── Embedder ───────────────────────────────────────────────────────────────
class Embedder:
    """
    Warstwa embeddingów dla Holona.
    Backend: KuRz (offline, hash-based) lub dowolny model przez podklasę.
    """

    def __init__(self, dim: int = 256,
                 dict_path: Optional[str] = None,
                 cache_size: int = 256,
                 time_dim: int = 8):
        self.dim         = dim
        self.time_dim    = time_dim
        self._kurz       = _KuRz(dim=dim, dict_path=dict_path)
        self._cache: dict = {}
        self._cache_size  = cache_size
        self._cache_hits  = 0

    def encode(self, text: str, timestamp: float = None) -> np.ndarray:
        key = (text or "")[:200]
        if timestamp is None:
            if key in self._cache:
                self._cache_hits += 1
                return self._cache[key]
            vec = self._kurz.encode(text or "")
            self._cache[key] = vec
            if len(self._cache) > self._cache_size:
                del self._cache[next(iter(self._cache))]
            return vec
        content = self._kurz.encode(text or "")
        t_vec   = time_embed(timestamp, self.time_dim)
        full    = np.concatenate([content * 0.7, t_vec * 0.3])
        n       = np.linalg.norm(full)
        return full / (n + 1e-8)

    def encode_timed(self, text: str) -> np.ndarray:
        return self.encode(text, timestamp=time.time())

    def save(self) -> None:
        if self._kurz.dict_path:
            self._kurz.save_dict()

    @property
    def vocab_size(self) -> int:
        return self._kurz.vocab_size
