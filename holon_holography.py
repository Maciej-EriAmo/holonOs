# -*- coding: utf-8 -*-
"""holon/holography.py — HRR, PrismRouter, fazowe przesunięcia"""

import os
import hashlib
import numpy as np
from dataclasses import dataclass


class HolographicInterference:
    _unitary_cache: dict = {}
    _ANCHOR_SEED: str = os.environ.get("HOLON_ANCHOR_SEED", "holon-eriamo-4242")

    @staticmethod
    def _to_unitary(v: np.ndarray) -> np.ndarray:
        key = np.round(v, 4).tobytes()
        if key in HolographicInterference._unitary_cache:
            return HolographicInterference._unitary_cache[key]
        v_fft  = np.fft.fft(v)
        result = v_fft / (np.abs(v_fft) + 1e-8)
        if len(HolographicInterference._unitary_cache) >= 512:
            HolographicInterference._unitary_cache.clear()
        HolographicInterference._unitary_cache[key] = result
        return result

    @staticmethod
    def _salt_key(key: np.ndarray, item_id: str) -> np.ndarray:
        combined = (item_id + HolographicInterference._ANCHOR_SEED).encode()
        h = int(hashlib.sha256(combined).hexdigest()[:16], 16) % (2**32)
        rng  = np.random.default_rng(h)
        salt = rng.standard_normal(len(key)).astype(np.float32) * 0.1
        salted = key + salt
        return salted / (np.linalg.norm(salted) + 1e-8)

    @staticmethod
    def bind(v1: np.ndarray, v2: np.ndarray, item_id: str = "") -> list:
        assert len(v1) == len(v2), f"bind: dim mismatch {len(v1)} != {len(v2)}"
        key  = HolographicInterference._salt_key(v2, item_id) if item_id else v2
        v2_u = HolographicInterference._to_unitary(key)
        bound = np.fft.ifft(np.fft.fft(v1) * v2_u).real.astype(np.float32)
        return bound.tolist()

    @staticmethod
    def unbind(bound_data: list, key: np.ndarray, item_id: str = "") -> np.ndarray:
        key   = HolographicInterference._salt_key(key, item_id) if item_id else key
        bound = np.array(bound_data, dtype=np.float32)
        min_len = min(len(bound), len(key))
        bound   = bound[:min_len]
        key_arr = key[:min_len]
        key_u   = HolographicInterference._to_unitary(key_arr)
        unbound = np.fft.ifft(np.fft.fft(bound) * np.conj(key_u)).real.astype(np.float32)
        return unbound / (np.linalg.norm(unbound) + 1e-8)

    @staticmethod
    def phase_shift(v: np.ndarray, shift: float) -> np.ndarray:
        if abs(shift) < 1e-6:
            return np.asarray(v, dtype=np.float32).copy()
        v_c    = np.asarray(v, dtype=np.complex128)
        fft_v  = np.fft.fft(v_c)
        dim    = len(v)
        freqs  = np.fft.fftfreq(dim)
        angles = 2.0 * np.pi * freqs * shift
        rotated = np.fft.ifft(fft_v * np.exp(1j * angles)).real.astype(np.float32)
        n = np.linalg.norm(rotated)
        return rotated / (n + 1e-8)


@dataclass
class PrismConfig:
    num_levels:           int        = 3
    A:                    np.ndarray = None
    n:                    np.ndarray = None
    gamma:                float      = 8.0
    alpha:                float      = 0.4
    theta_ref:            np.ndarray = None
    bias:                 float      = 0.03
    first_level_damping:  float      = 0.12

    def __post_init__(self):
        if self.A is None:
            self.A = np.deg2rad(np.array([60.0, 55.0, 50.0]))
        if self.n is None:
            self.n = np.array([1.52, 1.55, 1.58])
        if self.theta_ref is None:
            self.theta_ref = np.array([1.0, 2.2, 3.5])


class PrismRouter:
    def __init__(self, cfg: PrismConfig):
        self.cfg = cfg

    def deviation_angle(self, theta: np.ndarray) -> np.ndarray:
        phi1  = np.arcsin(np.clip(np.sin(theta) / self.cfg.n, -1.0, 1.0))
        phi2  = self.cfg.A - phi1
        delta = theta + np.arcsin(
            np.clip(self.cfg.n * np.sin(phi2), -1.0, 1.0)) - self.cfg.A
        return delta

    def _prism_shift(self, v: np.ndarray, delta: float) -> np.ndarray:
        fft_v   = np.fft.fft(v.astype(np.complex128))
        freqs   = np.fft.fftfreq(len(v))
        rotator = np.exp(1j * 2.0 * np.pi * freqs * delta)
        shifted = np.fft.ifft(fft_v * rotator).real.astype(np.float32)
        n = np.linalg.norm(shifted)
        return shifted / (n + 1e-8)

    def route(self, importance: float, pattern: np.ndarray):
        theta = (np.full(self.cfg.num_levels, 0.8)
                 + self.cfg.alpha * (importance - self.cfg.theta_ref))
        theta = np.clip(theta, 0.1, np.pi / 2 - 0.1)
        delta = self.deviation_angle(theta)
        target_delta = np.array([0.3, 0.9, 1.5])
        s = self.cfg.gamma * np.cos(delta - target_delta)
        p = np.exp(s - s.max())
        p = p / (p.sum() + 1e-8)
        p = p + self.cfg.bias
        p[0] *= self.cfg.first_level_damping
        p = p / (p.sum() + 1e-8)
        updates = [p[lv] * self._prism_shift(pattern, delta[lv])
                   for lv in range(self.cfg.num_levels)]
        return updates, p, delta
