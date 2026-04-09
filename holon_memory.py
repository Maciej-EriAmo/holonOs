# -*- coding: utf-8 -*-
"""holon/memory.py — Persystencja pamięci JSON z holograficznym szyfrowaniem"""

import os
import json
import time
import hashlib
import numpy as np
from pathlib import Path

from holon_config import Config
from holon_item import Item
from holon_holography import HolographicInterference
from holon_aii import TimeDecay
from holon_embedder import time_embed


class PersistentMemory:
    def __init__(self, path: str = "holon_memory.json", dim: int = 264):
        self.path    = Path(path)
        seed_str     = os.environ.get("HOLON_ANCHOR_SEED", "4242")
        seed_int     = int(hashlib.sha256(seed_str.encode()).hexdigest()[:8], 16) % (2**31)
        rng          = np.random.RandomState(seed_int)
        anchor       = rng.randn(dim).astype(np.float32)
        self.eriamo_anchor = anchor / (np.linalg.norm(anchor) + 1e-8)
        self.dim     = dim

    # ── Init ──────────────────────────────────────────────────────────────

    @staticmethod
    def _init_phi(cfg: Config) -> np.ndarray:
        total = cfg.total_dim
        phi   = np.random.randn(cfg.phi_levels, cfg.k, total).astype(np.float32) * 0.01
        norms = np.linalg.norm(phi, axis=2, keepdims=True)
        return phi / (norms + 1e-8)

    @staticmethod
    def _phi_center_static(phi: np.ndarray, level: int = 2) -> np.ndarray:
        layer  = phi[level] if phi.ndim == 3 else phi
        norms  = np.linalg.norm(layer, axis=1)
        exp_n  = np.exp(norms - norms.max())
        weights = exp_n / (exp_n.sum() + 1e-8)
        center  = sum(weights[k] * layer[k] for k in range(len(layer)))
        n = np.linalg.norm(center)
        return center / (n + 1e-8)

    def _safe_bind(self, emb: np.ndarray, state: np.ndarray) -> list:
        m = min(len(emb), len(state))
        return HolographicInterference.bind(emb[:m], state[:m])

    # ── Save ──────────────────────────────────────────────────────────────

    def save(self, phi: np.ndarray, store: list, turns: int, cfg: Config,
             aii: dict = None, stability=None,
             W_time: np.ndarray = None, W_gen: np.ndarray = None):
        state_now   = PersistentMemory._phi_center_static(phi, level=2)
        anchor_trim = self.eriamo_anchor[:len(state_now)]
        h_coherence = HolographicInterference.bind(state_now, anchor_trim)

        data = {
            "timestamp":     time.time(),
            "turns":         turns,
            "phi":           phi.tolist(),
            "phi_stability": stability if stability is not None else [],
            "phase_shifts":  cfg.phase_shifts,
            "h_coherence":   h_coherence,
            "aii":           aii or {},
            "W_time":        W_time.tolist() if W_time is not None else None,
            "W_gen":         W_gen.tolist()  if W_gen  is not None else None,
            "store": [
                {
                    "id":            i.id,
                    "content":       i.content,
                    "embedding":     self._safe_bind(i.emb_np(), state_now),
                    "age":           i.age,
                    "relevance":     i.relevance,
                    "created_at":    i.created_at,
                    "is_insight":    i.is_insight,
                    "insight_level": i.insight_level,
                    "cluster_size":  i.cluster_size,
                    "is_reminder":   i.is_reminder,
                    "is_fact":       i.is_fact,
                    "is_work":       i.is_work,
                }
                for i in store if i.age >= 1
            ],
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(self.path)
        except Exception:
            try:
                self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
            finally:
                if tmp.exists():
                    tmp.unlink()

    # ── Load ──────────────────────────────────────────────────────────────

    def load(self, cfg: Config) -> dict:
        _empty = lambda: {
            "phi": self._init_phi(cfg), "store": [], "turns": 0,
            "delta_hours": 0.0, "aii": {}, "phi_stability": None,
            "loaded": False, "coherence": 1.0, "wake": "",
            "W_time": None, "W_gen": None,
        }
        tmp = self.path.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()
        if not self.path.exists():
            return _empty()

        try:
            data        = json.loads(self.path.read_text())
            saved_at    = data["timestamp"]
            delta_hours = (time.time() - saved_at) / 3600.0
            turns       = data["turns"]
            total_dim   = cfg.total_dim

            if "phase_shifts" in data:
                cfg.phase_shifts = data["phase_shifts"]

            phi_raw = np.array(data["phi"], dtype=np.float32)
            if phi_raw.ndim == 2:
                phi_raw = np.stack([phi_raw.copy() * (1.0 - 0.05 * l)
                                    for l in range(cfg.phi_levels)])
            if phi_raw.shape[2] < total_dim:
                pad = np.zeros((*phi_raw.shape[:2],
                                total_dim - phi_raw.shape[2]), dtype=np.float32)
                phi_raw = np.concatenate([phi_raw, pad], axis=2)
                norms   = np.linalg.norm(phi_raw, axis=2, keepdims=True)
                phi_raw = phi_raw / (norms + 1e-8)

            state_at_save = PersistentMemory._phi_center_static(phi_raw, level=2)
            h_coherence   = data.get("h_coherence")
            if h_coherence is None:
                coherence       = 1.0
                recovered_state = state_at_save
            else:
                h_arr   = np.array(h_coherence, dtype=np.float32)
                use_dim = min(len(h_arr), len(self.eriamo_anchor))
                recovered_state = HolographicInterference.unbind(
                    h_arr[:use_dim].tolist(), self.eriamo_anchor[:use_dim])
                s_dim = len(state_at_save)
                if len(recovered_state) < s_dim:
                    pad = np.zeros(s_dim - len(recovered_state), dtype=np.float32)
                    recovered_state = np.concatenate([recovered_state, pad])
                    recovered_state /= (np.linalg.norm(recovered_state) + 1e-8)
                coherence = float(np.dot(recovered_state[:s_dim], state_at_save))

            phi_today = np.zeros_like(phi_raw)
            for lv in range(cfg.phi_levels):
                phi_today[lv] = TimeDecay.evolve_phi(
                    phi_raw[lv], delta_hours,
                    cfg.phi_half_life_hours, cfg.phi_min_norm, level=lv)

            store = []
            if coherence >= cfg.coherence_threshold:
                max_age = cfg.store_decay_hours * 4
                for obj in data.get("store", []):
                    age_now = obj["age"] + int(delta_hours * 4)
                    if age_now > max_age and not obj.get("is_insight", False):
                        continue
                    emb_arr = np.array(obj["embedding"], dtype=np.float32)
                    use_dim = min(len(emb_arr), len(recovered_state))
                    rec_emb = HolographicInterference.unbind(
                        emb_arr[:use_dim].tolist(), recovered_state[:use_dim])
                    raw_emb = rec_emb.tolist()
                    if len(raw_emb) < total_dim:
                        created = obj.get("created_at", time.time())
                        t_vec   = time_embed(created,
                                             total_dim - len(raw_emb)).tolist()
                        raw_emb = raw_emb + t_vec
                        v       = np.array(raw_emb, dtype=np.float32)
                        raw_emb = (v / (np.linalg.norm(v) + 1e-8)).tolist()
                    store.append(Item(
                        id=obj["id"], content=obj["content"], embedding=raw_emb,
                        age=age_now, recalled=False,
                        relevance=obj.get("relevance", 1.0),
                        created_at=obj.get("created_at", time.time()),
                        is_insight=obj.get("is_insight", False),
                        insight_level=obj.get("insight_level", -1),
                        cluster_size=obj.get("cluster_size", 1),
                        is_reminder=obj.get("is_reminder", False),
                        is_fact=obj.get("is_fact", False),
                        is_work=obj.get("is_work", False)))

            return {
                "phi":           phi_today,
                "store":         store,
                "turns":         turns,
                "delta_hours":   delta_hours,
                "aii":           data.get("aii", {}),
                "phi_stability": data.get("phi_stability"),
                "wake": TimeDecay.wake_message(
                    delta_hours, turns, len(store), coherence),
                "loaded":    True,
                "coherence": coherence,
                "W_time": np.array(data["W_time"], dtype=np.float32)
                          if data.get("W_time") else None,
                "W_gen":  np.array(data["W_gen"],  dtype=np.float32)
                          if data.get("W_gen")  else None,
            }
        except Exception as e:
            print(f"[Memory] Błąd wczytania: {e}")
            return _empty()

    def delete(self):
        if self.path.exists():
            self.path.unlink()
