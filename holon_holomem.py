# -*- coding: utf-8 -*-
"""holon/holomem.py — HoloMem: silnik pamięci kognitywnej"""

import re
import math
import time
import uuid
import datetime
import numpy as np
from typing import Optional, Tuple

from holon_config import Config
from holon_item import Item
from holon_holography import HolographicInterference, PrismConfig, PrismRouter
from holon_embedder import Embedder
from holon_aii import AIIState, TimeDecay
from holon_memory import PersistentMemory


class HoloMem:
    FACT_PATTERNS: Tuple[str, ...] = (
        "mój ulubiony", "jestem", "mam na imię", "nazywam się",
        "lubię", "pracuję nad",
    )
    FOCUS_PATTERNS: Tuple[str, ...] = (
        "holon", "holomem", "eriamo", "kurz", "harmonic attention",
        "adml", "archmind", "fehm", "qrm", "bielik", "speakleash",
        "implementuję", "implementacja", "debuguję", "refaktoruję",
        "klasa ", "metoda ", "funkcja ", "def ", "class ",
        "algorytm", "architektura", "moduł", "integracja",
        "trenuję", "fine-tuning", "embedding", "transformer",
        "naprawiam", "poprawka", "błąd w", "fix:",
    )

    def __init__(self, embedder: Embedder, cfg: Config = None,
                 memory_path: str = "holon_memory.json"):
        self.embedder = embedder
        self.cfg      = cfg or Config(dim=embedder.dim)
        self.memory   = PersistentMemory(memory_path, dim=self.cfg.total_dim)

        self.phi: np.ndarray          = None
        self.store: list              = []
        self.turns: int               = 0
        self.phi_stability            = np.zeros(
            (self.cfg.phi_levels, self.cfg.k), dtype=np.float32)
        self.aii                      = AIIState(embedder)
        self._session_start_turn      = 0
        self._delta_hours             = 0.0
        self.insight_llm_callback     = None

        self.last_error: Optional[np.ndarray]    = None
        self.prev_phi_center: Optional[np.ndarray] = None
        self._last_surprise: float               = 0.0
        self.W_time = np.random.randn(
            self.cfg.total_dim, self.cfg.total_dim) * 0.01
        self.W_gen  = np.random.randn(
            self.cfg.total_dim, self.cfg.total_dim) * 0.01
        self.temporal_error: Optional[np.ndarray] = None

        self.conversation_history: list = []
        self._topic_counter: dict       = {}

        if self.cfg.use_prism:
            pcfg = self.cfg.prism_cfg or PrismConfig()
            self.prism_router = PrismRouter(pcfg)
        else:
            self.prism_router = None

    # ── Session ────────────────────────────────────────────────────────────

    def start_session(self) -> dict:
        res               = self.memory.load(self.cfg)
        self.phi          = res["phi"]
        self.store        = res["store"]
        self.turns        = res["turns"]
        self._delta_hours = res["delta_hours"]
        self.aii.from_dict(res.get("aii", {}))

        saved_stab = res.get("phi_stability")
        if saved_stab is not None:
            try:
                arr = np.array(saved_stab, dtype=np.float32)
                if arr.shape == (self.cfg.phi_levels, self.cfg.k):
                    self.phi_stability = arr
                elif arr.ndim == 1 and len(arr) == self.cfg.k:
                    self.phi_stability = np.stack([
                        arr * (0.5 ** lv)
                        for lv in range(self.cfg.phi_levels)])
            except Exception:
                pass

        if res.get("W_time") is not None:
            wt = res["W_time"]
            if wt.shape == self.W_time.shape:
                self.W_time = wt
        if res.get("W_gen") is not None:
            wg = res["W_gen"]
            if wg.shape == self.W_gen.shape:
                self.W_gen = wg

        self._session_start_turn = self.turns
        return res

    # ── Cosine helpers ─────────────────────────────────────────────────────

    def _align(self, a: np.ndarray, b: np.ndarray):
        m = min(len(a), len(b))
        return a[:m], b[:m]

    def _cosine_sim(self, a: np.ndarray, b: np.ndarray) -> float:
        na = np.linalg.norm(a)
        nb = np.linalg.norm(b)
        if na < 1e-8 or nb < 1e-8:
            return 0.0
        return float(np.dot(a, b) / (na * nb))

    def _csim(self, a: np.ndarray, b: np.ndarray) -> float:
        a_, b_ = self._align(a, b)
        return self._cosine_sim(a_, b_)

    # ── Phi center ─────────────────────────────────────────────────────────

    def _phi_center(self, query_emb: np.ndarray = None,
                    level: int = 2) -> np.ndarray:
        layer = self.phi[level]
        if query_emb is not None:
            q_dim = len(query_emb)
            sims  = np.array([
                self._cosine_sim(query_emb, layer[k][:q_dim])
                for k in range(self.cfg.k)
            ], dtype=np.float32)
            exp_s   = np.exp(sims - sims.max())
            weights = exp_s / (exp_s.sum() + 1e-8)
        else:
            norms   = np.linalg.norm(layer, axis=1)
            exp_n   = np.exp(norms - norms.max())
            weights = exp_n / (exp_n.sum() + 1e-8)
        center = sum(weights[k] * layer[k] for k in range(self.cfg.k))
        n = np.linalg.norm(center)
        return center / (n + 1e-8)

    # ── Recall ─────────────────────────────────────────────────────────────

    def _recall(self, query_emb_timed: np.ndarray):
        if not self.store:
            return
        scores = {}
        cdim   = self.cfg.dim
        q_time = query_emb_timed[cdim:]

        for k in range(self.cfg.k):
            attractor = (0.6 * self.phi[2][k] +
                         0.3 * self.phi[1][k] +
                         0.1 * self.phi[0][k])
            for item in self.store:
                emb   = item.emb_np()
                s_att = self._csim(emb[:cdim], attractor[:cdim])
                s_qry = self._csim(emb[:cdim], query_emb_timed[:cdim])
                time_sim    = (self._cosine_sim(emb[cdim:], q_time)
                               if len(q_time) > 0 else 1.0)
                time_weight = np.exp(2.0 * (time_sim - 1.0))
                score = max(0.0, s_att) * max(0.0, s_qry) * time_weight
                if item.is_fact:
                    score *= (1.0 + 0.2 / (1.0 + item.age * 0.1))
                if item.is_work:
                    score *= (1.0 + 0.4 / (1.0 + item.age * 0.05))
                if id(item) not in scores or score > scores[id(item)][0]:
                    scores[id(item)] = (score, item, k)

        ranked = sorted(scores.values(), key=lambda x: -x[0])
        for _, item, k in ranked[:self.cfg.top_n_recall]:
            item.recalled = True
            self.phi_stability[2][k] += 1.0

    # ── Vacuum ─────────────────────────────────────────────────────────────

    def _vacuum(self, query_emb_timed: np.ndarray):
        center   = self._phi_center(query_emb_timed, level=2)
        cdim     = self.cfg.dim
        center_c = center[:cdim] / (np.linalg.norm(center[:cdim]) + 1e-8)
        q_time   = query_emb_timed[cdim:]

        if self.turns > 0 and self.turns % self.cfg.soft_vacuum_interval == 0:
            for item in self.store:
                if not item.is_insight:
                    item.relevance *= self.cfg.soft_decay_factor

        for item in self.store:
            sem = self._cosine_sim(item.emb_content(cdim), center_c)
            item.relevance = 0.6 * sem + 0.4 * item.relevance
            item.relevance = max(0.05, item.relevance)

        hpi = self.cfg.hard_prune_interval
        hpm = self.cfg.hard_prune_store_max
        if (self.turns > 0 and self.turns % hpi == 0) or len(self.store) > hpm:
            threshold    = self.cfg.threshold * self.aii.get_threshold_multiplier(
                self.cfg.aii_adapt_range)
            session_age  = self.turns - self._session_start_turn
            if session_age < self.cfg.vacuum_warmup_turns:
                threshold *= (0.5 + 0.5 * session_age / self.cfg.vacuum_warmup_turns)

            def _score(item):
                sim      = self._cosine_sim(item.emb_content(cdim), center_c)
                time_sim = (self._cosine_sim(item.emb_time(cdim), q_time)
                            if len(q_time) > 0 else 1.0)
                entropy  = 0.1 * (1.0 - abs(sim)) + max(0.0, 1.0 - time_sim)
                fe       = -sim + entropy
                base     = -(fe - 0.2 * item.relevance)
                return base * 0.5 if item.is_insight else base

            self.store = [
                i for i in self.store
                if ((i.age <= 1 and i.relevance > 0.2) or i.recalled
                    or i.is_fact or i.is_work
                    or i.relevance > 0.3 or _score(i) >= threshold)
            ]
            MAX_STORE = min(self.cfg.n * 6, hpm)
            if len(self.store) > MAX_STORE:
                self.store.sort(key=_score, reverse=True)
                self.store = self.store[:MAX_STORE]

    # ── Update phi ─────────────────────────────────────────────────────────

    def _update_phi(self, window: list):
        if not window:
            return
        window_ids = {id(i) for i in window}
        active = [i for i in self.store
                  if id(i) in window_ids or i.age <= 1 or i.recalled]
        if not active:
            return

        base_emo_w = self.aii.get_emotion_weight()
        emotion_w  = (base_emo_w * self.cfg.focus_boost
                      if self.aii.focus_active else base_emo_w)

        tdim    = self.cfg.total_dim
        pattern = np.zeros(tdim, dtype=np.float32)
        for item in active:
            phase  = math.exp(-item.age / self.cfg.vacuum_age_tau)
            weight = 2.0 if item.recalled else (1.5 if item.age <= 1 else 1.0)
            if item.is_insight:
                weight *= 2.0
            sign = 1.0 if (item.recalled or item.age <= 1 or item.is_insight) else -0.3
            emb  = item.emb_np()
            if len(emb) < tdim:
                emb = np.concatenate(
                    [emb, np.zeros(tdim - len(emb), dtype=np.float32)])
            pattern += sign * phase * weight * emotion_w * emb

        n = np.linalg.norm(pattern)
        if n < 1e-8:
            return
        pattern /= n

        recalled_count = sum(1 for i in window if i.recalled)
        importance     = emotion_w * (1.0 + 0.3 * recalled_count)

        def _norm_v(v):
            nv = np.linalg.norm(v)
            return v / (nv + 1e-8)

        if self.cfg.use_prism and self.prism_router is not None:
            prism_updates, prism_p, _ = self.prism_router.route(importance, pattern)
            self.W_gen *= 0.999

            for lv in range(self.cfg.phi_levels):
                if prism_p[lv] < 1e-4:
                    continue
                shifted_lv = prism_updates[lv] / (prism_p[lv] + 1e-8)
                layer_lv   = self.phi[lv]
                sims_lv    = np.array([
                    float(np.dot(shifted_lv, layer_lv[k]) /
                          (np.linalg.norm(layer_lv[k]) + 1e-8))
                    for k in range(self.cfg.k)], dtype=np.float32)
                exp_lv = np.exp(sims_lv - sims_lv.max())
                w_lv   = exp_lv / (exp_lv.sum() + 1e-8)
                w_lv   = w_lv + 0.05
                w_lv[0] *= 0.1
                w_lv   /= (w_lv.sum() + 1e-8)

                for k in range(self.cfg.k):
                    layer_old = layer_lv[k].copy()
                    mu_k      = np.tanh(self.W_gen @ layer_lv[k])
                    mu_k     /= (np.linalg.norm(mu_k) + 1e-8)
                    eps_local = shifted_lv - mu_k
                    eps_total = (
                        0.6 * _norm_v(eps_local)
                        + 0.25 * _norm_v(self.last_error[:len(eps_local)])
                        + 0.15 * _norm_v(
                            self.temporal_error[:len(eps_local)]
                            if self.temporal_error is not None
                            else np.zeros_like(eps_local))
                    ) if self.last_error is not None else eps_local
                    eps_total   = np.clip(eps_total, -0.3, 0.3)
                    sigma_k     = np.linalg.norm(eps_local)
                    precision_k = min(5.0, 1.0 / (sigma_k + 1e-4))
                    lr_k        = self.cfg.lr * w_lv[k] * precision_k * prism_p[lv]
                    layer_lv[k] += lr_k * eps_total
                    layer_lv[k] *= 0.9995
                    layer_lv[k] /= (np.linalg.norm(layer_lv[k]) + 1e-8)
                    self.W_gen  += lr_k * np.outer(eps_local, layer_old)

                self.phi_stability[lv] += w_lv * prism_p[lv]
                self.phi_stability[lv]  = np.clip(
                    self.phi_stability[lv], 0, self.cfg.phi_stability_max)
                self.phi_stability[lv] *= self.cfg.phi_stability_decay

            w_norm = np.linalg.norm(self.W_gen)
            if w_norm > 5.0:
                self.W_gen *= 5.0 / w_norm

            dom_lv       = int(np.argmax(prism_p))
            shifted_dom  = prism_updates[dom_lv] / (prism_p[dom_lv] + 1e-8)
            self._last_surprise = float(np.mean([
                np.linalg.norm(
                    shifted_dom - np.tanh(self.W_gen @ self.phi[dom_lv][k]))
                for k in range(self.cfg.k)]))
            level = dom_lv

        else:
            if importance < 1.2:   level = 0
            elif importance < 1.8: level = 1
            else:                  level = 2

            shift           = self.cfg.phase_shifts[level]
            shifted_pattern = HolographicInterference.phase_shift(pattern, shift)
            layer           = self.phi[level]
            sims            = np.array([
                float(np.dot(shifted_pattern, layer[k]) /
                      (np.linalg.norm(layer[k]) + 1e-8))
                for k in range(self.cfg.k)], dtype=np.float32)
            exp_s   = np.exp(sims - sims.max())
            weights = exp_s / (exp_s.sum() + 1e-8)
            weights = weights + 0.05
            weights[0] *= 0.1
            weights /= (weights.sum() + 1e-8)

            self.W_gen *= 0.999
            for k in range(self.cfg.k):
                layer_old = layer[k].copy()
                mu_k      = np.tanh(self.W_gen @ layer[k])
                mu_k     /= (np.linalg.norm(mu_k) + 1e-8)
                eps_local = shifted_pattern - mu_k
                eps_total = (
                    0.6 * _norm_v(eps_local)
                    + 0.25 * _norm_v(self.last_error[:len(eps_local)])
                    + 0.15 * _norm_v(
                        self.temporal_error[:len(eps_local)]
                        if self.temporal_error is not None
                        else np.zeros_like(eps_local))
                ) if self.last_error is not None else eps_local
                eps_total   = np.clip(eps_total, -0.3, 0.3)
                sigma_k     = np.linalg.norm(eps_local)
                precision_k = min(5.0, 1.0 / (sigma_k + 1e-4))
                lr_k        = self.cfg.lr * weights[k] * precision_k
                layer[k]   += lr_k * eps_total
                layer[k]   *= 0.9995
                layer[k]   /= (np.linalg.norm(layer[k]) + 1e-8)
                self.W_gen += lr_k * np.outer(eps_local, layer_old)

            w_norm = np.linalg.norm(self.W_gen)
            if w_norm > 5.0:
                self.W_gen *= 5.0 / w_norm
            self.phi_stability[level] += weights
            self.phi_stability[level]  = np.clip(
                self.phi_stability[level], 0, self.cfg.phi_stability_max)
            self.phi_stability[level] *= self.cfg.phi_stability_decay
            self._last_surprise = float(np.mean([
                np.linalg.norm(
                    shifted_pattern - np.tanh(self.W_gen @ self.phi[level][k]))
                for k in range(self.cfg.k)]))

        if self._last_surprise > self.cfg.surprise_trigger:
            self.cfg.lr *= (1.0 + self.cfg.surprise_adapt_rate)
        else:
            self.cfg.lr *= (1.0 - self.cfg.surprise_adapt_rate * 0.5)
        self.cfg.lr = float(np.clip(self.cfg.lr, self.cfg.lr_min, self.cfg.lr_max))

        self.phi *= 0.999
        self.phi  = np.clip(self.phi, -1.0, 1.0)

        beta = self.cfg.phi_ortho_beta
        if beta > 0.0:
            for lv in range(self.cfg.phi_levels):
                phi_new = self.phi[lv].copy()
                for i in range(self.cfg.k):
                    row = self.phi[lv][i].copy()
                    for j in range(self.cfg.k):
                        if i != j:
                            row -= (beta * float(np.dot(row, self.phi[lv][j]))
                                    * self.phi[lv][j])
                    phi_new[i] = row / (np.linalg.norm(row) + 1e-8)
                self.phi[lv] = phi_new

        lr_cross = self.cfg.lr * 0.3
        for lv in range(self.cfg.phi_levels - 1):
            low  = self._phi_center(level=lv)
            high = self._phi_center(level=lv + 1)
            p    = min(len(low), len(high))
            e    = high[:p] - low[:p]
            n    = np.linalg.norm(e)
            if n > 1e-8:
                e = np.clip(e / n, -0.3, 0.3)
                for k in range(self.cfg.k):
                    self.phi[lv][k][:p]   += lr_cross * e
                    self.phi[lv][k]       /= (np.linalg.norm(self.phi[lv][k]) + 1e-8)
                    self.phi[lv+1][k][:p] -= lr_cross * 0.5 * e
                    self.phi[lv+1][k]     /= (np.linalg.norm(self.phi[lv+1][k]) + 1e-8)

        for lv in range(self.cfg.phi_levels):
            if np.std(self.phi_stability[lv]) > 2.0:
                wi    = int(np.argmin(self.phi_stability[lv]))
                noise = np.random.randn(tdim).astype(np.float32) * 0.005
                self.phi[lv][wi] += noise
                self.phi[lv][wi] /= (np.linalg.norm(self.phi[lv][wi]) + 1e-8)

    # ── Merge / deduplicate ────────────────────────────────────────────────

    def _semantic_merge(self, item: Item, new_emb: np.ndarray) -> None:
        cdim     = self.cfg.dim
        c1, c2   = item.emb_content(cdim), new_emb[:cdim]
        t2       = new_emb[cdim:]
        c_merged = (item.cluster_size * c1 + c2) / (item.cluster_size + 1.0)
        merged   = np.concatenate([c_merged, t2])
        merged  /= (np.linalg.norm(merged) + 1e-8)
        old_size = item.cluster_size
        item.cluster_size += 1
        item.created_at    = (old_size * item.created_at + time.time()) / item.cluster_size
        item.embedding     = merged.tolist()
        item.relevance     = min(5.0, item.relevance + 0.2)
        item.age           = 0
        item._norm         = -1.0

    # ── Helpers ────────────────────────────────────────────────────────────

    def _detect_fact_work(self, text: str) -> tuple:
        is_fact = (any(p in text.lower() for p in self.FACT_PATTERNS)
                   and "?" not in text)
        is_work = (self.aii.focus_active
                   or any(p in text.lower() for p in self.FOCUS_PATTERNS))
        return is_fact, is_work

    def _find_best_match(self, emb: np.ndarray) -> tuple:
        best_sim, best_item = -1.0, None
        for i in self.store:
            sim = self._csim(emb, i.emb_np())
            if sim > best_sim:
                best_sim, best_item = sim, i
        return best_sim, best_item

    # ── Build messages ─────────────────────────────────────────────────────

    def _build_messages(self, window: list, user_message: str,
                        system_prompt: str) -> list:
        msgs = ([{"role": "system", "content": system_prompt}]
                if system_prompt else [])
        mem_parts = []
        emo_pl = {
            "radosc": "radość/ekscytacja", "zaskoczenie": "zaskoczenie/ciekawość",
            "strach": "niepokój/błąd",     "zlosc": "frustracja/złość",
            "smutek": "smutek/melancholia", "neutral": "spokój/neutralność",
        }.get(self.aii.emotion, self.aii.emotion)

        mem_parts.append(
            f"[SYSTEM - STAN WEWNĘTRZNY]\n"
            f"Dominująca emocja układu: {emo_pl}\n"
            f"Napięcie kognitywne (vacuum): {self.aii.vacuum_signal:+.2f} "
            f"(ujemne=błąd/niepokój, dodatnie=zgodność/przyjemność)\n"
            f"Focus na zadaniu: {'AKTYWNY' if self.aii.focus_active else 'BRAK'}\n"
            f"ZASADA BEZWZGLĘDNA: Nie recytuj tego bloku. Zabrania się mówić, "
            f"że nie masz uczuć. Zabarwiaj swoje odpowiedzi zgodnie z powyższym "
            f"stanem afektywnym."
        )

        if window:
            ctx        = [i for i in window if i.content != user_message]
            work_items = [i for i in ctx if i.is_work]
            fact_items = [i for i in ctx if i.is_fact and not i.is_work]
            regular    = [i for i in ctx if not i.is_fact and not i.is_work]

            if work_items:
                mem_parts.append(
                    "AKTYWNE PROJEKTY (najwyższy priorytet — to nad czym pracujemy):\n"
                    + "\n".join(f"• {i.content[:400]}" for i in work_items))
            if fact_items:
                mem_parts.append(
                    "TRWAŁE FAKTY (zawsze prawdziwe — nie mów że nie wiesz):\n"
                    + "\n".join(f"• {i.content[:300]}" for i in fact_items))
            if regular:
                max_chars = max(200, 9856 // max(1, len(regular)))
                mem_parts.append(
                    "PAMIĘĆ SESJI:\n" + "\n---\n".join(
                        f"[t-{i.age}{'★' if i.recalled else ''}"
                        f"{'💡' if i.is_insight else ''}] {i.content[:max_chars]}"
                        for i in regular))

        if mem_parts:
            msgs.append({"role": "system",
                         "content": "\n\n".join(mem_parts)})

        for entry in self.conversation_history:
            msgs.append(entry)
        msgs.append({"role": "user", "content": user_message})
        return msgs

    # ── Turn / after_turn ──────────────────────────────────────────────────

    def turn(self, user_message: str, system_prompt: str = "") -> list:
        # Auto-init jeśli start_session nie zostało wywołane
        if self.phi is None:
            self.start_session()
        
        q_timed        = self.embedder.encode(user_message, timestamp=time.time())
        current_center = self._phi_center(level=2)

        if self.prev_phi_center is not None:
            pred_center    = self.W_time @ self.prev_phi_center
            pred_center   /= (np.linalg.norm(pred_center) + 1e-8)
            temporal_error = current_center - pred_center
            temporal_error /= (np.linalg.norm(temporal_error) + 1e-8)
            self.temporal_error = temporal_error.copy()
            raw_spatial    = np.clip(
                q_timed[:len(current_center)] - current_center, -0.5, 0.5)
            combined       = (0.7 * raw_spatial
                              + 0.3 * temporal_error[:len(raw_spatial)])
            self.last_error = (0.7 * self.last_error + 0.3 * combined
                               if self.last_error is not None else combined)
            grad  = np.outer(
                current_center - self.prev_phi_center, self.prev_phi_center)
            g_norm = np.linalg.norm(grad)
            if g_norm > 1e-6:
                grad /= g_norm
            self.W_time += self.cfg.lr * 0.1 * grad
            decay = 0.999 - 0.2 * min(1.0, self._last_surprise)
            self.W_time = (decay * self.W_time
                           + (1 - decay) * np.eye(self.cfg.total_dim))
            w_norm = np.linalg.norm(self.W_time)
            if w_norm > 5.0:
                self.W_time *= 5.0 / w_norm
        else:
            self.last_error     = np.clip(
                q_timed[:len(current_center)] - current_center, -0.5, 0.5)
            self.temporal_error = None

        self._recall(q_timed)

        skip = False
        if self.store:
            best_sim, best_item = self._find_best_match(q_timed)
            is_new_fact, is_new_work = self._detect_fact_work(user_message)
            if best_sim > 0.95:
                self._semantic_merge(best_item, q_timed)
                best_item.is_fact = best_item.is_fact or is_new_fact
                best_item.is_work = best_item.is_work or is_new_work
                skip = True

        if not skip:
            is_fact, is_work = self._detect_fact_work(user_message)
            self.store.append(Item(
                id=str(uuid.uuid4()),
                content=user_message[:500],
                embedding=q_timed.tolist(),
                age=0, is_fact=is_fact, is_work=is_work))

        self._vacuum(q_timed)
        window = self._build_window(q_timed)
        self._update_phi(window)
        for item in self.store:
            item.recalled = False
        self.turns += 1
        self.prev_phi_center = self._phi_center(level=2).copy()
        return self._build_messages(window, user_message, system_prompt)

    def after_turn(self, user_message: str, response: str) -> None:
        response = response or "[brak odpowiedzi]"
        MAX_C    = 500
        combined = (f"User: {user_message[:MAX_C]}\n"
                    f"Assistant: {response[:MAX_C]}")
        t_now    = time.time()
        comb_emb = self.embedder.encode(combined, timestamp=t_now)
        self.aii.update(user_message + " " + response, comb_emb)

        skip = False
        if self.store:
            best_sim, best_item = self._find_best_match(comb_emb)
            is_new_fact, is_new_work = self._detect_fact_work(user_message)
            if best_sim > 0.95:
                self._semantic_merge(best_item, comb_emb)
                best_item.is_fact = best_item.is_fact or is_new_fact
                best_item.is_work = best_item.is_work or is_new_work
                skip = True

        if not skip:
            is_fact, is_work = self._detect_fact_work(user_message)
            self.store.append(Item(
                id=str(uuid.uuid4()),
                content=combined[:800],
                embedding=comb_emb.tolist(),
                relevance=self.aii.get_emotion_weight(),
                is_fact=is_fact, is_work=is_work))

        self._vacuum(comb_emb)
        self._update_phi(self._build_window(comb_emb))
        for it in self.store:
            it.age += 1

        # v5.11: conversation history
        self.conversation_history.append(
            {"role": "user", "content": user_message[:300]})
        self.conversation_history.append(
            {"role": "assistant", "content": response[:300]})
        max_h = self.cfg.conversation_history_size * 2
        if len(self.conversation_history) > max_h:
            self.conversation_history = self.conversation_history[-max_h:]

        # v5.11: topic counter
        STOP = {
            "i","w","z","na","do","że","to","a","o","się","jak","co","czy",
            "nie","tak","już","jest","tego","jego","jej","ich","ten","tej",
            "być","mnie","moje","swój","przez","przy","pod","nad","też","ale",
            "lub","the","is","in","of","and","it","this","that","are","was",
            "for","with","have","has","will","been","they","lubię","lubisz",
            "mówię","mówisz","myślę","myślisz","chcę","chcesz","mogę",
            "możesz","wiem","wiesz",
        }
        raw_words = re.sub(r'[^\w\s]', '', user_message.lower()).split()
        keywords  = [w for w in set(raw_words) if len(w) >= 5 and w not in STOP]
        for kw in keywords:
            self._topic_counter[kw] = self._topic_counter.get(kw, 0) + 1
            if self._topic_counter[kw] == self.cfg.topic_repeat_threshold:
                fact_content = f"Użytkownik wielokrotnie poruszał temat: {kw}"
                fact_emb     = self.embedder.encode(fact_content, timestamp=time.time())
                already = any(
                    self._cosine_sim(
                        np.array(i.embedding[:self.cfg.dim], dtype=np.float32),
                        fact_emb[:self.cfg.dim]) > 0.85
                    for i in self.store if i.is_fact)
                if not already:
                    self.store.append(Item(
                        id=str(uuid.uuid4()), content=fact_content,
                        embedding=fact_emb.tolist(), relevance=1.5,
                        is_fact=True))
                    print(f"[ConvTracker] Nowy fakt: '{fact_content}'")

        self.ruminate()
        self.memory.save(self.phi, self.store, self.turns, self.cfg,
                         self.aii.to_dict(), self.phi_stability.tolist(),
                         self.W_time, self.W_gen)
        if hasattr(self.embedder, 'save'):
            self.embedder.save()

    # ── Reminders ──────────────────────────────────────────────────────────

    def add_reminder(self, text: str, timestamp: float) -> None:
        emb = self.embedder.encode(text, timestamp=timestamp)
        self.store.append(Item(
            id=str(uuid.uuid4()), content=text,
            embedding=emb.tolist(), created_at=timestamp,
            is_reminder=True, relevance=2.0))
        print(f"[Przypomnienie] Dodano: '{text}' na "
              f"{datetime.datetime.fromtimestamp(timestamp)}")
        self.memory.save(self.phi, self.store, self.turns, self.cfg,
                         self.aii.to_dict(), self.phi_stability.tolist(),
                         self.W_time, self.W_gen)

    # POPRAWIONA METODA get_upcoming_reminders (bez AttributeError)
    def get_upcoming_reminders(self, within_seconds: int = 3600) -> list:
        now = time.time()
        out = [i for i in self.store
               if getattr(i, 'is_reminder', False) and now <= i.created_at <= now + within_seconds]
        out.sort(key=lambda x: x.created_at)
        return out

    # ── Ruminate ───────────────────────────────────────────────────────────

    def ruminate(self, force: bool = False) -> Optional[str]:
        if not force and self.turns % self.cfg.rumination_interval != 0:
            return None
        core  = self.phi[2].mean(axis=0)
        short = self.phi[0].mean(axis=0)
        mid   = self.phi[1].mean(axis=0)
        projs = [HolographicInterference.phase_shift(core, s)
                 for s in self.cfg.rumination_shifts]
        incs  = [abs(float(np.dot(p, short)) - float(np.dot(p, mid)))
                 for p in projs]
        max_inc = max(incs)

        if self.cfg.phase_shifts_learnable:
            target = self.cfg.rumination_threshold / 2.0
            lr_ps  = 0.05
            for lv in range(self.cfg.phi_levels):
                lv_lr = lr_ps * (0.5 ** (self.cfg.phi_levels - 1 - lv))
                self.cfg.phase_shifts[lv] += lv_lr * (target - max_inc)
                self.cfg.phase_shifts[lv] %= 1.0

        if max_inc <= self.cfg.rumination_threshold and not force:
            return None

        reflection = ""
        if self.insight_llm_callback is not None:
            try:
                prompt     = self.cfg.insight_prompt_template.format(max_inc=max_inc)
                reflection = self.insight_llm_callback(prompt)[:400]
            except Exception:
                pass

        if not reflection or "brak insightu" in reflection.lower():
            return None

        t_now = time.time()
        emb   = self.embedder.encode(reflection, timestamp=t_now)
        cdim  = self.cfg.dim
        sim_c = self._cosine_sim(emb[:cdim], self._phi_center(level=2)[:cdim])
        sim_s = self._cosine_sim(emb[:cdim], self._phi_center(level=0)[:cdim])
        score = 0.7 * sim_c + 0.3 * sim_s
        if score < 0.35:
            print(f"[Ruminacja t={self.turns}] Odrzucono insight "
                  f"(score: {score:.2f})")
            return None

        shifted = HolographicInterference.phase_shift(emb, 0.9)
        tdim    = self.cfg.total_dim
        if len(shifted) < tdim:
            shifted = np.concatenate(
                [shifted, np.zeros(tdim - len(shifted), dtype=np.float32)])
        shifted = shifted[:tdim]
        shifted /= (np.linalg.norm(shifted) + 1e-8)

        alpha = min(0.2, 0.02 + 0.1 * max(0.0, sim_c))
        for k in range(self.cfg.k):
            self.phi[2][k] = (1.0 - alpha) * self.phi[2][k] + alpha * shifted
            self.phi[2][k] /= (np.linalg.norm(self.phi[2][k]) + 1e-8)

        self.store.append(Item(
            id=f"insight-{uuid.uuid4().hex[:8]}", content=reflection,
            embedding=emb.tolist(), age=0, relevance=2.5, created_at=t_now,
            is_insight=True, insight_level=2, cluster_size=1))
        print(f"\n[Ruminacja] Niespójność: {max_inc:.3f} → insight zaktualizowany")
        return reflection

    # ── Build window ───────────────────────────────────────────────────────

    def _build_window(self, query_emb: np.ndarray) -> list:
        center      = self._phi_center(query_emb, level=2)
        cdim        = self.cfg.dim
        center_c    = center[:cdim] / (np.linalg.norm(center[:cdim]) + 1e-8)
        protected   = [i for i in self.store
                       if i.age <= 1 or i.recalled or i.is_fact or i.is_work]
        prot_ids    = {id(i) for i in protected}
        candidates  = sorted(
            [i for i in self.store if id(i) not in prot_ids],
            key=lambda x: -self._cosine_sim(x.emb_content(cdim), center_c))
        return (protected + candidates)[:self.cfg.n]

    # ── Recall at time ─────────────────────────────────────────────────────

    def recall_at(self, query: str, target_time: float, top_k: int = 5) -> list:
        hours_ago = (time.time() - target_time) / 3600.0
        phi_then  = np.zeros_like(self.phi)
        for lv in range(self.cfg.phi_levels):
            phi_then[lv] = TimeDecay.evolve_phi(
                self.phi[lv], hours_ago,
                self.cfg.phi_half_life_hours, self.cfg.phi_min_norm, level=lv)
        q_full   = self.embedder.encode(query, timestamp=target_time)
        cdim     = self.cfg.dim
        q_c      = q_full[:cdim]
        layer    = phi_then[2]
        norms    = np.linalg.norm(layer, axis=1)
        exp_n    = np.exp(norms - norms.max())
        wts      = exp_n / (exp_n.sum() + 1e-8)
        center_c = sum(wts[k] * layer[k] for k in range(self.cfg.k))
        center_c = center_c[:cdim] / (np.linalg.norm(center_c[:cdim]) + 1e-8)
        scored   = []
        for item in self.store:
            e_c = item.emb_content(cdim)
            e_t = item.emb_np()[cdim:]
            q_t = q_full[cdim:]
            s1  = self._cosine_sim(e_c, q_c)
            s2  = self._cosine_sim(e_t, q_t) if len(e_t) == len(q_t) else 0.0
            s3  = self._cosine_sim(e_c, center_c)
            scored.append((item, 0.5 * s1 + 0.2 * s2 + 0.3 * s3))
        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]

    # ── Stats / reset ──────────────────────────────────────────────────────

    def set_insight_callback(self, cb) -> None:
        self.insight_llm_callback = cb

    def stats(self) -> dict:
        if self.phi is None:
            return {"turns": 0, "store": 0, "phi_norms": [],
                    "phi_stability": [], "aii": self.aii.to_dict(),
                    "delta_hours": 0.0, "warning": "start_session() not called"}
        phi_norms = [np.linalg.norm(self.phi[lv], axis=1).tolist()
                     for lv in range(self.cfg.phi_levels)]
        return {
            "turns":         self.turns,
            "store":         len(self.store),
            "phi_norms":     phi_norms,
            "phi_stability": self.phi_stability.tolist(),
            "aii":           self.aii.to_dict(),
            "delta_hours":   round(self._delta_hours, 2),
            "phase_shifts":  list(self.cfg.phase_shifts),
            "last_error_norm": round(float(np.linalg.norm(self.last_error)), 4)
                               if self.last_error is not None else 0.0,
            "temporal_drift": round(float(np.linalg.norm(
                self._phi_center(level=2) - self.prev_phi_center))
                if self.prev_phi_center is not None else 0.0, 4),
            "surprise":      round(self._last_surprise, 4),
            "lr_current":    round(self.cfg.lr, 5),
            "prism_mode":    self.cfg.use_prism,
        }

    def reset(self):
        self.memory.delete()
        self.phi              = PersistentMemory._init_phi(self.cfg)
        self.phi_stability    = np.zeros(
            (self.cfg.phi_levels, self.cfg.k), dtype=np.float32)
        self.store            = []
        self.turns            = 0
        self._delta_hours     = 0.0
        self.aii              = AIIState(self.embedder)
        self._session_start_turn = 0
        self.last_error       = None
        self.prev_phi_center  = None
        self._last_surprise   = 0.0
        self.W_time = np.random.randn(
            self.cfg.total_dim, self.cfg.total_dim) * 0.01
        self.W_gen  = np.random.randn(
            self.cfg.total_dim, self.cfg.total_dim) * 0.01
        self.temporal_error       = None
        self.conversation_history = []
        self._topic_counter       = {}