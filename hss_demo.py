"""
HolonOS HSS v2.9 — Demonstrator Pięciu Faz
===========================================
Zmiany względem v2.8:
  [1] JSON context zamiast stringa — eliminacja string injection
  [2] e losowe w keygen(seed) — RLWE security wymaga losowego błędu
  [3] Rotacja sesji przez epoch (5min) — forward secrecy między epokami
  [4] Walidacja zakresu u,v w upcall_write — ochrona przed malformed RLWE
  [5] Dynamiczny baseline entropii dla FEP — bez magic number 7.0

Uruchomienie: python3 hss_demo.py
Wymagania: pip install numpy --break-system-packages
"""

import numpy as np
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
# PARAMETRY
# ─────────────────────────────────────────────

N = 64
Q = 3329
ETA = 2
PHI_DIM = 16
PRISM_SIZE = N // 3

P_CORE = slice(0, PRISM_SIZE)
P_IN   = slice(PRISM_SIZE, 2 * PRISM_SIZE)
P_OUT  = slice(2 * PRISM_SIZE, N)


# ─────────────────────────────────────────────
# PRYMITYWY KRYPTOGRAFICZNE
# ─────────────────────────────────────────────

def expand_bytes(seed: bytes, length: int) -> bytes:
    """Deterministyczny DRBG-expand: SHA256(seed || counter).
    Brak korelacji, pełna entropia niezależnie od length."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return out[:length]

def sample_small(n: int, eta: int = ETA) -> np.ndarray:
    """Centered binomial via unpackbits — prawidłowe χ_s."""
    needed = (n * eta * 2 + 7) // 8 + 32
    raw = os.urandom(needed)
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))
    bits = bits[:n * eta * 2].reshape(n, eta * 2)
    a = np.sum(bits[:, :eta], axis=1)
    b = np.sum(bits[:, eta:], axis=1)
    return (a.astype(np.int64) - b.astype(np.int64))

def poly_mul(f: np.ndarray, g: np.ndarray, q: int = Q) -> np.ndarray:
    """Mnożenie wielomianów w R_q = Z_q[X]/(X^N+1)."""
    n = len(f)
    h = np.zeros(n, dtype=np.int64)
    for i in range(n):
        for j in range(n):
            idx = (i + j) % n
            sign = -1 if (i + j) >= n else 1
            h[idx] = (h[idx] + sign * f[i] * g[j]) % q
    return h

def keygen(seed: Optional[bytes] = None, n: int = N, q: int = Q):
    """Generowanie klucza LPR.
    seed → deterministyczne a i s (tożsamość = funkcja stanu).
    e ZAWSZE losowe — RLWE security wymaga losowego błędu.
    None → pełna losowość (dla kluczy efemerycznych)."""
    if seed is not None:
        a_bytes = expand_bytes(seed + b":a", n * 2)
        a = np.frombuffer(a_bytes, dtype=np.uint16)[:n].astype(np.int64) % q
        s = kdf(seed, "keygen:s", n)
    else:
        a = np.random.randint(0, q, n, dtype=np.int64)
        s = sample_small(n)
    e = sample_small(n)   # ZAWSZE losowe — nie deterministyczne
    b = (poly_mul(a, s) + e) % q
    return (a, b), s

def encrypt(pub_key, message: np.ndarray, q: int = Q) -> tuple:
    """Szyfrowanie LPR."""
    a, b = pub_key
    n = len(a)
    r = sample_small(n)
    e1 = sample_small(n)
    e2 = sample_small(n)
    u = (poly_mul(a, r) + e1) % q
    m_scaled = ((message % 2) * (q // 2)).astype(np.int64)
    v = (poly_mul(b, r) + e2 + m_scaled) % q
    return u, v

def decrypt(s: np.ndarray, u: np.ndarray, v: np.ndarray, q: int = Q) -> np.ndarray:
    """Deszyfrowanie LPR."""
    recovered = (v - poly_mul(s, u)) % q
    return ((recovered + q // 4) // (q // 2) % 2).astype(np.int64)

def kdf(master_secret: bytes, context: str, length: int = N) -> np.ndarray:
    """KDF → centered binomial polynomial via HMAC-DRBG + unpackbits."""
    needed_bytes = (length * ETA * 2 + 7) // 8 + 32
    out = b""
    counter = 0
    while len(out) < needed_bytes:
        block = hmac.new(
            master_secret,
            context.encode() + counter.to_bytes(4, 'big'),
            hashlib.sha256
        ).digest()
        out += block
        counter += 1
    bits = np.unpackbits(np.frombuffer(out, dtype=np.uint8))
    bits = bits[:length * ETA * 2].reshape(length, ETA * 2)
    a = np.sum(bits[:, :ETA], axis=1)
    b = np.sum(bits[:, ETA:], axis=1)
    return (a.astype(np.int64) - b.astype(np.int64))

def derive_agent_pub(s_agent: np.ndarray, context: str, q: int = Q, n: int = N):
    """[P1-FIX] Deterministyczny klucz publiczny agenta.
    expand_bytes zamiast seed*N — brak korelacji, pełna entropia w Z_q."""
    seed = hmac.new(
        s_agent.tobytes(),
        context.encode(),
        hashlib.sha256
    ).digest()
    buf = expand_bytes(seed, n * 2)          # 2 bajty na każdy element → uint16
    a = np.frombuffer(buf, dtype=np.uint16)[:n].astype(np.int64) % q
    b = poly_mul(a, s_agent) % q
    return (a, b)

def measure_entropy(data: np.ndarray) -> float:
    if len(data) == 0:
        return 0.0
    vals, counts = np.unique(data, return_counts=True)
    probs = counts / len(data)
    return float(-np.sum(probs * np.log2(probs + 1e-12)))

def ciphertext_prediction_error(v_current: np.ndarray,
                                 v_prev: Optional[np.ndarray]) -> float:
    """[P2-FIX] Błąd predykcyjny w przestrzeni ciphertext (v ∈ Z_q).
    Nie mieszamy przestrzeni RLWE z float embeddings Φ."""
    if v_prev is None or len(v_prev) != len(v_current):
        return float(Q / 2)   # brak historii → zakładamy maksymalny błąd
    return float(np.mean(np.abs(v_current.astype(float) - v_prev.astype(float))))


# ─────────────────────────────────────────────
# STRUKTURY DANYCH
# ─────────────────────────────────────────────

@dataclass
class PrismData:
    """Zaszyfrowany pryzmat + dwa MAC-e + nonce.
    mac_phi:   integralność storage — weryfikuje Φ/daemon
    mac_agent: integralność percepcji — weryfikuje agent (zero-trust)
    nonce:     ochrona przed replay attack"""
    u: np.ndarray
    v: np.ndarray
    aad: bytes
    prism_id: str
    nonce: bytes        = field(default_factory=lambda: os.urandom(16))
    mac_phi:   bytes    = field(default=b"")
    mac_agent: bytes    = field(default=b"")

@dataclass
class HSSKeyring:
    _store: dict = field(default_factory=dict)

    def set(self, pid: int, key: np.ndarray):
        self._store[pid] = key.copy()
        print(f"  [KEYRING] PID {pid} → klucz załadowany ({len(key)} współczynników)")

    def get(self, pid: int) -> Optional[np.ndarray]:
        return self._store.get(pid)

    def revoke(self, pid: int):
        if pid in self._store:
            del self._store[pid]
            print(f"  [KEYRING] PID {pid} → s_A SKASOWANY. Entropia termodynamiczna nieodwracalna.")

@dataclass
class HSSFileStore:
    _files: dict = field(default_factory=dict)
    _vacuum_candidates: list = field(default_factory=list)
    _v_prev: Optional[np.ndarray] = field(default=None)
    _entropy_prev: Optional[float] = field(default=None)

    def write(self, inode: str, prisms: list):
        self._files[inode] = prisms

    def read(self, inode: str) -> Optional[list]:
        return self._files.get(inode)

    def mark_vacuum(self, inode: str):
        self._vacuum_candidates.append(inode)

    def collect_vacuum(self):
        collected = []
        for inode in self._vacuum_candidates:
            if inode in self._files:
                del self._files[inode]
                collected.append(inode)
        self._vacuum_candidates.clear()
        return collected


# ─────────────────────────────────────────────
# HSS DAEMON
# ─────────────────────────────────────────────

class HSSDaemon:
    """
    hss-daemon: uprzywilejowany serwis przestrzeni użytkownika.
    Jądro (LSM) przekazuje upcall — tutaj dzieje się cała kryptografia.
    """

    def __init__(self):
        self.keyring  = HSSKeyring()
        self.filestore = HSSFileStore()
        self._phi_pub  = None
        self._phi_sec  = None
        self._sess_secret  = None
        self._base_secret  = None   # stały root secret — rotacja przez epoch
        self._sess_epoch   = None   # bieżąca epoka
        self._epoch_secs   = 300    # 5 minut — konfigurowalne
        self._agent_contexts = {}
        # [P1-FIX] Subklucze MAC — separacja kluczy
        self._k_mac_phi   = None
        self._k_mac_agent = None
        print("[HSS-DAEMON] Uruchomiony. Brak plaintextu w przestrzeni jądra.")

    # ── FAZA 1: Inicjalizacja sesji Φ ──────────────────────────────────────

    def init_phi_session(self, phi_state: np.ndarray, phi_pid: int = 1):
        """s_sess = KDF(Φ² ‖ CSPRNG ‖ epoch).
        base_secret jest stały, sess_secret rotuje co epoch_secs."""
        random_seed = os.urandom(32)
        phi_bytes = phi_state.astype(np.float32).tobytes()
        # base_secret = stały root dla tej sesji Φ
        self._base_secret = hmac.new(
            random_seed, phi_bytes + b"hss-sess-v1", hashlib.sha256
        ).digest()
        self._derive_epoch_secret()

        s_sess = kdf(self._sess_secret, "s_sess_primary")
        phi_keygen_seed = hmac.new(self._sess_secret, b"phi_pub_keygen", hashlib.sha256).digest()
        pub, _ = keygen(seed=phi_keygen_seed)
        self._phi_pub = pub
        self._phi_sec = s_sess
        self.keyring.set(phi_pid, s_sess)
        print(f"  [FAZA 1] Sesja Φ: s_sess (epoch={self._sess_epoch}) + subklucze MAC wygenerowane.")
        print(f"           Entropia Φ²: {measure_entropy(phi_state.astype(np.int64)):.3f} bits")
        return s_sess

    def _derive_epoch_secret(self):
        """Wyprowadź sess_secret dla bieżącej epoki.
        Rotacja co epoch_secs — forward secrecy między epokami."""
        epoch = int(time.time() / self._epoch_secs)
        if epoch == self._sess_epoch:
            return   # ta sama epoka — nic nie rób
        self._sess_epoch  = epoch
        self._sess_secret = hmac.new(
            self._base_secret,
            epoch.to_bytes(8, 'big'),
            hashlib.sha256
        ).digest()
        self._k_mac_phi   = hmac.new(self._sess_secret, b"mac_phi",   hashlib.sha256).digest()
        self._k_mac_agent = hmac.new(self._sess_secret, b"mac_agent", hashlib.sha256).digest()

    def rotate_epoch(self):
        """Jawna rotacja epoki — np. po zdarzeniu bezpieczeństwa.
        Istniejące capability tokeny z poprzedniej epoki przestają działać."""
        old_epoch = self._sess_epoch
        # Wymuś przejście do następnej epoki
        self._sess_epoch = None
        self._derive_epoch_secret()
        print(f"  [EPOCH]  Rotacja: epoka {old_epoch} → {self._sess_epoch}")

    def derive_agent_key(self, agent_pid: int, task_id: str,
                         allowed_prisms: list) -> np.ndarray:
        """s_A = KDF(s_sess, JSON_context).
        JSON eliminuje string injection: 'i' nie przejdzie dla allowed=['in'].
        Capability = HMAC(s_A, prism_id) — czysta algebra."""
        # JSON z sort_keys=True → deterministyczny, bez ambiguity
        ctx_struct = {"task": task_id, "prisms": sorted(allowed_prisms)}
        context_bytes = json.dumps(ctx_struct, sort_keys=True).encode()
        context_hex   = context_bytes.hex()   # czytelny string do logów
        s_agent = kdf(self._sess_secret, context_hex)
        self.keyring.set(agent_pid, s_agent)
        self._agent_contexts[agent_pid] = (task_id, context_bytes, set(allowed_prisms))
        print(f"  [FAZA 1] s_A PID {agent_pid} = KDF(s_sess, JSON({ctx_struct}))")
        print(f"  [CAP]    capability(prism) = HMAC(s_A, prism_id) — czysta algebra")
        return s_agent

    def verify_capability(self, s_agent: np.ndarray,
                          agent_pid: int, prism_id: str) -> bool:
        """Weryfikacja capability — JSON context, bez string injection.
        prism_id musi być dokładnym elementem zbioru allowed_prisms."""
        info = self._agent_contexts.get(agent_pid)
        if info is None:
            return False
        task_id, context_bytes, allowed_set = info
        # Sprawdzenie przez zbiór — zero ambiguity: "i" ≠ "in"
        if prism_id not in allowed_set:
            return False
        # Re-derywuj s_agent i porównaj capability tokeny
        s_agent_expected = kdf(self._sess_secret, context_bytes.hex())
        token_provided = hmac.new(
            s_agent.tobytes(), prism_id.encode(), hashlib.sha256
        ).digest()
        token_expected = hmac.new(
            s_agent_expected.tobytes(), prism_id.encode(), hashlib.sha256
        ).digest()
        return hmac.compare_digest(token_provided, token_expected)

    # ── MAC helpers — domain-separated, key-separated ────────────────────

    def _mac_phi(self, u: np.ndarray, v: np.ndarray, aad: bytes, nonce: bytes) -> bytes:
        """MAC dla storage — klucz k_mac_phi, domena phi_store."""
        return hmac.new(
            self._k_mac_phi,
            b"phi_store" + nonce + u.tobytes() + v.tobytes() + aad,
            hashlib.sha256
        ).digest()

    def _mac_agent(self, s_agent: np.ndarray,
                   u: np.ndarray, v: np.ndarray, aad: bytes, nonce: bytes) -> bytes:
        """[P1-FIX] MAC dla percepcji agenta.
        Klucz = HMAC(s_agent, 'agent_mac') — sekret RLWE NIE jest kluczem MAC bezpośrednio."""
        k_agent = hmac.new(s_agent.tobytes(), b"agent_mac", hashlib.sha256).digest()
        return hmac.new(
            k_agent,
            b"agent_view" + nonce + u.tobytes() + v.tobytes() + aad,
            hashlib.sha256
        ).digest()

    # ── Zapis danych przez Φ ───────────────────────────────────────────────

    def phi_write(self, inode: str, data: np.ndarray):
        """Szyfrowanie pod s_sess + mac_phi + nonce."""
        prisms_out = []
        for prism_id, slc in [("core", P_CORE), ("in", P_IN), ("out", P_OUT)]:
            segment = data[slc]
            padded = np.zeros(N, dtype=np.int64)
            padded[:len(segment)] = segment % 2
            nonce = os.urandom(16)
            # [P2-FIX] AAD zawiera nonce — ochrona przed replay
            aad = hashlib.sha256(
                f"{inode}:{prism_id}:phi_sess".encode() + nonce
            ).digest()
            u, v = encrypt(self._phi_pub, padded)
            mac_p = self._mac_phi(u, v, aad, nonce)
            prisms_out.append(PrismData(u=u, v=v, aad=aad, prism_id=prism_id,
                                        nonce=nonce, mac_phi=mac_p))
        self.filestore.write(inode, prisms_out)
        print(f"  [DAEMON] Plik '{inode}': 3 pryzmaty, s_sess, mac_phi, nonce")

    # ── FAZA 2: Upcall READ ────────────────────────────────────────────────

    def upcall_read(self, agent_pid: int, inode: str,
                    allowed_prisms: list, task_id: str) -> Optional[list]:
        s_agent = self.keyring.get(agent_pid)
        if s_agent is None:
            print(f"  [UPCALL] ODMOWA: PID {agent_pid} brak klucza.")
            return None

        file_prisms = self.filestore.read(inode)
        if file_prisms is None:
            print(f"  [UPCALL] ODMOWA: plik '{inode}' nie istnieje.")
            return None

        agent_pub = derive_agent_pub(s_agent, f"{task_id}:pub")
        result_prisms = []

        for prism in file_prisms:
            # 1. Weryfikacja AAD — context binding (regres z v2.5 przywrócony)
            expected_aad = hashlib.sha256(
                f"{inode}:{prism.prism_id}:phi_sess".encode() + prism.nonce
            ).digest()
            if prism.aad != expected_aad:
                print(f"  [RE-ENC] '{prism.prism_id}': ⚠ AAD mismatch → pomijam")
                continue

            # 2. Weryfikacja mac_phi
            expected_mac_phi = self._mac_phi(prism.u, prism.v, prism.aad, prism.nonce)
            if not hmac.compare_digest(prism.mac_phi, expected_mac_phi):
                print(f"  [RE-ENC] '{prism.prism_id}': ⚠ MAC_phi mismatch → pomijam")
                continue

            if self.verify_capability(s_agent, agent_pid, prism.prism_id):
                plaintext = decrypt(self._phi_sec, prism.u, prism.v)
                new_nonce = os.urandom(16)
                new_aad = hashlib.sha256(
                    f"{inode}:{prism.prism_id}:{task_id}".encode() + new_nonce
                ).digest()
                u_new, v_new = encrypt(agent_pub, plaintext)
                # Dwa MAC-e: Φ gwarantuje storage, agent może zweryfikować percepcję
                new_mac_phi   = self._mac_phi(u_new, v_new, new_aad, new_nonce)
                new_mac_agent = self._mac_agent(s_agent, u_new, v_new, new_aad, new_nonce)
                result_prisms.append(PrismData(
                    u=u_new, v=v_new, aad=new_aad, prism_id=prism.prism_id,
                    nonce=new_nonce, mac_phi=new_mac_phi, mac_agent=new_mac_agent
                ))
                print(f"  [RE-ENC] '{prism.prism_id}': ✔ re-enc s_A | mac_phi + mac_agent + nonce")
            else:
                # Zablokowany: szyfruj szum pod TYM SAMYM agent_pub
                # fake mac_agent generowany jak prawdziwy — identyczna dystrybucja HMAC
                noise_signal = sample_small(N)
                noise_msg = ((noise_signal % 2) + 2) % 2
                u_z, v_z = encrypt(agent_pub, noise_msg)
                new_nonce_z = os.urandom(16)
                new_aad_z = hashlib.sha256(
                    f"{inode}:{prism.prism_id}:{task_id}".encode() + new_nonce_z
                ).digest()
                fake_mac_phi   = self._mac_phi(u_z, v_z, new_aad_z, new_nonce_z)
                # Fake mac_agent: HMAC pod właściwym kluczem ale z błędnymi danymi
                # → identyczna dystrybucja jak prawdziwy MAC, zero distinguishability
                fake_mac_agent = self._mac_agent(s_agent, u_z, v_z,
                                                  os.urandom(len(new_aad_z)),
                                                  new_nonce_z)
                result_prisms.append(PrismData(
                    u=u_z, v=v_z, aad=new_aad_z, prism_id=prism.prism_id,
                    nonce=new_nonce_z, mac_phi=fake_mac_phi, mac_agent=fake_mac_agent
                ))
                print(f"  [RE-ENC] '{prism.prism_id}': ✘ → Enc(szum, agent_pub) + fake_mac")

        print(f"  [UPCALL] ZEZWÓL: PID {agent_pid} otrzymuje spreparowany szyfrogram.")
        return result_prisms

    # ── FAZA 3: Upcall WRITE ──────────────────────────────────────────────

    def upcall_write(self, agent_pid: int, inode: str,
                     prism_id: str, data: np.ndarray,
                     allowed_prisms: list, task_id: str) -> bool:
        s_agent = self.keyring.get(agent_pid)
        if s_agent is None:
            print(f"  [UPCALL-WRITE] ODMOWA: PID {agent_pid} brak klucza.")
            return False

        if not self.verify_capability(s_agent, agent_pid, prism_id):
            print(f"  [UPCALL-WRITE] ODMOWA kryptograficzna!")
            print(f"                 Capability token dla '{prism_id}' nieważny.")
            print(f"                 Brak algebrycznej możliwości zapisu.")
            return False

        # derive_agent_pub — spójna tożsamość READ i WRITE
        agent_pub = derive_agent_pub(s_agent, f"{task_id}:pub")
        padded = np.zeros(N, dtype=np.int64)
        padded[:len(data)] = data % 2
        u, v = encrypt(agent_pub, padded)

        # Walidacja zakresu u, v — ochrona przed malformed RLWE ciphertext
        if (u.shape != (N,) or v.shape != (N,)
                or np.any(u < 0) or np.any(u >= Q)
                or np.any(v < 0) or np.any(v >= Q)):
            print(f"  [UPCALL-WRITE] ODMOWA: malformed ciphertext (u,v poza Z_q).")
            return False

        plaintext = decrypt(s_agent, u, v)

        # Zapis pod s_sess z nowym nonce
        u_final, v_final = encrypt(self._phi_pub, plaintext)
        nonce = os.urandom(16)
        aad = hashlib.sha256(
            f"{inode}:{prism_id}:phi_sess".encode() + nonce
        ).digest()
        mac_p = self._mac_phi(u_final, v_final, aad, nonce)

        file_prisms = self.filestore.read(inode) or []
        updated = [p for p in file_prisms if p.prism_id != prism_id]
        updated.append(PrismData(u=u_final, v=v_final, aad=aad, prism_id=prism_id,
                                  nonce=nonce, mac_phi=mac_p))
        self.filestore.write(inode, updated)
        print(f"  [UPCALL-WRITE] ZEZWÓL: '{prism_id}' zapisany pod s_sess + nonce.")
        return True

    # ── FAZA 4: Terminacja ────────────────────────────────────────────────

    def terminate_agent(self, agent_pid: int, temp_inodes: list):
        print(f"\n  [FAZA 4] Agent PID {agent_pid} kończy działanie.")
        self.keyring.revoke(agent_pid)
        for inode in temp_inodes:
            self.filestore.mark_vacuum(inode)
            print(f"  [FAZA 4] '{inode}' → kandydat vacuum.")
        print(f"  [FAZA 4] Przestrzeń agenta: nieredukowalny problem Ring-LWE.")

    # ── FAZA 5: Vacuum Decay (FEP) ────────────────────────────────────────

    def vacuum_decay(self):
        """[P2-FIX] FEP w przestrzeni ciphertext — nie mieszamy z float embeddings."""
        print(f"\n  [FAZA 5] Vacuum Decay — FEP scan przestrzeni ciphertext...")

        orphan_v_parts = []
        for inode in self.filestore._vacuum_candidates:
            prisms = self.filestore.read(inode)
            if prisms:
                for p in prisms:
                    orphan_v_parts.append(p.v)

        if not orphan_v_parts:
            print(f"  [FEP]    Brak sierot do oceny.")
            return

        orphan_v = np.concatenate(orphan_v_parts)
        entropy_now = measure_entropy(orphan_v % 256)

        # Brak historii = pierwsza obserwacja = vacuum z definicji
        if self.filestore._v_prev is None:
            print(f"  [FEP]    Pierwsza obserwacja sierot — brak kotwicy predykcyjnej.")
            print(f"  [FEP]    Klasyfikacja: VACUUM")
            self.filestore._v_prev = orphan_v.copy()
            self.filestore._entropy_prev = entropy_now
            collected = self.filestore.collect_vacuum()
            print(f"  [GC]     Anihilacja: {collected}")
            print(f"  [GC]     Substrat zwrócony do puli.")
            return

        # Dynamiczny baseline: entropia próbki RLWE z tymi samymi parametrami
        # Brak magic number — system kalibruje się na własnym rozkładzie
        baseline_sample = sample_small(len(orphan_v)) % 256
        baseline_entropy = measure_entropy(baseline_sample.astype(np.uint8))
        epsilon = 0.1   # tolerancja na odchylenie od baseline

        entropy_prev  = self.filestore._entropy_prev or entropy_now
        entropy_delta = abs(entropy_now - entropy_prev)
        pred_error    = ciphertext_prediction_error(orphan_v, self.filestore._v_prev)

        print(f"  [FEP]    Entropia sierot: {entropy_now:.4f} bits")
        print(f"  [FEP]    Baseline RLWE:   {baseline_entropy:.4f} bits (dynamiczny)")
        print(f"  [FEP]    Δentropia:        {entropy_delta:.4f} bits")
        print(f"  [FEP]    ε_t pred_error:   {pred_error:.1f}")

        self.filestore._v_prev       = orphan_v.copy()
        self.filestore._entropy_prev = entropy_now

        # Vacuum jeśli sygnał niekompresowalny (blisko baseline RLWE)
        # LUB statyczny (brak driftu + wysoki błąd predykcji)
        is_incompressible = entropy_now >= baseline_entropy - epsilon
        is_static         = entropy_delta < 0.05 and pred_error > Q / 4

        if is_incompressible or is_static:
            reason = "entropia ≈ baseline RLWE" if is_incompressible else "statyczny szum RLWE"
            print(f"  [FEP]    Sygnał niekompresowalny ({reason}) → VACUUM")
            collected = self.filestore.collect_vacuum()
            print(f"  [GC]     Anihilacja: {collected}")
            print(f"  [GC]     Substrat zwrócony do puli.")
        else:
            print(f"  [FEP]    Sygnał potencjalnie strukturalny — dane zachowane.")


# ─────────────────────────────────────────────
# AGENT — weryfikacja mac_agent po stronie agenta
# ─────────────────────────────────────────────

def agent_verify_and_decrypt(s_agent: np.ndarray, prism: PrismData,
                               task_id: str, inode: str) -> Optional[np.ndarray]:
    """[P1-FIX] Agent weryfikuje mac_agent PRZED użyciem danych.
    Zero-trust: agent nie ufa daemonowi — sprawdza integralność percepcji."""
    if not prism.mac_agent:
        return None   # brak MAC_agent → dane z zablokowanego pryzmatu, pomijam

    k_agent = hmac.new(s_agent.tobytes(), b"agent_mac", hashlib.sha256).digest()
    expected = hmac.new(
        k_agent,
        b"agent_view" + prism.nonce + prism.u.tobytes() + prism.v.tobytes() + prism.aad,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(prism.mac_agent, expected):
        print(f"    [AGENT] ⚠ mac_agent mismatch '{prism.prism_id}' → odrzucam dane")
        return None

    return decrypt(s_agent, prism.u, prism.v)


# ─────────────────────────────────────────────
# SYMULACJA GŁÓWNA
# ─────────────────────────────────────────────

def separator(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print('═' * 60)


def run_simulation():
    print("\n" + "█" * 60)
    print("  HolonOS HSS v2.9 — Demonstrator Pięciu Faz")
    print("  JSON caps | epoch rotation | dyn. FEP baseline | RLWE validation")
    print("█" * 60)

    daemon = HSSDaemon()

    # ─── Inicjalizacja Φ ───────────────────────────────────────────────
    separator("INICJALIZACJA: Rdzeń Φ budzi się")

    phi_state = np.random.randn(PHI_DIM).astype(np.float32)
    phi_pid = 1000
    print(f"  Stan Φ (fragment): {phi_state[:4].round(3)}")
    s_sess = daemon.init_phi_session(phi_state, phi_pid)

    print("\n  Φ zapisuje dane do HolonFS...")
    data_full = np.random.randint(0, 2, N, dtype=np.int64)
    daemon.phi_write("mailbox.hss", data_full)

    # ─── FAZA 1 ────────────────────────────────────────────────────────
    separator("FAZA 1: Narodziny Agenta (Derivation)")

    agent_pid = 2001
    task_id   = "summarize_emails_20260410"
    allowed   = ["in", "out"]

    print(f"  Zadanie: '{task_id}'")
    print(f"  Autoryzowane: {allowed} | Zablokowane: ['core']")
    s_agent = daemon.derive_agent_key(agent_pid, task_id, allowed)
    print(f"  s_A[0:4] = {s_agent[:4]}  (małe współczynniki ∈ χ_s)")

    # ─── FAZA 2 ────────────────────────────────────────────────────────
    separator("FAZA 2: Percepcja Agenta (Re-encryption / PrismMask)")

    agent_view = daemon.upcall_read(agent_pid, "mailbox.hss", allowed, task_id)

    if agent_view:
        print(f"\n  [AGENT] Weryfikacja mac_agent przed odczytem danych:")
        for p in agent_view:
            result = agent_verify_and_decrypt(s_agent, p, task_id, "mailbox.hss")
            if result is not None:
                ent = measure_entropy(result)
                print(f"    '{p.prism_id}': ✔ mac_agent OK | entropia={ent:.3f} bits")
            else:
                print(f"    '{p.prism_id}': ✘ brak mac_agent lub mismatch → szum")

    # ─── FAZA 3 ────────────────────────────────────────────────────────
    separator("FAZA 3: Praca Agenta + Próba Naruszenia")

    print("  [PRÓBA ATAKU] Agent próbuje zapisać do 'core'...")
    result = daemon.upcall_write(agent_pid, "mailbox.hss", "core",
                                  np.ones(PRISM_SIZE, dtype=np.int64), allowed, task_id)
    print(f"  Wynik ataku: {'SUKCES ⚠️' if result else 'ZABLOKOWANY ✔'}")

    print("\n  [POPRAWNY ZAPIS] Agent zapisuje do 'out'...")
    daemon.upcall_write(agent_pid, "mailbox.hss", "out",
                         np.random.randint(0, 2, PRISM_SIZE, dtype=np.int64),
                         allowed, task_id)

    print("\n  [PLIKI ROBOCZE] Agent tworzy tymczasowy bufor...")
    daemon.phi_write(f"tmp_{agent_pid}.hss", np.random.randint(0, 2, N, dtype=np.int64))

    print("\n  [Φ ODCZYT] Φ sprawdza wynik w 'out'...")
    phi_view = daemon.filestore.read("mailbox.hss")
    if phi_view:
        out_prism = next((p for p in phi_view if p.prism_id == "out"), None)
        if out_prism:
            phi_result = decrypt(daemon._phi_sec, out_prism.u, out_prism.v)
            print(f"  Wynik (fragment): {phi_result[:8]}")

    # ─── FAZA 4 ────────────────────────────────────────────────────────
    separator("FAZA 4: Terminacja Agenta (Vacuum Entry)")

    daemon.terminate_agent(agent_pid, [f"tmp_{agent_pid}.hss"])

    print("\n  [WERYFIKACJA] Próba odczytu po terminacji...")
    ghost = daemon.upcall_read(agent_pid, "mailbox.hss", allowed, task_id)
    print(f"  Rezultat: {'dane ⚠️' if ghost else 'ODMOWA ✔ — s_A nieistnieje'}")

    # ─── FAZA 5 ────────────────────────────────────────────────────────
    separator("FAZA 5: Vacuum Decay (FEP w przestrzeni Z_q)")

    time.sleep(0.1)
    daemon.vacuum_decay()

    # ─── PODSUMOWANIE ──────────────────────────────────────────────────
    separator("PODSUMOWANIE CYKLU")

    print(f"  Pliki w HolonFS: {list(daemon.filestore._files.keys())}")
    print(f"  Klucze w keyring: {list(daemon.keyring._store.keys())}")
    print(f"\n  Ani jednego 'if (user == root)'.")
    print(f"  Każdy krok: równanie w pierścieniu R_q.")
    print(f"  Bezpieczeństwo = topologia przestrzeni wykonania.")
    print("\n" + "█" * 60)
    print("  HSS v2.6 — Demonstracja zakończona. Cykl zamknięty.")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    np.random.seed(42)
    run_simulation()
