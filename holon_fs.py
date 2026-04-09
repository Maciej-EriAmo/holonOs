# -*- coding: utf-8 -*-
"""
holon_fs.py v1.1.0
HolonFS — Semantic Filesystem Index for Unix/Linux

NOWOŚCI v1.1.0:
- Rozszerzony słownik KuRz (PL+EN, terminologia techniczna)
- Daemon mode z Unix socket
- Tryb interaktywny z pętlą wyszukiwania
- Klient CLI

Użycie:
  python holon_fs.py                        # self-test
  python holon_fs.py <katalog> --interactive  # tryb interaktywny
  python holon_fs.py <katalog> --daemon       # daemon w tle
  python holon_fs.py <katalog> --scan         # skanuj i zapisz

Autor: Maciej Mazur, 2026
"""

import os
import sys
import re
import struct
import threading
import time
import json
import hashlib
import socket
import logging
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict

import numpy as np

SOCKET_PATH = '/tmp/holon_fs.sock'

# ── Opcjonalne xattr ─────────────────────────────────────────────────────────
try:
    import xattr as _xattr
    XATTR_AVAILABLE = True
except ImportError:
    XATTR_AVAILABLE = False

# ── Opcjonalne inotify ───────────────────────────────────────────────────────
try:
    import inotify.adapters
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# STAŁE
# ─────────────────────────────────────────────────────────────────────────────

HOLON_NS    = "user.holon"
AXES        = ['radość', 'smutek', 'strach', 'gniew', 'miłość', 'wstręt',
               'zaskoczenie', 'akceptacja', 'logika', 'wiedza', 'czas',
               'kreacja', 'byt', 'przestrzeń', 'chaos']
DIMENSION   = len(AXES)          # 15
DTYPE       = np.float32
DTYPE_BYTES = 4
VEC_BYTES   = DIMENSION * DTYPE_BYTES  # 60 bajtów

DEPTH_MAP = {
    1: 1.2,   # dialog/płytkie → wysoka krzywizna → zanika
    2: 0.5,   # przetworzone   → średnia krzywizna → trwa
    3: 0.15,  # rdzeń/pamiętaj → niska krzywizna   → zawsze
}

SUPPORTED_TEXT = {'.md', '.txt', '.py', '.sh', '.c', '.cpp', '.h',
                  '.rs', '.go', '.js', '.ts', '.json', '.yaml', '.yml',
                  '.toml', '.cfg', '.ini', '.log', '.html', '.css'}

logging.basicConfig(level=logging.INFO,
                    format='[HOLON] %(levelname)s %(message)s')
log = logging.getLogger('holon_fs')


# ─────────────────────────────────────────────────────────────────────────────
# XATTR BACKEND
# ─────────────────────────────────────────────────────────────────────────────

class XAttrBackend:
    """
    Cienka warstwa nad xattr syscall.
    Fallback: plik .holon_meta/<inode>.json gdy xattr niedostępne
    (FAT, FUSE /sdcard, itp.)
    """

    VECTOR_KEY   = f"{HOLON_NS}.vec"
    DEPTH_KEY    = f"{HOLON_NS}.depth"
    BORN_KEY     = f"{HOLON_NS}.born"
    HASH_KEY     = f"{HOLON_NS}.hash"

    def __init__(self, fallback_dir: Optional[str] = None):
        self.use_xattr    = XATTR_AVAILABLE
        self.fallback_dir = fallback_dir
        self._fallback_db: Dict[str, dict] = {}

        if not self.use_xattr:
            log.warning("python-xattr niedostępne — używam fallback JSON")
            if fallback_dir:
                self._load_fallback(fallback_dir)

    # ── Zapis ────────────────────────────────────────────────────────────────

    def write(self, path: str, vector: np.ndarray,
              depth: int = 1, born: Optional[float] = None) -> bool:
        born   = born or time.time()
        vec_b  = vector.astype(DTYPE).tobytes()
        born_b = struct.pack('d', born)
        h      = hashlib.sha1(vec_b).digest()[:8]

        if self.use_xattr:
            try:
                _xattr.setxattr(path, self.VECTOR_KEY, vec_b)
                _xattr.setxattr(path, self.DEPTH_KEY,  bytes([depth & 0xFF]))
                _xattr.setxattr(path, self.BORN_KEY,   born_b)
                _xattr.setxattr(path, self.HASH_KEY,   h)
                return True
            except OSError as e:
                log.debug(f"xattr write failed {path}: {e}")
                # Fallthrough do fallback

        # Fallback
        self._fallback_db[path] = {
            'vec':   vector.tolist(),
            'depth': depth,
            'born':  born,
        }
        return True

    # ── Odczyt ───────────────────────────────────────────────────────────────

    def read(self, path: str) -> Optional[Tuple[np.ndarray, int, float]]:
        if self.use_xattr:
            try:
                vec_b  = _xattr.getxattr(path, self.VECTOR_KEY)
                depth  = _xattr.getxattr(path, self.DEPTH_KEY)[0]
                born_b = _xattr.getxattr(path, self.BORN_KEY)
                vec    = np.frombuffer(vec_b, dtype=DTYPE).copy()
                born   = struct.unpack('d', born_b)[0]
                if len(vec) == DIMENSION:
                    return vec, depth, born
            except OSError:
                pass

        # Fallback
        rec = self._fallback_db.get(path)
        if rec:
            return np.array(rec['vec'], dtype=DTYPE), rec['depth'], rec['born']
        return None

    def delete(self, path: str):
        if self.use_xattr:
            for key in (self.VECTOR_KEY, self.DEPTH_KEY,
                        self.BORN_KEY,   self.HASH_KEY):
                try:
                    _xattr.removexattr(path, key)
                except OSError:
                    pass
        self._fallback_db.pop(path, None)

    def _load_fallback(self, directory: str):
        p = os.path.join(directory, '.holon_meta.json')
        if os.path.exists(p):
            try:
                with open(p, 'r') as f:
                    self._fallback_db = json.load(f)
                log.info(f"Fallback: wczytano {len(self._fallback_db)} rekordów")
            except Exception as e:
                log.warning(f"Fallback load error: {e}")

    def save_fallback(self, directory: str):
        p = os.path.join(directory, '.holon_meta.json')
        try:
            with open(p, 'w') as f:
                json.dump(self._fallback_db, f)
        except Exception as e:
            log.warning(f"Fallback save error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# KURZ EMBEDDER  (offline, bez modelu)
# ─────────────────────────────────────────────────────────────────────────────

class KuRzEmbedder:
    """
    Offline co-occurrence embedder do przestrzeni 15D (AXES).
    Dla każdego osi: liczy wagę przez słowa-klucze i ich co-occurrence.
    Deterministyczny — ten sam tekst → ten sam wektor.
    """

    # v1.1 — rozszerzony słownik PL+EN
    KEYWORDS: Dict[int, List[str]] = {
        0:  ['radość', 'szczęście', 'happy', 'joy', 'dobry', 'good', 'great',
             'awesome', 'success', 'pass', 'passed', 'ok', 'done', 'complete',
             'works', 'working', 'fixed', 'solved', 'win', 'perfect', 'yes'],
        1:  ['smutek', 'sad', 'brak', 'utrata', 'loss', 'missing',
             'deprecated', 'removed', 'deleted', 'gone', 'failed', 'failure',
             'broken', 'crash', 'dead', 'null', 'none', 'empty', 'void',
             'undefined', 'nan', 'unavailable'],
        2:  ['strach', 'fear', 'błąd', 'error', 'danger', 'warning', 'warn',
             'critical', 'fatal', 'panic', 'exception', 'traceback', 'stderr',
             'alert', 'unsafe', 'insecure', 'vulnerability', 'cve', 'exploit',
             'attack', 'threat', 'risk', 'abort', 'segfault', 'overflow',
             'invalid', 'unauthorized', '403', '500', '502', '503'],
        3:  ['gniew', 'anger', 'conflict', 'problem', 'issue', 'bug', 'fail',
             'reject', 'refused', 'blocked', 'timeout', 'deadlock', 'race',
             'leak', 'corruption', 'malformed', 'unexpected', 'wrong',
             'mismatch', 'collision', 'duplicate', 'denied', 'forbidden'],
        4:  ['miłość', 'love', 'pasja', 'beautiful', 'elegant', 'clean',
             'design', 'creative', 'inspired', 'vision', 'heart', 'soul',
             'magic', 'amazing', 'incredible', 'brilliant'],
        5:  ['wstręt', 'reject', 'deprecated', 'legacy', 'old', 'outdated',
             'obsolete', 'trash', 'garbage', 'junk', 'unused', 'hack',
             'workaround', 'fixme', 'bad', 'ugly', 'mess', 'bloat', 'waste'],
        6:  ['zaskoczenie', 'nowy', 'new', 'update', 'upgrade', 'release',
             'version', 'changelog', 'breaking', 'migration', 'refactor',
             'rewrite', 'feature', 'added', 'introducing', 'experimental',
             'beta', 'alpha', 'preview', 'discover'],
        7:  ['akceptacja', 'stable', 'ready', 'approved', 'merged', 'lgtm',
             'confirmed', 'verified', 'validated', 'production', 'prod',
             'shipped', 'deployed', 'live', 'main', 'master', 'accepted',
             'finalized', 'ok', 'done', 'pass', 'success'],
        8:  ['logika', 'logic', 'algorytm', 'algorithm', 'kod', 'code',
             'func', 'function', 'def', 'class', 'method', 'return',
             'import', 'if', 'for', 'while', 'loop', 'recursion',
             'sort', 'search', 'parse', 'compile', 'execute', 'runtime',
             'async', 'await', 'thread', 'struct', 'enum', 'interface',
             'inherit', 'lambda', 'iterator', 'decorator', 'module',
             'package', 'library', 'framework', 'api', 'sdk', 'impl',
             'implementation', 'optimize', 'benchmark', 'complexity',
             'cache', 'index', 'hash', 'tree', 'graph', 'queue', 'stack',
             'array', 'matrix', 'vector', 'tensor', 'dtype', 'numpy',
             'pandas', 'torch', 'sklearn', 'pytest', 'assert', 'mock'],
        9:  ['wiedza', 'knowledge', 'dane', 'data', 'info', 'information',
             'dokument', 'document', 'doc', 'docs', 'readme', 'note', 'notes',
             'wiki', 'manual', 'spec', 'specification', 'guide', 'tutorial',
             'howto', 'faq', 'reference', 'report', 'analysis', 'research',
             'paper', 'summary', 'description', 'comment', 'annotation',
             'metadata', 'schema', 'model', 'dataset', 'database', 'record',
             'table', 'query', 'sql', 'csv', 'json', 'xml'],
        10: ['czas', 'time', 'date', 'timestamp', 'datetime', 'historia',
             'history', 'log', 'logs', 'wersja', 'version', 'changelog',
             'schedule', 'cron', 'daily', 'weekly', 'created', 'modified',
             'updated', 'expired', 'deadline', 'duration', 'interval',
             'period', 'session', 'epoch', 'clock', 'timer', 'timeout',
             'delay', 'latency', 'uptime', 'backup', 'archive', 'snapshot',
             'rollback', 'restore', 'audit', 'retention'],
        11: ['kreacja', 'create', 'build', 'make', 'generate', 'new',
             'init', 'setup', 'install', 'scaffold', 'bootstrap', 'deploy',
             'projekt', 'project', 'design', 'architect', 'plan', 'draft',
             'prototype', 'template', 'boilerplate', 'write', 'compose',
             'develop', 'implement', 'construct', 'add', 'push', 'publish',
             'launch', 'ship', 'deliver', 'produce', 'artifact',
             'makefile', 'dockerfile', 'ci', 'cd', 'pipeline', 'workflow'],
        12: ['byt', 'system', 'kernel', 'daemon', 'service', 'server',
             'process', 'pid', 'thread', 'container', 'docker', 'pod',
             'kubernetes', 'k8s', 'vm', 'virtual', 'instance', 'node',
             'host', 'machine', 'os', 'linux', 'unix', 'windows', 'android',
             'config', 'konfiguracja', 'env', 'environment', 'variable',
             'setting', 'option', 'flag', 'parameter', 'systemd', 'init',
             'boot', 'startup', 'shutdown', 'restart', 'mount', 'filesystem',
             'partition', 'disk', 'memory', 'ram', 'cpu', 'gpu',
             'network', 'interface', 'socket', 'port', 'cgroup', 'sandbox'],
        13: ['przestrzeń', 'space', 'path', 'directory', 'folder', 'file',
             'katalog', 'root', 'home', 'usr', 'etc', 'var', 'tmp', 'opt',
             'lib', 'bin', 'location', 'address', 'url', 'uri', 'endpoint',
             'route', 'namespace', 'scope', 'domain', 'subnet', 'ip',
             'host', 'dns', 'gateway', 'proxy', 'cdn', 'bucket', 'storage',
             'volume', 'mount', 'symlink', 'inode', 'xattr', 'permission',
             'chmod', 'chown', 'owner', 'group', 'acl', 'ssh', 'rsync'],
        14: ['chaos', 'random', 'losowy', 'tmp', 'temp', 'temporary',
             'test', 'tests', 'testing', 'debug', 'experiment', 'draft',
             'wip', 'todo', 'fixme', 'hack', 'spike', 'scratch', 'junk',
             'misc', 'various', 'other', 'stuff', 'untitled', 'unnamed',
             'unknown', 'undefined', 'tbd', 'placeholder', 'dummy', 'mock',
             'fake', 'stub', 'noise', 'sandbox', 'playground'],
    }

    def embed(self, text: str) -> np.ndarray:
        if not text:
            return np.zeros(DIMENSION, dtype=DTYPE)

        # Tokenizacja przez regex — obsługuje PL znaki i separatory
        tokens = re.findall(
            r'[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ0-9]+', text.lower()
        )
        total = max(len(tokens), 1)
        vec   = np.zeros(DIMENSION, dtype=np.float64)

        # Frequency score — token może być podciągiem słowa kluczowego i odwrotnie
        for i, kw_list in self.KEYWORDS.items():
            for token in tokens:
                if any(kw in token or token in kw for kw in kw_list):
                    vec[i] += 1.0
            vec[i] /= total

        # Co-occurrence bonus (window=5)
        window = 5
        for pos, token in enumerate(tokens):
            hits_i = [i for i, kw_list in self.KEYWORDS.items()
                      if any(kw in token or token in kw for kw in kw_list)]
            if not hits_i:
                continue
            ctx = tokens[max(0, pos-window): pos+window+1]
            for ctx_tok in ctx:
                hits_j = [j for j, kw_list in self.KEYWORDS.items()
                          if j not in hits_i and
                          any(kw in ctx_tok or ctx_tok in kw
                              for kw in kw_list)]
                for i in hits_i:
                    for j in hits_j:
                        vec[i] += 0.05 / total
                        vec[j] += 0.05 / total

        # Normalizacja L2
        norm = np.linalg.norm(vec)
        if norm > 1e-10:
            vec /= norm
        else:
            h   = int(hashlib.md5(text[:100].encode()).hexdigest(), 16)
            rng = np.random.RandomState(h % (2**31))
            vec = rng.dirichlet(np.ones(DIMENSION))

        return vec.astype(DTYPE)

    def embed_path(self, path: str) -> np.ndarray:
        text = re.sub(r'[/_\-.]', ' ', path.lower())
        return self.embed(text)

    def embed_file(self, path: str, max_bytes: int = 16384) -> np.ndarray:
        """Embed z treści pliku (70%) + ścieżki (30%)."""
        name = Path(path).name.lower()
        ext  = Path(path).suffix.lower()
        if ext not in SUPPORTED_TEXT and name not in SUPPORTED_TEXT:
            return self.embed_path(path)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(max_bytes)
            v_content = self.embed(content)
            v_path    = self.embed_path(path)
            mixed     = 0.7 * v_content + 0.3 * v_path
            norm      = np.linalg.norm(mixed)
            return (mixed / norm).astype(DTYPE) if norm > 1e-10 else v_path
        except (OSError, PermissionError):
            return self.embed_path(path)


# ─────────────────────────────────────────────────────────────────────────────
# HOLON INDEX  (numpy SIMD-friendly)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileRecord:
    path:    str
    vector:  np.ndarray
    depth:   int   = 1
    born:    float = field(default_factory=time.time)
    weight:  float = 1.0


class HolonIndex:
    """
    In-memory semantyczny indeks plików.
    Pełny skan 500k wektorów float32×15 ≈ 30MB RAM, <10ms query (AVX2).
    """

    INITIAL_CAPACITY = 4096

    def __init__(self):
        cap = self.INITIAL_CAPACITY
        self._vectors  = np.zeros((cap, DIMENSION), dtype=DTYPE)
        self._depths   = np.zeros(cap, dtype=np.uint8)
        self._weights  = np.ones(cap,  dtype=np.float32)
        self._paths:   List[str]   = []
        self._path2idx: Dict[str, int] = {}
        self._n        = 0
        self._lock     = threading.RLock()

    # ── Dodawanie / aktualizacja ─────────────────────────────────────────────

    def upsert(self, record: FileRecord):
        with self._lock:
            if record.path in self._path2idx:
                idx = self._path2idx[record.path]
            else:
                idx = self._n
                if idx >= len(self._vectors):
                    self._grow()
                self._paths.append(record.path)
                self._path2idx[record.path] = idx
                self._n += 1

            self._vectors[idx] = record.vector
            self._depths[idx]  = record.depth
            self._weights[idx] = record.weight

    def remove(self, path: str):
        with self._lock:
            if path not in self._path2idx:
                return
            idx = self._path2idx.pop(path)
            # Swap-delete (O(1))
            last = self._n - 1
            if idx != last:
                last_path = self._paths[last]
                self._vectors[idx]  = self._vectors[last]
                self._depths[idx]   = self._depths[last]
                self._weights[idx]  = self._weights[last]
                self._paths[idx]    = last_path
                self._path2idx[last_path] = idx
            self._paths.pop()
            self._n -= 1

    # ── Zapytania ────────────────────────────────────────────────────────────

    def query(self, q_vec: np.ndarray,
              top_k: int = 10,
              depth_filter: Optional[int] = None,
              threshold: float = 0.0) -> List[Tuple[str, float]]:
        """
        Semantyczne wyszukiwanie.
        Zwraca listę (path, similarity) posortowaną malejąco.
        O(n) dot-product, SIMD przez numpy.
        """
        with self._lock:
            if self._n == 0:
                return []

            vecs = self._vectors[:self._n]

            # Normalizacja zapytania
            norm = np.linalg.norm(q_vec)
            q    = q_vec / norm if norm > 1e-10 else q_vec

            # Cosine similarity (wektory już znormalizowane przy upsert)
            sims = vecs @ q  # shape: (n,)

            # Wagi
            sims *= self._weights[:self._n]

            # Filtr głębokości
            if depth_filter is not None:
                mask = self._depths[:self._n] == depth_filter
                sims[~mask] = -1.0

            # Top-k przez argpartition (O(n) nie O(n log n))
            k = min(top_k, self._n)
            top_idx = np.argpartition(sims, -k)[-k:]
            top_idx = top_idx[np.argsort(sims[top_idx])[::-1]]

            results = []
            for i in top_idx:
                s = float(sims[i])
                if s >= threshold:
                    results.append((self._paths[i], s))
            return results

    def stats(self) -> dict:
        with self._lock:
            depth_counts = defaultdict(int)
            for d in self._depths[:self._n]:
                depth_counts[int(d)] += 1
            return {
                'total':       self._n,
                'capacity':    len(self._vectors),
                'by_depth':    dict(depth_counts),
                'ram_mb':      round(self._vectors.nbytes / 1024 / 1024, 2),
            }

    def _grow(self):
        new_cap = len(self._vectors) * 2
        new_v   = np.zeros((new_cap, DIMENSION), dtype=DTYPE)
        new_d   = np.zeros(new_cap, dtype=np.uint8)
        new_w   = np.ones(new_cap, dtype=np.float32)
        new_v[:self._n] = self._vectors[:self._n]
        new_d[:self._n] = self._depths[:self._n]
        new_w[:self._n] = self._weights[:self._n]
        self._vectors   = new_v
        self._depths    = new_d
        self._weights   = new_w
        log.debug(f"HolonIndex grown → {new_cap}")


# ─────────────────────────────────────────────────────────────────────────────
# HOLON FS DAEMON
# ─────────────────────────────────────────────────────────────────────────────

class HolonFSd:
    """
    Semantyczny daemon systemu plików.

    Cykl życia:
      1. scan(root)       → rebuild indeksu z xattrów lub treści
      2. watch(root)      → inotify loop (background thread)
      3. query(meaning)   → semantyczne wyszukiwanie
      4. save_snapshot()  → opcjonalny JSON snapshot dla szybkiego startu
    """

    SNAPSHOT_FILE = ".holon_snapshot.json"

    def __init__(self, root: str = ".",
                 embedder: Optional[KuRzEmbedder] = None,
                 fallback_dir: Optional[str] = None,
                 verbose: bool = False):

        self.root      = os.path.abspath(root)
        self.embedder  = embedder or KuRzEmbedder()
        self.index     = HolonIndex()
        self.xattr     = XAttrBackend(fallback_dir or root)
        self.verbose   = verbose
        self._watching = False
        self._watch_thread: Optional[threading.Thread] = None

        log.info(f"HolonFSd init — root={self.root}")

    # ── Skan startowy ────────────────────────────────────────────────────────

    def scan(self, use_snapshot: bool = True) -> int:
        """
        Buduje indeks z:
        1. Snapshotu JSON (fast path, O(1))
        2. xattr per-plik (medium, O(n) syscall)
        3. Treści pliku (slow, O(n) I/O + embed)
        """
        snap_path = os.path.join(self.root, self.SNAPSHOT_FILE)

        if use_snapshot and os.path.exists(snap_path):
            loaded = self._load_snapshot(snap_path)
            if loaded > 0:
                log.info(f"Snapshot: {loaded} rekordów wczytanych")
                return loaded

        count = 0
        t0    = time.time()

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Pomiń ukryte katalogi systemowe
            dirnames[:] = [d for d in dirnames
                           if not d.startswith('.')
                           and d not in ('proc', 'sys', 'dev', 'run')]

            for fname in filenames:
                if fname.startswith('.'):
                    continue
                path = os.path.join(dirpath, fname)
                if self._index_file(path, from_xattr=True):
                    count += 1

        dt = time.time() - t0
        log.info(f"Skan zakończony: {count} plików w {dt:.2f}s "
                 f"({count/max(dt,0.001):.0f} plików/s)")
        return count

    def _index_file(self, path: str, from_xattr: bool = True) -> bool:
        """Indeksuje pojedynczy plik. Zwraca True jeśli sukces."""
        try:
            # Próba odczytu z xattr
            if from_xattr:
                result = self.xattr.read(path)
                if result is not None:
                    vec, depth, born = result
                    self.index.upsert(FileRecord(
                        path=path, vector=vec, depth=depth, born=born
                    ))
                    return True

            # Embed z treści
            vec   = self.embedder.embed_file(path)
            depth = self._infer_depth(path)
            born  = os.path.getmtime(path)

            # Zapisz w xattr (source of truth)
            self.xattr.write(path, vec, depth, born)
            self.index.upsert(FileRecord(
                path=path, vector=vec, depth=depth, born=born
            ))
            return True

        except (OSError, PermissionError):
            return False

    def _infer_depth(self, path: str) -> int:
        """Heurystyczne przypisanie głębokości z ścieżki i rozszerzenia."""
        p   = path.lower()
        ext = Path(path).suffix.lower()

        # Głębokość 3 — rdzeń / konfiguracja stała
        if any(s in p for s in ('/etc/', '/usr/lib/', 'config', 'README',
                                  'readme', 'INSTALL', '.conf', '.toml')):
            return 3

        # Głębokość 2 — dokumenty przetworzone
        if ext in ('.md', '.rst', '.pdf', '.html', '.json', '.yaml'):
            return 2

        # Głębokość 1 — dialog / tymczasowe
        if any(s in p for s in ('/tmp/', '/var/log/', 'test', 'draft',
                                  'temp', 'wip', 'todo')):
            return 1

        return 2  # domyślnie

    # ── inotify watch ────────────────────────────────────────────────────────

    def watch(self, background: bool = True):
        """Uruchamia inotify watcher."""
        if not INOTIFY_AVAILABLE:
            log.warning("inotify niedostępne — watch wyłączony")
            return

        self._watching = True
        if background:
            self._watch_thread = threading.Thread(
                target=self._watch_loop, daemon=True
            )
            self._watch_thread.start()
            log.info("inotify watch uruchomiony (background)")
        else:
            self._watch_loop()

    def _watch_loop(self):
        i = inotify.adapters.InotifyTree(self.root)
        for event in i.event_gen(yield_nones=False):
            if not self._watching:
                break
            _, type_names, path, filename = event
            if not filename or filename.startswith('.'):
                continue
            full = os.path.join(path, filename)

            if 'IN_CLOSE_WRITE' in type_names or 'IN_MOVED_TO' in type_names:
                if os.path.isfile(full):
                    self._index_file(full, from_xattr=False)
                    if self.verbose:
                        log.info(f"→ zindeksowano: {full}")

            elif 'IN_DELETE' in type_names or 'IN_MOVED_FROM' in type_names:
                self.index.remove(full)
                self.xattr.delete(full)
                if self.verbose:
                    log.info(f"← usunięto z indeksu: {full}")

    def stop_watch(self):
        self._watching = False

    # ── Zapytania semantyczne ────────────────────────────────────────────────

    def query(self, meaning: str,
              top_k: int = 10,
              depth_filter: Optional[int] = None,
              threshold: float = 0.0) -> List[Tuple[str, float]]:
        """
        Semantyczne wyszukiwanie w systemie plików.

        Args:
            meaning:      dowolny tekst opisujący czego szukasz
            top_k:        ile wyników
            depth_filter: ogranicz do głębokości 1/2/3
            threshold:    minimalne podobieństwo (0.0–1.0)

        Returns:
            lista (path, similarity) posortowana malejąco
        """
        q_vec = self.embedder.embed(meaning)
        return self.index.query(q_vec, top_k, depth_filter, threshold)

    def query_axes(self, axis_weights: Dict[str, float],
                   top_k: int = 10) -> List[Tuple[str, float]]:
        """
        Zapytanie przez osie emocjonalne wprost.
        Np. {'kreacja': 0.9, 'logika': 0.7}
        """
        q_vec = np.zeros(DIMENSION, dtype=DTYPE)
        for axis, weight in axis_weights.items():
            if axis in AXES:
                q_vec[AXES.index(axis)] = weight
        norm = np.linalg.norm(q_vec)
        if norm > 1e-10:
            q_vec /= norm
        return self.index.query(q_vec, top_k)

    # ── Snapshot ─────────────────────────────────────────────────────────────

    def save_snapshot(self):
        """Zapisuje indeks jako JSON snapshot (szybki restart)."""
        snap_path = os.path.join(self.root, self.SNAPSHOT_FILE)
        records = []
        with self.index._lock:
            for i in range(self.index._n):
                records.append({
                    'path':   self.index._paths[i],
                    'vec':    self.index._vectors[i].tolist(),
                    'depth':  int(self.index._depths[i]),
                    'weight': float(self.index._weights[i]),
                })
        with open(snap_path, 'w', encoding='utf-8') as f:
            json.dump({'version': '1.0', 'records': records}, f)
        log.info(f"Snapshot zapisany: {len(records)} rekordów → {snap_path}")

    def _load_snapshot(self, snap_path: str) -> int:
        try:
            with open(snap_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for rec in data.get('records', []):
                vec = np.array(rec['vec'], dtype=DTYPE)
                self.index.upsert(FileRecord(
                    path=rec['path'],
                    vector=vec,
                    depth=rec.get('depth', 1),
                    weight=rec.get('weight', 1.0),
                ))
            return self.index._n
        except Exception as e:
            log.warning(f"Snapshot load error: {e}")
            return 0

    # ── Statystyki ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            **self.index.stats(),
            'root':           self.root,
            'xattr_backend':  'xattr' if XATTR_AVAILABLE else 'fallback_json',
            'inotify':        INOTIFY_AVAILABLE,
            'watching':       self._watching,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SOCKET SERVER  (daemon ↔ klient)
# ─────────────────────────────────────────────────────────────────────────────

def _start_server(daemon: 'HolonFSd', sock_path: str = SOCKET_PATH):
    """Uruchamia Unix socket server w tle."""
    if os.path.exists(sock_path):
        os.remove(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(8)
    os.chmod(sock_path, 0o600)
    log.info(f"Socket: {sock_path}")

    def _handle(conn):
        try:
            data = b''
            while b'\n' not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            req = json.loads(data.decode().strip())
            cmd = req.get('cmd', 'query')

            if cmd == 'query':
                results = daemon.query(
                    req.get('q', ''),
                    top_k=req.get('top_k', 10),
                    depth_filter=req.get('depth'),
                    threshold=req.get('threshold', 0.01),
                )
                resp = {'results': [
                    {'path': p, 'sim': round(s, 4)} for p, s in results
                ]}
            elif cmd == 'stats':
                resp = daemon.stats()
            elif cmd == 'index':
                ok = daemon._index_file(req.get('path', ''), from_xattr=False)
                resp = {'ok': ok}
            else:
                resp = {'error': f'unknown: {cmd}'}

            conn.sendall((json.dumps(resp) + '\n').encode())
        except Exception as e:
            try:
                conn.sendall((json.dumps({'error': str(e)}) + '\n').encode())
            except Exception:
                pass
        finally:
            conn.close()

    def _serve():
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=_handle, args=(conn,),
                                 daemon=True).start()
            except Exception:
                break

    t = threading.Thread(target=_serve, daemon=True, name='holon-server')
    t.start()
    return t


def _send(sock_path: str, req: dict) -> dict:
    """Wysyła request do działającego daemona."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(sock_path)
        s.sendall((json.dumps(req) + '\n').encode())
        data = b''
        while b'\n' not in data:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data.decode())
    except Exception as e:
        return {'error': str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# TRYB INTERAKTYWNY
# ─────────────────────────────────────────────────────────────────────────────

def _interactive(daemon: 'HolonFSd'):
    """Pętla interaktywna — wpisujesz zapytania, dostajesz wyniki."""
    s = daemon.stats()
    print(f"\n{'═'*62}")
    print(f"  HolonFS v1.1.0 — Semantic Search (interactive)")
    print(f"  Katalog : {s['root']}")
    print(f"  Pliki   : {s['total']}  |  RAM: {s.get('ram_mb','?')} MB")
    print(f"  xattr   : {s['xattr_backend']}  |  inotify: {s['inotify']}")
    print(f"{'═'*62}")
    print("  Wpisz zapytanie semantyczne po polsku lub angielsku.")
    print("  Komendy: :q  :stats  :top N  :depth N|off  :rescan")
    print(f"{'═'*62}\n")

    top_k = 10; depth = None; threshold = 0.01

    while True:
        try:
            line = input("holon> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[bye]")
            break

        if not line:
            continue
        if line == ':q':
            break
        if line == ':stats':
            for k, v in daemon.stats().items():
                print(f"  {k:20s}: {v}")
            continue
        if line == ':rescan':
            n = daemon.scan(use_snapshot=False)
            print(f"  Przeskanowano {n} plików.")
            continue
        if line.startswith(':top '):
            top_k = int(line.split()[1])
            print(f"  top_k = {top_k}")
            continue
        if line.startswith(':depth '):
            v = line.split()[1]
            depth = int(v) if v != 'off' else None
            print(f"  depth_filter = {depth}")
            continue
        if line.startswith(':threshold '):
            threshold = float(line.split()[1])
            print(f"  threshold = {threshold}")
            continue

        t0      = time.time()
        results = daemon.query(line, top_k, depth, threshold)
        dt      = (time.time() - t0) * 1000

        if not results:
            print("  (brak wyników — spróbuj :threshold 0.0)")
        else:
            print(f"  {len(results)} wyników ({dt:.1f}ms)\n")
            for path, sim in results:
                bar = '█' * int(sim * 24)
                rel = os.path.relpath(path, daemon.root)
                di  = daemon.index._depths[
                    daemon.index._path2idx.get(path, 0)]
                sym = {1: '○', 2: '◑', 3: '●'}.get(int(di), '?')
                print(f"  {sim:.3f} {sym} {bar:<24} {rel}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI v1.1
# ─────────────────────────────────────────────────────────────────────────────

def cli():
    import argparse

    parser = argparse.ArgumentParser(
        prog='holon_fs',
        description='HolonFS v1.1.0 — semantyczny indeks systemu plików',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tryby:
  python holon_fs.py <root> --interactive   pętla wyszukiwania
  python holon_fs.py <root> --daemon        daemon + socket server
  python holon_fs.py --query "<tekst>"      zapytaj działający daemon
  python holon_fs.py <root> --scan          skanuj i zapisz snapshot
  python holon_fs.py --stats                statystyki daemona
        """
    )
    parser.add_argument('root',           nargs='?', help='katalog główny')
    parser.add_argument('--interactive',  action='store_true', help='tryb interaktywny')
    parser.add_argument('--daemon',       action='store_true', help='daemon + socket')
    parser.add_argument('--query', '-q',  metavar='TEKST',     help='zapytaj daemon')
    parser.add_argument('--scan',         action='store_true', help='skanuj i zapisz')
    parser.add_argument('--stats',        action='store_true', help='statystyki')
    parser.add_argument('--top',          type=int, default=10)
    parser.add_argument('--depth',        type=int, default=None)
    parser.add_argument('--threshold',    type=float, default=0.01)
    parser.add_argument('--socket',       default=SOCKET_PATH)
    parser.add_argument('--no-snapshot',  action='store_true')
    parser.add_argument('-v', '--verbose',action='store_true')
    args = parser.parse_args()

    # ── Tryby klienckie (nie potrzebują roota) ───────────────────────────────
    if args.query:
        resp = _send(args.socket, {
            'cmd': 'query', 'q': args.query,
            'top_k': args.top, 'threshold': args.threshold,
        })
        if 'error' in resp:
            print(f"Błąd: {resp['error']}")
            print("(Daemon nie działa? python holon_fs.py <root> --daemon)")
            sys.exit(1)
        results = resp.get('results', [])
        print(f"\nWyniki dla: '{args.query}'\n{'─'*54}")
        for r in results:
            bar = '█' * int(r['sim'] * 24)
            print(f"  {r['sim']:.3f} {bar:<24} {r['path']}")
        if not results:
            print("  (brak wyników)")
        return

    if args.stats:
        resp = _send(args.socket, {'cmd': 'stats'})
        if 'error' in resp:
            print(f"Błąd: {resp['error']}")
        else:
            for k, v in resp.items():
                print(f"  {k:20s}: {v}")
        return

    # ── Tryby wymagające roota ────────────────────────────────────────────────
    if not args.root:
        parser.print_help()
        return

    d = HolonFSd(root=args.root, verbose=args.verbose)
    d.scan(use_snapshot=not args.no_snapshot)

    if args.scan:
        d.save_snapshot()
        print(f"Snapshot zapisany. {d.stats()}")
        return

    if args.interactive:
        d.watch(background=True)
        _interactive(d)
        d.save_snapshot()
        return

    if args.daemon:
        d.watch(background=True)
        _start_server(d, args.socket)
        log.info("Daemon aktywny. Ctrl+C = stop + snapshot.")
        try:
            while True:
                time.sleep(60)
                d.save_snapshot()
        except KeyboardInterrupt:
            d.save_snapshot()
            log.info("Zatrzymano.")
        return

    parser.print_help()


# ─────────────────────────────────────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

def _run_test():
    import tempfile
    print("=" * 58)
    print("  TEST HolonFS v1.1.0")
    print("=" * 58)

    emb = KuRzEmbedder()

    tests = [
        ("def quicksort arr return sorted algorithm class method", "kod/algorytm"),
        ("host localhost port 8080 dns gateway config yaml",       "sieć/config"),
        ("error exception traceback failed crash timeout warning", "błąd/strach"),
        ("readme documentation guide tutorial howto spec notes",   "dokumentacja"),
        ("tmp test debug wip todo scratch dummy mock placeholder", "chaos/temp"),
        ("docker container kubernetes service daemon pid linux",   "system/infra"),
        ("create build deploy init setup install publish release", "kreacja"),
    ]

    print("\nEmbedder — top 3 osie:")
    for text, label in tests:
        v    = emb.embed(text)
        top3 = np.argsort(v)[::-1][:3]
        axes = [(AXES[i], round(float(v[i]), 3)) for i in top3 if v[i] > 0.0]
        print(f"  [{label:22s}]: {axes}")

    with tempfile.TemporaryDirectory() as tmpdir:
        files = {
            'main.py':      "def quicksort(arr):\n    return sorted(arr)\n# algorithm sort implementation",
            'network.yaml': "host: localhost\nport: 8080\ndns: 8.8.8.8\ngateway: 192.168.1.1",
            'README.md':    "# HolonFS\ndocumentation guide tutorial installation howto spec",
            'error.log':    "ERROR: connection failed exception traceback timeout\nWARNING: retry",
            'notes.md':     "TODO: implement feature\nWIP: refactoring build system create project",
            'config.toml':  "version = '1.0'\nenvironment = 'production'\nservice = 'daemon'",
            'test_sort.py': "def test_quicksort():\n    assert quicksort([3,1]) == [1,3]\n# test debug",
            'deploy.sh':    "#!/bin/bash\ndocker build .\nkubectl apply -f deploy.yaml\n# deploy service",
        }
        for fname, content in files.items():
            with open(os.path.join(tmpdir, fname), 'w') as f:
                f.write(content)

        d = HolonFSd(root=tmpdir, verbose=False)
        n = d.scan(use_snapshot=False)
        print(f"\nHolonFSd: {n} plików | {d.stats()}")

        print("\nQuery:")
        for q_text in [
            "algorytm sortowania kod python",
            "błąd połączenia sieciowego error",
            "dokumentacja projektu readme",
            "konfiguracja systemu produkcja",
            "tymczasowy test do usunięcia",
            "deploy kontener docker kubernetes",
        ]:
            results = d.query(q_text, top_k=2, threshold=0.0)
            top2    = [(os.path.basename(p), round(s, 3)) for p, s in results]
            print(f"\n  '{q_text}'")
            for fname, sim in top2:
                bar = '█' * int(sim * 20)
                print(f"    {sim:.3f} {bar:<20} {fname}")

        # Test socket daemon
        print("\nSocket daemon test...")
        _start_server(d, '/tmp/holon_test.sock')
        time.sleep(0.2)
        resp = _send('/tmp/holon_test.sock',
                     {'cmd': 'query', 'q': 'kod algorytm python', 'top_k': 3})
        print(f"  Socket query → {resp.get('results', [])[:2]}")

        resp2 = _send('/tmp/holon_test.sock', {'cmd': 'stats'})
        print(f"  Socket stats → total={resp2.get('total','?')}")

    print(f"\n{'='*58}\n  TEST ZAKOŃCZONY\n{'='*58}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        _run_test()
