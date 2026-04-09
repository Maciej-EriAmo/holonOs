# -*- coding: utf-8 -*-
"""
knowledge_store.py v1.0
Most między WebExtractor, FractalMemory i holonP.

Przepływ:
  URL → WebExtractor → .md na SD → FractalMemory (indeks) → Holon (recall)

Autor koncepcji: Maciej Mazur
"""

import os
import re
import json
import hashlib
import numpy as np
from pathlib import Path
from typing import Optional, List

# FractalMemory — importuj jeśli dostępna
try:
    from fractal_memory import FractalMemory, AXES, DIMENSION
    HAS_FRACTAL = True
except ImportError:
    HAS_FRACTAL = False
    AXES = [
        'radość', 'smutek', 'strach', 'gniew', 'miłość', 'wstręt',
        'zaskoczenie', 'akceptacja', 'logika', 'wiedza', 'czas',
        'kreacja', 'byt', 'przestrzeń', 'chaos'
    ]
    DIMENSION = 15
    print("[knowledge_store] Brak fractal_memory.py — tryb bez indeksu fraktalnego")

# WebExtractor
try:
    from web_extractor import WebExtractor
    HAS_EXTRACTOR = True
except ImportError:
    HAS_EXTRACTOR = False
    print("[knowledge_store] Brak web_extractor.py")


# ============================================================
# PROJEKCJA TEKSTU NA OSIE EMOCJONALNO-SEMANTYCZNE
# ============================================================

# Słowa kluczowe mapowane na osie AXES
# Każda oś ma listę słów które ją aktywują
AXIS_KEYWORDS = {
    'radość':      ['super', 'świetnie', 'doskonale', 'sukces', 'happy', 'great',
                    'wspaniały', 'piękny', 'radość', 'cieszy', 'pozytyw'],
    'smutek':      ['smutek', 'żal', 'strata', 'niestety', 'szkoda', 'sad',
                    'smutny', 'trudny', 'ból', 'cierpienie'],
    'strach':      ['błąd', 'error', 'problem', 'ryzyko', 'niebezpieczeństwo',
                    'awaria', 'crash', 'ostrzeżenie', 'kryzys', 'fail'],
    'gniew':       ['zły', 'frustracja', 'złość', 'angry', 'nie działa',
                    'broken', 'wrong', 'skandal'],
    'miłość':      ['miłość', 'przyjaźń', 'relacja', 'rodzina', 'love',
                    'bliski', 'razem', 'wspólnie', 'partner'],
    'wstręt':      ['brzydki', 'odrzucenie', 'wstręt', 'disgusting',
                    'odpychający', 'zły smak'],
    'zaskoczenie': ['nowy', 'odkrycie', 'nieoczekiwany', 'zaskoczenie',
                    'innowacja', 'przełom', 'wow', 'surprising'],
    'akceptacja':  ['ok', 'akceptacja', 'zgoda', 'rozumiem', 'dobrze',
                    'accept', 'agree', 'tak', 'potwierdzam'],
    'logika':      ['algorytm', 'kod', 'funkcja', 'logika', 'analiza',
                    'system', 'architektura', 'implementacja', 'logic',
                    'metoda', 'klasa', 'dane', 'struktura'],
    'wiedza':      ['nauka', 'wiedza', 'informacja', 'fakty', 'historia',
                    'teoria', 'badania', 'naukowy', 'knowledge', 'learn',
                    'edukacja', 'artykuł', 'wikipedia'],
    'czas':        ['czas', 'historia', 'przeszłość', 'przyszłość', 'data',
                    'rok', 'wiek', 'chronologia', 'time', 'timeline'],
    'kreacja':     ['tworzenie', 'projekt', 'design', 'budowanie', 'develop',
                    'build', 'create', 'nowy', 'innowacja', 'wynalazek',
                    'architektura', 'prototyp'],
    'byt':         ['istnienie', 'filozofia', 'świadomość', 'tożsamość',
                    'sens', 'cel', 'życie', 'being', 'existence'],
    'przestrzeń':  ['przestrzeń', 'miejsce', 'lokalizacja', 'mapa', 'geograficzny',
                    'region', 'kraj', 'space', 'location', 'system plików'],
    'chaos':       ['chaos', 'losowy', 'nieporządek', 'entropia', 'random',
                    'nieprzewidywalny', 'złożony', 'complex'],
}


def text_to_vector(text: str) -> np.ndarray:
    """
    Projektuje tekst na 15D przestrzeń emocjonalno-semantyczną (AXES).
    Prosta metoda: zlicza trafienia słów kluczowych per oś.
    Zwraca znormalizowany wektor.
    """
    text_lower = text.lower()
    vec = np.zeros(DIMENSION, dtype=np.float32)

    for i, axis in enumerate(AXES):
        keywords = AXIS_KEYWORDS.get(axis, [])
        score = sum(1 for kw in keywords if kw in text_lower)
        vec[i] = float(score)

    # Normalizacja
    n = np.linalg.norm(vec)
    if n > 0.01:
        vec /= n
    else:
        # Brak trafień → wektor wiedzy + byt (neutralny dokument)
        vec[AXES.index('wiedza')] = 0.7
        vec[AXES.index('byt')]    = 0.3

    return vec


# ============================================================
# KNOWLEDGE STORE
# ============================================================

class KnowledgeStore:
    """
    Zarządza wiedzą w postaci plików .md z fraktalnym indeksem.

    Użycie:
        ks = KnowledgeStore(md_dir="knowledge", soul_file="data/knowledge.soul")
        path = ks.learn_url("https://pl.wikipedia.org/wiki/Kajak")
        results = ks.recall("kajak łódź wiosło", top_k=3)
    """

    def __init__(
        self,
        md_dir:    str = "knowledge",
        soul_file: str = "data/knowledge.soul",
        verbose:   bool = False
    ):
        self.md_dir   = Path(md_dir)
        self.md_dir.mkdir(parents=True, exist_ok=True)
        self.verbose  = verbose

        # FractalMemory — indeks
        if HAS_FRACTAL:
            self.fractal = FractalMemory(soul_file, verbose=verbose)
        else:
            self.fractal = None

        # WebExtractor — pobieranie stron
        if HAS_EXTRACTOR:
            self.extractor = WebExtractor(md_dir=str(self.md_dir))
        else:
            self.extractor = None

        # Indeks path → mem_id (szybki lookup)
        self._path_index: dict = {}
        self._build_path_index()

    # ── Indeks ───────────────────────────────────────────────────────────────

    def _build_path_index(self):
        """Buduje indeks path→mem_id z istniejącego D_Map."""
        if not self.fractal:
            return
        for mid, rec in self.fractal.D_Map.items():
            path = rec.get('md_path')
            if path:
                self._path_index[path] = mid

    # ── Główne API ───────────────────────────────────────────────────────────

    def learn_url(self, url: str, weight: float = None) -> Optional[Path]:
        """
        Pobiera URL, zapisuje jako .md i indeksuje w FractalMemory.
        Zwraca ścieżkę do pliku lub None przy błędzie.
        """
        if not self.extractor:
            print("[knowledge_store] Brak WebExtractor")
            return None

        # Pobierz i zapisz .md
        path = self.extractor.extract(url)
        if not path:
            return None

        # Indeksuj w FractalMemory
        self.index_file(path, source_url=url, weight=weight)
        return path

    def learn_many(self, urls: list, delay: float = 1.5) -> list:
        """Pobiera i indeksuje wiele URL."""
        import time
        results = []
        for i, url in enumerate(urls):
            path = self.learn_url(url)
            results.append(path)
            if i < len(urls) - 1:
                time.sleep(delay)
        return results

    def index_file(
        self,
        path,
        source_url: str = "",
        weight:     float = None,
        rec_type:   str = "@KNOWLEDGE"
    ) -> Optional[str]:
        """
        Indeksuje istniejący plik .md w FractalMemory.
        Zwraca mem_id lub None.
        """
        path = Path(path)
        if not path.exists():
            print(f"[knowledge_store] Plik nie istnieje: {path}")
            return None

        # Sprawdź czy już zaindeksowany
        path_str = str(path)
        if path_str in self._path_index:
            if self.verbose:
                print(f"[knowledge_store] Już zaindeksowany: {path.name}")
            return self._path_index[path_str]

        # Wczytaj treść
        text = path.read_text(encoding="utf-8")

        # Wyznacz wagę na podstawie długości jeśli nie podano
        if weight is None:
            length = len(text)
            if length > 5000:
                weight = 0.85
            elif length > 1000:
                weight = 0.65
            else:
                weight = 0.45

        # Projektuj na wektor 15D
        vector = text_to_vector(text)

        if not self.fractal:
            if self.verbose:
                print(f"[knowledge_store] Brak FractalMemory — plik zapisany ale nie zaindeksowany")
            return None

        # Skróć treść do opisu (pierwsze 500 znaków bez nagłówka)
        lines = [l for l in text.split('\n') if l.strip() and not l.startswith('#')]
        summary = ' '.join(lines)[:500]

        # Dodaj metadane ścieżki do rekordu przez monkey-patch store
        mem_id = self.fractal.store(
            content=f"{path.stem}: {summary}",
            vector=vector,
            rec_type=rec_type,
            weight=weight,
        )

        # Dołącz ścieżkę do rekordu (FractalMemory nie ma tego pola — dodajemy)
        if mem_id in self.fractal.D_Map:
            self.fractal.D_Map[mem_id]['md_path']    = path_str
            self.fractal.D_Map[mem_id]['source_url'] = source_url
            self.fractal.D_Map[mem_id]['filename']   = path.name

        self._path_index[path_str] = mem_id

        if self.verbose:
            print(f"[knowledge_store] Zaindeksowano: {path.name} → {mem_id} (weight={weight:.2f})")

        return mem_id

    def index_all(self) -> int:
        """Indeksuje wszystkie .md w katalogu które jeszcze nie są w indeksie."""
        count = 0
        for md_file in sorted(self.md_dir.glob("*.md")):
            mid = self.index_file(md_file)
            if mid:
                count += 1
        if self.verbose:
            print(f"[knowledge_store] Zaindeksowano {count} nowych plików")
        return count

    def recall(self, query: str, top_k: int = 3) -> List[dict]:
        """
        Szuka wiedzy pasującej do zapytania.
        Zwraca listę słowników: {path, filename, content, score, mem_id}
        """
        if not self.fractal:
            return self._fallback_recall(query, top_k)

        # Projektuj zapytanie na wektor 15D
        query_vec = text_to_vector(query)

        # Proustian recall z FractalMemory
        matches = self.fractal.proustian_recall(query_vec, threshold=0.3)

        results = []
        for rec in matches[:top_k * 2]:
            path_str = rec.get('md_path')
            if not path_str:
                continue
            path = Path(path_str)
            if not path.exists():
                continue
            content = path.read_text(encoding="utf-8")
            results.append({
                'path':     path_str,
                'filename': path.name,
                'content':  content,
                'summary':  content[:800],
                'score':    rec.get('weight', 0.5),
                'mem_id':   rec.get('id', ''),
                'source_url': rec.get('source_url', ''),
            })
            if len(results) >= top_k:
                break

        return results

    def _fallback_recall(self, query: str, top_k: int = 3) -> List[dict]:
        """Recall bez FractalMemory — proste wyszukiwanie tekstowe po plikach .md"""
        query_lower = query.lower()
        words = set(query_lower.split())
        scored = []
        for md_file in self.md_dir.glob("*.md"):
            try:
                content = md_file.read_text(encoding="utf-8")
                content_lower = content.lower()
                score = sum(1 for w in words if w in content_lower)
                if score > 0:
                    scored.append((score, md_file, content))
            except Exception:
                continue
        scored.sort(key=lambda x: -x[0])
        results = []
        for score, md_file, content in scored[:top_k]:
            results.append({
                'path':     str(md_file),
                'filename': md_file.name,
                'content':  content,
                'summary':  content[:800],
                'score':    float(score),
                'mem_id':   '',
                'source_url': '',
            })
        return results

    def save(self):
        """Zapisuje indeks FractalMemory."""
        if self.fractal:
            self.fractal.save()

    def stats(self) -> dict:
        """Statystyki bazy wiedzy."""
        md_files = list(self.md_dir.glob("*.md"))
        total_size = sum(f.stat().st_size for f in md_files)
        fractal_stats = self.fractal.get_statistics() if self.fractal else {}
        return {
            'md_files':      len(md_files),
            'total_size_kb': round(total_size / 1024, 1),
            'indexed':       len(self._path_index),
            'fractal':       fractal_stats,
        }


# ============================================================
# INTEGRACJA Z HOLONP
# ============================================================

def inject_knowledge(holomem, knowledge_store: KnowledgeStore, query: str,
                     top_k: int = 2) -> list:
    """
    Wstrzykuje wiedzę z KnowledgeStore do window Holona jako Item.
    Wywołaj przed turn() jeśli chcesz wzbogacić kontekst.

    Przykład użycia w Session.chat():
        inject_knowledge(self.holomem, self.knowledge_store, user_input)
        messages = self.holomem.turn(user_input, self.system)
    """
    import time as _time
    import uuid as _uuid

    try:
        from holonP import Item
    except ImportError:
        return []

    results = knowledge_store.recall(query, top_k=top_k)
    injected = []

    for res in results:
        if res['score'] < 0.1:
            continue
        # Wstrzyknij jako is_fact=True z niskim age (zawsze w window)
        item = Item(
            id=f"know_{_uuid.uuid4().hex[:8]}",
            content=f"[WIEDZA] {res['filename']}:\n{res['summary']}",
            embedding=[0.0] * holomem.cfg.total_dim,  # placeholder
            age=0,
            recalled=True,
            relevance=1.5,
            is_fact=True,
            created_at=_time.time(),
        )
        holomem.store.append(item)
        injected.append(item)

    return injected


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    import shutil

    print("=== TEST KnowledgeStore ===\n")

    TEST_DIR  = "test_knowledge"
    TEST_SOUL = "test_knowledge/test.soul"

    # Przygotuj testowe pliki .md
    os.makedirs(TEST_DIR, exist_ok=True)

    md_kajak = """# Kajak eskimoski

**Źródło:** https://pl.wikipedia.org/wiki/Kajak  
**Data pobrania:** 2026-03-31

---

Kajak eskimoski to tradycyjna łódź używana przez ludy Arktyki.
Wykonana z lekkiego szkieletu drewnianego lub kostnego, pokrytego skórą foczą.
Kajaki były używane przez Inuitów od ponad 4000 lat do polowania na morzu.
Były niezwykle zwrotne i ciche, co czyniło je idealnymi łodziami myśliwskimi.
Szkielet wykonany z drewna lub kości wieloryba.

## Współczesne kajaki

Współcześnie kajaki wykonuje się z laminatów, kevlaru lub polietylenu.
Są popularne jako sport wodny i forma rekreacji na rzekach i jeziorach.
"""

    md_holon = """# Architektura Holon

**Źródło:** lokalny  
**Data pobrania:** 2026-03-31

---

Holon to system pamięci holograficznej dla asystentów AI.
Używa holograficznych reduced representations (HRR) do kodowania wiedzy.
Architektura opiera się na matrycy Phi, predictive coding i FEP.

## Komponenty

- HolographicInterference: FFT-based circular convolution
- PersistentMemory: atomowy zapis JSON z weryfikacją koherencji
- AIIState: emocjonalne ważenie wspomnień
- PrismRouter: ciągły routing na poziomy pamięci
- ConvTracker: śledzenie tematów rozmowy
"""

    # Zapisz testowe .md
    Path(f"{TEST_DIR}/kajak.md").write_text(md_kajak, encoding="utf-8")
    Path(f"{TEST_DIR}/holon_architektura.md").write_text(md_holon, encoding="utf-8")

    # Test projekcji wektora
    print("Test text_to_vector:")
    v_kajak = text_to_vector(md_kajak)
    v_holon = text_to_vector(md_holon)
    print(f"  kajak.md  → wektor (top-3 osie):", end=" ")
    top3 = np.argsort(v_kajak)[::-1][:3]
    for i in top3:
        print(f"{AXES[i]}={v_kajak[i]:.2f}", end=" ")
    print()
    print(f"  holon.md  → wektor (top-3 osie):", end=" ")
    top3 = np.argsort(v_holon)[::-1][:3]
    for i in top3:
        print(f"{AXES[i]}={v_holon[i]:.2f}", end=" ")
    print()

    # Test KnowledgeStore
    ks = KnowledgeStore(md_dir=TEST_DIR, soul_file=TEST_SOUL, verbose=True)

    print("\nIndeksowanie plików:")
    count = ks.index_all()
    print(f"  Zaindeksowano: {count} plików")

    print("\nStatystyki:")
    s = ks.stats()
    print(f"  {s}")

    print("\nRecall 'kajak łódź wiosło':")
    results = ks.recall("kajak łódź wiosło", top_k=2)
    for r in results:
        print(f"  [{r['score']:.2f}] {r['filename']}: {r['summary'][:80]}...")

    print("\nRecall 'holograficzna pamięć architektura':")
    results = ks.recall("holograficzna pamięć architektura", top_k=2)
    for r in results:
        print(f"  [{r['score']:.2f}] {r['filename']}: {r['summary'][:80]}...")

    # Zapis
    ks.save()
    print("\nZapisano indeks.")

    # Cleanup
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("\n=== TEST OK ===")
