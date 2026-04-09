# Holon v5.11 — Architektura systemu

**Data:** 2026-04-09  
**Autor:** Maciej Mazur  
**Repo:** github.com/Maciej-EriAmo/Holomem

---

## Przegląd

Holon to warstwa kognitywna dla LLM — zapewnia:
- **Pamięć persystentną** z holograficznym szyfrowaniem (HRR)
- **Śledzenie stanu emocjonalnego** (AIIState + vacuum_signal)
- **Świadomość czasową** (time_embed, TimeDecay)
- **Predictive coding** (Rao-Ballard/FEP) dla aktualizacji Phi
- **Ciągły routing** na poziomy pamięci (PrismRouter)

System działa jako middleware między użytkownikiem a dowolnym LLM (Groq, Ollama, DeepSeek).

---

## Moduły — tabela

| Moduł | Plik | Funkcja | Zależności |
|-------|------|---------|------------|
| **Entry point** | `main.py` | CLI loop, komendy | Session |
| **Session** | `holon_session.py` | API użytkownika, reminder parser | HoloMem, LLM, Watcher |
| **HoloMem** | `holon_holomem.py` | Silnik kognitywny — turn(), vacuum, recall, ruminate | Config, Item, Embedder, AII, Memory, Holography |
| **Config** | `holon_config.py` | Wszystkie parametry systemu | — |
| **Item** | `holon_item.py` | Dataclass elementu pamięci | numpy |
| **Embedder** | `holon_embedder.py` | KuRz offline + time_embed | KuRz (opcjonalnie) |
| **AIIState** | `holon_aii.py` | Stan emocjonalny, vacuum_signal | numpy, Embedder |
| **TimeDecay** | `holon_aii.py` | Decay czasowy Phi | numpy |
| **PersistentMemory** | `holon_memory.py` | JSON persistence + HRR koherencja | Config, Item, Holography, AII |
| **Holography** | `holon_holography.py` | HRR (FFT bind/unbind), PrismRouter, phase_shift | numpy |
| **LLM Client** | `holon_llm.py` | OpenAI-compatible (Groq/Ollama/DeepSeek) | requests |
| **ReminderWatcher** | `holon_watcher.py` | Daemon thread dla przypomnień | HoloMem |
| **PromptScanner** | `prompt_scanner.py` | Layer 0 security, jailbreak detection | negative_patterns.json |
| **WebExtractor** | `web_extractor.py` | URL → .md (cleaned) | requests, beautifulsoup4 |
| **KnowledgeStore** | `knowledge_store.py` | Most WebExtractor ↔ FractalMemory ↔ Holon | WebExtractor, FractalMemory (opcjonalnie) |
| **HolonFS** | `holon_fs.py` | Semantic filesystem index (xattr/JSON) + daemon | numpy, xattr (opcjonalnie), inotify (opcjonalnie) |
| **NotesManager** | `notes_manager.py` | Notatki jako .md z integracją Holon | — |
| **TasksManager** | `tasks.py` | Zadania jako tasks.md z integracją Holon | — |

---

## Przepływ danych

```
User input
    │
    ▼
┌─────────────────────────────────────────────┐
│  Session.chat()                              │
│  └─ parse reminder → add_reminder()          │
│  └─ time context injection                   │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  HoloMem.turn(user_message, system)          │
│  ├─ encode() → query embedding + time        │
│  ├─ predictive coding error → W_time update  │
│  ├─ _recall() → activate relevant items      │
│  ├─ _vacuum() → soft decay + hard prune      │
│  ├─ _update_phi() → PrismRouter / PhaseShift │
│  └─ _build_messages() → inject memory        │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  LLM API (Groq / Ollama / DeepSeek)          │
│  ← system prompt + memory context + user msg │
└─────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────┐
│  HoloMem.after_turn()                        │
│  ├─ encode combined (user + response)        │
│  ├─ aii.update() → emotion detection         │
│  ├─ store new item or semantic_merge         │
│  ├─ topic_counter → auto-fact generation     │
│  ├─ conversation_history append              │
│  ├─ ruminate() → insight generation          │
│  └─ memory.save() → JSON + HRR coherence     │
└─────────────────────────────────────────────┘
    │
    ▼
Response to user
```

---

## Kluczowe mechanizmy

### 1. Phi Matrix (3 poziomy × 4 attraktory)

```
phi[0] = short-term (hours)    — fast decay
phi[1] = medium-term (days)    — medium decay  
phi[2] = long-term (weeks)     — slow decay, core identity
```

Każdy poziom ma 4 attraktory (wektory). Elementy pamięci są przyciągane do najbliższego attraktora i uczą go poprzez predictive coding.

### 2. HRR (Holographic Reduced Representations)

- **bind(v1, v2)**: circular convolution via FFT
- **unbind(bound, key)**: circular correlation
- **Coherence check**: przy wczytaniu pamięci sprawdza czy φ_recovered ≈ φ_saved

### 3. PrismRouter (v5.x+)

Zastępuje hard-threshold routing ciągłą funkcją opartą na prawie Snella:
```
deviation_angle(θ) = θ + arcsin(n·sin(A-arcsin(sin(θ)/n))) - A
```
Probability distribution na poziomy = softmax(cos(δ - target))

### 4. AIIState + Vacuum Signal

- **Emocje**: radość, zaskoczenie, strach, złość, smutek, neutral
- **vacuum_signal**: EMA (-1.0 do +1.0) — ujemny = błąd/frustracja, dodatni = sukces
- **Wpływ**: modyfikuje threshold vacuum, learning rate, relevance decay

### 5. ConversationTracker (v5.11)

- **conversation_history**: ostatnie 12 wymian (24 wiadomości)
- **topic_counter**: zlicza powtórzenia słów kluczowych (≥5 znaków)
- **Auto-fact**: po 3 powtórzeniach tematu → nowy is_fact

---

## Integracje opcjonalne

### KnowledgeStore + WebExtractor
```python
ks = KnowledgeStore(md_dir="knowledge")
ks.learn_url("https://en.wikipedia.org/wiki/Transformer")
results = ks.recall("attention mechanism", top_k=3)
inject_knowledge(holomem, ks, "transformer")  # przed turn()
```

### HolonFS (semantic filesystem)
```bash
python holon_fs.py ~/projects --daemon     # uruchom daemon
python holon_fs.py --query "config yaml"   # zapytaj
```

### PromptScanner (Layer 0)
```python
from prompt_scanner import scan_for_injection
result = scan_for_injection(user_input)
if result.blocked:
    return scanner.explain(result)
```

---

## Pliki konfiguracyjne

| Plik | Funkcja |
|------|---------|
| `holon_memory.json` | Persystentna pamięć (Phi, store, timestamps) |
| `holon_memory_kurz.json` | Słownik KuRz (hash → embedding) |
| `negative_patterns.json` | Wzorce jailbreak/injection dla skanera |
| `tasks/tasks.md` | Lista zadań (human-readable) |
| `notes/*.md` | Notatki (human-readable) |
| `knowledge/*.md` | Wiedza z sieci |

---

## Uruchomienie

```bash
# Instalacja jako pakiet
pip install -e .

# Lub ręcznie
pip install numpy requests beautifulsoup4 python-dateutil

# Opcjonalnie
pip install xattr inotify  # dla HolonFS

# Start (podstawowy)
export GROQ_API_KEY="gsk_..."  # lub uruchom `ollama serve`
python main.py

# Start (z pełną integracją: scanner + notes + tasks)
python main_secure.py
```

### Pliki w pakiecie

| Plik | Opis |
|------|------|
| `main.py` | Podstawowy entry point |
| `main_secure.py` | Entry point z PromptScanner + Notes + Tasks |
| `holon_session.py` | Oryginalna Session |
| `holon_session_secure.py` | Session z integracją Layer 0 |
| `setup.py` | Instalacja pakietu |
| `__init__.py` | Eksport głównych klas |
| `verify_imports.py` | Weryfikacja zależności |

### Komendy CLI
- `quit` — zakończ
- `stats` — statystyki (turns, store, phi_norms, aii)
- `reset` — wyczyść pamięć
- `ruminate` — wymuś ruminację

---

## Status implementacji

| Komponent | Status | Uwagi |
|-----------|--------|-------|
| HoloMem core | ✅ stable | v5.11 |
| PrismRouter | ✅ stable | opcjonalny (use_prism=True) |
| Predictive coding | ✅ stable | W_time, W_gen, temporal_error |
| ConversationTracker | ✅ stable | v5.11 |
| ReminderWatcher | ✅ stable | daemon thread |
| PromptScanner | ✅ stable | v1.9.1, intent scoring |
| WebExtractor | ✅ stable | v1.0 |
| KnowledgeStore | ✅ stable | v1.0 |
| HolonFS | ✅ stable | v1.1.0, daemon mode |
| NotesManager | ✅ stable | v1.0 |
| TasksManager | ✅ stable | v1.0 |
| Android (Kotlin) | 🔧 in progress | APK z persistence |

---

## Roadmap → HolonOS

1. **Integracja pełna** — Session + Scanner + KnowledgeStore + Notes + Tasks jako jeden pakiet
2. **HolonFS on Android** — xattr fallback działa, potrzebny inotify substitute
3. **API REST** — dla integracji z innymi aplikacjami
4. **B2B targeting** — Nothing/Carl Pei, Xiaomi, Samsung, Nokia, Microsoft
5. **Harmonic Attention** — publikacja + integracja bias do Phi

---

*Dokument wygenerowany automatycznie z analizy kodu źródłowego.*
