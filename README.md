# Holon: Holographic Cognitive Architecture

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Version](https://img.shields.io/badge/Version-5.11-green.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Termux%20%7C%20ARM64-orange.svg)](#)
[![HSS](https://img.shields.io/badge/Security-HSS%20v2.9-red.svg)](#holonos-security-layer-hss)

> **Persistent Memory and Temporal Awareness for Conversational AI.**  
> **Cryptographic Execution Isolation for AI Agents.**

**Holon** to nakładka architektury poznawczej (cognitive architecture overlay) dla modeli LLM, która zapewnia trwałą, strukturalną pamięć w poprzek sesji konwersacyjnych oraz kryptograficzną izolację między agentami. W przeciwieństwie do klasycznych systemów RAG opartych na bazach wektorowych, Holon implementuje wewnątrzprocesowy system pamięci holograficznej inspirowany **Holographic Reduced Representations (HRR)**, zasadą wolnej energii (**Free Energy Principle**) oraz kodowaniem predykcyjnym (**Rao–Ballard predictive coding**).

System został zaprojektowany z myślą o pracy lokalnej na urządzeniach mobilnych (ARM64/Termux), zużywając zaledwie ~30 MB pamięci RAM.

---

## 🧠 Kluczowe Innowacje

### 1. Macierz Φ (Phi)

Trójwarstwowa struktura pamięci ewoluująca w czasie, mapująca warstwy świadomości wg Damasio:

- **Φ⁰ (Episodic):** Krótkotrwały kontekst (T₁/₂ = 24h). Odpowiednik *proto-self*.
- **Φ¹ (Mid-term):** Powracające tematy i projekty (T₁/₂ = 168h). Odpowiednik *core self*.
- **Φ² (Identity):** Fakty o użytkowniku i tożsamość (T₁/₂ = 720h). Odpowiednik *narrative self*.

### 2. PrismRouter

Autorski mechanizm routingu ciągłego inspirowany optyką. Zastępuje twarde progi decyzyjne funkcją odchylenia pryzmatu, co eliminuje nieciągłości gradientu i poprawia retencję faktów o **+0.018**.

### 3. Predictive Coding Update

Aktualizacja pamięci następuje poprzez minimalizację błędu predykcji (surprise). System uczy się na podstawie różnicy między stanem macierzy a nową obserwacją, co pozwala na dynamiczne dostosowanie wagi nowych informacji.

### 4. HSS — Holographic Session Spaces

Warstwa kryptograficznej izolacji agentów oparta na **Ring-LWE (post-quantum)**. Każdy agent otrzymuje capability token wyprowadzony algebraicznie z Φ². Dostęp do danych nie jest kontrolowany przez listy ACL — jest **niemożliwością matematyczną**.

Centralna teza: **agent istnieje tylko w przestrzeni zdefiniowanej przez ukryty operator projekcji zależny od sekretu, a wszystkie operacje poza tą przestrzenią są informacyjnie zerowe.**

---

## 🚀 Wydajność i Benchmarki

| Metryka | Wynik |
|---|---|
| **Recall** (80 tur szumu) | **100%** |
| **Precyzja** | **93–100%** |
| **GPU** | **Zero** – CPU (NumPy) |
| **RAM** | **~30 MB** |
| **HSS demo testy** | **20/20** ✔ |

---

## 🛡 HolonOS Security Layer (HSS)

HSS v2.9 to samodzielna warstwa bezpieczeństwa dla systemów multi-agentowych. Działa **bez modyfikacji jądra** (FUSE deployment) lub jako moduł LSM.

### Co daje HSS

- **Brak ACL, RBAC, Vault** — dostęp = `HMAC(s_A, prism_id)`, czysta algebra
- **Capability tokens** wyprowadzone z Φ² przez KDF — agent sam generuje token, daemon weryfikuje
- **Zero plaintextu w jądrze** — LSM jako relay, cała kryptografia w userspace
- **Dual MAC** — `mac_phi` (integralność storage) + `mac_agent` (integralność percepcji)
- **Vacuum Decay** — GC wyzwalany przez FEP na podstawie entropii ciphertext
- **Epoch rotation** — forward secrecy co 5 minut
- **Indistinguishability** — zablokowane pryzmaty nieodróżnialne statystycznie od autoryzowanych

### Warstwy izolacji

```
┌─────────────────────────────────────┐
│  Warstwa fizyczna: VM / cgroups     │  ← izolacja zasobów
├─────────────────────────────────────┤
│  Warstwa semantyczna: HSS / RLWE    │  ← izolacja informacyjna
├─────────────────────────────────────┤
│  Warstwa kognitywna: Φ / PrismMask  │  ← izolacja percepcji
└─────────────────────────────────────┘
```

### Deployment bez HolonOS

HSS działa jako standalone na **istniejącej infrastrukturze**:

- **FUSE sidecar** — montuje katalog w userspace, zero zmian w jądrze, zero zmian w aplikacji
- **Kubernetes sidecar** — `hss-daemon` w każdym podzie, re-encryption per-prism na poziomie proxy
- **Zastąpienie Vault+ACL** — cztery systemy enterprise zastąpione jednym modelem matematycznym

**Primary market:** multi-agent AI pipelines — pierwsza kryptograficzna izolacja percepcji między agentami AI na istniejącej infrastrukturze.

---

## 🛠 Ekosystem HolonOS

| Moduł | Funkcja | Status |
|---|---|---|
| `holonP.py` | Główny silnik poznawczy (v5.11) | ✅ Produkcja |
| `notes_manager.py` | Zarządzanie notatkami `.md` | ✅ Produkcja |
| `tasks.py` | System zadań i planowania | ✅ Produkcja |
| `fractal_memory.py` | Hierarchiczny indeks fraktalny | ✅ Produkcja |
| `knowledge_store.py` | Integracja wiedzy z plików lokalnych | ✅ Produkcja |
| `holon_fs.py` | Semantyczny filesystem (xattr + numpy) | ✅ Produkcja |
| `web_extractor.py` | Web → `.md` knowledge acquisition | ✅ Produkcja |
| `hss_demo.py` | HSS v2.9 — demonstrator pięciu faz | ✅ 20/20 testów |
| `holo_lsm.c` | Moduł LSM jądra Linux (pseudokod) | 🔬 Research |
| Android/Kotlin port | Natywny deployment mobilny | 📅 Q2 2026 |

---

## 🔧 Instalacja (Termux / Android)

```bash
# Wymagania: Python 3.10+, NumPy
git clone https://github.com/Maciej-EriAmo/HolonOS.git
cd HolonOS
pip install numpy requests --break-system-packages

# Uruchomienie demonstratora HSS
python3 hss_demo.py

# Uruchomienie silnika kognitywnego
python3 holonP.py
```

---

## 📖 Podstawy Teoretyczne

### Pamięć holograficzna (HRR)

$$H(e, k) = \text{IFFT}\big( \text{FFT}(e) \odot \text{FFT}_{\text{unitary}}(k) \big)$$

Gdzie `e` — timed embedding (KuRz + sinusoidal time), `k` — unikalny klucz sesji.

### Kryptograficzne wiązanie capability (Ring-LWE / LPR)

$$b = a \cdot s + e \pmod{q}, \quad s_A = \text{KDF}(s_{\text{sess}},\; \text{JSON}(\{\text{task}, \mathcal{P}_{\text{allow}}\}))$$

$$\text{capability}(\text{prism}) = \text{HMAC}(s_A,\; \text{prism\_id})$$

### Vacuum Decay (Free Energy Principle)

GC wyzwalany gdy entropia ciphertextu sierot jest nieodróżnialna od baseline RLWE — sygnał niekompresowalny oznacza utratę klucza i powrót do substratu.

---

## 📄 Publikacje

| Dokument | DOI |
|---|---|
| Holon: Holographic Cognitive Architecture | [10.5281/zenodo.19371554](https://doi.org/10.5281/zenodo.19371554) |
| HolonFS: Semantic Filesystem | [10.5281/zenodo.19366419](https://doi.org/10.5281/zenodo.19366419) |
| Prismatic Attention | [10.5281/zenodo.19371560](https://doi.org/10.5281/zenodo.19371560) |
| Harmonic Attention | [10.5281/zenodo.19387523](https://doi.org/10.5281/zenodo.19387523) |
| HSS: Holographic Session Spaces | [10.5281/zenodo.19548693](https://doi.org/10.5281/zenodo.19548693) |

Papier HSS dostępny w repozytorium: [`HSS_Paper_v2.5.0.md`](HSS_Paper_v2.5.0.md) (EN) · [`HSS_Paper_v2.5.0_PL.md`](HSS_Paper_v2.5.0_PL.md) (PL)

---

## 📜 Licencja i Autor

- **Autor:** Maciej Mazur — Independent AI Researcher, Warsaw, Poland
- **GitHub:** [@Maciej-EriAmo](https://github.com/Maciej-EriAmo) · **Medium:** [@drwisz](https://medium.com/@drwisz)
- **Licencja:** GPL-3.0

---

*Projekt dedykowany dla użytkowników ceniących prywatność, autonomię systemów AI oraz optymalizację pod kątem neuroróżnorodności (ADHD friendly).*
