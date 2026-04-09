
# Holon: Holographic Cognitive Architecture

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Version](https://img.shields.io/badge/Version-5.11-green.svg)](#)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Termux%20%7C%20ARM64-orange.svg)](#)

> **Persistent Memory and Temporal Awareness for Conversational AI.**

**Holon** to nakładka architektury poznawczej (cognitive architecture overlay) dla modeli LLM, która zapewnia trwałą, strukturalną pamięć w poprzek sesji konwersacyjnych. W przeciwieństwie do klasycznych systemów RAG opartych na bazach wektorowych, Holon implementuje wewnątrzprocesowy system pamięci holograficznej inspirowany **Holographic Reduced Representations (HRR)**, zasadą wolnej energii (**Free Energy Principle**) oraz kodowaniem predykcyjnym (**Rao–Ballard predictive coding**).

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

---

## 🚀 Wydajność i Benchmarki

Holon wykazuje wyjątkową odporność na szum informacyjny:

| Metryka                | Wynik           |
|------------------------|-----------------|
| **Recall** (80 tur szumu) | **100%**    |
| **Precyzja**           | **93–100%**     |
| **GPU**                | **Zero** – CPU (NumPy) |

---

## 🛠 Ekosystem HolonOS

Holon jest fundamentem szerszego ekosystemu "edge-native":

- `holonP.py` – Główny silnik poznawczy (v5.11)
- `notes_manager.py` – Zarządzanie notatkami w formacie `.md`
- `tasks.py` – System zadań i planowania
- `fractal_memory.py` – Hierarchiczny indeks fraktalny
- `knowledge_store.py` – Integracja wiedzy z plików lokalnych

---

## 🔧 Instalacja (Termux / Android)

System jest zoptymalizowany pod środowisko Termux na architekturze ARM64.

```bash
# Wymagania: Python 3.10+, NumPy
git clone https://github.com/Maciej-EriAmo/HolonOS.git
cd HolonOS
pip install numpy requests
```

---

## 📖 Podstawy teoretyczne

Architektura implementuje matematyczne sploty kołowe (Circular Convolution) do wiązania informacji:

$$H(e, k) = \text{IFFT}\big( \text{FFT}(e) \odot \text{FFT}_{\text{unitary}}(k) \big)$$

Gdzie:
- `e` – timed embedding (KuRz + sinusoidal time)
- `k` – unikalny klucz sesji

---

## 📄 Licencja i Autor

- **Autor:** Maciej Mazur (Independent AI Researcher, Warsaw, Poland)
- **Licencja:** GPL-3.0 – Wolność oprogramowania i transparentność kodu.

---
*Projekt dedykowany dla użytkowników ceniących prywatność, autonomię systemów AI oraz optymalizację pod kątem neuroróżnorodności (ADHD friendly).*
```

### ✅ Co poprawiono względem oryginału

| Element                      | Przed zmianą                                                                 | Po zmianie                                                                                     |
|------------------------------|------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| **Blok kodu instalacji**     | Niezamknięty cudzysłów w adresie URL                                          | Poprawny adres w formacie `git clone https://...` bez dodatkowych znaków                        |
| **Tabela wydajności**        | Tekst w formie listy                                                         | Przejrzysta tabela markdown                                                                     |
| **Lista komponentów**        | Rozdzielona myślnikami bez formatowania                                       | Poprawna lista nienumerowana z kodowaniem nazw plików                                           |
| **Odstępy i nagłówki**       | Brakujące puste linie przed sekcjami                                          | Zachowane puste linie dla czytelności źródła                                                    |
| **Składnia LaTeX**           | `$$H(e, k) = IFFT( FFT(e) \odot FFT_{unitary}(k) )$$` (brak spacji)          | `$$H(e, k) = \text{IFFT}\big( \text{FFT}(e) \odot \text{FFT}_{\text{unitary}}(k) \big)$$`       |
| **Uwagi końcowe**            | Zbędne komentarze w kodzie                                                    | Usunięte, pozostawiono tylko czysty markdown                                                    |

