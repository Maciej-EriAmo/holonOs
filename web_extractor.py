# -*- coding: utf-8 -*-
"""
web_extractor.py v1.0
Ekstraktor wiedzy z sieci do plików .md

Przepływ:
  URL → pobierz → wyczyść HTML → .md na SD/dysku

Autor koncepcji: Maciej Mazur
"""

import os
import re
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[web_extractor] Brak beautifulsoup4. Zainstaluj: pip install beautifulsoup4")


# ============================================================
# KONFIGURACJA
# ============================================================

DEFAULT_MD_DIR   = "knowledge"          # katalog na pliki .md
REQUEST_TIMEOUT  = 15                   # sekundy
MIN_TEXT_LENGTH  = 200                  # minimalna długość tekstu (chars)
MAX_TEXT_LENGTH  = 50_000              # maksymalna długość (chars)

# Tagi HTML które ignorujemy
IGNORED_TAGS = [
    "script", "style", "nav", "footer", "header",
    "aside", "form", "button", "iframe", "noscript",
    "advertisement", "cookie", "popup"
]

# Nagłówki HTTP — udajemy przeglądarkę
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Mobile Safari/537.36"
    ),
    "Accept-Language": "pl-PL,pl;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


# ============================================================
# EKSTRAKTOR
# ============================================================

class WebExtractor:
    """
    Pobiera strony internetowe i konwertuje je do formatu .md.

    Użycie:
        ext = WebExtractor(md_dir="knowledge")
        path = ext.extract("https://pl.wikipedia.org/wiki/Kajak")
        # → knowledge/kajak_pl_wikipedia_org.md
    """

    def __init__(self, md_dir: str = DEFAULT_MD_DIR):
        self.md_dir = Path(md_dir)
        self.md_dir.mkdir(parents=True, exist_ok=True)
        self._session = requests.Session()
        self._session.headers.update(HEADERS)

    # ── Pobieranie ──────────────────────────────────────────────────────────

    def fetch(self, url: str) -> Optional[str]:
        """Pobiera surowy HTML ze strony. Zwraca None przy błędzie."""
        try:
            resp = self._session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            resp.encoding = resp.apparent_encoding or "utf-8"
            return resp.text
        except requests.exceptions.Timeout:
            print(f"[web_extractor] Timeout: {url}")
        except requests.exceptions.HTTPError as e:
            print(f"[web_extractor] HTTP {e.response.status_code}: {url}")
        except requests.exceptions.ConnectionError:
            print(f"[web_extractor] Brak połączenia: {url}")
        except Exception as e:
            print(f"[web_extractor] Błąd: {e}")
        return None

    # ── Parsowanie HTML → tekst ─────────────────────────────────────────────

    def parse(self, html: str, url: str) -> dict:
        """
        Parsuje HTML i zwraca słownik:
            title, text, url, domain, extracted_at
        """
        if not HAS_BS4:
            return {"title": url, "text": "", "url": url,
                    "domain": "", "extracted_at": ""}

        soup = BeautifulSoup(html, "html.parser")

        # Usuń niepotrzebne tagi
        for tag in soup(IGNORED_TAGS):
            tag.decompose()

        # Tytuł
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
        elif soup.find("h1"):
            title = soup.find("h1").get_text(strip=True)
        title = self._clean_text(title)[:200]

        # Główna treść — szukamy article, main, content
        content_elem = (
            soup.find("article") or
            soup.find("main") or
            soup.find(id=re.compile(r"content|main|article", re.I)) or
            soup.find(class_=re.compile(r"content|main|article|post", re.I)) or
            soup.body
        )

        if content_elem:
            # Zbierz tekst z nagłówków i paragrafów
            parts = []
            for elem in content_elem.find_all(
                ["h1", "h2", "h3", "h4", "p", "li", "blockquote", "pre"]
            ):
                txt = elem.get_text(separator=" ", strip=True)
                if len(txt) < 20:
                    continue
                tag = elem.name
                if tag == "h1":
                    parts.append(f"\n# {txt}\n")
                elif tag == "h2":
                    parts.append(f"\n## {txt}\n")
                elif tag == "h3":
                    parts.append(f"\n### {txt}\n")
                elif tag == "h4":
                    parts.append(f"\n#### {txt}\n")
                elif tag == "blockquote":
                    parts.append(f"\n> {txt}\n")
                elif tag == "pre":
                    parts.append(f"\n```\n{txt}\n```\n")
                elif tag == "li":
                    parts.append(f"- {txt}")
                else:
                    parts.append(txt)
            text = "\n".join(parts)
        else:
            text = soup.get_text(separator="\n", strip=True)

        text = self._clean_text(text)
        text = text[:MAX_TEXT_LENGTH]

        domain = urlparse(url).netloc

        return {
            "title": title or domain,
            "text": text,
            "url": url,
            "domain": domain,
            "extracted_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

    # ── Konwersja do .md ────────────────────────────────────────────────────

    def to_md(self, parsed: dict) -> str:
        """Formatuje sparsowane dane jako Markdown."""
        lines = [
            f"# {parsed['title']}",
            "",
            f"**Źródło:** {parsed['url']}  ",
            f"**Data pobrania:** {parsed['extracted_at']}  ",
            f"**Domena:** {parsed['domain']}",
            "",
            "---",
            "",
            parsed["text"],
        ]
        return "\n".join(lines)

    # ── Zapis ───────────────────────────────────────────────────────────────

    def save_md(self, parsed: dict, filename: str = None) -> Path:
        """Zapisuje .md do katalogu. Zwraca ścieżkę pliku."""
        if not filename:
            filename = self._url_to_filename(parsed["url"])
        path = self.md_dir / filename
        path.write_text(self.to_md(parsed), encoding="utf-8")
        return path

    # ── Główna metoda ───────────────────────────────────────────────────────

    def extract(self, url: str, filename: str = None) -> Optional[Path]:
        """
        Pobiera URL, parsuje i zapisuje do .md.
        Zwraca ścieżkę do pliku lub None przy błędzie.
        """
        print(f"[web_extractor] Pobieranie: {url}")

        html = self.fetch(url)
        if not html:
            return None

        parsed = self.parse(html, url)

        if len(parsed["text"]) < MIN_TEXT_LENGTH:
            print(f"[web_extractor] Za mało treści ({len(parsed['text'])} znaków): {url}")
            return None

        path = self.save_md(parsed, filename)
        print(f"[web_extractor] Zapisano: {path} ({len(parsed['text'])} znaków)")
        return path

    def extract_many(self, urls: list, delay: float = 1.0) -> list:
        """
        Pobiera wiele URL z opóźnieniem między requestami.
        Zwraca listę ścieżek (None dla błędów).
        """
        results = []
        for i, url in enumerate(urls):
            path = self.extract(url)
            results.append(path)
            if i < len(urls) - 1:
                time.sleep(delay)
        return results

    # ── Narzędzia ───────────────────────────────────────────────────────────

    @staticmethod
    def _clean_text(text: str) -> str:
        """Czyści tekst — usuwa nadmiarowe białe znaki."""
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = text.strip()
        return text

    @staticmethod
    def _url_to_filename(url: str) -> str:
        """Konwertuje URL na bezpieczną nazwę pliku .md"""
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        path   = parsed.path.strip("/").replace("/", "_")
        base   = f"{path}_{domain}" if path else domain
        # Usuń znaki specjalne
        base = re.sub(r"[^\w\-]", "_", base)
        base = re.sub(r"_+", "_", base).strip("_")
        # Skróć i dodaj hash dla unikalności
        h = hashlib.md5(url.encode()).hexdigest()[:6]
        return f"{base[:60]}_{h}.md"

    def load_md(self, path: str) -> str:
        """Wczytuje plik .md. Skrót dla Holona."""
        try:
            return Path(path).read_text(encoding="utf-8")
        except Exception as e:
            print(f"[web_extractor] Błąd odczytu {path}: {e}")
            return ""

    def list_knowledge(self) -> list:
        """Zwraca listę wszystkich .md w katalogu."""
        return sorted(self.md_dir.glob("*.md"))


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    ext = WebExtractor(md_dir="knowledge_test")

    # Test lokalny bez sieci
    test_html = """
    <html>
    <head><title>Kajak eskimoski – Wikipedia</title></head>
    <body>
    <article>
    <h1>Kajak eskimoski</h1>
    <p>Kajak eskimoski to tradycyjna łódź używana przez ludy Arktyki.
    Wykonana z lekkiego szkieletu drewnianego lub kostnego, pokrytego skórą foczą.</p>
    <h2>Historia</h2>
    <p>Kajaki były używane przez Inuitów od ponad 4000 lat do polowania na morzu.
    Były niezwykle zwrotne i ciche, co czyniło je idealnymi łodziami myśliwskimi.</p>
    <h2>Budowa</h2>
    <p>Szkielet wykonany z drewna lub kości wieloryba. Pokrycie ze skóry foczej
    lub morsa, naoliwionej aby była wodoodporna.</p>
    </article>
    </body>
    </html>
    """

    parsed = ext.parse(test_html, "https://pl.wikipedia.org/wiki/Kajak_eskimoski")
    print(f"Tytuł: {parsed['title']}")
    print(f"Tekst ({len(parsed['text'])} znaków):")
    print(parsed['text'][:300])
    print("\n--- MD ---")
    print(ext.to_md(parsed)[:400])

    import shutil
    shutil.rmtree("knowledge_test", ignore_errors=True)
    print("\n[OK] Test zakończony")
