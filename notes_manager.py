# -*- coding: utf-8 -*-
"""
notes_manager.py v1.4
Notatki jako pliki .md z integracją holonP.
Autor: Maciej Mazur
"""

import re
import time
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

DEFAULT_NOTES_DIR = "notes"
DATE_FORMAT       = "%Y-%m-%d"
TIME_FORMAT       = "%H:%M"
DATETIME_FORMAT   = "%Y-%m-%d %H:%M"

TAG_PATTERN = re.compile(r'#(\w+)')
NOTE_PREFIX = "[NOTATKA]"


class Note:
    def __init__(self, title: str, content: str, path: Path = None,
                 created_at: float = None, updated_at: float = None,
                 tags: List[str] = None, pinned: bool = False):
        self.title = title.strip()
        self.content = content.strip()
        self.path = path
        self.created_at = created_at or time.time()
        self.updated_at = updated_at or self.created_at
        self.tags = tags or self._extract_tags(content)
        self.pinned = pinned

    @staticmethod
    def _extract_tags(text: str) -> List[str]:
        return list({t.lower() for t in TAG_PATTERN.findall(text)})

    @property
    def filename(self) -> str:
        if self.path:
            return self.path.name
        date_str = datetime.fromtimestamp(self.created_at).strftime(DATE_FORMAT)
        safe = re.sub(r'[^\w\s-]', '', self.title.lower())
        safe = re.sub(r'[\s-]+', '_', safe).strip('_')
        return f"{date_str}_{safe[:40]}.md"

    @property
    def summary(self) -> str:
        lines = [l.strip() for l in self.content.split('\n') if l.strip() and not l.startswith('#')]
        return ' '.join(lines)[:150]

    def to_md(self) -> str:
        created_str = datetime.fromtimestamp(self.created_at).strftime(DATETIME_FORMAT)
        updated_str = datetime.fromtimestamp(self.updated_at).strftime(DATETIME_FORMAT)
        header = f"# {self.title}\n\n"
        meta = (f"**Utworzono:** {created_str}  \n"
                f"**Zaktualizowano:** {updated_str}  \n")
        if self.tags:
            meta += f"**Tagi:** {' '.join('#' + t for t in self.tags)}  \n"
        if self.pinned:
            meta += "**Przypięta:** tak  \n"
        return header + meta + "\n---\n\n" + self.content

    @classmethod
    def from_md(cls, path: Path) -> Optional['Note']:
        try:
            text = path.read_text(encoding='utf-8')
            lines = text.split('\n')
            title = path.stem.replace('_', ' ')
            for line in lines:
                if line.startswith('# '):
                    title = line[2:].strip()
                    break
            created_at = path.stat().st_ctime
            updated_at = path.stat().st_mtime
            pinned = False
            for line in lines:
                if line.startswith('**Utworzono:**'):
                    try:
                        ds = line.split('**Utworzono:**')[1].strip()
                        created_at = datetime.strptime(ds, DATETIME_FORMAT).timestamp()
                    except Exception:
                        pass
                elif line.startswith('**Zaktualizowano:**'):
                    try:
                        ds = line.split('**Zaktualizowano:**')[1].strip()
                        updated_at = datetime.strptime(ds, DATETIME_FORMAT).timestamp()
                    except Exception:
                        pass
                elif '**Przypięta:** tak' in line:
                    pinned = True
            sep_idx = text.find('\n---\n')
            if sep_idx != -1:
                content = text[sep_idx + 5:].strip()
            else:
                content_lines = []
                past_header = False
                for line in lines:
                    if line.startswith('# ') and not past_header:
                        past_header = True
                        continue
                    if past_header:
                        content_lines.append(line)
                content = '\n'.join(content_lines).strip()
            tags = cls._extract_tags(content)
            return cls(title=title, content=content, path=path,
                       created_at=created_at, updated_at=updated_at,
                       tags=tags, pinned=pinned)
        except Exception as e:
            print(f"[notes] Błąd odczytu {path}: {e}")
            return None

    def __repr__(self):
        return f"Note('{self.title}', tags={self.tags})"


class NotesManager:
    def __init__(self, notes_dir: str = DEFAULT_NOTES_DIR):
        self.notes_dir = Path(notes_dir)
        self.notes_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Note] = {}
        self._load_all()

    def create(self, title: str, content: str, tags: List[str] = None, pinned: bool = False) -> Note:
        note = Note(title=title, content=content, tags=tags, pinned=pinned)
        path = self.notes_dir / note.filename
        if path.exists():
            stem = path.stem
            path = self.notes_dir / f"{stem}_{uuid.uuid4().hex[:4]}.md"
        note.path = path
        path.write_text(note.to_md(), encoding='utf-8')
        self._cache[str(path)] = note
        print(f"[notes] Zapisano: {path.name}")
        return note

    def create_quick(self, text: str) -> Note:
        lines = text.strip().split('\n', 1)
        title = lines[0].strip()[:80]
        content = lines[1].strip() if len(lines) > 1 else title
        return self.create(title=title, content=content)

    def update(self, note: Note, new_content: str = None, new_title: str = None) -> Note:
        if new_content is not None:
            note.content = new_content.strip()
            note.tags = Note._extract_tags(new_content)
        if new_title is not None:
            note.title = new_title.strip()
        note.updated_at = time.time()
        if note.path and note.path.exists():
            note.path.write_text(note.to_md(), encoding='utf-8')
            self._cache[str(note.path)] = note
            print(f"[notes] Zaktualizowano: {note.path.name}")
        return note

    def append(self, note: Note, text: str) -> Note:
        new_content = note.content + "\n\n" + text.strip()
        return self.update(note, new_content=new_content)

    def pin(self, note: Note, pinned: bool = True) -> Note:
        note.pinned = pinned
        return self.update(note)

    def delete(self, note: Note) -> bool:
        if not note.path or not note.path.exists():
            return False
        trash = self.notes_dir / '.trash'
        trash.mkdir(exist_ok=True)
        dest = trash / note.path.name
        note.path.rename(dest)
        self._cache.pop(str(note.path), None)
        print(f"[notes] Usunięto: {note.path.name} → .trash")
        return True

    def search(self, query: str, top_k: int = 5) -> List[Note]:
        query_lower = query.lower()
        words = [w for w in query_lower.split() if len(w) >= 3]
        scored = []
        for note in self._cache.values():
            haystack = (note.title + ' ' + note.content).lower()
            score = sum(2 if w in note.title.lower() else 1 for w in words if w in haystack)
            score += sum(2 for w in words if any(w in t for t in note.tags))
            if note.pinned:
                score += 1
            if score > 0:
                scored.append((score, note))
        scored.sort(key=lambda x: (-x[0], -x[1].updated_at))
        return [n for _, n in scored[:top_k]]

    def by_tag(self, tag: str) -> List[Note]:
        tag = tag.lower().lstrip('#')
        return [n for n in self._cache.values() if tag in n.tags]

    def recent(self, n: int = 5) -> List[Note]:
        notes = list(self._cache.values())
        notes.sort(key=lambda x: -x.updated_at)
        return notes[:n]

    def pinned(self) -> List[Note]:
        return [n for n in self._cache.values() if n.pinned]

    def list_all(self) -> List[Note]:
        notes = list(self._cache.values())
        notes.sort(key=lambda x: -x.updated_at)
        return notes

    def inject_note(self, holomem, note: Note) -> None:
        """Wstrzykuje pojedynczą notatkę do pamięci Holona jako fakt."""
        try:
            from holonP import Item
        except ImportError:
            # Jeśli nie ma holonP, próbujemy dodać do store bezpośrednio
            if hasattr(holomem, 'store') and isinstance(holomem.store, list):
                fake_item = type('Item', (), {})
                fake_item.id = f"note_{uuid.uuid4().hex[:8]}"
                fake_item.content = f"{NOTE_PREFIX} {note.title}:\n{note.summary}"
                fake_item.embedding = [0.0] * holomem.cfg.total_dim
                fake_item.age = 0
                fake_item.recalled = True
                fake_item.relevance = 2.0 if note.pinned else 1.5
                fake_item.is_fact = True
                fake_item.created_at = note.updated_at
                holomem.store.append(fake_item)
            return
        content = f"{NOTE_PREFIX} {note.title}:\n{note.summary}"
        item = Item(
            id=f"note_{uuid.uuid4().hex[:8]}",
            content=content,
            embedding=[0.0] * holomem.cfg.total_dim,
            age=0,
            recalled=True,
            relevance=2.0 if note.pinned else 1.5,
            is_fact=True,
            created_at=note.updated_at,
        )
        holomem.store.append(item)

    def inject_into_holon(self, holomem, query: str, top_k: int = 2) -> list:
        """Wstrzykuje relewantne notatki do store Holona."""
        results = self.search(query, top_k=top_k)
        injected = []
        for note in results:
            self.inject_note(holomem, note)
            injected.append(note)
        return injected

    def save_from_conversation(self, holomem, title: str = None) -> Optional[Note]:
        history = getattr(holomem, 'conversation_history', [])
        if not history:
            return None
        recent_h = history[-4:]
        lines = []
        for entry in recent_h:
            role = "Ty" if entry['role'] == 'user' else "Holon"
            lines.append(f"**{role}:** {entry['content']}")
        content = '\n\n'.join(lines)
        auto_title = title or f"Rozmowa {datetime.now().strftime(DATETIME_FORMAT)}"
        note = self.create(title=auto_title, content=content)
        self.inject_note(holomem, note)
        return note

    def format_list(self, notes: List[Note] = None) -> str:
        if notes is None:
            notes = self.recent(10)
        if not notes:
            return "Brak notatek."
        lines = []
        for i, note in enumerate(notes, 1):
            date_str = datetime.fromtimestamp(note.updated_at).strftime(DATE_FORMAT)
            pin = "📌 " if note.pinned else ""
            tags = (" " + " ".join("#" + t for t in note.tags[:3]) if note.tags else "")
            lines.append(f"{i}. {pin}{note.title} [{date_str}]{tags}\n   {note.summary[:80]}{'...' if len(note.summary) > 80 else ''}")
        return '\n'.join(lines)

    def format_note(self, note: Note) -> str:
        date_str = datetime.fromtimestamp(note.updated_at).strftime(DATETIME_FORMAT)
        tags = " ".join("#" + t for t in note.tags) if note.tags else "brak"
        return f"📝 **{note.title}**\nZaktualizowano: {date_str} | Tagi: {tags}\n\n{note.content}"

    def _load_all(self):
        count = 0
        for md_file in sorted(self.notes_dir.glob("*.md")):
            note = Note.from_md(md_file)
            if note:
                self._cache[str(md_file)] = note
                count += 1
        if count:
            print(f"[notes] Wczytano {count} notatek z {self.notes_dir}")

    def reload(self):
        self._cache.clear()
        self._load_all()

    @property
    def count(self) -> int:
        return len(self._cache)


def parse_note_command(text: str, nm: NotesManager, holomem=None) -> Optional[str]:
    t = text.strip()
    tl = t.lower()

    # ============================================================
    # WYSZUKAJ I ZAPISZ – poprawione parsowanie
    # ============================================================
    # Pełna forma: "wyszukaj wszystko o X i zapisz jako notatkę Y"
    # Jeśli Y zawiera "dysk", ignorujemy i używamy X jako nazwy pliku.
    m = re.match(r'wyszukaj\s+(?:wszystko\s+o|informacje\s+o)\s+(.+?)\s+i\s+zapisz(?:\s+jako\s+notatk(?:ę|e))?\s+(.+)$', t, re.IGNORECASE)
    if m:
        query = m.group(1).strip()
        filename_part = m.group(2).strip()
        # Jeśli filename_part to "na dysk" lub zawiera słowo "dysk", generuj nazwę z query
        if re.search(r'(na\s+)?dysk|dysku', filename_part, re.IGNORECASE):
            filename = query.replace(' ', '_')[:40] + '.md'
        else:
            filename = filename_part
            if not filename.endswith('.md'):
                filename += '.md'
        return f"__SEARCH_AND_SAVE__|{query}|{filename}"

    # Krótsza forma: "wyszukaj o X i zapisz"
    m = re.match(r'wyszukaj\s+o\s+(.+?)\s+i\s+zapisz(?:\s+jako\s+notatkę)?\s*$', t, re.IGNORECASE)
    if m:
        query = m.group(1).strip()
        filename = query.replace(' ', '_')[:40] + '.md'
        return f"__SEARCH_AND_SAVE__|{query}|{filename}"

    # ============================================================
    # ZAPISZ NOTATKĘ (istniejącą)
    # ============================================================
    m = re.match(r'zapisz\s+notatk(?:ę|e)?\s+["\']?(.+?)["\']?\s*$', t, re.IGNORECASE)
    if m:
        title_or_filename = m.group(1).strip()
        found = None
        for note in nm.list_all():
            if note.title.lower() == title_or_filename.lower():
                found = note
                break
            if note.path and note.path.name.lower() == title_or_filename.lower():
                found = note
                break
        if not found:
            results = nm.search(title_or_filename, top_k=1)
            if results:
                found = results[0]
        if found:
            if found.path and found.path.exists():
                return f"✅ Notatka **{found.title}** już istnieje jako plik: `{found.path.name}`"
            else:
                found.path = nm.notes_dir / found.filename
                found.path.write_text(found.to_md(), encoding='utf-8')
                nm._cache[str(found.path)] = found
                if holomem:
                    nm.inject_note(holomem, found)
                return f"📝 Zapisano notatkę **{found.title}** jako plik: `{found.path.name}`"
        return f"⚠️ Nie znaleziono notatki o tytule '{title_or_filename}'."

    # ============================================================
    # ZAPISZ TĘ NOTATKĘ
    # ============================================================
    if re.search(r'zapisz\s+t[ęe]\s+notatk[ęe]', t, re.IGNORECASE):
        if holomem and hasattr(holomem, 'conversation_history'):
            for entry in reversed(holomem.conversation_history):
                if entry['role'] == 'assistant' and 'Notatka' in entry['content']:
                    m_t = re.search(r'\*\*([^*]+)\*\*', entry['content'])
                    if m_t:
                        title = m_t.group(1).strip()
                        for note in nm.list_all():
                            if note.title == title:
                                if note.path and note.path.exists():
                                    return f"✅ Notatka **{note.title}** już jest zapisana jako `{note.path.name}`"
                                else:
                                    note.path = nm.notes_dir / note.filename
                                    note.path.write_text(note.to_md(), encoding='utf-8')
                                    nm._cache[str(note.path)] = note
                                    nm.inject_note(holomem, note)
                                    return f"📝 Zapisano notatkę **{note.title}** jako plik: `{note.path.name}`"
                        return f"⚠️ Nie mogę znaleźć notatki o tytule '{title}'."
        return "⚠️ Nie wiem, którą notatkę zapisać. Powiedz: 'zapisz notatkę <tytuł>'."

    # ============================================================
    # ZAPISZ ROZMOWĘ
    # ============================================================
    if re.search(r'zapisz\s+(tę\s+)?rozmow[ęe]|zapisz\s+chat', tl):
        if holomem is None:
            return "⚠️ Funkcja wymaga podłączenia do Holona."
        note = nm.save_from_conversation(holomem)
        if note:
            return f"📝 Zapisano rozmowę: **{note.title}**\nPlik: {note.path.name}"
        return "⚠️ Brak historii rozmowy do zapisania."

    # ============================================================
    # TWORZENIE NOWEJ NOTATKI (rozszerzone formy)
    # ============================================================
    m = re.match(r'(?:zanotuj|zapisz|zrób|napisz|stwórz|utwórz)\s+(?:krótk[aą]\s+)?(?:notatkę?\s+)?(?:na\s+temat\s+|o\s+)?(.+)', t, re.IGNORECASE | re.DOTALL)
    if m:
        content = m.group(1).strip()
        if len(content) < 2:
            return "💡 Co chcesz zanotować? Podaj treść notatki."
        note = nm.create_quick(content)
        if holomem:
            nm.inject_note(holomem, note)
        return f"📝 Zapisano notatkę: **{note.title}**\nPlik: {note.path.name}"

    m = re.match(r'(?:zanotuj|zapisz):?\s+(.+)', t, re.IGNORECASE | re.DOTALL)
    if m:
        content = m.group(1).strip()
        if len(content) < 2:
            return "💡 Co chcesz zanotować? Podaj treść notatki."
        note = nm.create_quick(content)
        if holomem:
            nm.inject_note(holomem, note)
        return f"📝 Zapisano notatkę: **{note.title}**\nPlik: {note.path.name}"

    # ============================================================
    # POMOC / SAMO ZAPISZ
    # ============================================================
    if re.match(r'^zapisz$', tl):
        return "💡 Użyj: `zapisz: <treść>` lub `zanotuj: <treść>`\nNp: zapisz: spotkanie z klientem o 14:00"

    # ============================================================
    # POKAŻ NOTATKI
    # ============================================================
    if re.search(r'(pokaż|lista|wyświetl)\s+notatk', tl):
        notes = nm.recent(8)
        return f"📋 Twoje notatki:\n\n{nm.format_list(notes)}"

    # ============================================================
    # SZUKAJ W NOTATKACH
    # ============================================================
    m = re.search(r'(?:szukaj\s+(?:w\s+)?notatk(?:ach|i)|notatki\s+o)\s+(.+)', tl)
    if m:
        query = m.group(1).strip()
        results = nm.search(query, top_k=5)
        if not results:
            return f"Nie znalazłem notatek o '{query}'."
        return f"📋 Notatki o '{query}':\n\n{nm.format_list(results)}"

    # ============================================================
    # NOTATKI Z TAGIEM
    # ============================================================
    m = re.search(r'notatki\s+(?:z\s+)?(?:tagiem\s+)?#?(\w+)', tl)
    if m:
        tag = m.group(1)
        results = nm.by_tag(tag)
        if not results:
            return f"Brak notatek z tagiem #{tag}."
        return f"📋 Notatki #{tag}:\n\n{nm.format_list(results)}"

    return None


if __name__ == "__main__":
    import shutil
    TEST_DIR = "test_notes"
    print("=== TEST NotesManager v1.4 ===\n")
    nm = NotesManager(notes_dir=TEST_DIR)
    nm.create("Kajak eskimoski", "Kajak... #kajak")
    nm.create("Architektura Holona", "Holon... #holon", pinned=True)
    nm.create_quick("Pomysł na LinkedIn\nNapisać post...")
    print(f"Liczba notatek: {nm.count}")
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("=== TEST OK ===")