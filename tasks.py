# -*- coding: utf-8 -*-
"""
tasks.py v1.0
Lista zadań jako pliki .md z integracją holonP.

Filozofia:
  - Każde zadanie to wpis w tasks.md — czytelny bez oprogramowania
  - Priorytety: wysoki / normalny / niski
  - Kontekst: projekt, termin, tagi
  - Holon automatycznie widzi aktywne zadania w kontekście
  - Jeden plik tasks.md per projekt lub jeden globalny

Autor koncepcji: Maciej Mazur
"""

import os
import re
import time
import uuid
from pathlib import Path
from datetime import datetime, date
from typing import Optional, List, Dict
from dataclasses import dataclass, field
from enum import Enum


# ============================================================
# STAŁE
# ============================================================

DEFAULT_TASKS_DIR  = "tasks"
TASKS_FILE         = "tasks.md"
DATETIME_FORMAT    = "%Y-%m-%d %H:%M"
DATE_FORMAT        = "%Y-%m-%d"

TASK_PREFIX = "[ZADANIE]"


# ============================================================
# ENUMS
# ============================================================

class Priority(Enum):
    HIGH   = "wysoki"
    NORMAL = "normalny"
    LOW    = "niski"

    @classmethod
    def from_str(cls, s: str) -> 'Priority':
        s = s.lower().strip()
        if s in ('wysoki', 'high', '!', 'pilne', 'ważne'):
            return cls.HIGH
        if s in ('niski', 'low', 'kiedyś', 'opcjonalne'):
            return cls.LOW
        return cls.NORMAL

    @property
    def icon(self) -> str:
        return {'wysoki': '🔴', 'normalny': '🟡', 'niski': '🟢'}[self.value]


class Status(Enum):
    TODO       = "todo"
    IN_PROGRESS = "w toku"
    DONE       = "zrobione"
    CANCELLED  = "anulowane"

    @property
    def checkbox(self) -> str:
        return {
            'todo':       '[ ]',
            'w toku':     '[~]',
            'zrobione':   '[x]',
            'anulowane':  '[-]',
        }[self.value]

    @classmethod
    def from_checkbox(cls, s: str) -> 'Status':
        s = s.strip()
        if s == '[x]': return cls.DONE
        if s == '[~]': return cls.IN_PROGRESS
        if s == '[-]': return cls.CANCELLED
        return cls.TODO


# ============================================================
# TASK
# ============================================================

@dataclass
class Task:
    id:          str            = field(default_factory=lambda: uuid.uuid4().hex[:8])
    title:       str            = ""
    description: str            = ""
    status:      Status         = Status.TODO
    priority:    Priority       = Priority.NORMAL
    project:     str            = ""
    tags:        List[str]      = field(default_factory=list)
    due_date:    Optional[float] = None
    created_at:  float          = field(default_factory=time.time)
    updated_at:  float          = field(default_factory=time.time)
    done_at:     Optional[float] = None

    @property
    def is_done(self) -> bool:
        return self.status in (Status.DONE, Status.CANCELLED)

    @property
    def is_overdue(self) -> bool:
        if not self.due_date or self.is_done:
            return False
        return time.time() > self.due_date

    @property
    def due_str(self) -> str:
        if not self.due_date:
            return ""
        return datetime.fromtimestamp(self.due_date).strftime(DATE_FORMAT)

    @property
    def summary(self) -> str:
        parts = [self.title]
        if self.project:
            parts.append(f"[{self.project}]")
        if self.due_date:
            parts.append(f"do {self.due_str}")
        return " ".join(parts)

    def to_md_line(self) -> str:
        """Serializacja do jednej linii .md."""
        parts = [f"{self.status.checkbox} {self.priority.icon} {self.title}"]
        if self.project:
            parts.append(f"@{self.project}")
        if self.due_date:
            parts.append(f"📅{self.due_str}")
        if self.tags:
            parts.append(" ".join(f"#{t}" for t in self.tags))
        parts.append(f"<!-- id:{self.id} -->")
        line = " ".join(parts)
        if self.description:
            line += f"\n  > {self.description[:200]}"
        return line

    @classmethod
    def from_md_line(cls, line: str, desc_line: str = "") -> Optional['Task']:
        """Deserializacja z linii .md."""
        # Wyciągnij id
        id_match = re.search(r'<!-- id:([a-f0-9]+) -->', line)
        task_id  = id_match.group(1) if id_match else uuid.uuid4().hex[:8]

        # Status z checkboxa
        cb_match = re.match(r'\[([ x~\-])\]', line.strip())
        if not cb_match:
            return None
        status = Status.from_checkbox(f"[{cb_match.group(1)}]")

        # Usuń checkbox i id z linii
        clean = re.sub(r'\[[ x~\-]\]\s*', '', line)
        clean = re.sub(r'<!--.*?-->', '', clean).strip()

        # Priorytet z ikony
        priority = Priority.NORMAL
        for p in Priority:
            if p.icon in clean:
                priority = p
                clean = clean.replace(p.icon, '').strip()
                break

        # Projekt @projekt
        project = ""
        proj_m = re.search(r'@(\w+)', clean)
        if proj_m:
            project = proj_m.group(1)
            clean = clean.replace(proj_m.group(0), '').strip()

        # Termin 📅YYYY-MM-DD
        due_date = None
        due_m = re.search(r'📅(\d{4}-\d{2}-\d{2})', clean)
        if due_m:
            try:
                due_date = datetime.strptime(
                    due_m.group(1), DATE_FORMAT).timestamp()
            except ValueError:
                pass
            clean = clean.replace(due_m.group(0), '').strip()

        # Tagi #tag
        tags = [t.lower() for t in re.findall(r'#(\w+)', clean)]
        clean = re.sub(r'#\w+', '', clean).strip()

        # Tytuł — reszta
        title = clean.strip()
        if not title:
            return None

        # Opis z linii > ...
        description = ""
        if desc_line:
            desc_clean = desc_line.strip().lstrip('>')
            description = desc_clean.strip()

        return cls(
            id=task_id,
            title=title,
            description=description,
            status=status,
            priority=priority,
            project=project,
            tags=tags,
            due_date=due_date,
        )


# ============================================================
# TASKS MANAGER
# ============================================================

class TasksManager:
    """
    Zarządza zadaniami jako plikami .md.

    Format pliku tasks.md:
      # Zadania
      ## Projekt: holon
      [ ] 🔴 Zrób notatki @holon 📅2026-04-01 #pilne <!-- id:abc123 -->
      [x] 🟡 Napisz testy @holon <!-- id:def456 -->

    Użycie:
        tm = TasksManager(tasks_dir="tasks")
        task = tm.add("Zrób zakupy", priority=Priority.HIGH)
        tm.done(task)
        active = tm.list_active()
    """

    def __init__(self, tasks_dir: str = DEFAULT_TASKS_DIR):
        self.tasks_dir = Path(tasks_dir)
        self.tasks_dir.mkdir(parents=True, exist_ok=True)
        self.tasks_file = self.tasks_dir / TASKS_FILE
        self._tasks: Dict[str, Task] = {}
        self._load()

    # ── Tworzenie ────────────────────────────────────────────────────────────

    def add(
        self,
        title:       str,
        description: str      = "",
        priority:    Priority = Priority.NORMAL,
        project:     str      = "",
        tags:        List[str] = None,
        due_date:    Optional[float] = None,
    ) -> Task:
        """Dodaje nowe zadanie."""
        task = Task(
            title=title.strip(),
            description=description.strip(),
            priority=priority,
            project=project.strip(),
            tags=[t.lower().lstrip('#') for t in (tags or [])],
            due_date=due_date,
        )
        self._tasks[task.id] = task
        self._save()
        print(f"[tasks] Dodano: {task.priority.icon} {task.title}")
        return task

    def add_quick(self, text: str) -> Task:
        """
        Szybkie dodanie z tekstu naturalnego.
        Parsuje priorytet, projekt, tagi, termin z tekstu.
        """
        text = text.strip()

        # Priorytet ze słów kluczowych
        priority = Priority.NORMAL
        if re.search(r'\b(pilne|ważne|natychmiast|asap|!)\b', text, re.I):
            priority = Priority.HIGH
            text = re.sub(r'\b(pilne|ważne|natychmiast|asap)\b', '',
                          text, flags=re.I).strip(' !')
        elif re.search(r'\b(kiedyś|opcjonalnie|może)\b', text, re.I):
            priority = Priority.LOW
            text = re.sub(r'\b(kiedyś|opcjonalnie|może)\b', '',
                          text, flags=re.I).strip()

        # Projekt @projekt
        project = ""
        proj_m = re.search(r'@(\w+)', text)
        if proj_m:
            project = proj_m.group(1)
            text = text.replace(proj_m.group(0), '').strip()

        # Tagi #tag
        tags = [t.lower() for t in re.findall(r'#(\w+)', text)]
        text = re.sub(r'#\w+', '', text).strip()

        # Termin — "do YYYY-MM-DD" lub "jutro" lub "za X dni"
        due_date = None
        due_m = re.search(r'do\s+(\d{4}-\d{2}-\d{2})', text, re.I)
        if due_m:
            try:
                due_date = datetime.strptime(
                    due_m.group(1), DATE_FORMAT).timestamp()
            except ValueError:
                pass
            text = text.replace(due_m.group(0), '').strip()
        elif 'jutro' in text.lower():
            import datetime as dt
            tomorrow = dt.date.today() + dt.timedelta(days=1)
            due_date = datetime.combine(tomorrow, datetime.min.time()).timestamp()
            text = re.sub(r'\bjutro\b', '', text, flags=re.I).strip()

        return self.add(
            title=text,
            priority=priority,
            project=project,
            tags=tags,
            due_date=due_date,
        )

    # ── Zmiana statusu ───────────────────────────────────────────────────────

    def done(self, task_or_id) -> Optional[Task]:
        """Oznacza zadanie jako zrobione."""
        task = self._resolve(task_or_id)
        if not task:
            return None
        task.status   = Status.DONE
        task.done_at  = time.time()
        task.updated_at = time.time()
        self._save()
        print(f"[tasks] Zrobione: ✅ {task.title}")
        return task

    def start(self, task_or_id) -> Optional[Task]:
        """Oznacza zadanie jako w toku."""
        task = self._resolve(task_or_id)
        if not task:
            return None
        task.status = Status.IN_PROGRESS
        task.updated_at = time.time()
        self._save()
        return task

    def cancel(self, task_or_id) -> Optional[Task]:
        """Anuluje zadanie."""
        task = self._resolve(task_or_id)
        if not task:
            return None
        task.status = Status.CANCELLED
        task.updated_at = time.time()
        self._save()
        return task

    def set_priority(self, task_or_id, priority: Priority) -> Optional[Task]:
        task = self._resolve(task_or_id)
        if not task:
            return None
        task.priority = priority
        task.updated_at = time.time()
        self._save()
        return task

    # ── Wyszukiwanie ─────────────────────────────────────────────────────────

    def list_active(self) -> List[Task]:
        """Aktywne zadania (todo + w toku), priorytet malejąco."""
        tasks = [t for t in self._tasks.values() if not t.is_done]
        tasks.sort(key=lambda t: (
            {'wysoki': 0, 'normalny': 1, 'niski': 2}[t.priority.value],
            t.is_overdue and -1 or 0,
            t.created_at
        ))
        return tasks

    def list_done(self, last_n: int = 10) -> List[Task]:
        """Ostatnio ukończone zadania."""
        tasks = [t for t in self._tasks.values() if t.status == Status.DONE]
        tasks.sort(key=lambda t: -(t.done_at or 0))
        return tasks[:last_n]

    def list_overdue(self) -> List[Task]:
        """Przeterminowane zadania."""
        return [t for t in self._tasks.values() if t.is_overdue]

    def by_project(self, project: str) -> List[Task]:
        """Zadania z projektu."""
        return [t for t in self._tasks.values()
                if t.project.lower() == project.lower()]

    def by_tag(self, tag: str) -> List[Task]:
        tag = tag.lower().lstrip('#')
        return [t for t in self._tasks.values() if tag in t.tags]

    def search(self, query: str) -> List[Task]:
        """Wyszukiwanie po tytule i opisie."""
        q = query.lower()
        return [t for t in self._tasks.values()
                if q in t.title.lower() or q in t.description.lower()]

    def get_by_id(self, task_id: str) -> Optional[Task]:
        return self._tasks.get(task_id)

    # ── Formatowanie ─────────────────────────────────────────────────────────

    def format_active(self) -> str:
        """Lista aktywnych zadań do wyświetlenia."""
        tasks = self.list_active()
        if not tasks:
            return "✅ Brak aktywnych zadań!"

        lines = []
        current_project = None
        for t in tasks:
            if t.project != current_project:
                current_project = t.project
                if t.project:
                    lines.append(f"\n**{t.project}:**")
            overdue = " ⚠️ PRZETERMINOWANE" if t.is_overdue else ""
            due = f" 📅{t.due_str}" if t.due_date else ""
            status_icon = "▶️ " if t.status == Status.IN_PROGRESS else ""
            lines.append(
                f"{t.priority.icon} {status_icon}{t.title}{due}{overdue}"
                + (f"\n   `{t.id}`" if t.description else "")
            )
        return "\n".join(lines)

    def format_summary(self) -> str:
        """Krótkie podsumowanie dla Holona."""
        active   = len(self.list_active())
        overdue  = len(self.list_overdue())
        high     = sum(1 for t in self.list_active()
                       if t.priority == Priority.HIGH)
        parts = [f"{active} aktywnych zadań"]
        if high:
            parts.append(f"{high} pilnych 🔴")
        if overdue:
            parts.append(f"{overdue} przeterminowanych ⚠️")
        return ", ".join(parts)

    # ── Integracja z holonP ──────────────────────────────────────────────────

    def inject_into_holon(self, holomem, max_tasks: int = 5) -> list:
        """
        Wstrzykuje aktywne zadania do store Holona.
        Pilne zadania trafiają jako is_work=True.
        """
        try:
            from holonP import Item
        except ImportError:
            return []

        tasks = self.list_active()[:max_tasks]
        if not tasks:
            return []

        # Zbuduj blok zadań
        lines = ["Aktywne zadania:"]
        for t in tasks:
            due = f" [do {t.due_str}]" if t.due_date else ""
            overdue = " ⚠️" if t.is_overdue else ""
            lines.append(f"- {t.priority.icon} {t.title}{due}{overdue}")

        content = f"{TASK_PREFIX}\n" + "\n".join(lines)

        has_high = any(t.priority == Priority.HIGH for t in tasks)

        item = __import__('holonP', fromlist=['Item']).Item(
            id=f"tasks_{uuid.uuid4().hex[:8]}",
            content=content,
            embedding=[0.0] * holomem.cfg.total_dim,
            age=0,
            recalled=True,
            relevance=2.5 if has_high else 2.0,
            is_fact=True,
            is_work=has_high,
            created_at=time.time(),
        )
        holomem.store.append(item)
        return [item]

    # ── Wewnętrzne ───────────────────────────────────────────────────────────

    def _resolve(self, task_or_id) -> Optional[Task]:
        """Przyjmuje Task lub id jako string/int."""
        if isinstance(task_or_id, Task):
            return self._tasks.get(task_or_id.id)
        # Szukaj po id lub po numerze z listy
        if isinstance(task_or_id, str):
            if task_or_id in self._tasks:
                return self._tasks[task_or_id]
            # Szukaj po tytule (częściowe dopasowanie)
            matches = [t for t in self._tasks.values()
                       if task_or_id.lower() in t.title.lower()]
            return matches[0] if matches else None
        if isinstance(task_or_id, int):
            active = self.list_active()
            if 1 <= task_or_id <= len(active):
                return active[task_or_id - 1]
        return None

    def _save(self):
        """Zapisuje wszystkie zadania do tasks.md."""
        lines = [
            "# Zadania",
            f"*Zaktualizowano: {datetime.now().strftime(DATETIME_FORMAT)}*",
            "",
        ]

        # Grupuj po projektach
        projects: Dict[str, List[Task]] = {}
        no_project: List[Task] = []

        for task in sorted(self._tasks.values(),
                           key=lambda t: (t.is_done, t.created_at)):
            if task.project:
                projects.setdefault(task.project, []).append(task)
            else:
                no_project.append(task)

        if no_project:
            lines.append("## Ogólne\n")
            for task in no_project:
                lines.append(task.to_md_line())
            lines.append("")

        for proj, tasks in projects.items():
            lines.append(f"## Projekt: {proj}\n")
            for task in tasks:
                lines.append(task.to_md_line())
            lines.append("")

        # Statystyki na dole
        active = len(self.list_active())
        done   = sum(1 for t in self._tasks.values() if t.status == Status.DONE)
        lines += [
            "---",
            f"*Aktywne: {active} | Zrobione: {done} | Łącznie: {len(self._tasks)}*"
        ]

        self.tasks_file.write_text('\n'.join(lines), encoding='utf-8')

    def _load(self):
        """Wczytuje zadania z tasks.md."""
        if not self.tasks_file.exists():
            return
        try:
            lines = self.tasks_file.read_text(encoding='utf-8').split('\n')
            i = 0
            while i < len(lines):
                line = lines[i]
                # Linia z zadaniem — zaczyna się od checkboxa
                if re.match(r'\s*\[([ x~\-])\]', line):
                    desc_line = ""
                    if i + 1 < len(lines) and lines[i+1].strip().startswith('>'):
                        desc_line = lines[i+1]
                        i += 1
                    task = Task.from_md_line(line, desc_line)
                    if task:
                        self._tasks[task.id] = task
                i += 1
            if self._tasks:
                print(f"[tasks] Wczytano {len(self._tasks)} zadań")
        except Exception as e:
            print(f"[tasks] Błąd wczytywania: {e}")

    @property
    def count(self) -> int:
        return len(self._tasks)


# ============================================================
# PARSER KOMEND DLA HOLONA
# ============================================================

def parse_task_command(text: str, tm: TasksManager) -> Optional[str]:
    """
    Rozpoznaje komendy zadań w tekście użytkownika.
    Zwraca odpowiedź lub None jeśli nie rozpoznano.

    Komendy:
      "dodaj zadanie: X"        → dodaje zadanie
      "zadanie: X"              → dodaje zadanie
      "zrób: X"                 → oznacza jako done
      "zrobione: X"             → oznacza jako done
      "pokaż zadania"           → lista aktywnych
      "co mam do zrobienia"     → lista aktywnych
      "pilne zadania"           → filtr wysoki priorytet
    """
    t  = text.strip()
    tl = t.lower()

    # dodaj zadanie: X  /  zadanie: X  /  todo: X
    m = re.match(
        r'(?:dodaj\s+)?(?:zadanie|todo|task):?\s+(.+)',
        t, re.IGNORECASE | re.DOTALL
    )
    if m:
        content = m.group(1).strip()
        task = tm.add_quick(content)
        due = f" do {task.due_str}" if task.due_date else ""
        return (f"✅ Dodano zadanie: {task.priority.icon} **{task.title}**{due}\n"
                f"`id: {task.id}`")

    # zrobione: X  /  zrób: X  /  ukończ: X
    m = re.match(
        r'(?:zrobione|zrób|ukończ|done):?\s+(.+)',
        t, re.IGNORECASE
    )
    if m:
        query = m.group(1).strip()
        task = tm._resolve(query)
        if task:
            tm.done(task)
            return f"✅ Oznaczono jako zrobione: **{task.title}**"
        return f"Nie znalazłem zadania: '{query}'"

    # pokaż zadania / co mam do zrobienia / lista zadań / moje zadania
    if re.search(
        r'(pokaż|lista|wyświetl)\s+zadania?|co\s+mam\s+(do\s+zrobienia|zrobić)|'
        r'moje\s+zadania?|aktywne\s+zadania?',
        tl
    ):
        active = tm.list_active()
        if not active:
            return "✅ Nie masz żadnych aktywnych zadań!"
        return f"📋 Twoje zadania ({len(active)}):\n\n{tm.format_active()}"

    # pilne zadania / co jest pilne
    if re.search(r'(pilne|wysokii?\s+priorytet|najpilniejsze)', tl):
        tasks = [t for t in tm.list_active()
                 if t.priority == Priority.HIGH]
        if not tasks:
            return "Nie masz pilnych zadań. 👍"
        lines = [f"🔴 **{t.title}**" +
                 (f" 📅{t.due_str}" if t.due_date else "")
                 for t in tasks]
        return "🔴 Pilne zadania:\n\n" + "\n".join(lines)

    # przeterminowane
    if re.search(r'(przeterminowane|spóźnione|po terminie)', tl):
        tasks = tm.list_overdue()
        if not tasks:
            return "Żadne zadanie nie jest przeterminowane. ✅"
        lines = [f"⚠️ **{t.title}** [było do {t.due_str}]" for t in tasks]
        return "⚠️ Przeterminowane:\n\n" + "\n".join(lines)

    return None


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    import shutil

    TEST_DIR = "test_tasks"
    print("=== TEST TasksManager ===\n")

    tm = TasksManager(tasks_dir=TEST_DIR)

    # Dodaj zadania
    t1 = tm.add("Zrób zakupy", priority=Priority.NORMAL,
                 tags=["dom"])
    t2 = tm.add("Napisz testy holonP", priority=Priority.HIGH,
                 project="holon", tags=["kod"])
    t3 = tm.add("Przeczytaj artykuł o AI",
                 priority=Priority.LOW, tags=["nauka"])
    t4 = tm.add_quick("pilne zadzwoń do Ani @kontakty #telefon")
    t5 = tm.add_quick("zadanie: napisz dokumentację @holon do 2026-12-31")

    print(f"\nLiczba zadań: {tm.count}")

    # Lista aktywnych
    print("\nAktywne zadania:")
    print(tm.format_active())

    # Podsumowanie
    print(f"\nPodsumowanie: {tm.format_summary()}")

    # Done
    tm.done(t1)
    tm.start(t2)
    print(f"\nPo done+start: {tm.format_summary()}")

    # Wyszukiwanie
    print("\nSzukaj 'holon':")
    for t in tm.search("holon"):
        print(f"  → {t.priority.icon} {t.title} [{t.status.value}]")

    # Parser komend
    print("\nTest parsera:")
    cmds = [
        "dodaj zadanie: Kupić kawę #zakupy",
        "pokaż zadania",
        "pilne zadania",
        "zrobione: przeczytaj",
    ]
    for cmd in cmds:
        result = parse_task_command(cmd, tm)
        if result:
            print(f"\n  '{cmd}'")
            print(f"  → {result[:120]}")

    # Reload z dysku
    tm2 = TasksManager(tasks_dir=TEST_DIR)
    print(f"\nPo reload: {tm2.count} zadań")
    assert tm2.count == tm.count

    # Sprawdź plik .md
    md_content = (Path(TEST_DIR) / TASKS_FILE).read_text(encoding='utf-8')
    print(f"\nFragment tasks.md:\n{md_content[:300]}")

    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("\n=== TEST OK ===")
