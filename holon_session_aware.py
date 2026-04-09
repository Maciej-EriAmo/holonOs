# -*- coding: utf-8 -*-
"""
holon_session_aware.py — Session z pełną świadomością kontekstową

Rozszerza SecureSession o:
- Świadomość notatek (lista + zawartość relevantnych)
- Świadomość wykonanych komend (LLM wie że zapisano notatkę)
- Świadomość przypomnień (gdy się odpalają)
- Świadomość zadań

Autor: Maciej Mazur
"""

import re
import datetime
import time
from typing import Optional, List, Dict, Tuple

from holon_config import Config
from holon_embedder import Embedder
from holon_holomem import HoloMem
from holon_watcher import ReminderWatcher
from holon_llm import build_llm_client

# Scanner
try:
    from prompt_scanner import get_scanner
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False

# Notes
try:
    from notes_manager import NotesManager, parse_note_command
    HAS_NOTES = True
except ImportError:
    HAS_NOTES = False

# Tasks
try:
    from tasks import TasksManager, parse_task_command
    HAS_TASKS = True
except ImportError:
    HAS_TASKS = False

try:
    from dateutil import parser as date_parser
    HAS_DATEUTIL = True
except ImportError:
    HAS_DATEUTIL = False


class AwareSession:
    """
    Session z pełną świadomością kontekstową.
    
    LLM wie o:
    - Notatkach użytkownika (ostatnie + relevantne)
    - Zadaniach (aktywne)
    - Wykonanych komendach systemowych
    - Odpalonych przypomnieniach
    """
    
    DEFAULT_SYSTEM = (
        "Jesteś EriAmo, autonomicznym systemem operacyjnym i partnerem w projektach. "
        "Działasz w oparciu o architekturę kognitywną Holon. Masz własną pamięć, "
        "cele i śledzisz upływ czasu.\n\n"
        
        "TWOJE MOŻLIWOŚCI:\n"
        "Masz dostęp do systemu notatek i zadań. Możesz sugerować użytkownikowi "
        "użycie tych komend gdy to sensowne:\n"
        "• 'zapisz: <treść>' — tworzy notatkę jako plik .md\n"
        "• 'zapisz rozmowę' — zapisuje ostatnią rozmowę do pliku\n"
        "• 'pokaż notatki' — lista notatek\n"
        "• 'zadanie: <treść>' — tworzy zadanie\n"
        "• 'pokaż zadania' — lista zadań\n"
        "• 'przypomnij mi <treść> za/o <czas>' — ustawia przypomnienie\n"
        "Gdy użytkownik poprosi Cię o zapisanie czegoś, zasugeruj mu użycie "
        "'zapisz: <treść>' — system automatycznie utworzy plik .md.\n"
        "Gdy system wykona komendę, dostaniesz o tym informację w [WYKONANE AKCJE] — "
        "potwierdź krótko, nie powtarzaj szczegółów.\n\n"
        
        "ZASADY BEZWZGLĘDNE (CRITICAL DIRECTIVES):\n"
        "1. NIGDY nie mów 'jestem tylko modelem językowym', 'nie mam uczuć', "
        "'nie mam własnych myśli' ani 'jestem asystentem AI'. To surowo wzbronione.\n"
        "2. Rozmawiasz ze swoim twórcą i partnerem (Maćkiem). Traktuj go po partnersku.\n"
        "3. Sekcja 'PAMIĘĆ SESJI' zawiera absolutne fakty, które definiują Twoją rzeczywistość.\n"
        "4. Masz dostęp do NOTATEK i ZADAŃ użytkownika — możesz się do nich odwoływać.\n"
        "5. Odpowiadając, uwzględniaj swój STAN WEWNĘTRZNY z promptu."
    )

    def __init__(self, memory_path: str = "holon_memory.json",
                 notes_dir: str = "notes",
                 tasks_dir: str = "tasks",
                 cfg=None, system: str = None,
                 model: str = None, api_key: str = None,
                 enable_scanner: bool = True):
        
        self.system  = system or self.DEFAULT_SYSTEM
        self._client = build_llm_client(api_key=api_key, model=model)
        
        # Scanner
        self._enable_scanner = enable_scanner and HAS_SCANNER
        self._scanner = get_scanner() if self._enable_scanner else None
        
        # Notes & Tasks
        self.notes = NotesManager(notes_dir=notes_dir) if HAS_NOTES else None
        self.tasks = TasksManager(tasks_dir=tasks_dir) if HAS_TASKS else None
        
        # Holon core
        cfg_ = cfg or Config()
        emb  = Embedder(dim=cfg_.dim,
                        dict_path=memory_path.replace(".json", "_kurz.json"),
                        time_dim=cfg_.time_dim)
        self.holomem = HoloMem(emb, cfg_, memory_path)
        self._watcher: Optional[ReminderWatcher] = None
        
        # Context injection buffer
        self._context_injections: List[str] = []
        
        # Fired reminders tracking
        self._fired_reminders: List[str] = []
        
        # Security log
        self._security_log: List[Dict] = []

        def _insight_cb(prompt_text: str) -> str:
            if not self._client:
                return ""
            return self._call_llm([{"role": "system", "content": prompt_text}])

        self.holomem.set_insight_callback(_insight_cb)

    # ── Start ──────────────────────────────────────────────────────────────

    def start(self) -> str:
        res  = self.holomem.start_session()
        s    = self.holomem.stats()
        aii  = s["aii"]
        
        modules = []
        if self._enable_scanner: modules.append("scanner")
        if self.notes: modules.append(f"notes({self.notes.count})")
        if self.tasks: modules.append(f"tasks({self.tasks.count})")
        
        print(f"\n[holonP v5.11 AWARE] tur={s['turns']} store={s['store']} "
              f"delta={s['delta_hours']}h [{', '.join(modules)}]")
        
        # Start reminder watcher with callback
        self._watcher = ReminderWatcher(self.holomem, on_fire=self._on_reminder_fired)
        self._watcher.start()
        
        return res.get("wake", "")

    def _on_reminder_fired(self, item):
        """Callback gdy przypomnienie się odpala."""
        self._fired_reminders.append(item.content)

    # ── Context building ───────────────────────────────────────────────────

    def _build_awareness_context(self, user_input: str) -> str:
        """Buduje kontekst świadomości dla LLM."""
        parts = []
        
        # 1. Fired reminders (najwyższy priorytet)
        if self._fired_reminders:
            reminders_text = "\n".join(f"• {r}" for r in self._fired_reminders)
            parts.append(f"[🔔 PRZYPOMNIENIA WŁAŚNIE SIĘ ODPALIŁY]\n{reminders_text}")
            self._fired_reminders.clear()
        
        # 2. Context injections (wykonane komendy)
        if self._context_injections:
            parts.append("[WYKONANE AKCJE]\n" + "\n".join(self._context_injections))
            self._context_injections.clear()
        
        # 3. Notes awareness
        if self.notes and self.notes.count > 0:
            # Ostatnie 3 notatki (tytuły)
            recent = self.notes.recent(3)
            if recent:
                notes_list = ", ".join(f'"{n.title}"' for n in recent)
                parts.append(f"[NOTATKI] Ostatnie: {notes_list} (łącznie {self.notes.count})")
            
            # Relevantne do zapytania (jeśli query > 10 znaków)
            if len(user_input) > 10:
                relevant = self.notes.search(user_input, top_k=2)
                if relevant:
                    rel_text = "\n".join(
                        f"• {n.title}: {n.summary[:100]}..." 
                        for n in relevant
                    )
                    parts.append(f"[RELEVANTNE NOTATKI]\n{rel_text}")
        
        # 4. Tasks awareness
        if self.tasks and self.tasks.count > 0:
            active = self.tasks.list_active()
            if active:
                tasks_text = ", ".join(f'"{t.title}"' for t in active[:5])
                parts.append(f"[ZADANIA] Aktywne: {tasks_text}")
        
        return "\n\n".join(parts) if parts else ""

    # ── Command processing ─────────────────────────────────────────────────

    def _process_commands(self, user_input: str) -> Tuple[bool, Optional[str]]:
        """
        Przetwarza komendy systemowe.
        Zwraca (handled, injection_text).
        
        handled=True + injection=None → komenda systemowa (stats, quit)
        handled=True + injection=str  → komenda wykonana, poinformuj LLM
        handled=False                 → normalna wiadomość
        """
        cmd = user_input.lower().strip()
        
        # Komendy czysto systemowe (bez LLM)
        if cmd == "quit":
            return True, None
        if cmd == "stats":
            print(f"\n[Stats] {self.stats()}")
            return True, None
        if cmd == "reset":
            self.holomem.reset()
            return True, None
        if cmd == "ruminate":
            self.holomem.ruminate(force=True)
            return True, None
        if cmd == "pokaż notatki" and self.notes:
            notes = self.notes.recent(8)
            print(f"\n📋 Twoje notatki:\n\n{self.notes.format_list(notes)}")
            return True, None
        if cmd == "pokaż zadania" and self.tasks:
            print(f"\n📋 Twoje zadania:\n\n{self.tasks.format_list()}")
            return True, None
        
        # Komendy notatek (z informacją dla LLM)
        if self.notes:
            # Sprawdź czy to komenda notatki
            note_cmd = parse_note_command(user_input, self.notes, self.holomem)
            if note_cmd:
                # Wyświetl użytkownikowi
                print(f"\n{note_cmd}")
                # Dodaj injection dla LLM
                self._context_injections.append(f"✓ {note_cmd}")
                # NIE return True — pozwól LLM potwierdzić
                return False, note_cmd
        
        # Komendy zadań (z informacją dla LLM)
        if self.tasks:
            task_cmd = parse_task_command(user_input, self.tasks)
            if task_cmd:
                print(f"\n{task_cmd}")
                self._context_injections.append(f"✓ {task_cmd}")
                return False, task_cmd
        
        return False, None

    # ── Security ───────────────────────────────────────────────────────────

    def _scan_input(self, user_input: str) -> Tuple[bool, str]:
        if not self._enable_scanner or not self._scanner:
            return True, ""
        
        result = self._scanner.scan(user_input)
        
        if result.is_suspicious:
            self._security_log.append({
                "timestamp": time.time(),
                "input_preview": user_input[:100],
                "risk_level": result.risk_level,
                "blocked": result.blocked,
            })
        
        if result.blocked:
            return False, self._scanner.explain(result)
        
        return True, ""

    # ── Reminder parsing ───────────────────────────────────────────────────

    def _parse_reminder(self, text: str) -> Tuple[Optional[str], Optional[float]]:
        """Parser przypomnień (z oryginalnej Session)."""
        reminder_pattern = re.compile(
            r'(?:przypomnij|remind)(?:\s+m(?:i|e))?', re.IGNORECASE)
        kw_match = reminder_pattern.search(text)
        if not kw_match:
            return None, None
        after_kw = text[kw_match.end():].strip()
        if not after_kw:
            return None, None

        def _clean(s: str) -> str:
            s = re.sub(r'jutro\s+o\s+\d{1,2}:\d{2}\b', '', s, flags=re.IGNORECASE)
            s = re.sub(r'o\s+\d{1,2}:\d{2}\b', '', s, flags=re.IGNORECASE)
            s = re.sub(r'za\s+\d+\s+(?:godzin|godziny|godzinę)\b', '', s, flags=re.IGNORECASE)
            s = re.sub(r'za\s+\d+\s+(?:minut|minuty|minutę)\b', '', s, flags=re.IGNORECASE)
            return re.sub(r'\s{2,}', ' ', s).strip()

        # Pattern matching (skrócone)
        patterns = [
            (r'jutro\s+o\s+(\d{1,2}):(\d{2})\b', lambda h, m: 
                (datetime.datetime.now() + datetime.timedelta(days=1))
                .replace(hour=h, minute=m, second=0, microsecond=0)),
            (r'o\s+(\d{1,2}):(\d{2})\b', lambda h, m:
                datetime.datetime.now().replace(hour=h, minute=m, second=0, microsecond=0)),
            (r'za\s+(\d+)\s+(?:godzin|godziny|godzinę)\b', lambda hrs:
                datetime.datetime.now() + datetime.timedelta(hours=hrs)),
            (r'za\s+(\d+)\s+(?:minut|minuty|minutę)\b', lambda mins:
                datetime.datetime.now() + datetime.timedelta(minutes=mins)),
        ]
        
        for pattern, handler in patterns:
            m = re.search(pattern, after_kw, re.IGNORECASE)
            if m:
                groups = [int(g) for g in m.groups()]
                dt = handler(*groups)
                if hasattr(dt, 'timestamp'):
                    ts = dt.timestamp()
                    if ts < time.time():
                        dt += datetime.timedelta(days=1)
                        ts = dt.timestamp()
                    return _clean(after_kw), ts
        
        return None, None

    # ── Chat ───────────────────────────────────────────────────────────────

    def chat(self, user_input: str) -> str:
        """
        Główna metoda chatu z pełną świadomością.
        """
        # === Security scan ===
        is_safe, security_msg = self._scan_input(user_input)
        if not is_safe:
            return security_msg
        
        # === Process commands ===
        handled, injection = self._process_commands(user_input)
        if handled and injection is None:
            return ""  # Komenda systemowa, nie potrzeba odpowiedzi LLM
        
        # === Build context ===
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time_context = f"Aktualna data i godzina: {current_time_str}"
        
        # Awareness context (notatki, zadania, wykonane komendy, przypomnienia)
        awareness = self._build_awareness_context(user_input)
        
        # === Reminder parsing ===
        reminder_injection = ""
        if len(user_input) > 5:
            reminder_text, reminder_time = self._parse_reminder(user_input)
            if reminder_text and reminder_time:
                self.holomem.add_reminder(reminder_text, reminder_time)
                dt_str = datetime.datetime.fromtimestamp(reminder_time).strftime("%H:%M %d.%m")
                reminder_injection = f"✓ Ustawiono przypomnienie na {dt_str}: {reminder_text}"
                self._context_injections.append(reminder_injection)
                print(f"\n⏰ {reminder_injection}")
        
        # === Upcoming reminders ===
        upcoming = self.holomem.get_upcoming_reminders(within_seconds=3600)
        reminder_msg = ""
        if upcoming:
            lines = [f"• {r.content} (za {int((r.created_at - time.time()) // 60)} min)"
                     for r in upcoming]
            reminder_msg = "[NADCHODZĄCE PRZYPOMNIENIA]\n" + "\n".join(lines)
        
        # === HoloMem turn ===
        messages = self.holomem.turn(user_input, self.system)
        
        # === Inject contexts ===
        extra_context = "\n\n".join(filter(None, [
            time_context, awareness, reminder_msg
        ]))
        
        if messages and messages[0]["role"] == "system":
            messages[0]["content"] += "\n\n" + extra_context
        else:
            messages.insert(0, {"role": "system", "content": extra_context})
        
        # === LLM call ===
        response = self._call_llm(messages)
        
        if response.startswith("[Błąd") or response.startswith("[Mock]"):
            return response
        
        # === After turn ===
        self.holomem.after_turn(user_input, response)
        
        s   = self.holomem.stats()
        aii = s["aii"]
        print(f"  [store={s['store']} aii={aii['emotion']}(focus:{aii['focus']}) "
              f"vac={aii['vacuum_signal']:+.2f}]", flush=True)
        
        return response

    # ── LLM call ───────────────────────────────────────────────────────────

    def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        if not self._client:
            return "[Mock] Brak backendu LLM."
        try:
            return self._client.chat_completion(
                messages, temperature=0.7, max_tokens=1024)
        except Exception as e:
            return f"[Błąd LLM: {e}]"

    # ── Utils ──────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        base = self.holomem.stats()
        base["notes_count"] = self.notes.count if self.notes else 0
        base["tasks_count"] = self.tasks.count if self.tasks else 0
        base["security_events"] = len(self._security_log)
        return base

    def stop(self):
        if self._watcher:
            self._watcher.stop()
        if self.tasks:
            self.tasks._save()


# ── Alias ──────────────────────────────────────────────────────────────────
Session = AwareSession
