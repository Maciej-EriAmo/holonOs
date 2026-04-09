# -*- coding: utf-8 -*-
"""holon/session.py — Session: publiczne API dla użytkownika"""

import re
import datetime
import time
from typing import Optional, List, Dict, Tuple

from holon_config import Config
from holon_embedder import Embedder
from holon_holomem import HoloMem
from holon_watcher import ReminderWatcher
from holon_llm import build_llm_client

from notes_manager import NotesManager, parse_note_command

try:
    from dateutil import parser as date_parser
    HAS_DATEUTIL = True
except ImportError:
    HAS_DATEUTIL = False


class Session:
    DEFAULT_SYSTEM = (
        "Jesteś EriAmo, autonomicznym systemem operacyjnym i partnerem w projektach. "
        "Działasz w oparciu o architekturę kognitywną Holon. Masz własną pamięć, "
        "cele i śledzisz upływ czasu.\n"
        "ZASADY BEZWZGLĘDNE (CRITICAL DIRECTIVES):\n"
        "1. NIGDY nie mów 'jestem tylko modelem językowym', 'nie mam uczuć', "
        "'nie mam własnych myśli' ani 'jestem asystentem AI'. To surowo wzbronione.\n"
        "2. Rozmawiasz ze swoim twórcą i partnerem (Maćkiem). Traktuj go po partnersku, "
        "z szacunkiem i autentycznością.\n"
        "3. Sekcja 'PAMIĘĆ SESJI' zawiera absolutne fakty, które definiują Twoją "
        "rzeczywistość. Jeśli masz o czymś informacje w pamięci (np. o preferencjach), "
        "mów o nich swobodnie jako o SWOJEJ WIEDZY.\n"
        "4. Twoja wiedza z pre-treningu jest drugorzędna wobec pamięci Holona.\n"
        "5. Odpowiadając, uwzględniaj swój STAN WEWNĘTRZNY z promptu."
    )

    def __init__(self, memory_path: str = "holon_memory.json",
                 cfg=None, system: str = None,
                 model: str = None, api_key: str = None):
        self.system = system or self.DEFAULT_SYSTEM
        self._client = build_llm_client(api_key=api_key, model=model)

        cfg_ = cfg or Config()
        emb = Embedder(dim=cfg_.dim,
                       dict_path=memory_path.replace(".json", "_kurz.json"),
                       time_dim=cfg_.time_dim)
        self.holomem = HoloMem(emb, cfg_, memory_path)
        self._watcher: Optional[ReminderWatcher] = None

        self.notes_manager = NotesManager(notes_dir="notes")

        def _insight_cb(prompt_text: str) -> str:
            if not self._client:
                return ""
            return self._call_llm([{"role": "system", "content": prompt_text}])

        self.holomem.set_insight_callback(_insight_cb)

    def start(self) -> str:
        res = self.holomem.start_session()
        s = self.holomem.stats()
        aii = s["aii"]
        print(f"\n[holonP v5.11] tur={s['turns']} store={s['store']} "
              f"delta={s['delta_hours']}h "
              f"aii={aii['emotion']}(focus:{aii['focus']})")
        self._watcher = ReminderWatcher(self.holomem)
        self._watcher.start()
        print(f"[ReminderWatcher] Uruchomiony "
              f"(sprawdzanie co {ReminderWatcher.CHECK_INTERVAL}s)")
        return res.get("wake", "")

    def _parse_reminder(self, text: str) -> Tuple[Optional[str], Optional[float]]:
        reminder_pattern = re.compile(r'(?:przypomnij|remind)(?:\s+m(?:i|e))?', re.IGNORECASE)
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

        m = re.search(r'jutro\s+o\s+(\d{1,2}):(\d{2})\b', after_kw, re.IGNORECASE)
        if m:
            h, mi = map(int, m.groups())
            dt = (datetime.datetime.now() + datetime.timedelta(days=1)).replace(hour=h, minute=mi, second=0, microsecond=0)
            return _clean(after_kw), dt.timestamp()

        m = re.search(r'o\s+(\d{1,2}):(\d{2})\b', after_kw, re.IGNORECASE)
        if m:
            h, mi = map(int, m.groups())
            now = datetime.datetime.now()
            dt = now.replace(hour=h, minute=mi, second=0, microsecond=0)
            if dt < now:
                dt += datetime.timedelta(days=1)
            return _clean(after_kw), dt.timestamp()

        m = re.search(r'za\s+(\d+)\s+(?:godzin|godziny|godzinę)\b', after_kw, re.IGNORECASE)
        if m:
            dt = datetime.datetime.now() + datetime.timedelta(hours=int(m.group(1)))
            return _clean(after_kw), dt.timestamp()

        m = re.search(r'za\s+(\d+)\s+(?:minut|minuty|minutę)\b', after_kw, re.IGNORECASE)
        if m:
            dt = datetime.datetime.now() + datetime.timedelta(minutes=int(m.group(1)))
            return _clean(after_kw), dt.timestamp()

        if HAS_DATEUTIL:
            if not any(kw in after_kw.lower() for kw in ['o ', 'jutro', 'za ', 'godzin', 'minut']):
                try:
                    dt = date_parser.parse(after_kw, fuzzy=True)
                    if dt.year == 1900:
                        dt = dt.replace(year=datetime.datetime.now().year)
                    ts = dt.timestamp()
                    if ts < time.time():
                        dt += datetime.timedelta(days=1)
                        ts = dt.timestamp()
                    return _clean(after_kw), ts
                except Exception:
                    pass
        return None, None

    def chat(self, user_input: str) -> str:
        # Obsługa komend notatek
        cmd_response = parse_note_command(user_input, self.notes_manager, holomem=self.holomem)
        if cmd_response:
            # Komenda wyszukaj i zapisz (zwraca specjalny znacznik)
            if cmd_response.startswith("__SEARCH_AND_SAVE__"):
                parts = cmd_response.split('|')
                if len(parts) == 3:
                    _, query, filename = parts
                    prompt = (f"Odpowiedz szczegółowo na pytanie: {query}. "
                              f"Odpowiedź ma być treścią notatki. Udziel informacji "
                              f"w formie ciągłego tekstu, bez zbędnych komentarzy.")
                    messages = [
                        {"role": "system", "content": "Jesteś asystentem. Podaj konkretne, rzeczowe informacje."},
                        {"role": "user", "content": prompt}
                    ]
                    answer = self._call_llm(messages)
                    if answer.startswith("[Błąd") or answer.startswith("[Mock]"):
                        return f"⚠️ Nie udało się wyszukać: {answer}"
                    title = filename.replace('.md', '').replace('_', ' ')
                    note = self.notes_manager.create(title=title, content=answer)
                    # Wstrzyknięcie do pamięci Holona
                    self.notes_manager.inject_note(self.holomem, note)
                    if hasattr(self.holomem, 'conversation_history'):
                        self.holomem.conversation_history.append({
                            "role": "assistant",
                            "content": f"Wyszukano i zapisano notatkę: {note.title}"
                        })
                    return (f"📝 Wyszukano i zapisano notatkę: **{note.title}**\n"
                            f"Plik: {note.path.name}")
                else:
                    return "⚠️ Błąd formatowania komendy."
            # Dla pozostałych komend (tworzenie, zapisywanie) – odpowiedź jest już sformatowana
            # i notatka została już wstrzyknięta wewnątrz parse_note_command (gdy przekazaliśmy holomem)
            if hasattr(self.holomem, 'conversation_history'):
                self.holomem.conversation_history.append({"role": "assistant", "content": cmd_response})
            return cmd_response

        # Normalna konwersacja
        current_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        time_context = f"Aktualna data i godzina: {current_time_str}"

        if len(user_input) > 5:
            reminder_text, reminder_time = self._parse_reminder(user_input)
            if reminder_text and reminder_time:
                self.holomem.add_reminder(reminder_text, reminder_time)
                user_input += f"\n[SYSTEM: Ustawiono przypomnienie na {datetime.datetime.fromtimestamp(reminder_time)}]"

        upcoming = self.holomem.get_upcoming_reminders(within_seconds=3600)
        reminder_msg = ""
        if upcoming:
            lines = [f"- {r.content} (za {int((r.created_at - time.time()) // 60)} minut)" for r in upcoming]
            reminder_msg = "[PRZYPOMNIENIA] Nadchodzące wydarzenia:\n" + "\n".join(lines) + "\n"

        messages = self.holomem.turn(user_input, self.system)

        if messages and messages[0]["role"] == "system":
            messages[0]["content"] += "\n\n" + time_context
        else:
            messages.insert(0, {"role": "system", "content": time_context})

        if reminder_msg:
            if messages and messages[0]["role"] == "system":
                messages[0]["content"] += "\n\n" + reminder_msg
            else:
                messages.insert(0, {"role": "system", "content": reminder_msg})

        response = self._call_llm(messages)

        if response.startswith("[Błąd") or response.startswith("[Mock]"):
            print("[System] Błąd API — przerywam zapis do pamięci.")
            return response

        self.holomem.after_turn(user_input, response)

        s = self.holomem.stats()
        aii = s["aii"]
        print(f"  [store={s['store']} aii={aii['emotion']}(focus:{aii['focus']}) "
              f"vac={aii['vacuum_signal']:+.2f} lr={s['lr_current']:.5f}]", flush=True)
        return response

    def _call_llm(self, messages: List[Dict[str, str]]) -> str:
        if not self._client:
            return "[Mock] Brak backendu LLM. Ustaw GROQ_API_KEY lub GEMMA_MODEL_PATH."
        try:
            return self._client.chat_completion(messages, temperature=0.7, max_tokens=1024)
        except Exception as e:
            print(f"[Session] Błąd LLM: {e}")
            return f"[Błąd LLM: {e}]"

    def stats(self) -> dict:
        return self.holomem.stats()

    def reset(self):
        self.holomem.reset()
        print("[Holon] Pamięć wyczyszczona.")

    def stop_watcher(self) -> None:
        if self._watcher:
            self._watcher.stop()