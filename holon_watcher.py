# -*- coding: utf-8 -*-
"""holon/watcher.py — ReminderWatcher: daemon sprawdzający przypomnienia"""

import time
import threading


class ReminderWatcher:
    CHECK_INTERVAL: int = 15

    def __init__(self, holomem, on_fire=None,
                 check_interval: int = CHECK_INTERVAL):
        self.holomem         = holomem
        self.on_fire         = on_fire
        self._check_interval = check_interval
        self._stop_event     = threading.Event()
        self._thread         = threading.Thread(
            target=self._run, daemon=True, name="ReminderWatcher")

    def start(self) -> None:
        self._stop_event.clear()
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        while not self._stop_event.wait(self._check_interval):
            self._check()

    def _check(self) -> None:
        now = time.time()
        # Poprawka logiczna: sprawdzamy cel czasowy (created_at przechowuje timestamp docelowy)
        # oraz upewniamy się, że nie sprawdzamy już wykonanych przypomnień
        fired = []
        
        # Tworzymy kopię listy do iteracji, aby uniknąć problemów z modyfikacją w locie
        current_store = list(self.holomem.store)
        
        for i in current_store:
            # Sprawdzenie typu (is_reminder) i czy nadszedł już czas (created_at jako cel)
            is_rem = getattr(i, 'is_reminder', False)
            is_fired = getattr(i, 'is_fired', False) # Nowa flaga stanu
            
            if is_rem and not is_fired and i.created_at <= now:
                fired.append(i)

        for item in fired:
            # Oznaczamy jako wykonane zamiast zmieniać typ obiektu
            # Zapobiega to błędom spójności przy zapisie do JSON
            if hasattr(item, 'is_fired'):
                item.is_fired = True
            else:
                setattr(item, 'is_fired', True)
                
            # Powiadomienie wizualne i dźwiękowe
            msg = (f"\n\a"
                   f"╔══════════════════════════════════════╗\n"
                   f"║  🔔 PRZYPOMNIENIE: {item.content[:35]:<35} ║\n"
                   f"╚══════════════════════════════════════╝")
            print(msg, flush=True)
            
            # Wywołanie callbacku, jeśli jest zdefiniowany (np. dla LLM)
            if self.on_fire:
                try:
                    self.on_fire(item)
                except Exception as e:
                    print(f"[ReminderWatcher] callback error: {e}")
