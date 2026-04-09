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
        now   = time.time()
        # Zabezpieczenie: sprawdzamy czy item ma atrybut is_reminder, domyślnie False
        fired = [i for i in list(self.holomem.store)
                 if getattr(i, 'is_reminder', False) and i.created_at <= now]
        for item in fired:
            # Ustawiamy is_reminder na False, aby nie odpalać ponownie
            if hasattr(item, 'is_reminder'):
                item.is_reminder = False
            msg = (f"\n\a"
                   f"╔══════════════════════════════════════╗\n"
                   f"║  🔔 PRZYPOMNIENIE: {item.content[:35]:<35} ║\n"
                   f"╚══════════════════════════════════════╝")
            print(msg, flush=True)
            if self.on_fire:
                try:
                    self.on_fire(item)
                except Exception as e:
                    print(f"[ReminderWatcher] callback error: {e}")