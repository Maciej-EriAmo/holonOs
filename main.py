#!/usr/bin/env python3
# main.py — EriAmo / HolonOS
from holon_session import Session

print("=" * 60)
print("holonP v5.11 — EriAmo / HolonOS")
print("=" * 60)

session  = Session(memory_path="holon_memory.json")
wake_msg = session.start()
if wake_msg:
    print(f"\n{wake_msg}\n")

print("Komendy: quit, stats, reset, ruminate")
print("-" * 60)

try:
    while True:
        try:
            user = input("\nTy: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nDo widzenia.")
            break
        if not user: continue
        if user.lower() == "quit": break
        if user.lower() == "stats":
            print(f"\n[Stats] {session.stats()}"); continue
        if user.lower() == "reset":
            session.reset(); continue
        if user.lower() == "ruminate":
            session.holomem.ruminate(force=True); continue
        print("\nAsystent: ", end="", flush=True)
        print(session.chat(user))
finally:
    session.stop_watcher()
