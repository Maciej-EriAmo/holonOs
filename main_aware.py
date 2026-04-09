#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main_aware.py — EriAmo z pełną świadomością kontekstową

LLM wie o:
- Notatkach (ostatnie + relevantne do zapytania)
- Zadaniach (aktywne)
- Wykonanych komendach (zapisz, przypomnij)
- Odpalonych przypomnieniach

Komendy:
  quit, stats, reset, ruminate
  zapisz: <tekst>       — notatka
  zapisz rozmowę        — zapisz ostatnią rozmowę
  pokaż notatki
  zadanie: <tekst>      — nowe zadanie
  pokaż zadania
  przypomnij mi o X za Y minut/godzin
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from holon_session_aware import AwareSession


def main():
    print("=" * 60)
    print("  holonP v5.11 AWARE — EriAmo z pełną świadomością")
    print("=" * 60)
    
    session = AwareSession(
        memory_path="holon_memory.json",
        notes_dir="notes",
        tasks_dir="tasks"
    )
    
    wake_msg = session.start()
    if wake_msg:
        print(f"\n{wake_msg}\n")
    
    print("\nKomendy: quit, stats, reset, ruminate")
    print("         zapisz: <tekst>, pokaż notatki")
    print("         zadanie: <tekst>, pokaż zadania")
    print("         przypomnij mi [treść] za/o [czas]")
    print("-" * 60)

    try:
        while True:
            try:
                user = input("\nTy: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nDo widzenia.")
                break
            
            if not user:
                continue
            
            if user.lower() == "quit":
                break
            
            print("\nEriAmo: ", end="", flush=True)
            response = session.chat(user)
            if response:
                print(response)
    
    finally:
        session.stop()
        print("[Holon] Sesja zakończona.")


if __name__ == "__main__":
    main()
