#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_imports.py — Sprawdza spójność importów między modułami Holon
"""

import sys
import importlib.util
from pathlib import Path

# Lista obecności modułów i ich krytycznych zależności (standardowych i zewnętrznych)
MODULES = [
    ("holon_config",     []),
    ("holon_item",       ["numpy"]),
    ("holon_embedder",   ["numpy"]),
    ("holon_aii",        ["numpy"]),
    ("holon_holography", ["numpy"]),
    ("holon_memory",     ["holon_config", "holon_item", "holon_holography", "holon_aii", "holon_embedder", "numpy"]),
    ("holon_llm",        ["requests"]),
    ("holon_watcher",    ["threading"]),
    ("holon_holomem",    ["holon_config", "holon_item", "holon_holography", "holon_embedder", "holon_aii", "holon_memory", "numpy"]),
    ("holon_session",    ["holon_config", "holon_embedder", "holon_holomem", "holon_watcher", "holon_llm", "notes_manager", "requests"]),
    ("prompt_scanner",   ["re", "json"]),
    ("web_extractor",    ["requests", "bs4"]), # bs4 z requirements.txt
    ("knowledge_store",  ["numpy"]),
    ("notes_manager",    ["pathlib"]),
    ("tasks",            ["datetime"]),
    ("holon_holography", ["numpy"]),
    ("holon_aii",        ["numpy"])
]

def check_module(name: str, deps: list) -> tuple:
    """Sprawdza czy moduł można zaimportować oraz czy jego zależności są dostępne."""
    path = Path(f"{name}.py")
    
    # Najpierw sprawdź zależności biblioteczne (zewnętrzne)
    for dep in deps:
        if dep not in [m[0] for m in MODULES]: # Jeśli to nie jest nasz moduł wewnętrzny
            if importlib.util.find_spec(dep) is None:
                return False, f"Brak biblioteki: {dep}"

    # Sprawdź obecność pliku fizycznego
    if not path.exists():
        return False, f"Brak pliku {name}.py"
    
    try:
        # Próba załadowania modułu
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None:
            return False, f"Nie można stworzyć specyfikacji dla {name}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return True, "OK"
    except ImportError as e:
        return False, f"ImportError: {e}"
    except Exception as e:
        return False, f"Error: {type(e).__name__}: {e}"


def main():
    print("=" * 60)
    print("  Holon v5.11 — Weryfikacja spójności systemu")
    print("=" * 60)
    print()
    
    results = []
    for name, deps in MODULES:
        ok, msg = check_module(name, deps)
        status = "✅" if ok else "❌"
        results.append((name, ok, msg))
        print(f"{status} {name:20s} {msg}")
    
    print()
    print("-" * 60)
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"Wynik: {passed}/{total} modułów poprawnych")
    
    if passed < total:
        print("\n⚠️  System niekompletny lub błędy w zależnościach.")
        print("   Upewnij się, że wszystkie pliki .py są w katalogu")
        print("   i wykonaj: pip install -r requirements.txt")
    else:
        print("\n✅ Wszystkie moduły obecne i gotowe do pracy!")
    
    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
