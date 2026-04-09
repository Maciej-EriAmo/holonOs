#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_imports.py — Sprawdza spójność importów między modułami Holon
"""

import sys
import importlib.util
from pathlib import Path

MODULES = [
    ("holon_config",     []),
    ("holon_item",       ["numpy"]),
    ("holon_embedder",   ["numpy"]),
    ("holon_aii",        ["numpy"]),
    ("holon_holography", ["numpy"]),
    ("holon_memory",     ["holon_config", "holon_item", "holon_holography", "holon_aii", "holon_embedder"]),
    ("holon_llm",        ["requests"]),
    ("holon_watcher",    []),
    ("holon_holomem",    ["holon_config", "holon_item", "holon_holography", "holon_embedder", "holon_aii", "holon_memory"]),
    ("holon_session",    ["holon_config", "holon_embedder", "holon_holomem", "holon_watcher", "holon_llm"]),
    ("prompt_scanner",   []),
    ("web_extractor",    ["requests"]),
    ("knowledge_store",  ["numpy"]),
    ("notes_manager",    []),
    ("tasks",            []),
]

def check_module(name: str, deps: list) -> tuple:
    """Sprawdza czy moduł można zaimportować."""
    path = Path(f"{name}.py")
    if not path.exists():
        return False, f"Brak pliku {name}.py"
    
    try:
        spec = importlib.util.spec_from_file_location(name, path)
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
    print("  Holon v5.11 — Weryfikacja importów")
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
        print("\n⚠️  Niektóre moduły mają problemy z importem.")
        print("   Sprawdź brakujące zależności lub popraw ścieżki.")
    else:
        print("\n✅ Wszystkie moduły gotowe do użycia!")
    
    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
