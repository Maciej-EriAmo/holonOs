# -*- coding: utf-8 -*-
"""
Holon v5.11 — Cognitive Architecture Layer for LLMs

Holon provides:
- Persistent holographic memory (HRR encoding)
- Emotional state tracking (AIIState)
- Temporal awareness (time_embed, TimeDecay)
- Predictive coding (Rao-Ballard/FEP)
- Continuous routing (PrismRouter)

Usage:
    from holon import Session
    
    session = Session(memory_path="holon_memory.json")
    session.start()
    response = session.chat("Hello!")

Author: Maciej Mazur
GitHub: github.com/Maciej-EriAmo/Holomem
"""

__version__ = "5.11.0"
__author__ = "Maciej Mazur"

# Core
from holon_config import Config
from holon_item import Item
from holon_embedder import Embedder
from holon_aii import AIIState, TimeDecay
from holon_holography import HolographicInterference, PrismRouter, PrismConfig
from holon_memory import PersistentMemory
from holon_holomem import HoloMem
from holon_session import Session
from holon_llm import build_llm_client, OpenAIClient
from holon_watcher import ReminderWatcher

# Optional modules - import only if needed
def get_scanner():
    """Returns PromptScanner singleton."""
    from prompt_scanner import get_scanner
    return get_scanner()

def get_web_extractor(md_dir="knowledge"):
    """Returns WebExtractor instance."""
    from web_extractor import WebExtractor
    return WebExtractor(md_dir=md_dir)

def get_knowledge_store(md_dir="knowledge", soul_file="data/knowledge.soul"):
    """Returns KnowledgeStore instance."""
    from knowledge_store import KnowledgeStore
    return KnowledgeStore(md_dir=md_dir, soul_file=soul_file)

def get_notes_manager(notes_dir="notes"):
    """Returns NotesManager instance."""
    from notes_manager import NotesManager
    return NotesManager(notes_dir=notes_dir)

def get_tasks_manager(tasks_dir="tasks"):
    """Returns TasksManager instance."""
    from tasks import TasksManager
    return TasksManager(tasks_dir=tasks_dir)

def get_holon_fs(root_dir):
    """Returns HolonFSd instance."""
    from holon_fs import HolonFSd
    return HolonFSd(root=root_dir)


__all__ = [
    # Version
    "__version__",
    "__author__",
    # Core classes
    "Config",
    "Item",
    "Embedder",
    "AIIState",
    "TimeDecay",
    "HolographicInterference",
    "PrismRouter",
    "PrismConfig",
    "PersistentMemory",
    "HoloMem",
    "Session",
    "OpenAIClient",
    "build_llm_client",
    "ReminderWatcher",
    # Factory functions
    "get_scanner",
    "get_web_extractor",
    "get_knowledge_store",
    "get_notes_manager",
    "get_tasks_manager",
    "get_holon_fs",
]
