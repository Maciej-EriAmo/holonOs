#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup script for Holon package.

Install:
    pip install -e .

Or build:
    python setup.py sdist bdist_wheel
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README if exists
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")
else:
    long_description = """
# Holon v5.11

Cognitive Architecture Layer for LLMs.

Features:
- Persistent holographic memory (HRR encoding)
- Emotional state tracking (AIIState)
- Temporal awareness (time_embed, TimeDecay)
- Predictive coding (Rao-Ballard/FEP)
- Continuous routing (PrismRouter)
- Security layer (PromptScanner)

Usage:
    from holon import Session
    
    session = Session(memory_path="holon_memory.json")
    session.start()
    response = session.chat("Hello!")

Author: Maciej Mazur
GitHub: github.com/Maciej-EriAmo/Holomem
"""

setup(
    name="holon",
    version="5.11.0",
    author="Maciej Mazur",
    author_email="maciej@eriamo.ai",
    description="Cognitive Architecture Layer for LLMs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Maciej-EriAmo/Holomem",
    
    # Package discovery
    py_modules=[
        "holon_config",
        "holon_item",
        "holon_embedder",
        "holon_aii",
        "holon_holography",
        "holon_memory",
        "holon_holomem",
        "holon_session",
        "holon_session_secure",
        "holon_llm",
        "holon_watcher",
        "holon_fs",
        "prompt_scanner",
        "web_extractor",
        "knowledge_store",
        "notes_manager",
        "tasks",
    ],
    
    # Include data files
    package_data={
        "": ["*.json", "*.md"],
    },
    include_package_data=True,
    
    # Dependencies
    install_requires=[
        "numpy>=1.21.0",
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
        "python-dateutil>=2.8.0",
    ],
    
    extras_require={
        "full": [
            "xattr>=0.9.0",      # HolonFS xattr support
            "inotify>=0.2.0",   # HolonFS file watching
        ],
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "mypy>=0.950",
        ],
    },
    
    # Entry points
    entry_points={
        "console_scripts": [
            "holon=main:main",
            "holon-fs=holon_fs:cli",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    
    python_requires=">=3.9",
    
    # Keywords
    keywords=[
        "llm", "memory", "cognitive", "holographic", 
        "neural", "ai", "assistant", "embeddings",
        "predictive-coding", "attention"
    ],
)
