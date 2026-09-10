"""
Configuración del Agente Inspector.
"""

import os
from dataclasses import dataclass, field
from typing import List, Set

DEFAULT_IGNORE_DIRS: Set[str] = {
    ".git",
    ".github",
    ".agents",
    ".vscode",
    ".idea",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "target",
    "vendor",
    ".cargo",
    "coverage",
    ".next",
    ".nuxt",
    "tests",
}

DEFAULT_IGNORE_FILES: Set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "composer.lock",
}

DEFAULT_EXTENSIONS: Set[str] = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".env.example",
    ".sh",
    ".bash",
    ".sql",
    ".html",
    ".css",
    ".go",
    ".rs",
    ".java",
    ".php",
    ".rb",
    ".c",
    ".cpp",
    ".h",
}

@dataclass
class InspectorConfig:
    """Opciones de configuración para la ejecución del inspector."""
    target_path: str = "."
    ignore_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    ignore_files: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_FILES))
    allowed_extensions: Set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    max_file_size_bytes: int = 1_000_000  # 1MB
    enable_ai: bool = False
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    fail_on_severity: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, NONE
    output_markdown: bool = True
    markdown_path: str = "INSPECTION_REPORT.md"
    output_sarif: bool = False
    sarif_path: str = "inspector-results.sarif"
    auto_fix: bool = False
