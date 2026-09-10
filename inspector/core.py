"""
Núcleo del Agente Inspector (Engine).
Orquesta el descubrimiento de archivos, ejecución de escáneres y generación de métricas.
"""

import os
import time
from typing import List
from inspector.models import Finding, InspectionSummary, Severity
from inspector.config import InspectorConfig
from inspector.scanners.base import BaseScanner
from inspector.scanners.secrets_scanner import SecretsScanner
from inspector.scanners.security_scanner import SecurityScanner
from inspector.scanners.quality_scanner import QualityScanner
from inspector.scanners.ai_analyzer import AIAnalyzer
from inspector.reporters.markdown_reporter import MarkdownReporter
from inspector.reporters.sarif_reporter import SarifReporter
from inspector.fixer import CodeFixer


class InspectorEngine:
    """Orquestador principal de auditorías e inspecciones."""

    def __init__(self, config: InspectorConfig = None):
        self.config = config or InspectorConfig()
        self.scanners: List[BaseScanner] = [
            SecretsScanner(self.config),
            SecurityScanner(self.config),
            QualityScanner(self.config),
        ]
        if self.config.enable_ai:
            self.scanners.append(AIAnalyzer(self.config))

    def _is_binary_file(self, file_path: str) -> bool:
        """Verifica si un archivo es binario para evitar escanearlo como texto."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(1024)
                return b"\x00" in chunk
        except Exception:
            return True

    def discover_files(self, target_path: str) -> List[str]:
        """Encuentra todos los archivos a inspeccionar según las reglas de configuración."""
        discovered: List[str] = []

        if os.path.isfile(target_path):
            return [target_path]

        for root, dirs, files in os.walk(target_path):
            # Filtrar directorios ignorados in-place
            dirs[:] = [
                d for d in dirs
                if d not in self.config.ignore_dirs
                and not d.startswith(".git")
            ]

            for file_name in files:
                if file_name in self.config.ignore_files:
                    continue

                ext = os.path.splitext(file_name)[1].lower()
                # Si no tiene extensión, verificar si es ejecutable o script común
                if ext not in self.config.allowed_extensions and not (
                    file_name.startswith(".env") or file_name in ["Dockerfile", "Makefile"]
                ):
                    continue

                full_path = os.path.join(root, file_name)

                # Verificar tamaño máximo
                try:
                    if os.path.getsize(full_path) > self.config.max_file_size_bytes:
                        continue
                except OSError:
                    continue

                # Verificar si es binario
                if not self._is_binary_file(full_path):
                    rel_path = os.path.relpath(full_path, target_path)
                    discovered.append(full_path)

        return sorted(discovered)

    def _clone_remote_repo_if_needed(self, target: str) -> tuple[str, bool]:
        """Si el target es una URL de Git/GitHub, clona temporalmente el repositorio."""
        import tempfile
        import subprocess

        if target.startswith(("https://github.com/", "http://github.com/", "git@github.com:")):
            temp_dir = tempfile.mkdtemp(prefix="inspector_repo_")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", target, temp_dir],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return temp_dir, True
            except Exception as err:
                raise RuntimeError(f"Error al clonar el repositorio remoto '{target}': {err}")

        return target, False

    def scan(self, target_path: str = None) -> InspectionSummary:
        """Ejecuta una inspección completa sobre la ruta objetivo o URL remota de GitHub."""
        target_raw = target_path or self.config.target_path
        actual_target, is_temporary = self._clone_remote_repo_if_needed(target_raw)

        try:
            start_time = time.time()
            files_to_scan = self.discover_files(actual_target)
            all_findings: List[Finding] = []
            total_lines = 0

            for file_path in files_to_scan:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                lines_count = len(content.splitlines())
                total_lines += lines_count

                rel_file_path = os.path.relpath(file_path, start=actual_target)
                for scanner in self.scanners:
                    try:
                        findings = scanner.scan_file(rel_file_path, content)
                        all_findings.extend(findings)
                    except Exception:
                        continue

            duration = time.time() - start_time

            summary = InspectionSummary(
                total_files_scanned=len(files_to_scan),
                total_lines_scanned=total_lines,
                findings=all_findings,
                duration_seconds=duration,
                scanners_executed=[s.name for s in self.scanners],
            )

            # Generar reporte Markdown si está configurado
            if self.config.output_markdown and self.config.markdown_path:
                md_content = MarkdownReporter().generate(summary)
                try:
                    with open(self.config.markdown_path, "w", encoding="utf-8") as f:
                        f.write(md_content)
                except OSError:
                    pass  # inspector:ignore

            # Generar reporte SARIF si está configurado
            if self.config.output_sarif and self.config.sarif_path:
                sarif_content = SarifReporter().generate(summary)
                try:
                    with open(self.config.sarif_path, "w", encoding="utf-8") as f:
                        f.write(sarif_content)
                except OSError:
                    pass  # inspector:ignore

            # Aplicar correcciones automáticas si está habilitado
            if self.config.auto_fix:
                fixer = CodeFixer()
                fixer.apply_fixes(summary.findings)

            return summary

        finally:
            if is_temporary:
                import shutil
                shutil.rmtree(actual_target, ignore_errors=True)
