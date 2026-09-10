"""
Escáner de Calidad de Código, Complejidad y Code Smells.
Detecta malas prácticas, funciones gigantes, prints/logs residuales y excepciones silenciadas.
"""

import re
from typing import List
from inspector.models import Finding, Severity, Category
from inspector.config import InspectorConfig
from inspector.scanners.base import BaseScanner


class QualityScanner(BaseScanner):
    """Analiza la calidad, complejidad, malas prácticas y olores de código."""

    name = "Code Quality & Smells Scanner"
    description = "Detecta malas prácticas, prints/logs olvidados, archivos gigantes y excepciones silenciadas"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        total_lines = len(lines)

        # 1. Archivo demasiado grande
        if total_lines > 600:
            findings.append(
                Finding(
                    id=f"QUAL-001-{file_path}",
                    rule_id="QUAL-001",
                    title="Archivo excesivamente grande",
                    description=f"El archivo tiene {total_lines} líneas. Archivos mayores a 600 líneas violan el principio de responsabilidad única.",
                    severity=Severity.LOW,
                    category=Category.QUALITY,
                    file_path=file_path,
                    line_number=1,
                    suggestion="Considera modularizar este archivo dividiéndolo en módulos o componentes más pequeños.",
                )
            )

        # 2. Análisis línea por línea
        is_test_file = any(
            t in file_path.lower() for t in ["test_", "_test.", "spec.", "/tests/"]
        )

        in_python = file_path.endswith(".py")
        in_js_ts = file_path.endswith((".js", ".jsx", ".ts", ".tsx"))

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            if "inspector:ignore" in line:
                continue

            # 2.1 Sentencias de depuración residuales (prints, console.log, debugger, breakpoint)
            if not is_test_file:
                if in_python and re.match(r"^print\s*\(", stripped):
                    findings.append(
                        Finding(
                            id=f"QUAL-002-{file_path}-{idx}",
                            rule_id="QUAL-002",
                            title="Uso de print() residual para depuración",
                            description="Se encontró un 'print()' en código de producción.",
                            severity=Severity.LOW,
                            category=Category.QUALITY,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped,
                            suggestion="Usa el módulo `logging` estándar de Python en lugar de `print()`.",
                            auto_fixable=False,
                        )
                    )
                elif in_python and (re.search(r"^\s*breakpoint\s*\(", line) or re.search(r"^\s*import\s+pdb\b", line)):
                    findings.append(
                        Finding(
                            id=f"QUAL-003-{file_path}-{idx}",
                            rule_id="QUAL-003",
                            title="Breakpoint / debugger residual en código",
                            description="Punto de interrupción de depuración olvidado en el código.",
                            severity=Severity.HIGH,
                            category=Category.QUALITY,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped,
                            suggestion="Elimina las llamadas a breakpoint() y depuradores interactivos.",
                            auto_fixable=True,
                        )
                    )
                elif in_js_ts and (
                    re.match(r"^console\.(?:log|debug|info)\s*\(", stripped)
                    or re.search(r"^\s*debugger\s*;", line)
                ):
                    severity = Severity.HIGH if "debugger" in stripped else Severity.INFO
                    findings.append(
                        Finding(
                            id=f"QUAL-004-{file_path}-{idx}",
                            rule_id="QUAL-004",
                            title="Llamada a console.log o debugger residual",
                            description="Se detectó una llamada a consola o debugger en JavaScript/TypeScript.",
                            severity=severity,
                            category=Category.QUALITY,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped,
                            suggestion="Elimina los console.log o usa un logger estructurado.",
                            auto_fixable=False,
                        )
                    )

            # 2.2 Excepciones capturadas y silenciadas (Silent Error Swallowing)
            if in_python and (
                stripped == "except:"
                or stripped.startswith("except Exception:")
                and idx < total_lines
                and lines[idx].strip() == "pass"
            ):
                findings.append(
                    Finding(
                        id=f"QUAL-005-{file_path}-{idx}",
                        rule_id="QUAL-005",
                        title="Captura genérica de excepciones silenciada (except: pass)",
                        description="Silenciar excepciones oculta errores graves y dificulta la depuración.",
                        severity=Severity.MEDIUM,
                        category=Category.QUALITY,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped,
                        suggestion="Captura excepciones específicas o al menos registra el error con logging.error().",
                    )
                )

            # 2.3 Wildcard Imports (`from x import *`)
            if in_python and re.match(r"^from\s+[a-zA-Z0-9_.]+\s+import\s+\*", stripped):
                findings.append(
                    Finding(
                        id=f"QUAL-006-{file_path}-{idx}",
                        rule_id="QUAL-006",
                        title="Importación con comodín (from module import *)",
                        description="Los imports con '*' contaminan el espacio de nombres y dificultan el rastreo de dependencias.",
                        severity=Severity.LOW,
                        category=Category.QUALITY,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped,
                        suggestion="Importa explícitamente solo los módulos y funciones que necesitas.",
                    )
                )

            # 2.4 URLs locales hardcodeadas
            if re.search(r"""https?:\/\/(?:localhost|127\.0\.0\.1)(?::[0-9]+)?""", stripped):
                if not is_test_file and not file_path.endswith((".example", ".env.example", ".md")):
                    findings.append(
                        Finding(
                            id=f"QUAL-007-{file_path}-{idx}",
                            rule_id="QUAL-007",
                            title="URL de localhost hardcodeada",
                            description="La URL apunta a localhost o 127.0.0.1 de forma fija.",
                            severity=Severity.LOW,
                            category=Category.QUALITY,
                            file_path=file_path,
                            line_number=idx,
                            snippet=stripped,
                            suggestion="Configura la URL base mediante variables de entorno (ej. BASE_URL o API_URL).",
                        )
                    )

            # 2.5 TODOs y FIXMEs pendientes
            if re.search(r"\b(?:TODO|FIXME|HACK|XXX)\b\s*[:\-]", stripped):
                findings.append(
                    Finding(
                        id=f"QUAL-008-{file_path}-{idx}",
                        rule_id="QUAL-008",
                        title="Comentario de tarea pendiente (TODO / FIXME)",
                        description=f"Marcador de deuda técnica: '{stripped[:60]}...'",
                        severity=Severity.INFO,
                        category=Category.QUALITY,
                        file_path=file_path,
                        line_number=idx,
                        snippet=stripped,
                        suggestion="Asegúrate de resolver o rastrear esta tarea en los issues del proyecto.",
                    )
                )

        return findings
