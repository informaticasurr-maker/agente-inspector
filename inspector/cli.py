"""
Línea de comandos (CLI) del Agente Inspector.
"""

import argparse
import sys
import os
from inspector import __version__
from inspector.config import InspectorConfig
from inspector.core import InspectorEngine
from inspector.models import Severity
from inspector.reporters.console_reporter import ConsoleReporter
from inspector.fixer import CodeFixer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspector",
        description="Agente Inspector de Código, Seguridad y Calidad para repositorios locales y CI/CD.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")

    # Comando: scan
    scan_parser = subparsers.add_parser("scan", help="Escanear un repositorio o directorio")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Ruta al directorio o archivo a inspeccionar (por defecto: .)",
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Habilitar análisis semántico profundo con Gemini IA (requiere GEMINI_API_KEY)",
    )
    scan_parser.add_argument(
        "--fix",
        action="store_true",
        help="Aplicar correcciones mecánicas automáticas cuando sea posible",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="HIGH",
        help="Nivel de severidad que causará código de salida 1 (útil en CI/CD)",
    )
    scan_parser.add_argument(
        "--no-md",
        action="store_true",
        help="Desactivar generación automática del archivo INSPECTION_REPORT.md",
    )
    scan_parser.add_argument(
        "--sarif",
        action="store_true",
        help="Generar archivo SARIF (inspector-results.sarif) para GitHub Security",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Modo silencioso: solo imprime resumen o errores",
    )

    # Comando: init
    init_parser = subparsers.add_parser(
        "init", help="Crear configuración inicial y Workflow de GitHub Actions en el repositorio"
    )

    return parser


def handle_init():
    """Genera la configuración inicial y el workflow de GitHub Actions."""
    reporter = ConsoleReporter()
    workflow_dir = os.path.join(".github", "workflows")
    workflow_file = os.path.join(workflow_dir, "inspector.yml")

    os.makedirs(workflow_dir, exist_ok=True)

    workflow_content = """name: Agente Inspector - Auditoría Automática

on:
  push:
    branches: [ main, master, dev ]
  pull_request:
    branches: [ main, master, dev ]

jobs:
  inspect:
    name: Inspección de Código y Seguridad
    runs-on: ubuntu-latest
    steps:
      - name: Checkout del repositorio
        uses: actions/checkout@v4

      - name: Configurar Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Instalar Agente Inspector
        run: |
          python -m pip install --upgrade pip
          pip install git+https://github.com/informaticasurr-maker/agente-inspector.git

      - name: Ejecutar Auditoría
        run: |
          inspector scan . --fail-on HIGH --sarif
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}

      - name: Subir Reporte SARIF a GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: inspector-results.sarif

      - name: Publicar Reporte Markdown en GitHub Actions Summary
        if: always()
        run: |
          if [ -f INSPECTION_REPORT.md ]; then
            cat INSPECTION_REPORT.md >> $GITHUB_STEP_SUMMARY
          fi
"""
    with open(workflow_file, "w", encoding="utf-8") as f:
        f.write(workflow_content)

    reporter.console.print(
        f"[bold green]✓[/bold green] Workflow de GitHub Actions creado con éxito en: [underline]{workflow_file}[/underline]"
    )
    reporter.console.print(
        "[dim]Cada vez que subas cambios o crees un PR, el agente auditará el código automáticamente.[/dim]"
    )


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Si no se especifica subcomando, asumir 'scan .'
    if not args.command:
        args.command = "scan"
        args.target = "."
        args.ai = False
        args.fix = False
        args.fail_on = "HIGH"
        args.no_md = False
        args.sarif = False
        args.quiet = False

    if args.command == "init":
        handle_init()
        return

    if args.command == "scan":
        config = InspectorConfig(
            target_path=args.target,
            enable_ai=args.ai,
            auto_fix=args.fix,
            fail_on_severity=args.fail_on,
            output_markdown=not args.no_md,
            output_sarif=args.sarif,
        )

        reporter = ConsoleReporter()
        if not args.quiet:
            reporter.print_banner(__version__)

        engine = InspectorEngine(config)
        summary = engine.scan(args.target)

        if not args.quiet:
            reporter.print_findings(summary)
            reporter.print_summary_table(summary)

        if args.fix:
            fixer = CodeFixer()
            fixed_count, modified_files = fixer.apply_fixes(summary.findings)
            if fixed_count > 0:
                reporter.console.print(
                    f"[bold green]✓ Se aplicaron {fixed_count} correcciones automáticas en {len(modified_files)} archivo(s).[/bold green]"
                )

        # Determinar código de salida según la severidad configurada
        if args.fail_on == "NONE":
            sys.exit(0)

        threshold_rank = {
            "CRITICAL": Severity.CRITICAL.rank,
            "HIGH": Severity.HIGH.rank,
            "MEDIUM": Severity.MEDIUM.rank,
            "LOW": Severity.LOW.rank,
        }.get(args.fail_on, Severity.HIGH.rank)

        has_blocking_findings = any(
            f.severity.rank >= threshold_rank for f in summary.findings
        )

        if has_blocking_findings:
            if not args.quiet:
                reporter.console.print(
                    f"[bold red]❌ La inspección falló debido a hallazgos de severidad >= {args.fail_on}[/bold red]"
                )
            sys.exit(1)

        sys.exit(0)


if __name__ == "__main__":
    main()
