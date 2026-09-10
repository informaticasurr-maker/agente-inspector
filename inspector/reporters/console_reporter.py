"""
Reportero de Consola con formato visual enriquecido (Rich).
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from inspector.models import InspectionSummary, Finding, Severity


class ConsoleReporter:
    """Imprime los hallazgos del inspector de manera visual y estructurada."""

    def __init__(self, console: Console = None):
        self.console = console or Console()

    def print_banner(self, version: str = "1.0.0"):
        title = Text("🔍 AGENTE INSPECTOR DE CÓDIGO Y SEGURIDAD", style="bold cyan")
        subtitle = Text(f"v{version} | Auditoría Estática + Análisis con IA", style="dim")
        self.console.print(Panel(Text.assemble(title, "\n", subtitle), border_style="cyan"))

    def print_findings(self, summary: InspectionSummary):
        if not summary.findings:
            self.console.print(
                Panel(
                    "✨ [bold green]¡Excelente! No se encontraron problemas de seguridad ni calidad.[/bold green]\n"
                    "El repositorio cumple con todas las reglas y políticas analizadas.",
                    title="Resultado de la Inspección",
                    border_style="green",
                )
            )
            return

        self.console.print(f"\n[bold underline]Hallazgos Detectados ({len(summary.findings)}):[/bold underline]\n")

        # Ordenar hallazgos por severidad descendente
        sorted_findings = sorted(
            summary.findings, key=lambda f: f.severity.rank, reverse=True
        )

        for idx, finding in enumerate(sorted_findings, start=1):
            severity_style = finding.severity.color
            header = f"[{severity_style}][{finding.severity.badge}][/{severity_style}] [bold]{finding.title}[/bold] ({finding.rule_id or 'CUSTOM'})"

            body_lines = [
                f"[dim]📁 Archivo:[/dim] [underline]{finding.file_path}[/underline]"
                + (f":{finding.line_number}" if finding.line_number else ""),
                f"[dim]📝 Descripción:[/dim] {finding.description}",
            ]

            if finding.snippet:
                body_lines.append(f"[dim]🔎 Código:[/dim] [yellow]{finding.snippet}[/yellow]")

            if finding.suggestion:
                body_lines.append(f"[bold green]💡 Sugerencia de Corrección:[/bold green] {finding.suggestion}")

            panel_border = "red" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow" if finding.severity == Severity.MEDIUM else "blue"
            self.console.print(
                Panel("\n".join(body_lines), title=header, border_style=panel_border, padding=(0, 1))
            )

    def print_summary_table(self, summary: InspectionSummary):
        table = Table(title="📊 Resumen Ejecutivo de Inspección", border_style="cyan")
        table.add_column("Métrica", style="bold white")
        table.add_column("Valor", justify="right")

        table.add_row("Archivos Analizados", str(summary.total_files_scanned))
        table.add_row("Líneas de Código", str(summary.total_lines_scanned))
        table.add_row("Tiempo de Ejecución", f"{summary.duration_seconds:.2f}s")
        table.add_row("🚨 Críticos", f"[bold red]{summary.critical_count}[/bold red]")
        table.add_row("⚠️ Altos", f"[red]{summary.high_count}[/red]")
        table.add_row("⚡ Medios", f"[yellow]{summary.medium_count}[/yellow]")
        table.add_row("ℹ️ Bajos / Info", f"[blue]{summary.low_count + summary.info_count}[/blue]")

        score_color = "green" if summary.score >= 85 else "yellow" if summary.score >= 60 else "red"
        table.add_row(
            "Puntuación de Salud",
            f"[{score_color}]{summary.score} / 100[/{score_color}]",
        )

        self.console.print("\n", table, "\n")
