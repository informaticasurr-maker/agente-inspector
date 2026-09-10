"""
Reportero en formato Markdown para reportes de auditoría y comentarios de PR en GitHub.
"""

from inspector.models import InspectionSummary, Finding, Severity


class MarkdownReporter:
    """Genera un archivo Markdown con el reporte detallado de auditoría."""

    def generate(self, summary: InspectionSummary) -> str:
        status_emoji = "✅" if not summary.has_critical_or_high else "❌"
        score_badge = f"**{summary.score} / 100**"

        lines = [
            f"# {status_emoji} Reporte de Auditoría: Agente Inspector",
            "",
            "> Reporte automático generado por el Agente Inspector de Código y Seguridad.",
            "",
            "## 📊 Resumen Ejecutivo",
            "",
            f"| Métrica | Resultado |",
            f"| :--- | :--- |",
            f"| **Puntuación de Salud** | {score_badge} |",
            f"| **Archivos Analizados** | {summary.total_files_scanned} |",
            f"| **Líneas Escaneadas** | {summary.total_lines_scanned} |",
            f"| **🚨 Críticos** | {summary.critical_count} |",
            f"| **⚠️ Altos** | {summary.high_count} |",
            f"| **⚡ Medios** | {summary.medium_count} |",
            f"| **ℹ️ Bajos / Info** | {summary.low_count + summary.info_count} |",
            f"| **Tiempo de Auditoría** | {summary.duration_seconds:.2f}s |",
            "",
        ]

        if not summary.findings:
            lines.extend([
                "### 🎉 ¡Sin problemas detectados!",
                "No se encontraron vulnerabilidades ni problemas de calidad en los archivos analizados.",
                "",
            ])
            return "\n".join(lines)

        lines.extend([
            "## 🔍 Detalle de Hallazgos",
            "",
            "| Severidad | Regla / ID | Archivo | Línea | Descripción |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        sorted_findings = sorted(
            summary.findings, key=lambda f: f.severity.rank, reverse=True
        )

        for finding in sorted_findings:
            line_str = str(finding.line_number) if finding.line_number else "-"
            rule_str = finding.rule_id or "GENÉRICO"
            lines.append(
                f"| {finding.severity.badge} | `{rule_str}` | `{finding.file_path}` | {line_str} | **{finding.title}**: {finding.description} |"
            )

        lines.extend([
            "",
            "## 💡 Recomendaciones y Soluciones",
            "",
        ])

        for idx, finding in enumerate(sorted_findings, start=1):
            if finding.suggestion or finding.snippet:
                lines.extend([
                    f"### {idx}. [{finding.severity.badge}] {finding.title} (`{finding.file_path}`)",
                    f"- **Problema:** {finding.description}",
                ])
                if finding.snippet:
                    lines.extend([
                        f"- **Código:**",
                        "```",
                        f"{finding.snippet}",
                        "```",
                    ])
                if finding.suggestion:
                    lines.extend([
                        f"- **Solución sugerida:** {finding.suggestion}",
                    ])
                lines.append("")

        lines.extend([
            "---",
            "*Generado por [Agente Inspector](https://github.com/informaticasurr-maker)*",
        ])

        return "\n".join(lines)
