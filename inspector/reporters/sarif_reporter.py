"""
Reportero en formato SARIF (Static Analysis Results Interchange Format)
Compatible con la pestaña de Seguridad y Code Scanning de GitHub.
"""

import json
from typing import Dict, Any
from inspector.models import InspectionSummary, Finding, Severity


class SarifReporter:
    """Genera reportes compatibles con el estándar OASIS SARIF v2.1.0."""

    def generate(self, summary: InspectionSummary) -> str:
        sarif_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        rules: Dict[str, Any] = {}
        results = []

        for finding in summary.findings:
            rule_id = finding.rule_id or "GENERIC-001"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {
                        "level": sarif_level_map.get(finding.severity, "warning")
                    },
                    "help": {
                        "text": finding.suggestion or finding.description,
                        "markdown": f"{finding.description}\n\n**Solución:** {finding.suggestion or 'N/A'}",
                    },
                }

            result_entry: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": sarif_level_map.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {
                                "startLine": finding.line_number or 1,
                                "startColumn": finding.column_number or 1,
                            },
                        }
                    }
                ],
            }
            results.append(result_entry)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Agente Inspector",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/informaticasurr-maker",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif_data, indent=2)
