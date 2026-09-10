"""
Motor de Auto-Corrección (Fixer) para resolver hallazgos comunes automáticamente.
"""

from typing import List, Tuple
from inspector.models import Finding


class CodeFixer:
    """Aplica soluciones automáticas a problemas que admiten corrección mecánica."""

    def apply_fixes(self, findings: List[Finding]) -> Tuple[int, List[str]]:
        """Aplica las correcciones en disco para los hallazgos que sean auto_fixables."""
        fixable_findings = [f for f in findings if f.auto_fixable and f.file_path]
        if not fixable_findings:
            return 0, []

        files_modified = set()
        fixes_applied = 0

        # Agrupar por archivo
        by_file = {}
        for f in fixable_findings:
            by_file.setdefault(f.file_path, []).append(f)

        for file_path, file_findings in by_file.items():
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()

                modified = False
                for finding in file_findings:
                    if not finding.line_number or finding.line_number > len(lines):
                        continue
                    line_idx = finding.line_number - 1
                    original_line = lines[line_idx]

                    # 1. yaml.load -> yaml.safe_load
                    if finding.rule_id == "VULN-005" and "yaml.load(" in original_line:
                        lines[line_idx] = original_line.replace("yaml.load(", "yaml.safe_load(")
                        modified = True
                        fixes_applied += 1

                    # 2. breakpoint() / debugger -> comentar o remover
                    elif finding.rule_id in ("QUAL-003", "QUAL-004"):
                        if "breakpoint()" in original_line:
                            lines[line_idx] = original_line.replace("breakpoint()", "# [inspector-fixed] breakpoint()")
                            modified = True
                            fixes_applied += 1
                        elif "debugger;" in original_line:
                            lines[line_idx] = original_line.replace("debugger;", "// [inspector-fixed] debugger;")
                            modified = True
                            fixes_applied += 1

                if modified:
                    with open(file_path, "w", encoding="utf-8") as fp:
                        fp.writelines(lines)
                    files_modified.add(file_path)

            except Exception:
                continue

        return fixes_applied, list(files_modified)
