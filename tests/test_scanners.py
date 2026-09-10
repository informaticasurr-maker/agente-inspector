"""
Pruebas unitarias para los escáneres, reporteros y fixer del Agente Inspector.
Compatible con unittest estándar y pytest.
"""

import unittest
from inspector.config import InspectorConfig
from inspector.scanners.secrets_scanner import SecretsScanner
from inspector.scanners.security_scanner import SecurityScanner
from inspector.scanners.quality_scanner import QualityScanner
from inspector.models import Finding, Severity, Category, InspectionSummary
from inspector.reporters.markdown_reporter import MarkdownReporter
from inspector.reporters.sarif_reporter import SarifReporter
from inspector.fixer import CodeFixer


class TestInspectorScanners(unittest.TestCase):

    def test_secrets_scanner_detects_tokens(self):
        config = InspectorConfig()
        scanner = SecretsScanner(config)

        dummy_content = """
        # Dummy configuration
        API_KEY = "AIzaSyDummyGoogleKey1234567890abcdef"
        GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
        AWS_ID = "AKIA1234567890ABCDEF"
        """

        findings = scanner.scan_file("config.py", dummy_content)
        rule_ids = [f.rule_id for f in findings]

        self.assertIn("SEC-001", rule_ids)  # Google API key
        self.assertIn("SEC-002", rule_ids)  # GitHub Token
        self.assertIn("SEC-003", rule_ids)  # AWS Key

    def test_security_scanner_detects_vulnerabilities(self):
        config = InspectorConfig()
        scanner = SecurityScanner(config)

        dummy_content = """
        import subprocess
        import yaml

        def run_user_code(user_input):
            eval(user_input)
            subprocess.run(user_input, shell=True)
            data = yaml.load(user_input)
            cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
        """

        findings = scanner.scan_file("app.py", dummy_content)
        rule_ids = [f.rule_id for f in findings]

        self.assertIn("VULN-001", rule_ids)  # eval()
        self.assertIn("VULN-002", rule_ids)  # shell=True
        self.assertIn("VULN-003", rule_ids)  # SQL injection
        self.assertIn("VULN-005", rule_ids)  # yaml.load

    def test_quality_scanner_detects_smells(self):
        config = InspectorConfig()
        scanner = QualityScanner(config)

        dummy_content = """
        from math import *

        def calculate():
            print("Debugging values...")
            breakpoint()
            try:
                do_something()
            except:
                pass
        """

        findings = scanner.scan_file("math_ops.py", dummy_content)
        rule_ids = [f.rule_id for f in findings]

        self.assertIn("QUAL-002", rule_ids)  # print()
        self.assertIn("QUAL-003", rule_ids)  # breakpoint()
        self.assertIn("QUAL-005", rule_ids)  # except: pass
        self.assertIn("QUAL-006", rule_ids)  # from math import *

    def test_markdown_and_sarif_reporters(self):
        summary = InspectionSummary(
            total_files_scanned=2,
            total_lines_scanned=100,
            findings=[
                Finding(
                    id="TEST-1",
                    rule_id="SEC-001",
                    title="Clave de API expuesta",
                    description="Se detectó una clave de API",
                    severity=Severity.CRITICAL,
                    category=Category.SECRETS,
                    file_path="secret.py",
                    line_number=10,
                    snippet="API_KEY = 'AIzaSy...'",
                    suggestion="Usa variables de entorno",
                )
            ],
            duration_seconds=0.15,
        )

        md_output = MarkdownReporter().generate(summary)
        self.assertIn("# ❌ Reporte de Auditoría", md_output)
        self.assertIn("Clave de API expuesta", md_output)

        sarif_output = SarifReporter().generate(summary)
        self.assertIn("Agente Inspector", sarif_output)
        self.assertIn("SEC-001", sarif_output)


if __name__ == "__main__":
    unittest.main()
