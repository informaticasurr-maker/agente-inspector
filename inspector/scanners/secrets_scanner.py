"""
Escáner de Secretos y Credenciales Expuestas.
Detecta claves de API, tokens privados, certificados y contraseñas hardcodeadas.
"""

import re
from typing import List, Pattern, Tuple
from inspector.models import Finding, Severity, Category
from inspector.config import InspectorConfig
from inspector.scanners.base import BaseScanner

SECRET_RULES: List[Tuple[str, str, Pattern[str], Severity, str]] = [
    (
        "SEC-001",
        "Clave de API de Google expuesta",
        re.compile(r"(AIzaSy[0-9A-Za-z_-]{30,40})"),  # inspector:ignore
        Severity.CRITICAL,
        "Usa variables de entorno o un gestor de secretos (ej. Secret Manager / .env) en lugar de hardcodear la API Key de Google.",
    ),
    (
        "SEC-002",
        "Token de GitHub expuesto",
        re.compile(r"((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,})"),  # inspector:ignore
        Severity.CRITICAL,
        "Revoca inmediatamente este token de GitHub y utiliza GitHub Secrets.",
    ),
    (
        "SEC-003",
        "Clave de acceso AWS (Access Key ID)",
        re.compile(r"(AKIA[0-9A-Z]{16})"),  # inspector:ignore
        Severity.CRITICAL,
        "No expongas credenciales de AWS en el código fuente. Usa IAM Roles o AWS Secrets Manager.",
    ),
    (
        "SEC-004",
        "Clave de API de OpenAI expuesta",
        re.compile(r"(sk-[a-zA-Z0-9]{32,})"),  # inspector:ignore
        Severity.CRITICAL,
        "Mueve la clave de OpenAI a una variable de entorno `OPENAI_API_KEY`.",
    ),
    (
        "SEC-005",
        "Clave privada RSA / SSH / PGP detectada",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),  # inspector:ignore
        Severity.CRITICAL,
        "Nunca subas claves privadas a repositorios de código. Agrégalas a .gitignore y usa un almacén seguro.",
    ),
    (
        "SEC-006",
        "Clave secreta de Stripe en producción",
        re.compile(r"(sk_live_[0-9a-zA-Z]{24,})"),  # inspector:ignore
        Severity.CRITICAL,
        "¡PELIGRO! Clave de pagos en vivo expuesta. Rota la clave inmediatamente en el dashboard de Stripe.",
    ),
    (
        "SEC-007",
        "Token de Slack expuesto",
        re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,48})"),  # inspector:ignore
        Severity.HIGH,
        "Almacena los tokens de Slack en variables de entorno seguras.",
    ),
    (
        "SEC-008",
        "URL de Base de Datos con contraseña embebida",
        re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:([^@\s]+)@[^\s]+"),  # inspector:ignore
        Severity.HIGH,
        "Parametriza la conexión a la base de datos usando variables de entorno para usuario y contraseña.",
    ),
    (
        "SEC-009",
        "Posible contraseña hardcodeada en asignación",
        re.compile(  # inspector:ignore
            r"""(?i)(?:password|passwd|api_secret|client_secret|db_pass)\s*[:=]\s*["']([^"'\s]{6,})["']"""
        ),
        Severity.MEDIUM,
        "Evita almacenar contraseñas o secretos en texto plano en el código. Cárgalos desde el entorno.",
    ),
    (
        "SEC-010",
        "Token JWT expuesto",
        re.compile(r"(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),  # inspector:ignore
        Severity.HIGH,
        "No incluyas tokens JWT estáticos en el código.",
    ),
]


class SecretsScanner(BaseScanner):
    """Escanea archivos en busca de credenciales, tokens y secretos expuestos."""

    name = "Secrets & Credentials Scanner"
    description = "Detecta tokens de API, credenciales en texto plano y claves privadas"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        # Si el archivo es un ejemplo o dummy, solo alertar en baja severidad si no es crítico
        is_example_file = any(
            x in file_path.lower()
            for x in [".example", "example.", "fixture", "mock", "test_secrets", "dummy"]
        )

        for line_idx, line in enumerate(lines, start=1):
            # Ignorar comentarios que explicitan falsos positivos o ignore
            if "inspector:ignore" in line or "pragma: allowlist secret" in line:
                continue

            for rule_id, title, pattern, severity, suggestion in SECRET_RULES:
                matches = pattern.finditer(line)
                for match in matches:
                    matched_str = match.group(0)

                    # Redactar parte del secreto para no exponerlo en logs
                    if len(matched_str) > 8:
                        redacted = matched_str[:3] + "..." + matched_str[-3:]
                    else:
                        redacted = "***"

                    effective_severity = severity
                    if is_example_file and severity != Severity.CRITICAL:
                        effective_severity = Severity.INFO

                    findings.append(
                        Finding(
                            id=f"{rule_id}-{file_path}-{line_idx}",
                            rule_id=rule_id,
                            title=title,
                            description=f"Se detectó un patrón de secreto coincidente con '{rule_id}' (valor ofuscado: {redacted})",
                            severity=effective_severity,
                            category=Category.SECRETS,
                            file_path=file_path,
                            line_number=line_idx,
                            column_number=match.start() + 1,
                            snippet=line.strip(),
                            suggestion=suggestion,
                            auto_fixable=False,
                            metadata={"matched_pattern": rule_id},
                        )
                    )

        return findings
