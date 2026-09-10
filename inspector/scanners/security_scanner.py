"""
Escáner de Seguridad y Vulnerabilidades Comunes.
Analiza patrones de inyección SQL, ejecución insegura de comandos, deserialización peligrosa y malas configuraciones.
"""

import re
from typing import List, Pattern, Tuple
from inspector.models import Finding, Severity, Category
from inspector.config import InspectorConfig
from inspector.scanners.base import BaseScanner

SECURITY_RULES: List[Tuple[str, str, Pattern[str], Severity, str, bool]] = [
    (
        "VULN-001",
        "Uso peligroso de eval() o exec()",  # inspector:ignore
        re.compile(r"\b(?:eval|exec)\s*\("),  # inspector:ignore
        Severity.CRITICAL,
        "Evita el uso de eval() o exec(). Son vectores críticos de inyección de código remoto (RCE). Usa parsers seguros como ast.literal_eval() o JSON.",  # inspector:ignore
        False,
    ),
    (
        "VULN-002",
        "Subprocess ejecutado con shell=True",
        re.compile(r"subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True"),  # inspector:ignore
        Severity.HIGH,
        "Usar shell=True con parámetros variables permite inyección de comandos en el SO. Usa listas de argumentos [cmd, arg1, arg2] y shell=False.",
        False,
    ),
    (
        "VULN-003",
        "Posible inyección SQL por formateo de cadenas",
        re.compile(  # inspector:ignore
            r"""(?i)(?:execute|query|cursor\.execute)\s*\(\s*(?:f["'].*SELECT|["'].*SELECT.*%s|f["'].*INSERT|f["'].*UPDATE|f["'].*DELETE|["'].*\+.*SELECT)"""
        ),
        Severity.HIGH,
        "Usa consultas parametrizadas o un ORM en lugar de interpolar cadenas en sentencias SQL.",
        False,
    ),
    (
        "VULN-004",
        "Deserialización insegura con pickle",
        re.compile(r"pickle\.(?:loads|load)\s*\("),  # inspector:ignore
        Severity.HIGH,
        "El módulo pickle puede ejecutar código arbitrario durante la deserialización. Usa formatos seguros como JSON o Protocol Buffers.",
        False,
    ),
    (
        "VULN-005",
        "Carga insegura de YAML (PyYAML sin SafeLoader)",
        re.compile(r"yaml\.load\s*\([^,)]*\)(?!\s*Loader\s*=\s*yaml\.SafeLoader)"),  # inspector:ignore
        Severity.HIGH,
        "Usa yaml.safe_load() en lugar de yaml.load() para evitar ejecución de código.",  # inspector:ignore
        True,
    ),
    (
        "VULN-006",
        "Desactivación de verificación SSL/TLS",
        re.compile(r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning)"""),  # inspector:ignore
        Severity.HIGH,
        "Desactivar la verificación SSL permite ataques Man-in-the-Middle (MitM). Mantén verify=True en producción.",
        False,
    ),
    (
        "VULN-007",
        "Uso de algoritmo de hash criptográficamente roto (MD5/SHA1)",
        re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),  # inspector:ignore
        Severity.MEDIUM,
        "MD5 y SHA-1 son vulnerables a colisiones. Usa SHA-256 o SHA-3 para integridad, y bcrypt/argon2 para contraseñas.",
        False,
    ),
    (
        "VULN-008",
        "Uso de dangerouslySetInnerHTML en frontend",
        re.compile(r"dangerouslySetInnerHTML\s*="),  # inspector:ignore
        Severity.MEDIUM,
        "dangerouslySetInnerHTML puede provocar vulnerabilidades XSS (Cross-Site Scripting). Sanitiza el contenido con DOMPurify.",
        False,
    ),
    (
        "VULN-009",
        "Servidor web en modo Debug o expuesto en 0.0.0.0",
        re.compile(r"""(?:app\.run\s*\([^)]*debug\s*=\s*True|host\s*=\s*['"]0\.0\.0\.0['"])"""),  # inspector:ignore
        Severity.LOW,
        "Asegúrate de que debug=False en producción y que la interfaz de red esté protegida.",
        False,
    ),
    (
        "VULN-010",
        "CORS configurado con comodín abierto (*)",
        re.compile(r"""(?i)(?:Access-Control-Allow-Origin\s*['":]+\s*\*|cors\(\s*\{?\s*origin\s*:\s*['"]\*['"])"""),  # inspector:ignore
        Severity.LOW,
        "Permitir cualquier origen ('*') puede exponer recursos sensibles a sitios de terceros. Especifica los dominios permitidos.",
        False,
    ),
]


class SecurityScanner(BaseScanner):
    """Escanea el código fuente en busca de vulnerabilidades de seguridad comunes (OWASP Top 10)."""

    name = "Security & Vulnerability Scanner"
    description = "Detecta inyecciones SQL, RCE, problemas de deserialización y riesgos OWASP"

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "/*", "*", '"""', "'''")):
                continue
            if "inspector:ignore" in line or "nosec" in line:
                continue

            for rule_id, title, pattern, severity, suggestion, auto_fixable in SECURITY_RULES:
                match = pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            id=f"{rule_id}-{file_path}-{line_idx}",
                            rule_id=rule_id,
                            title=title,
                            description=f"Patrón de riesgo de seguridad detectado: {title}",
                            severity=severity,
                            category=Category.SECURITY,
                            file_path=file_path,
                            line_number=line_idx,
                            column_number=match.start() + 1,
                            snippet=line.strip(),
                            suggestion=suggestion,
                            auto_fixable=auto_fixable,
                            metadata={"matched_pattern": rule_id},
                        )
                    )

        return findings
