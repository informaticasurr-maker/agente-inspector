"""
Analizador Semántico Profundo con IA (Gemini API).
Examina la arquitectura, detecta bugs lógicos complejos y propone soluciones estructuradas.
"""

import json
import os
from typing import List
from inspector.models import Finding, Severity, Category
from inspector.config import InspectorConfig
from inspector.scanners.base import BaseScanner


class AIAnalyzer(BaseScanner):
    """Utiliza Gemini para realizar un análisis semántico profundo de código."""

    name = "Gemini AI Deep Analyzer"
    description = "Inspección semántica con IA para bugs sutiles, arquitectura y remediación"

    def __init__(self, config: InspectorConfig):
        super().__init__(config)
        self.api_key = config.gemini_api_key or os.getenv("GEMINI_API_KEY", "")
        self.client = None
        if self.config.enable_ai and self.api_key:
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        if not self.config.enable_ai or not self.client:
            return []

        # Solo inspeccionar archivos de código fuente no triviales
        if len(content.strip()) < 50 or len(content.splitlines()) > 500:
            return []

        prompt = f"""Eres un auditor de seguridad y arquitecto de software senior (Agente Inspector).
Analiza el siguiente archivo de código fuente: `{file_path}`.

Identifica ÚNICAMENTE problemas reales, críticos o relevantes de:
1. Vulnerabilidades de seguridad sutiles (Race conditions, Auth bypass, SSRF, Desbordamientos).
2. Errores graves de lógica o rendimiento.
3. Violaciones severas de arquitectura o diseño.

Si el archivo está limpio, responde con una lista JSON vacía `[]`.

Responde estrictamente en formato JSON válido con esta estructura:
[
  {{
    "title": "Título corto y descriptivo",
    "description": "Explicación clara del problema encontrado",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "category": "SECURITY" | "PERFORMANCE" | "ARCHITECTURE" | "QUALITY",
    "line_number": 12,
    "suggestion": "Instrucción clara de cómo corregirlo",
    "auto_fixable": false
  }}
]

Código a inspeccionar:
```
{content}
```
"""

        try:
            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            raw_text = response.text.strip()
            # Limpiar bloques markdown si el modelo responde con ```json
            if raw_text.startswith("```"):
                lines = raw_text.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                raw_text = "\n".join(lines).strip()

            findings_data = json.loads(raw_text)
            findings: List[Finding] = []

            for idx, item in enumerate(findings_data):
                sev_str = item.get("severity", "MEDIUM").upper()
                severity = getattr(Severity, sev_str, Severity.MEDIUM)
                cat_str = item.get("category", "QUALITY").upper()
                category = getattr(Category, cat_str, Category.QUALITY)

                findings.append(
                    Finding(
                        id=f"AI-AUDIT-{file_path}-{idx+1}",
                        rule_id="AI-DEEP-SCAN",
                        title=item.get("title", "Hallazgo de IA"),
                        description=item.get("description", ""),
                        severity=severity,
                        category=category,
                        file_path=file_path,
                        line_number=item.get("line_number"),
                        suggestion=item.get("suggestion"),
                        auto_fixable=item.get("auto_fixable", False),
                        metadata={"ai_generated": True},
                    )
                )

            return findings

        except Exception as err:
            # En caso de fallo con la API de IA, el escáner se degrada graciosamente
            return []
