---
name: code-inspector
description: >-
  Audita y analiza repositorios de código en busca de vulnerabilidades de seguridad,
  secretos o tokens expuestos, problemas de calidad, code smells y buenas prácticas.
  Úsalo cuando el usuario pida inspeccionar, auditar o verificar el código del proyecto.
---

# Agente Inspector de Código

Esta habilidad permite ejecutar auditorías automatizadas estáticas y con IA sobre cualquier archivo o directorio del proyecto.

## Modos de Ejecución

### 1. Auditoría Rápida Local (CLI)
Para auditar el repositorio completo:
```bash
python3 -m inspector.cli scan .
```

Para auditar un archivo o subdirectorio específico:
```bash
python3 -m inspector.cli scan src/
```

### 2. Auto-Corrección Mecánica
Para aplicar correcciones automáticas sobre problemas detectados (breakpoints, loaders inseguros, etc.):
```bash
python3 -m inspector.cli scan . --fix
```

### 3. Inspección Semántica Profunda con IA (Gemini)
Si dispones de `GEMINI_API_KEY`:
```bash
python3 -m inspector.cli scan . --ai
```

## Reportes Generados
* **Consola:** Tablas de resumen visual e indicadores de severidad (Crítico, Alto, Medio, Bajo).
* **Markdown:** `INSPECTION_REPORT.md` (resumen detallado de hallazgos y sugerencias de remediación).
* **SARIF:** `inspector-results.sarif` (estándar OASIS para la pestaña de seguridad de GitHub).

## Pautas de Remediación
1. **Secretos:** Rotar credenciales comprometidas y moverlas inmediatamente a variables de entorno (`.env` o GitHub Secrets).
2. **Seguridad:** Reemplazar `eval()` / `exec()` por parsers seguros, evitar interpolación en consultas SQL y verificar configuraciones de CORS y TLS.
3. **Calidad:** Eliminar prints/console.logs residuales y no silenciar excepciones (`except: pass`).
