# 🔍 Agente Inspector de Código y Seguridad

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Code%20Inspector-blue.svg?logo=github)](https://github.com/informaticasurr-maker)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Un **Agente Inspector autónomo** diseñado para auditar, detectar vulnerabilidades de seguridad, descubrir credenciales/secretos expuestos, analizar calidad de código y sugerir correcciones automáticas con **Inteligencia Artificial (Gemini)**.

Funciona de manera híbrida: **localmente en tu PC (CLI)** y **en la nube (GitHub Actions)** para auditar cualquier repositorio automáticamente en cada `git push` o Pull Request.

---

## 🚀 Características Principales

* 🚨 **Detector de Secretos y Credenciales:** Localiza tokens de GitHub, AWS, Google Cloud, Stripe, JWTs, claves privadas RSA/SSH y contraseñas hardcodeadas.
* 🛡️ **Seguridad y OWASP Top 10:** Detecta inyecciones SQL, ejecución insegura de comandos (`eval`, `exec`, `shell=True`), deserialización peligrosa (`pickle`, `yaml.load`), desactivación de TLS/SSL y configuraciones inseguras de CORS.
* ⚡ **Calidad de Código y Code Smells:** Encuentra prints/logs residuales, breakpoints olvidados, excepciones silenciadas (`except: pass`), archivos excesivamente grandes y comodines de importación.
* 🤖 **Análisis Semántico Profundo con IA (Gemini):** Auditoría arquitectónica y detección de bugs sutiles de concurrencia y lógica.
* 🛠️ **Auto-Fixing Mecánico:** Corrige automáticamente problemas comunes con `--fix`.
* 📊 **Multi-Formato de Reportes:**
  * Consola interactiva con formato enriquecido (`Rich`).
  * Reportes en Markdown (`INSPECTION_REPORT.md`) para Pull Requests.
  * Reportes estándar **SARIF** compatibles con la pestaña de *Security / Code Scanning* de GitHub.

---

## 💻 1. Uso Local en tu PC

### Instalación
```bash
# Clonar el repositorio
git clone https://github.com/informaticasurr-maker/agente-inspector.git
cd agente-inspector

# Instalar dependencias en modo editable
pip install -e .
```

### Comandos del CLI
```bash
# Inspeccionar el directorio actual
inspector scan .

# Inspeccionar con Auto-Fix (corrección automática de problemas mecánicos)
inspector scan . --fix

# Inspeccionar con Análisis Profundo de IA (requiere GEMINI_API_KEY)
export GEMINI_API_KEY="tu-api-key"
inspector scan . --ai

# Fallar solo si hay problemas CRÍTICOS (útil en scripts)
inspector scan . --fail-on CRITICAL

# Generar reporte SARIF para herramientas de seguridad
inspector scan . --sarif
```

---

## ☁️ 2. Uso en Cualquier Repositorio de GitHub

Puedes hacer que este Agente audite **cualquier otro repositorio** que subas a GitHub agregando un archivo `.github/workflows/audit.yml`:

```yaml
name: Auditoría con Agente Inspector

on:
  push:
    branches: [ main, master, dev ]
  pull_request:
    branches: [ main, master, dev ]

jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - name: Descargar Código
        uses: actions/checkout@v4

      - name: Ejecutar Agente Inspector
        uses: informaticasurr-maker/agente-inspector@main
        with:
          target: '.'
          fail-on: 'HIGH'
          sarif: 'true'
          enable-ai: 'false' # Cambia a 'true' si configuras GEMINI_API_KEY en los Secrets
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

---

## 🧪 Pruebas Unitarias
Para ejecutar la suite de pruebas del inspector:
```bash
pytest tests/
```

---

## 📄 Licencia
Este proyecto está bajo la Licencia MIT.
