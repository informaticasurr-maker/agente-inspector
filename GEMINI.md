# Guías del Espacio de Trabajo: Agente Inspector

## Reglas de Seguridad y Calidad del Código

1. **Gestión de Secretos:** Nunca incluir tokens de API, contraseñas ni claves privadas en el código fuente. Usar variables de entorno o gestores de secretos.
2. **Seguridad OWASP:**
   - No utilizar `eval()` o `exec()` con entradas dinámicas.
   - Usar consultas SQL parametrizadas o un ORM seguro.
   - En PyYAML usar siempre `yaml.safe_load()`.
   - Mantener activada la verificación de certificados TLS (`verify=True`).
3. **Calidad y Mantenibilidad:**
   - Evitar dejar `print()` o `debugger;` en código de producción.
   - No silenciar excepciones con bloques `except: pass`.
   - Documentar funciones públicas y mantener modularidad (máx. 600 líneas por archivo).
