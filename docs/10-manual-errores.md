# 10 · Manual de Errores y Resolución de Problemas (SOC-Lite)

## 1. Propósito
Este manual cataloga los códigos de error estandarizados de **SOC-Lite**, su causa raíz técnica, el comportamiento esperado de resiliencia y los pasos exactos de remediación para el equipo de operaciones y soporte.

---

## 2. Arquitectura de Manejo de Errores

SOC-Lite implementa un esquema de manejo de excepciones unificado en el backend (`backend/app/core/exceptions.py`) y en el cliente HTTP del frontend (`frontend/src/utils/errors.ts`):
- **Trazabilidad Completa (`trace_id`)**: Toda respuesta HTTP incluye la cabecera `X-Trace-Id` y, en caso de error, un cuerpo JSON estructurado:
  ```json
  {
    "detail": "Descripción amigable del error para el usuario.",
    "code": "CODIGO_ESTANDARIZADO",
    "trace_id": "45e5df99-a4d6-4291-97eb-e1604f1d234e"
  }
  ```
- **No Exposición de Detalles Internos (OWASP API8:2023)**: Los *stack traces* de Python o SQL nunca se envían al navegador; quedan registrados exclusivamente en el log estructurado del contenedor junto al `trace_id`.

---

## 3. Catálogo de Códigos de Error HTTP y de Aplicación

| Código HTTP | Código Interno (`code`) | Mensaje al Usuario | Causa Probable | Solución / Acción Correctiva |
| :---: | :--- | :--- | :--- | :--- |
| **400** | `BAD_REQUEST` | Solicitud inválida o parámetros mal formados. | Filtros de fecha invertidos (`from > to`) o JSON malformado. | Verificar el formato ISO-8601 de las fechas y la estructura del payload. |
| **401** | `UNAUTHENTICATED` | Usuario o contraseña incorrectos / Credenciales inválidas o expiradas. | Token JWT expirado (> 60 min) o contraseña errónea en `/auth/login`. | El frontend intenta renovar automáticamente con `refresh_token`; si falla, redirige a `/login`. |
| **403** | `FORBIDDEN` | Permisos insuficientes para realizar esta operación. | El rol actual del usuario carece del permiso requerido (ej. `visor1` intentando cerrar una alerta). | Solicitar al Administrador (`admin`) la asignación del permiso correspondiente en `/roles`. |
| **403** | `INVALID_INGEST_KEY` | Clave de ingesta inválida (`X-Ingest-Key`). | El webhook de Wazuh o n8n envió una cabecera `X-Ingest-Key` distinta a `INGEST_API_KEY`. | Alinear el valor de `INGEST_API_KEY` en `.env` y en la credencial HTTP Header de n8n/Wazuh. |
| **404** | `NOT_FOUND` | Recurso no encontrado (Alerta, Incidente, Usuario o Reporte). | El ID solicitado no existe o fue eliminado lógicamente (`deleted_at IS NOT NULL`). | Refrescar la tabla en la interfaz web y verificar el identificador. |
| **409** | `CONFLICT` | La alerta ya tiene un triaje vigente; use `?force=true` para volver a ejecutarlo. | Se invocó `POST /api/v1/triage/{id}/run` sobre una alerta ya analizada sin el parámetro `force`. | Enviar `?force=true` en la petición o usar el botón "Re-ejecutar Triaje" en la UI. |
| **410** | `GONE` | El archivo del reporte ya no está disponible. | El archivo físico en `/app/storage/reports` fue purgado por retención o reinicio de contenedor sin volumen. | Generar nuevamente el reporte desde `/reports`. |
| **422** | `VALIDATION_ERROR` | Error de validación de campos de entrada. | Contraseña que no cumple la política (mín. 8–12 caracteres, mayúscula, minúscula, dígito y símbolo) o campos faltantes. | Revisar la lista de campos rechazados devuelta por Pydantic en `detail`. |
| **423** | `ACCOUNT_LOCKED` | Cuenta bloqueada temporalmente hasta `YYYY-MM-DD HH:MM:SS UTC`. | Se superaron los 5 intentos fallidos de inicio de sesión (`MAX_LOGIN_ATTEMPTS=5`). | Esperar 15 minutos (`LOCKOUT_MINUTES`) o desbloquear la cuenta desde una sesión de `admin`. |
| **500** | `INTERNAL_ERROR` | Error interno del servidor. Contacte al administrador con el identificador de traza. | Excepción no controlada o pérdida temporal de conexión con PostgreSQL. | Buscar el `trace_id` en `docker logs soc-lite-backend` para inspeccionar la traza exacta. |
| **503** | `SERVICE_UNAVAILABLE` | Fallo de comunicación con el microservicio de triaje. | El contenedor `soc-lite-langchain` está detenido o inalcanzable en la red Docker. | Ejecutar `docker start soc-lite-langchain` y verificar `GET http://localhost:8001/health`. |

---

## 4. Resiliencia y Degradación Elegante (Contingencia IA)

### 4.1 Indisponibilidad del Motor LLM Local (Ollama)
- **Síntoma**: El servidor Ollama local (`http://host.docker.internal:11434`) no está en ejecución o no tiene descargado el modelo `llama3.1:8b` / `llama3.2:3b`.
- **Comportamiento del Sistema (Zero-Downtime Triage)**:
  El microservicio `soc-lite-langchain` **no falla ni bloquea el flujo del SOC**. Automáticamente activa el **Motor Heurístico Determinista de Contingencia** (`_heuristic_fallback` en `triage_agent.py`), el cual:
  1. Evalúa el nivel de regla Wazuh (`rule_level`), la severidad, la criticidad del activo (`asset_criticality`) y los resultados de Threat Intelligence en caché.
  2. Calcula un `risk_score` ponderado (0–100) y emite un veredicto (`true_positive`, `suspicious`, `benign`) con `degraded_mode: true` y confianza ajustada (`0.35` – `0.55`).
  3. Escala automáticamente a Incidente si `risk_score >= 75`, garantizando que ninguna alerta crítica quede sin atención.

---

## 5. Incidencias Técnicas Resueltas Durante la Puesta en Producción

Durante la validación de ingeniería de software de la plataforma se identificaron y corrigieron de raíz 5 defectos de integración:

1. **Resolución de Relaciones Ambiguas en SQLAlchemy 2.0 (`AmbiguousForeignKeysError`)**:
   - *Causa*: La tabla intermedia `soclite.user_roles` posee dos llaves foráneas hacia `users.id` (`user_id` y `granted_by`).
   - *Solución aplicada*: Se definieron explícitamente `primaryjoin` y `secondaryjoin` en las relaciones `User.roles` y `Role.users` dentro de [`backend/app/models/user.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/models/user.py).
2. **Compatibilidad de Identificador Único de Token (`jti`) con PostgreSQL `UUID`**:
   - *Causa*: `secrets.token_urlsafe(16)` generaba cadenas de 22 caracteres, rechazadas por la columna `jti UUID` en `soclite.refresh_tokens`.
   - *Solución aplicada*: Se actualizó `_create_token` en [`backend/app/core/security.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/core/security.py) para emitir `str(uuid.uuid4())` (RFC 4122, 36 caracteres).
3. **Soporte de Dominios Corporativos Internos (`.local`) en Esquemas de Usuario**:
   - *Causa*: `EmailStr` de `email-validator` bloquea por defecto dominios reservados RFC 6762 como `@org.local` usados en redes SOC internas.
   - *Solución aplicada*: Se ajustaron los esquemas Pydantic en [`backend/app/schemas/user.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/schemas/user.py) para admitir correos corporativos internos `@org.local`.
4. **Serialización de Columnas PostgreSQL `INET` (`IPv4Address` / `IPv6Address`) en Pydantic v2**:
   - *Causa*: `asyncpg` devuelve objetos `ipaddress.IPv4Address` para columnas `INET`, provocando `ValidationError` en campos tipados como `str`.
   - *Solución aplicada*: Se incorporaron validadores `mode="before"` (`_ip_to_str`) en [`backend/app/schemas/alert.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/schemas/alert.py), [`backend/app/schemas/dashboard.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/schemas/dashboard.py) y [`backend/app/schemas/user.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/schemas/user.py), además de casteo explícito `cast(Asset.ip_address, String)` en [`backend/app/api/v1/routers/alerts.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/api/v1/routers/alerts.py).
5. **Conflicto de Versiones `httpx` + `ollama` en `langchain-service`**:
   - *Causa*: `ollama==0.4.5` requiere `httpx<0.28.0`.
   - *Solución aplicada*: Se fijó `httpx==0.27.2` y se añadió `gunicorn==23.0.0` en [`langchain-service/requirements.txt`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/langchain-service/requirements.txt).
