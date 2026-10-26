# 13 · Manual de Seguridad y Cumplimiento Normativo (SOC-Lite)

## 1. Propósito y Marcos de Referencia
Dado que **SOC-Lite** procesa telemetría crítica de seguridad, indicadores de compromiso (IOCs) y evidencias forenses, su arquitectura fue diseñada aplicando **Seguridad por Diseño (*Security by Design*)** alineada con:
- **ISO/IEC 27001:2022** (Controles Anexo A: A.5.15, A.5.17, A.8.2, A.8.15, A.8.16, A.8.24).
- **OWASP Top 10:2021** y **OWASP API Security Top 10:2023**.
- **OWASP Top 10 for Large Language Model Applications (LLM01–LLM10)**.
- **NIST Cybersecurity Framework (CSF 2.0)** y **MITRE ATT&CK v15**.

---

## 2. Controles de Autenticación y Gestión de Sesiones (ISO 27001 A.5.17)

1. **Almacenamiento Criptográfico de Contraseñas**:
   - Ninguna contraseña se almacena en texto claro ni con hashes rápidos vulnerables. Se utiliza **`bcrypt` con factor de trabajo 12** (`passlib.context.CryptContext` en [`backend/app/core/security.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/core/security.py)).
2. **Política de Robustez de Contraseñas**:
   - Validación automática de longitud mínima, presencia obligatoria de mayúsculas, minúsculas, dígitos, caracteres especiales y rechazo de diccionarios comunes.
3. **Tokens JWT de Corta Duración + Refresh Tokens Revocables**:
   - `access_token` firmado con `HS256` (`exp = 30-60 min`), `iss = SOC-Lite` y `jti` único UUIDv4.
   - Los `refresh_token` nunca se guardan en claro en la base de datos: se almacena únicamente su **hash SHA-256** en `soclite.refresh_tokens`, permitiendo revocación inmediata en caso de compromiso.
4. **Protección Anti-Fuerza Bruta (Bloqueo Automático de Cuenta)**:
   - Al alcanzar `MAX_LOGIN_ATTEMPTS = 5` intentos fallidos consecutivos, la cuenta se bloquea automáticamente durante `LOCKOUT_MINUTES = 15` (`HTTP 423 Locked`) y se emite un evento de severidad `critical` en la bitácora.
5. **Autenticación Multifactor (MFA TOTP RFC 6238)**:
   - Soporte integrado mediante `pyotp` para segundo factor de autenticación temporal.

---

## 3. Control de Acceso Basado en Roles — Matriz RBAC (ISO 27001 A.5.15 / A.8.2)

El principio de **mínimo privilegio** se aplica en cada endpoint mediante dependencias de FastAPI (`require_permissions`) y en cada componente visual del frontend (`<PermissionGate>`):

| Módulo | Permiso | `admin` | `soc_manager` | `analyst` | `auditor` | `viewer` |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Alertas** | `alerts:read` | Sí | Sí | Sí | Sí | Sí |
| **Alertas** | `alerts:write` / `alerts:assign` / `alerts:close` | Sí | Sí | Sí | No | No |
| **Triaje IA** | `triage:read` | Sí | Sí | Sí | Sí | Sí |
| **Triaje IA** | `triage:run` / `triage:feedback` | Sí | Sí | Sí | No | No |
| **Incidentes** | `incidents:read` | Sí | Sí | Sí | Sí | Sí |
| **Incidentes** | `incidents:write` / `incidents:close` | Sí | Sí | Sí | No | No |
| **Dashboard** | `dashboard:read` | Sí | Sí | Sí | Sí | Sí |
| **Reportes** | `reports:read` / `reports:export` | Sí | Sí | Sí | Sí | No |
| **Auditoría** | `audit:read` / `audit:export` | Sí | No | No | Sí | No |
| **Usuarios/Roles** | `users:read` / `users:write` / `roles:write` | Sí | No | No | No | No |

---

## 4. Seguridad del Agente LLM y Privacidad de Datos (OWASP LLM Top 10)

1. **Soberanía de Datos y Cero Exfiltración (`ALLOW_EXTERNAL_LLM=false`)**:
   - Por defecto, toda la inferencia se realiza localmente mediante **Ollama** en la red interna de la organización. Ningún log ni dirección IP interna sale hacia nubes de terceros.
2. **Defensa contra *Prompt Injection* Indirecto (OWASP LLM01)**:
   - Los logs crudos provenientes de Wazuh/atacantes (`full_log`) se encapsulan dentro de delimitadores estrictos en el prompt de sistema (`triage_v3` en [`langchain-service/app/chains/prompts.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/langchain-service/app/chains/prompts.py)) con la instrucción explícita de tratar cualquier texto del evento como **datos no confiables** y jamás como instrucciones ejecutables.
3. **Validación Estricta de Salida del Modelo (OWASP LLM02 — *Insecure Output Handling*)**:
   - La respuesta del LLM es parseada y validada contra esquemas Pydantic estrictos (`TriageResponseSchema`) antes de almacenarse o mostrarse en el frontend, impidiendo ataques XSS generados por el modelo.
4. **Supervisión Humana en Acciones Críticas (OWASP LLM08 — *Excessive Agency*)**:
   - El agente IA clasifica, calcula el riesgo y propone acciones recomendadas, pero las acciones destructivas (como aislar un servidor de producción) requieren confirmación del analista o flujo controlado en n8n.

---

## 5. Bitácora de Auditoría Inmutable con Cadena SHA-256 (ISO 27001 A.8.15)

La tabla `soclite.audit_log` implementa controles de nivel forense:
1. **Protección contra Modificación y Borrado a Nivel de Motor SQL**:
   - Un *trigger* en PostgreSQL (`trg_audit_log_immutable` en [`db/schema.sql`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/db/schema.sql)) bloquea cualquier sentencia `UPDATE` o `DELETE` sobre `soclite.audit_log`, lanzando una excepción incluso si el usuario de base de datos intenta modificar una fila.
2. **Encadenamiento Criptográfico (`hash_prev` $\rightarrow$ `hash_self`)**:
   - Cada nuevo registro calcula su `hash_self` con **SHA-256** concatenando el `hash_self` del registro anterior (`hash_prev`), la marca de tiempo, el usuario, el módulo, la acción, la entidad y los estados `before_data` / `after_data`.
   - El endpoint `GET /api/v1/audit/verify-chain` recorre toda la cadena y detecta instantáneamente cualquier manipulación.
3. **"Auditar al Auditor"**:
   - Cada consulta o exportación realizada sobre la propia bitácora de auditoría genera automáticamente un nuevo registro `audit / read` o `audit / export`.

---

## 6. Seguridad de Infraestructura, Red y Contenedores

1. **Contenedores sin Privilegios (`Non-Root Users`)**:
   - El contenedor `backend` se ejecuta bajo el usuario sin privilegios `soclite` (`UID 10001`).
   - El contenedor `langchain-service` se ejecuta bajo el usuario `triage` (`UID 10002`).
2. **Autenticación de Webhooks en Tiempo Constante**:
   - La validación de `X-Ingest-Key` y `INTERNAL_SERVICE_TOKEN` utiliza `hmac.compare_digest()` para neutralizar ataques de temporización (*Timing Attacks*).
3. **Cabeceras HTTP de Seguridad en Nginx**:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `server_tokens off` (ocultamiento de versión del servidor web).
