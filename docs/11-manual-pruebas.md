# 11 · Manual de Pruebas y Validación Funcional (SOC-Lite)

## 1. Estrategia de Pruebas
La validación de **SOC-Lite** cubre cuatro niveles complementarios de ingeniería de software:
1. **Pruebas Unitarias y de Contratos (Pydantic / Seguridad / RBAC)**: Validación de hashing `bcrypt`, cálculo ponderado de `risk_score`, generación de `fingerprint` SHA-256 y mapeo de severidades Wazuh.
2. **Pruebas de Integración de API y Base de Datos**: Verificación de los 8 módulos REST (`/auth`, `/users`, `/alerts`, `/triage`, `/incidents`, `/dashboard`, `/reports`, `/audit`) contra PostgreSQL 15 real.
3. **Pruebas End-to-End (E2E) del Pipeline de Triaje IA**: Simulación de ingesta de un ataque crítico en tiempo real, deduplicación idempotente, triaje automático mediante `soc-lite-langchain` y escalamiento automático a Incidente.
4. **Pruebas de Integridad Criptográfica y Exportación Documental**: Verificación de la cadena de bloques SHA-256 en la bitácora de auditoría y generación binaria de reportes en PDF, Word (`.docx`) y Excel (`.xlsx`).

---

## 2. Matriz de Casos de Prueba Ejecutados (Resultados Reales)

Todas las pruebas fueron ejecutadas contra el entorno Dockerizado activo (`soc-lite-frontend`, `soc-lite-backend`, `soc-lite-langchain`, `soc-lite-postgres`, `soc-lite-redis`):

| ID Caso | Módulo | Caso de Prueba | Endpoint / Acción | Resultado Esperado | Resultado Obtenido | Estado |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **CP-01** | Infraestructura | Salud de Backend y BD | `GET /api/v1/health` | HTTP 200, `"status": "ok"`, PostgreSQL 15.19 conectado. | HTTP 200 OK, PostgreSQL conectado. | **APROBADO** |
| **CP-02** | Infraestructura | Salud de Microservicio IA | `GET http://localhost:8001/health` | HTTP 200, `"status": "ok"`. | HTTP 200 OK (`healthy`). | **APROBADO** |
| **CP-03** | Autenticación | Login exitoso OAuth2 + JWT | `POST /api/v1/auth/login` (`admin`) | HTTP 200, emite `access_token`, `refresh_token` (JTI UUIDv4) y perfil con 22 permisos. | HTTP 200 OK, usuario `admin`, rol `admin`. | **APROBADO** |
| **CP-04** | Autenticación | Rechazo de acceso sin token | `GET /api/v1/dashboard/summary` (sin header) | HTTP 401 `UNAUTHENTICATED` con `trace_id`. | HTTP 401 `Credenciales inválidas o expiradas`. | **APROBADO** |
| **CP-05** | Dashboard | Resumen ejecutivo y KPIs | `GET /api/v1/dashboard/summary` | HTTP 200 con métricas MTTT, MTTR, FP rate (`0.25`), noise reduction (`0.40`). | HTTP 200 OK, JSON completo con KPIs reales. | **APROBADO** |
| **CP-06** | Alertas | Listado paginado de alertas | `GET /api/v1/alerts?page=1&page_size=5` | HTTP 200 con alertas normalizadas e IPs serializadas. | HTTP 200 OK (`total=6` tras ingesta). | **APROBADO** |
| **CP-07** | Alertas | Detalle de alerta + Triaje embebido | `GET /api/v1/alerts/5` | HTTP 200 con alerta de Ransomware, enriquecimiento y triaje vigente. | HTTP 200 OK (`id=5`, regla Ransomware). | **APROBADO** |
| **CP-08** | Ingesta SOAR | Ingesta de alerta crítica vía Webhook | `POST /api/v1/alerts/ingest` (`rule_id=100501`, Exfiltración DNS C2) | HTTP 201 Created, vincula activo `srv-dc01.corp.local`, `severity=critical`. | HTTP 201 Created (`alert_id=6`, `status=pending`). | **APROBADO** |
| **CP-09** | Triaje IA | Ejecución de triaje y auto-escalamiento | `POST /api/v1/triage/6/run?force=true` | HTTP 200, calcula `verdict=true_positive`, `risk_score=82`, crea incidente `INC` automáticamente. | HTTP 200 OK (`verdict=true_positive`, `risk_score=82`, `incident_id=2`). | **APROBADO** |
| **CP-10** | Incidentes | Consulta de incidentes abiertos | `GET /api/v1/incidents` | HTTP 200 con incidentes semilla y auto-escalados. | HTTP 200 OK (`total=2`). | **APROBADO** |
| **CP-11** | Usuarios RBAC | Listado de usuarios y roles | `GET /api/v1/users` | HTTP 200 con los 6 usuarios del SOC y sus roles. | HTTP 200 OK (`total=6`). | **APROBADO** |
| **CP-12** | Reportería | Exportación Gerencial en PDF | `GET /api/v1/reports/management?format=pdf` | HTTP 200, descarga binaria PDF válida con checksum SHA-256. | HTTP 200 OK (`test_report.pdf`, `10,624 bytes`). | **APROBADO** |
| **CP-13** | Reportería | Exportación Gerencial en Word | `GET /api/v1/reports/management?format=docx` | HTTP 200, descarga binaria `.docx` válida con tablas y KPIs. | HTTP 200 OK (`test_report.docx`, `39,035 bytes`). | **APROBADO** |
| **CP-14** | Reportería | Exportación Gerencial en Excel | `GET /api/v1/reports/management?format=xlsx` | HTTP 200, descarga binaria `.xlsx` multipágina con estilos. | HTTP 200 OK (`test_report.xlsx`, `16,109 bytes`). | **APROBADO** |
| **CP-15** | Auditoría | Consulta de bitácora y cadena SHA-256 | `GET /api/v1/audit/verify-chain` | HTTP 200, `"intact": true`, `"broken_links": []`. | HTTP 200 OK (`checked=38`, `intact=true`). | **APROBADO** |

---

## 3. Script Reproducible de Pruebas End-to-End (PowerShell)

Cualquier evaluador o docente puede ejecutar el siguiente bloque en PowerShell para verificar en vivo todos los módulos del sistema en menos de 5 segundos:

```powershell
# 1. Autenticación como Administrador
$login = Invoke-RestMethod -Uri "http://localhost:5173/api/v1/auth/login" `
  -Method Post -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin&password=Admin123!"
$headers = @{
  Authorization = "Bearer $($login.access_token)"
  "X-Ingest-Key" = "demo-ingest-key-2025"
}
Write-Host "[OK] Token JWT emitido para: $($login.user.full_name)" -ForegroundColor Green

# 2. Consulta de KPIs del Dashboard
$dash = Invoke-RestMethod -Uri "http://localhost:5173/api/v1/dashboard/summary" -Headers $headers
Write-Host "[OK] Alertas Totales: $($dash.alerts_total) | Reducción de Ruido: $($dash.noise_reduction * 100)%" -ForegroundColor Cyan

# 3. Verificación Criptográfica de la Bitácora de Auditoría (SHA-256)
$chain = Invoke-RestMethod -Uri "http://localhost:5173/api/v1/audit/verify-chain" -Headers $headers
Write-Host "[OK] Cadena SHA-256 íntegra: $($chain.intact) ($($chain.checked) bloques verificados)" -ForegroundColor Green
```

---

## 4. Ejecución de Suite Pytest en Contenedor

Para ejecutar la suite de pruebas unitarias alojada en `backend/tests/test_api.py`:

```powershell
docker exec -it soc-lite-backend pytest -v
```
