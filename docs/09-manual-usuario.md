# 09 · Manual de Usuario (SOC-Lite)

## 1. Introducción
Bienvenido a **SOC-Lite**, la plataforma de **Triaje Automático de Alertas para Centros de Operaciones de Seguridad (SOC)** impulsada por orquestación SOAR (`n8n`), agentes de Inteligencia Artificial (`LangChain` + `LangGraph`) e Inteligencia de Amenazas (`Threat Intelligence`).

Este manual está dirigido a los operadores, analistas, jefes de SOC y auditores que utilizan la interfaz web en su operación diaria.

---

## 2. Acceso al Sistema y Perfiles de Usuario (RBAC)

### 2.1 URL de Acceso
Abra su navegador web e ingrese a:
- **Consola Web SOC-Lite**: `http://localhost:5173` (o `http://localhost:8080`)

### 2.2 Credenciales de Demostración por Rol
El sistema implementa **Control de Acceso Basado en Roles (RBAC)** estricto. Puede iniciar sesión con cualquiera de las siguientes cuentas preconfiguradas para evaluar los distintos niveles de privilegio:

| Usuario | Contraseña | Rol en el Sistema | Alcance Operativo |
| :--- | :--- | :--- | :--- |
| `admin` | `Admin123!` | **Administrador** | Acceso total: usuarios, roles, alertas, triaje, incidentes, reportes y auditoría. |
| `soc_manager` | `Manager123!` | **Jefe de SOC** | Supervisión ejecutiva, KPIs, gestión de incidentes, SLA y descarga de reportes. |
| `analista1` | `Analyst123!` | **Analista SOC N1/N2** | Operación de alertas, ejecución de triaje IA, calificación de falsos positivos e incidentes. |
| `auditor1` | `Audit123!` | **Auditor** | Acceso de solo lectura a la bitácora inmutable, verificación SHA-256 y exportación de evidencias. |
| `visor1` | `Viewer123!` | **Consulta** | Visualización de tableros de control y listado de alertas sin permisos de modificación. |

> **Nota de Seguridad**: Tras **5 intentos fallidos** de inicio de sesión, la cuenta se bloquea automáticamente durante **15 minutos** y se genera una alerta crítica en la bitácora de auditoría.

---

## 3. Recorrido por los Módulos del Sistema

### 3.1 Dashboard Ejecutivo (`/`)
Al iniciar sesión, la vista principal presenta en tiempo real el estado operativo del SOC:
- **Tarjetas KPI Superiores**:
  - **Total de Alertas** y **Alertas Pendientes de Triaje**.
  - **MTTT (Mean Time To Triage)**: Tiempo medio de triaje (meta $< 180\text{ s}$).
  - **MTTR (Mean Time To Respond)**: Tiempo medio de contención/resolución.
  - **Tasa de Falsos Positivos (FP Rate)** y **Reducción de Ruido (%)** lograda por el agente IA.
  - **Incidentes Abiertos / Críticos** y **Cumplimiento de SLA**.
- **Gráficos Interactivos**:
  - Serie temporal de alertas apiladas por severidad (`Critical`, `High`, `Medium`, `Low`, `Info`).
  - Curva de evolución diaria del MTTT promedio y percentil 95 frente a la meta SLA.
  - Distribución de veredictos del motor IA (`True Positive`, `False Positive`, `Benign`, `Suspicious`).
  - Top técnicas MITRE ATT&CK detectadas y carga de trabajo por analista.

### 3.2 Bandeja de Alertas (`/alerts`) y Detalle de Alerta (`/alerts/:id`)
Módulo central de trabajo para el Analista SOC:
1. **Filtros Avanzados**: Filtre por severidad, estado (`pending`, `triaged`, `escalated`, `closed`, `false_positive`), veredicto IA, técnica MITRE ATT&CK o búsqueda libre por dirección IP / hostname.
2. **Inspección de Alerta (`/alerts/:id`)**:
   - Muestra los metadatos normalizados de Wazuh/OPNsense (regla, nivel, IP origen/destino, activo afectado, log original).
   - **Panel de Triaje IA (LangChain/LLM)**: Presenta el veredicto (`true_positive`, `false_positive`, etc.), el **Risk Score (0–100)**, el porcentaje de **Confianza**, el resumen ejecutivo en español, la cadena de razonamiento paso a paso y las **Acciones Recomendadas** priorizadas.
   - **Ejecutar / Re-ejecutar Triaje**: Botón **"Ejecutar Triaje IA"** que invoca en tiempo real al agente LangGraph (`POST /api/v1/triage/{id}/run`).
   - **Retroalimentación Humana (Human-in-the-Loop)**: El analista puede confirmar el veredicto o marcar la alerta como **Falso Positivo**, registrando su comentario para alimentar las métricas de precisión del modelo.
   - **Línea de Tiempo (Timeline)**: Historial cronológico completo desde la ingesta hasta el cierre.

### 3.3 Gestión de Incidentes (`/incidents` y `/incidents/:id`)
Cuando una alerta supera el umbral de riesgo (`risk_score >= 75` o severidad crítica), se escala a un **Incidente de Seguridad**:
- Visualice el código único (ej. `INC-2025-0001`), prioridad (`P1` a `P4`), estado (`open`, `contained`, `eradicated`, `recovered`, `closed`), propietario y alertas vinculadas.
- Registre **Acciones de Respuesta y Contención** (ej. bloqueo de IP en firewall OPNsense, aislamiento de host en Wazuh, reseteo de credenciales).
- Documente el **Impacto**, la **Causa Raíz (Root Cause)** y las **Lecciones Aprendidas** antes del cierre formal.

### 3.4 Estadísticas de Precisión del Triaje IA (`/triage-stats`)
Permite evaluar el desempeño del motor de Inteligencia Artificial:
- Métricas de **Precisión**, ** Acuerdo con el Analista Humano (Human Agreement)**, **Confianza Promedio** y **Latencia en milisegundos**.
- Desglose de uso por modelo (`llama3.1:8b`, `heuristic-fallback`) y herramientas de Threat Intelligence invocadas (`virustotal`, `abuseipdb`, `geoip`).

### 3.5 Centro de Reportes Exportables (`/reports`)
Genere evidencias ejecutivas y técnicas con un solo clic en formatos **PDF**, **Word (`.docx`)**, **Excel (`.xlsx`)** y **CSV**:
1. **Reporte Operativo SOC**: Volumen de alertas, tiempos MTTT/MTTR, desempeño por regla y carga operativa.
2. **Reporte Gerencial y de Cumplimiento**: Resumen ejecutivo para dirección, postura de riesgo, cumplimiento de SLA y mapeo MITRE ATT&CK.
3. **Reporte de Auditoría**: Extracto formal de la bitácora de seguridad con hashes criptográficos SHA-256 de integridad.

### 3.6 Bitácora de Auditoría Inmutable (`/audit`)
Visible para Administradores y Auditores:
- Registra **toda acción** realizada en el sistema (inicios de sesión exitosos/fallidos, lecturas sensibles, cambios de estado, ejecuciones de triaje, exportaciones de reportes y cambios de permisos).
- Incluye botón **"Verificar Cadena SHA-256"**, el cual comprueba matemáticamente que ningún registro histórico ha sido modificado o eliminado desde su creación.
- Al hacer clic en un evento, muestra el **Diff Antes / Después (`before` / `after`)** en formato JSON.

### 3.7 Administración de Usuarios (`/users`) y Roles (`/roles`)
Exclusivo para Administradores:
- Creación y edición de cuentas de usuario, activación/desactivación, desbloqueo de cuentas y reseteo de contraseñas.
- Asignación granular de los **22 permisos del sistema** agrupados por módulo (`alerts`, `triage`, `incidents`, `dashboard`, `reports`, `audit`, `users`, `roles`).
