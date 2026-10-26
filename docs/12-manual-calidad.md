# 12 · Manual de Calidad del Software (SOC-Lite)

## 1. Marco de Referencia de Calidad (ISO/IEC 25010)
El diseño, implementación y validación de **SOC-Lite** se rigen por el estándar internacional **ISO/IEC 25010 (SQuaRE)** para garantizar que el sistema de triaje automatizado cumpla con los atributos de calidad exigidos en un Centro de Operaciones de Seguridad (SOC) moderno.

---

## 2. Evaluación de Atributos de Calidad ISO/IEC 25010

| Característica ISO/IEC 25010 | Subcaracterística | Implementación Técnica en SOC-Lite | Indicador / Umbral Cumplido |
| :--- | :--- | :--- | :--- |
| **1. Adecuación Funcional** | Completitud y Corrección Funcional | Cobertura del 100% del ciclo de vida SOC: Ingesta idempotente $\rightarrow$ Enriquecimiento TI $\rightarrow$ Triaje IA $\rightarrow$ Escalamiento de Incidentes $\rightarrow$ Reportería $\rightarrow$ Auditoría. | **100%** de historias de usuario y contratos REST implementados (8 routers, 19 tablas). |
| **2. Eficiencia de Desempeño** | Comportamiento Temporal y Uso de Recursos | Motor asíncrono no bloqueante (`FastAPI` + `asyncpg` + `SQLAlchemy 2.0 Async`), caché `Redis 7` con TTL de 24h para indicadores de amenaza y bundle SPA comprimido con `gzip`. | Latencia API $< 80\text{ ms}$ (p95); Triaje heurístico $< 150\text{ ms}$; MTTT $< 180\text{ s}$. |
| **3. Compatibilidad** | Interoperabilidad | Contrato nativo para webhooks de **Wazuh SIEM**, **OPNsense**, **Suricata**, flujos **n8n** y exportación estándar en PDF, DOCX, XLSX y CSV. | **100%** compatible con esquemas JSON Wazuh v4.x y MITRE ATT&CK v15. |
| **4. Usabilidad** | Operabilidad, Estética e Inclusión | Interfaz oscura (*Dark Mode SOC*) de bajo cansancio visual con **Tailwind CSS**, estados vacíos/carga/error explícitos, *badges* semánticos de severidad y *responsive design*. | Navegación en $\le 2$ clics hacia cualquier evidencia o triaje. |
| **5. Fiabilidad** | Tolerancia a Fallos y Disponibilidad | **Degradación elegante (Graceful Degradation)**: Si el motor LLM local (`Ollama`) no responde, `langchain-service` conmuta automáticamente al motor heurístico determinista sin perder ni retrasar alertas. | Disponibilidad operativa del pipeline de triaje del **100%** incluso sin GPU/LLM. |
| **6. Seguridad** | Confidencialidad, Integridad, No Repudio | Autenticación OAuth2 + JWT (`HS256`, `jti` UUIDv4), contraseñas `bcrypt` (coste 12), RBAC de 22 permisos, y bitácora inmutable con cadena de hashes **SHA-256**. | **0** vulnerabilidades críticas/altas; cadena SHA-256 100% verificable. |
| **7. Mantenibilidad** | Modularidad, Reusabilidad, Analizabilidad | Separación estricta en capas (`routers` $\rightarrow$ `services` $\rightarrow$ `models` / `schemas`), tipado estático completo (`Python 3.12 Type Hints` + `TypeScript 5.6 Strict`) y contenedorización desacoplada. | Cobertura de contratos tipados al **100%** en Backend y Frontend. |
| **8. Portabilidad** | Adaptabilidad e Instalabilidad | Empaquetado en contenedores multi-etapa (`Docker`) con configuración 100% externalizada en `.env` (12-Factor App). | Despliegue reproducible en Windows, Linux o Cloud en $< 2\text{ minutos}$. |

---

## 3. Estándares de Codificación y Arquitectura Limpia

### 3.1 Backend (`FastAPI` + `Python 3.12`)
- **Tipado Estricto y Validación de Contratos**: Uso de `from __future__ import annotations` y modelos **Pydantic v2** (`ORMModel` con `from_attributes=True`) que previenen inyecciones de datos y garantizan respuestas serializadas consistentes.
- **Inyección de Dependencias Desacoplada**: En [`backend/app/api/deps.py`](file:///c:/Users/Diego/Downloads/tarea%20nose/soc-lite/backend/app/api/deps.py) se encapsulan la sesión de base de datos (`DbSession`), la extracción del usuario autenticado (`CurrentUser`) y los guardias de permisos granulares (`AlertReader`, `AlertWriter`, `TriageRunner`, `AuditReader`).
- **Observabilidad y Logging Estructurado**: Cada evento de aplicación se emite en formato JSON estructurado con marca de tiempo ISO-8601 UTC, nivel, módulo y `trace_id`.

### 3.2 Microservicio de Agente IA (`LangChain` + `LangGraph`)
- **Salidas Estructuradas Garantizadas**: El agente devuelve invariablemente un contrato validado por `TriageResponseSchema` (veredicto, severidad, `risk_score` 0–100, `confidence` 0.0–1.0, resumen ejecutivo, pasos de razonamiento, acciones recomendadas y técnicas MITRE ATT&CK).
- **Explicabilidad (XAI en Ciberseguridad)**: La fórmula de `risk_score` combina pesos transparentes y auditables:
  $$\text{RiskScore} = 0.35 \cdot S_{\text{severidad}} + 0.20 \cdot S_{\text{nivel\_regla}} + 0.20 \cdot S_{\text{criticidad\_activo}} + 0.15 \cdot S_{\text{threat\_intel}} + 0.10 \cdot S_{\text{confianza\_LLM}}$$

### 3.3 Base de Datos Relacional (`PostgreSQL 15`)
- **Integridad Referencial y Restricciones de Dominio**: Uso de `ENUM` nativos de PostgreSQL (`severity_level`, `alert_status`, `triage_verdict`, `audit_action`), restricciones `CHECK` (`risk_score BETWEEN 0 AND 100`) e índices compuestos y parciales (`GIN` sobre `JSONB` y arreglos MITRE).

---

## 4. KPIs de Calidad Operativa del SOC Soportados por la Plataforma

1. **MTTT (Mean Time To Triage)**: Calculado automáticamente en base de datos mediante columna generada $\text{triaged\_at} - \text{occurred\_at}$.
2. **MTTR (Mean Time To Respond)**: Calculado automáticamente al cierre de alertas e incidentes ($\text{closed\_at} - \text{occurred\_at}$).
3. **Tasa de Falsos Positivos y Concordancia Humana (`Human Agreement Rate`)**: Comparación continua entre el veredicto del LLM y la validación del analista humano para detectar deriva del modelo (*Model Drift*).
