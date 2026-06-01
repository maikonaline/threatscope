# PROJECT STATE — ThreatScope
**Ultima actualizacion:** 2026-06-01
**Confianza del estado:** ALTA

---

## PRODUCT

- **Nombre:** ThreatScope — Sistema de deteccion de amenazas
- **Proposito:** Demo tecnica para entrevista de trabajo (puesto junior ciberseguridad)
- **Que resuelve:** Deteccion automatica de amenazas de red usando ML (Isolation Forest), enriquecimiento de IPs con reputacion real (AbuseIPDB), mapeo a framework MITRE ATT&CK, y notificacion a herramientas SIEM/SOC (Slack, Splunk, Sentinel, Teams)
- **Usuario objetivo:** Evaluadores tecnicos en entrevista de ciberseguridad

---

## STACK

- **Backend:** Python 3.11, FastAPI, Isolation Forest (scikit-learn), AbuseIPDB API, SHAP
- **Frontend:** HTML/CSS/JS vanilla (dashboard.html — sin framework)
- **Deploy backend:** Render.com (free tier) — https://threatscope-uoza.onrender.com
- **Deploy frontend:** Vercel — https://threatscope-three.vercel.app
- **Repositorio:** https://github.com/maikonaline/threatscope (rama: master)
- **Base de datos:** SQLite local (via database.py)

---

## ARCHITECTURE

- **pipeline.py** — orquesta el flujo: CSV entrada -> validacion IP -> analyzer -> threat_intel -> notifier
- **analyzer.py** — Isolation Forest entrenado con baseline sintetico (500 muestras normales); SHAP para feature importance real; joblib para persistencia
- **threat_intel.py** — enriquecimiento AbuseIPDB + 17 tecnicas MITRE ATT&CK con subtecnicas
- **notifier.py** — alertas multi-canal via webhooks (Slack, Splunk HEC, Azure Sentinel, Teams)
- **api.py** — FastAPI: /analyze, /status, /detections, /integrations/test, /integrations/status; autenticacion API key opcional; CORS restrictivo; pipeline async
- **config.py** — settings centralizados: API_KEY, ALLOWED_ORIGINS, MAX_UPLOAD_BYTES, DASHBOARD_URL
- **main.py, logger.py, database.py** — infraestructura base

---

## COMPLETED

- [x] Backend Python completo: config, logger, database, analyzer, threat_intel, pipeline, main
- [x] API FastAPI con todos los endpoints + Swagger automatico
- [x] notifier.py: Slack (activo produccion), Splunk HEC, Azure Sentinel, Teams (codigo listo)
- [x] dashboard.html — panel de monitoreo con metricas, upload CSV, tabla detecciones, estado integraciones
- [x] Datos de demo en D:\Desktop\examples:
  - ataque_fuerza_bruta.csv — IP Tor 185.220.101.5, 537 intentos de login → CRITICO
  - escaneo_puertos.csv — Shodan 80.82.77.33, 74 puertos → ALTO
  - exfiltracion_datos.csv — 1.8GB a las 3am → ALTO
- [x] Git con commits semanticos; push a GitHub
- [x] Deploy en Render.com — API online
- [x] Deploy en Vercel — dashboard accesible
- [x] Slides de presentacion con Reveal.js (https://threatscope-three.vercel.app/slides)
- [x] **Sesion 01/06/2026 — mejoras de seguridad y calidad (commit 6ed58dd):**
  - API key auth (X-API-Key header, deshabilitada = modo demo abierto)
  - CORS restrictivo (ALLOWED_ORIGINS desde env var)
  - Limite upload 10MB (MAX_UPLOAD_BYTES)
  - Pipeline async con run_in_executor (no bloquea event loop)
  - HTTPException no capturada por except generico
  - ML: baseline sintetico 500 muestras (elimina auto-fit que entrenaba con sus propios datos)
  - ML: SHAP para feature importance real (con fallback uniforme si shap no instalado)
  - ML: joblib en lugar de pickle (mas seguro para sklearn)
  - Validacion IP con ipaddress antes de AbuseIPDB (previene SSRF)
  - MITRE_DB: 5 → 17 tecnicas con subtecnicas granulares
  - database.py: IPv6 (String 45), datetime timezone-naive para SQLite, session.merge() en save_batch
  - notifier.py: DASHBOARD_URL desde config (corrige URL incorrecta)
  - Tests: 38 → 48 tests; TestNotifier completa (7 tests)

---

## IN PROGRESS

- Configurar variables de entorno en Render.com para activar integraciones reales

---

## BACKLOG

**INMEDIATO — necesario para el demo:**

1. **Variables de entorno en Render** (dashboard.render.com → threatscope → Environment):
   - `ALLOWED_ORIGINS` = `https://threatscope-three.vercel.app`
   - `DASHBOARD_URL` = `https://threatscope-three.vercel.app`
   - `ABUSEIPDB_API_KEY` = (key de abuseipdb.com — gratis, 1000 req/dia)
   - `SLACK_WEBHOOK_URL` = (webhook de Slack)
   - `THREATSCOPE_API_KEY` = (dejar vacio = modo demo abierto)

2. **Prueba del flujo completo tras deploy:**
   - Abrir https://threatscope-three.vercel.app
   - Subir D:\Desktop\examples\ataque_fuerza_bruta.csv
   - Verificar alerta en canal Slack
   - Verificar panel integraciones muestra Slack como "Activo"

3. **Instalar shap en el entorno de Render:**
   - Ya esta en requirements.txt — Render lo instalara en el proximo deploy automaticamente

**FUTURO — mejoras opcionales:**

- Endpoint GET /batches — listar historico de analisis
- Endpoint GET /detections/export — exportar CSV/JSON
- Deduplicacion de IPs entre batches
- Grafico de timeline de detecciones en dashboard
- Reentrenamiento periodico del modelo con nuevas detecciones almacenadas
- Reemplazar CSV manual por conector a logs de servidor (Nginx/Apache/Filebeat)
- Streaming con Kafka para ingesta en tiempo real
- Accion automatica de bloqueo de IP via firewall API
- Integracion misobras -> ThreatScope (misobras_connector.py listo, falta SERVICE_ROLE_KEY Supabase)
- Configurar Splunk trial para demo enterprise
- Configurar Microsoft Sentinel (Azure trial) para demo corporativo

---

## RISKS

- 🟡 MEDIO — Render.com free tier: cold start ~30s si no recibe trafico. Calentar antes de la demo.
- 🟡 MEDIO — AbuseIPDB sin configurar en Render: detecciones funcionan pero sin enriquecimiento real de IP.
- 🟡 MEDIO — shap no instalado en Render hasta proximo deploy: feature importance devuelve distribucion uniforme como fallback (no crashea).
- 🔵 BAJO — SQLite en Render: se resetea en cada deploy. Datos de demo se pierden. Para produccion real: PostgreSQL.
- 🔵 BAJO — Integraciones Splunk/Sentinel sin configurar: no afectan demo basico con Slack.

---

## TECH DECISIONS

| Decision | Elegida | Alternativa | Razon |
|----------|---------|-------------|-------|
| ML algorithm | Isolation Forest | LSTM, Autoencoder | No supervisado, no necesita datos etiquetados |
| ML baseline | Sintetico 500 muestras | Auto-fit con batch | Auto-fit es incorrecto: entrena con sus propios datos de prediccion |
| Feature importance | SHAP TreeExplainer | Uniform placeholder | SHAP da valores reales interpretables para la entrevista |
| Serialización modelo | joblib | pickle | pickle permite ejecucion de codigo arbitrario; joblib es estandar sklearn |
| IP validation | ipaddress stdlib | regex | ipaddress valida IPv4 e IPv6 correctamente; regex no |
| API auth | X-API-Key header | OAuth2, JWT | Simple, stateless, facil de explicar; deshabilitado por defecto para demo |
| Backend | FastAPI | Flask, Django | Async nativo, OpenAPI automatico, performance superior |
| Deploy backend | Render.com | Railway, Fly.io | Free tier con HTTPS, facil configuracion env vars |
| Deploy frontend | Vercel | Netlify, GitHub Pages | Zero-config para HTML estatico |
| Frontend | HTML vanilla | React, Vue | Sin overhead de build para un dashboard de demo |
| SIEM alerts | Webhooks HTTP | SDK nativos | Universalmente soportado, sin dependencias pesadas |

---

## OPEN PROBLEMS

- Ninguno critico. Sistema funcional end-to-end con 48 tests pasando.
- Activacion de AbuseIPDB y Slack depende de configurar env vars en Render.

---

## PARA LA ENTREVISTA — speech preparado

1. **Sobre el modelo ML:**
   "ThreatScope usa Isolation Forest, un algoritmo no supervisado. No necesita datos etiquetados. Aprende la normalidad del trafico desde un baseline sintetico de 500 muestras, y aísla automaticamente los eventos que se alejan de ese patron. Los ataques son anomalias por naturaleza."

2. **Sobre la decision de baseline sintetico:**
   "Una trampa clasica con Isolation Forest es entrenar con los mismos datos que vas a predecir. Si el primer batch tiene solo ataques, el modelo aprende que los ataques son normales. El baseline sintetico resuelve esto: el modelo ya sabe lo que es trafico normal antes de ver el primer CSV real."

3. **Sobre SHAP:**
   "Para explicar las predicciones del modelo uso SHAP — SHapley Additive exPlanations. Mide cuanto contribuye cada feature a la decision del modelo usando teoria de juegos. Esto es clave en ciberseguridad: no basta detectar, hay que poder justificar por que una IP es sospechosa."

4. **Sobre AbuseIPDB:**
   "La integracion con AbuseIPDB enriquece cada IP con reputacion real — score 0-100 y historial de reportes de la comunidad global. Reduce falsos positivos: si una IP ya tiene 800 reportes en el mundo, la confianza en la deteccion sube automaticamente."

5. **Sobre MITRE ATT&CK:**
   "El sistema mapea cada patron de ataque al framework MITRE ATT&CK — el estandar de la industria para clasificar tecnicas y tacticas. Permite hablar el mismo lenguaje que los equipos de SOC y threat intelligence. Tenemos 17 tecnicas mapeadas incluyendo subtecnicas como T1110.001 (Password Guessing) vs T1110.003 (Password Spraying)."

6. **Sobre las integraciones:**
   "Las alertas van via webhooks. Cada SIEM expone una URL de entrada con su propio formato: Slack usa Block Kit, Splunk usa HEC con sourcetype, Sentinel usa la Azure Monitor Data Collector API con firma HMAC-SHA256. notifier.py abstrae esas diferencias y dispara todos los canales en paralelo via threading."

7. **Sobre seguridad de la propia API:**
   "El sistema de deteccion de amenazas tambien tiene que ser seguro. Implementamos: API key opcional para autenticacion, CORS restrictivo (solo el dominio del dashboard), validacion de IP antes de llamar a AbuseIPDB para prevenir SSRF, limite de 10MB en uploads, y pipeline async para no bloquear el servidor."

8. **Sobre la ruta a produccion real:**
   "Para produccion: reemplazar CSV manual por Filebeat o Logstash conectado a logs de servidor. Kafka para manejar volumen. PostgreSQL en lugar de SQLite. Reentrenamiento continuo del modelo con las detecciones almacenadas. Y accion automatica de bloqueo de IP via firewall API cuando la confianza supera un umbral."

---

## NEXT BEST ACTION

Configurar variables de entorno en Render.com para activar AbuseIPDB y Slack, luego probar el flujo completo con ataque_fuerza_bruta.csv desde el dashboard.

---

## CHANGELOG

| Fecha | Cambio |
|-------|--------|
| 2026-05-30 | Estado inicial. Sistema completo y deployado. Pendiente: configurar API keys en Render. |
| 2026-06-01 | Mejoras de seguridad y calidad: API key auth, CORS, upload limit, async pipeline, ML baseline sintetico, SHAP, joblib, validacion IP, 17 tecnicas MITRE, 48 tests. Commit 6ed58dd pusheado a GitHub. |
