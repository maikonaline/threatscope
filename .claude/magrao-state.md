# PROJECT STATE — ThreatScope
**Ultima actualizacion:** 2026-05-30
**Confianza del estado:** ALTA (cargado manualmente por el usuario)

---

## PRODUCT

- **Nombre:** ThreatScope — Sistema de deteccion de amenazas
- **Proposito:** Demo tecnica para entrevista de trabajo (puesto junior ciberseguridad)
- **Que resuelve:** Deteccion automatica de amenazas de red usando ML (Isolation Forest), enriquecimiento de IPs con reputacion real (AbuseIPDB), mapeo a framework MITRE ATT&CK, y notificacion a herramientas SIEM/SOC (Slack, Splunk, Sentinel, Teams)
- **Usuario objetivo:** Evaluadores tecnicos en entrevista de ciberseguridad

---

## STACK

- **Backend:** Python, FastAPI, Isolation Forest (scikit-learn), AbuseIPDB API
- **Frontend:** HTML/CSS/JS vanilla (dashboard.html — sin framework)
- **Deploy backend:** Render.com (free tier) — https://threatscope-uoza.onrender.com
- **Deploy frontend:** Vercel — https://threatscope.vercel.app
- **Repositorio:** https://github.com/maikonaline/threatscope (rama: master)
- **Base de datos:** SQLite local (via database.py)

---

## ARCHITECTURE

- **pipeline.py** — orquesta el flujo: CSV entrada -> analyzer -> threat_intel -> notifier
- **analyzer.py** — Isolation Forest para deteccion de anomalias (ML no supervisado, sin datos etiquetados)
- **threat_intel.py** — enriquecimiento de IPs via AbuseIPDB (score 0-100, reportes historicos)
- **notifier.py** — envio de alertas a multiples destinos via webhooks (POST a URL de entrada de cada herramienta)
- **api.py** — FastAPI: endpoints /analyze, /status, /detections, /integrations/test, /integrations/status
- **main.py** — entrypoint
- **config.py, logger.py, database.py** — infraestructura base
- **dashboard.html** — SPA con: metricas en tiempo real, upload CSV, tabla de detecciones, panel de estado de integraciones

---

## COMPLETED

- [x] Backend Python completo: config, logger, database, analyzer, threat_intel, pipeline, main
- [x] API FastAPI con todos los endpoints necesarios para el demo
- [x] notifier.py con soporte para Slack, Splunk HEC, Microsoft Sentinel, Microsoft Teams
- [x] dashboard.html — panel de monitoreo completo y funcional
- [x] Datos de demo en examples/:
  - ataque_fuerza_bruta.csv — IP Tor 185.220.101.5, 537 intentos de login
  - escaneo_puertos.csv — Shodan scanner 80.82.77.33, 74 puertos escaneados
  - exfiltracion_datos.csv — 1.8GB descargados a las 3am
- [x] Git inicializado con 6+ commits semanticos
- [x] Deploy en Render.com — API online y respondiendo
- [x] Deploy en Vercel — dashboard accesible y funcional
- [x] AbuseIPDB integrado en threat_intel.py (variable ABUSEIPDB_API_KEY lista, falta configurar en Render)
- [x] misobras_connector.py — script de integracion Supabase misobras -> ThreatScope (pausado)

---

## IN PROGRESS

- Configuracion de variables de entorno en Render para activar integraciones reales
- Verificacion de flujo completo: CSV -> deteccion -> alerta Slack

---

## BACKLOG

**INMEDIATO — necesario para el demo:**

1. **AbuseIPDB API key** (gratis, 1000 req/dia):
   - Registrarse en: https://abuseipdb.com/register
   - Obtener key: Dashboard -> API -> Create Key
   - Configurar en Render: dashboard.render.com -> threatscope -> Environment -> ABUSEIPDB_API_KEY

2. **Slack webhook** (para demo de alertas en tiempo real):
   - Crear workspace gratis: https://slack.com (Get started for free)
   - Nombre sugerido: "ThreatScope Security"
   - Crear canal: #alertas-seguridad
   - Crear webhook: https://api.slack.com/apps -> Create New App -> Incoming Webhooks -> Add New Webhook -> elegir canal -> copiar URL
   - Configurar en Render: Environment -> SLACK_WEBHOOK_URL

3. **Prueba del flujo completo:**
   - Abrir https://threatscope.vercel.app
   - Subir examples/ataque_fuerza_bruta.csv
   - Verificar que llega alerta al canal de Slack
   - Verificar que el panel de integraciones muestra Slack como "Activo"

**FUTURO — mejoras opcionales:**

- Integracion misobras -> ThreatScope: script listo en misobras_connector.py, falta SERVICE_ROLE_KEY de Supabase misobras
- Configurar Splunk trial (https://splunk.com) para demo enterprise
- Configurar Microsoft Sentinel (Azure trial) para demo corporativo
- Agregar grafico de timeline de detecciones en dashboard
- Reentrenamiento periodico del modelo ML con nuevas detecciones
- Reemplazar CSV manual por conector a logs de servidor (Nginx/Apache)
- Streaming con Kafka para ingesta en tiempo real
- Accion automatica de bloqueo de IP ante deteccion critica

---

## RISKS

- 🟡 MEDIO — Render.com free tier: la API tiene cold start (~30s) si no recibe trafico. En entrevista, hacer una peticion previa para "calentar" el servicio antes de la demo.
- 🟡 MEDIO — AbuseIPDB sin configurar: las detecciones funcionan, pero el enriquecimiento de IP no se ejecuta hasta configurar la API key en Render.
- 🔵 BAJO — misobras_connector.py pausado: no bloquea el demo, es una mejora futura.
- 🔵 BAJO — Integraciones Splunk/Sentinel sin configurar: solo afectan el demo avanzado, no el flujo basico con Slack.

---

## TECH DECISIONS

| Decision | Elegida | Alternativa | Razon |
|----------|---------|-------------|-------|
| ML algorithm | Isolation Forest | LSTM, Autoencoder | No supervisado, no necesita datos etiquetados, ideal para demo con datos sinteticos |
| Backend | FastAPI | Flask, Django | Async nativo, OpenAPI automatico, performance superior |
| Deploy backend | Render.com | Railway, Fly.io | Free tier con dominio HTTPS, facil configuracion de env vars |
| Deploy frontend | Vercel | Netlify, GitHub Pages | Zero-config para HTML estatico, deploy instantaneo |
| Frontend | HTML vanilla | React, Vue | Sin overhead de build para un dashboard de demo |
| SIEM alerts | Webhooks HTTP | SDK nativos | Universalmente soportado, sin dependencias pesadas, facil de explicar en entrevista |

---

## OPEN PROBLEMS

- Ninguno critico. El sistema es funcional end-to-end.
- La activacion de AbuseIPDB y Slack depende de acciones del usuario (registro externo).

---

## PARA LA ENTREVISTA — speech preparado

El usuario debe poder explicar con sus propias palabras:

1. **Sobre el modelo ML:**
   "ThreatScope usa Isolation Forest, un algoritmo de ML no supervisado. No necesita datos etiquetados como 'esto es un ataque / esto es normal'. En cambio, aprende el comportamiento tipico del trafico y aísla automaticamente los puntos que se alejan de ese patron. Los ataques son, por naturaleza, anomalias."

2. **Sobre AbuseIPDB:**
   "La integracion con AbuseIPDB enriquece cada IP detectada con reputacion real — un score de 0 a 100 y el historial de reportes de la comunidad. Esto reduce falsos positivos: si la IP ya tiene 800 reportes de otros sistemas en el mundo, la confianza en la deteccion sube automaticamente."

3. **Sobre MITRE ATT&CK:**
   "El sistema mapea cada tipo de ataque al framework MITRE ATT&CK, que es el estandar de la industria para clasificar tecnicas y tacticas de ataque. Esto permite hablar el mismo lenguaje que los equipos de SOC y threat intelligence."

4. **Sobre las integraciones (Slack/Splunk/Sentinel):**
   "Las integraciones funcionan via webhooks. Cada herramienta expone una URL de entrada. Cuando ThreatScope detecta algo critico, hace un POST a esa URL con el payload formateado para cada sistema. Slack, Splunk HEC y Sentinel tienen formatos distintos — notifier.py abstrae esa diferencia."

5. **Sobre la ruta a produccion real:**
   "Para pasar de demo a produccion: reemplazar el upload CSV manual por un conector a logs de servidor en tiempo real (Nginx, Apache, o un agente como Filebeat). Agregar una cola de mensajes como Kafka para manejar volumen. Y agregar accion automatica de bloqueo de IP via firewall API cuando la confianza supera un umbral."

---

## NEXT BEST ACTION

Configurar ABUSEIPDB_API_KEY en Render.com (es gratis y tarda 5 minutos). Esto activa el enriquecimiento de IP y hace el demo significativamente mas impresionante para la entrevista.

---

## CHANGELOG

| Fecha | Cambio |
|-------|--------|
| 2026-05-30 | Estado inicial guardado. Sistema completo y deployado. Pendiente: configurar API keys en Render. |
