# ThreatScope — Dosier de Presentación para Entrevista
## Junior Cybersecurity Engineer

---

## LINKS DEL PROYECTO

| Recurso | URL |
|---|---|
| Dashboard en producción | https://threatscope-three.vercel.app |
| API (backend) | https://threatscope-uoza.onrender.com |
| Documentación API (Swagger) | https://threatscope-uoza.onrender.com/docs |
| Repositorio GitHub | https://github.com/maikonaline/threatscope |

---

## 1. RESUMEN EJECUTIVO

**ThreatScope es un sistema de detección de amenazas en tiempo real para tráfico de red.**

Analiza logs de actividad (intentos de login, bytes transferidos, puertos escaneados, hora del evento) usando Machine Learning no supervisado para identificar comportamiento anómalo, enriquece cada amenaza con inteligencia de reputación real de IPs (AbuseIPDB), mapea los patrones a técnicas del framework MITRE ATT&CK, y envía alertas automáticas a Slack en tiempo real.

**El sistema está desplegado y funcionando en producción**, con backend en Render.com, frontend en Vercel, y código abierto en GitHub.

**Resultado demostrable en la entrevista:** subir el CSV `ataque_fuerza_bruta.csv` al dashboard, esperar 5-10 segundos, y el sistema detecta la IP `185.220.101.5` (nodo Tor real, con reputación 100/100 en AbuseIPDB) como CRÍTICO, mapea las técnicas T1110 (Brute Force) y T1078 (Valid Accounts), y envía la alerta a Slack automáticamente — todo sin intervención manual.

**Tecnologías principales:** Python 3.11, FastAPI, scikit-learn (Isolation Forest), AbuseIPDB, MITRE ATT&CK, HTML/CSS/JS vanilla, Docker, pytest (38 tests, 100% pasando), Render.com, Vercel.

---

## 2. EL PROBLEMA REAL

### Por qué las empresas necesitan esto

Una empresa mediana genera miles de eventos de red por hora: intentos de acceso, transferencias de datos, conexiones a distintos puertos. Nadie puede revisar esos logs manualmente.

**Los ataques ocurren cuando nadie mira:**
- Un atacante intenta 537 veces hacer login a las 3 de la madrugada. Sin automatización, nadie lo ve hasta el día siguiente — cuando ya es tarde.
- Un nodo Tor (IP 185.220.101.5) hace 531 intentos de login fallidos en una hora. El firewall no lo bloquea porque el tráfico parece "normal" en volumen, solo es anómalo en patrón.
- Un servidor interno descarga 1.85 GB en un horario inusual. Podría ser exfiltración de datos — o podría ser un backup legítimo. Sin contexto de reputación, es imposible saberlo.

**El gap que ThreatScope cubre:**

| Problema real | Lo que hace ThreatScope |
|---|---|
| Logs no monitoreados 24/7 | Análisis automatizado de cada batch de eventos |
| Ataques de fuerza bruta pasan desapercibidos | Isolation Forest detecta patrones de login anómalos |
| No se sabe si una IP es conocida maliciosa | AbuseIPDB proporciona reputación real (0-100) con historial |
| Alertas llegan tarde (email al día siguiente) | Slack en tiempo real cuando el análisis termina |
| Analista SOC no sabe qué técnica está usando el atacante | MITRE ATT&CK mapea el comportamiento a técnicas documentadas |
| Falsos positivos desperdician tiempo del analista | Score combinado ML + reputación reduce alertas irrelevantes |

---

## 3. CÓMO FUNCIONA — FLUJO COMPLETO

### Paso a paso (versión no técnica)

1. **Entrada:** Se sube un CSV con los logs de tráfico de red (quién se conectó, cuántas veces intentó hacer login, cuántos datos descargó, a qué horas, desde qué IP).

2. **Detección ML:** El sistema tiene un modelo de Machine Learning que aprendió cómo es el tráfico "normal" en esa red. Cuando una IP hace algo que se sale de ese patrón (demasiados intentos de login, demasiados puertos distintos, actividad a las 3am), el modelo la marca como anómala.

3. **Verificación externa:** Para cada IP anómala, el sistema consulta AbuseIPDB — una base de datos global donde la comunidad de seguridad reporta IPs maliciosas. Si esa IP ya tiene historial de ataques, el nivel de riesgo sube automáticamente.

4. **Clasificación MITRE:** El sistema cruza el comportamiento observado con el framework MITRE ATT&CK — la enciclopedia de técnicas que usan los atacantes reales. Si hay 531 fallos de login, eso es T1110 (Brute Force). Si hay escaneo de 74 puertos, es T1046 (Network Service Scanning).

5. **Clasificación de riesgo:** Combina el score del ML con la reputación para decidir el nivel: CRÍTICO / ALTO / MEDIO / BAJO.

6. **Alerta:** Si el nivel es CRÍTICO o ALTO, el sistema envía inmediatamente un mensaje a Slack con todos los detalles. Sin intervención humana.

7. **Dashboard:** Todo queda visible en tiempo real en el dashboard web, con auto-refresh cada 30 segundos.

### Diagrama del flujo de datos (versión técnica)

```
CSV de tráfico de red
(ip, intentos_login, fallos_login, bytes_descargados, horas_actividad, puertos_distintos)
         |
         v
POST /analyze  (FastAPI — api.py)
         |
         v
pipeline.py  [ORQUESTADOR]
    |
    |--- 1. Ingesta y validación de columnas
    |
    |--- 2. analyzer.py  [MOTOR ML]
    |         IsolationForest.fit() en el batch actual
    |         IsolationForest.decision_function() → score_anomalia (más negativo = más raro)
    |         IsolationForest.predict() → -1 (anomalia) o 1 (normal)
    |         Solo las filas con es_anomalia=True pasan a la siguiente fase
    |
    |--- 3. threat_intel.py  [ENRIQUECIMIENTO] — por cada IP anómala:
    |         _query_abuseipdb() → reputación real 0-100 + reportes históricos
    |         map_mitre() → técnicas MITRE según comportamiento observado
    |         evaluate_threat_level() → score_combinado = (|anomaly_score| × 200) + reputation_score
    |             > 110 → CRITICO
    |             > 70  → ALTO
    |             > 40  → MEDIO
    |             ≤ 40  → BAJO
    |
    |--- 4. database.py  [PERSISTENCIA]
    |         SQLAlchemy ORM → tabla detections + tabla analysis_batches
    |         SQLite en desarrollo / PostgreSQL en producción
    |
    |--- 5. notifier.py  [ALERTAS]  — solo para CRITICO y ALTO
              Slack webhook → #alertas-seguridad
              (código listo para: Splunk HEC, Microsoft Sentinel, Teams)
              Diseño: fallo silencioso — nunca crashea el pipeline principal
         |
         v
Dashboard HTML/JS vanilla
    Auto-refresh cada 30s via GET /detections
    Gráficos Chart.js: distribución de riesgos, línea temporal, tabla de IPs
```

---

## 4. STACK TECNOLÓGICO — CADA HERRAMIENTA Y POR QUÉ

### Backend

| Tecnología | Versión | Función | Por qué se eligió |
|---|---|---|---|
| **Python** | 3.11 | Lenguaje principal | Ecosistema de datos y ML sin rival; estándar en ciberseguridad para scripting y análisis |
| **FastAPI** | última | API REST + Swagger automático | Async nativo, validación automática con Pydantic, documentación Swagger generada sola; más rápido que Flask para APIs |
| **scikit-learn** | última | Isolation Forest (ML) | Librería de referencia para ML en Python; IsolationForest bien implementada y estable |
| **pandas** | última | Procesamiento de CSV y DataFrames | Estándar para manipulación de datos tabulares; lectura, validación y transformación del CSV en una línea |
| **SQLAlchemy** | última | ORM para base de datos | Agnóstico a BD (SQLite en dev, PostgreSQL en prod) sin cambiar una línea de código; previene SQL injection por diseño |
| **SQLite** | 3.x | Base de datos (desarrollo) | Sin configuración, archivo local; suficiente para demo y desarrollo |
| **requests** | última | Llamadas HTTP a AbuseIPDB | Librería HTTP estándar de Python |
| **pytest** | última | Suite de 38 tests | Framework de tests más popular en Python; fixtures, mocks, cobertura |

### ML

| Componente | Detalle |
|---|---|
| **Algoritmo** | Isolation Forest (no supervisado) |
| **Features** | intentos_login, fallos_login, bytes_descargados, horas_actividad, puertos_distintos |
| **Parámetro contamination** | 0.05 (espera ~5% de datos anómalos en el batch) |
| **n_estimators** | 100 árboles de aislamiento |
| **Persistencia del modelo** | pickle a disco, se recarga automáticamente en cada arranque |

### Inteligencia de Amenazas

| Servicio | Función | Estado |
|---|---|---|
| **AbuseIPDB** | Reputación real de IPs (0-100), reportes históricos de la comunidad, país | Activo en producción |
| **ipwho.is** | Geolocalización, ISP, org — fallback si AbuseIPDB no responde | Activo (fallback) |
| **MITRE ATT&CK** | Base de conocimiento de técnicas de atacantes: T1110, T1046, T1041, T1078, T1090.003 | Implementado localmente |

### Frontend

| Tecnología | Función | Por qué sin frameworks |
|---|---|---|
| **HTML5 + CSS3 + JS vanilla** | Dashboard con gráficos y tabla de detecciones | Cero dependencias, carga instantánea, deployable como archivo estático en Vercel |
| **Chart.js** | Gráficos de distribución de riesgo y línea temporal | Librería ligera, sin npm, via CDN |

### DevOps e Infraestructura

| Herramienta | Función |
|---|---|
| **Docker** | Containerización del backend; Dockerfile incluido en el repo |
| **Render.com** | Deploy del backend Python (render.yaml en repo para deploy automático) |
| **Vercel** | Deploy del frontend estático (vercel.json en repo) |
| **Git + GitHub** | Control de versiones, historial de 10 commits documentados |

---

## 5. ARQUITECTURA DEL SISTEMA

### Módulos y responsabilidades

```
threatscope/
├── config.py           → Configuración centralizada via env vars. Cero hardcoding.
├── logger.py           → Logging estructurado con rotación (10MB, 5 backups).
├── database.py         → ORM SQLAlchemy. Tablas: detections, analysis_batches.
├── analyzer.py         → Motor ML. IsolationForest: train(), predict(), auto-fit.
├── threat_intel.py     → AbuseIPDB + ipwho.is + MITRE ATT&CK mapping.
├── pipeline.py         → Orquestador end-to-end de los 5 pasos.
├── notifier.py         → Slack / Splunk HEC / Sentinel / Teams. Fallo silencioso.
├── api.py              → FastAPI: POST /analyze, GET /detections, GET /status.
├── main.py             → CLI: analyze --csv, stats, health.
├── tests.py            → 38 tests: unit + integración + end-to-end.
├── Dockerfile          → Containerización lista para producción.
├── render.yaml         → Deploy automático en Render.com.
├── vercel.json         → Sirve dashboard.html como sitio estático.
└── dashboard.html      → Dashboard web con auto-refresh cada 30s.
```

### Modelo de datos

```
Tabla: detections
─────────────────────────────────────────────────────────────
id               INTEGER   PK autoincrement
ip               STRING    IP analizada (indexada para búsquedas rápidas)
risk_level       STRING    CRITICO | ALTO | MEDIO | BAJO
anomaly_score    FLOAT     Score ML (-0.5 a 0.5; más negativo = más anómalo)
reputation_score FLOAT     Reputación AbuseIPDB (0-100)
is_known_malicious BOOL    True si aparece en bases de datos de IPs maliciosas
country          STRING    País de origen (ISO 3166-1, ej: "DE", "RU")
isp              STRING    Proveedor de internet de la IP
mitre_techniques STRING    JSON: ["T1110", "T1046"]
summary          STRING    Descripción en lenguaje natural + acción recomendada
batch_id         STRING    UUID del lote de análisis (indexado)
created_at       DATETIME  Timestamp UTC (indexado)

Tabla: analysis_batches
─────────────────────────────────────────────────────────────
id               STRING    UUID (PK)
source           STRING    csv | postgresql | api
total_events     INTEGER   Eventos procesados en el batch
anomalies_found  INTEGER   Anomalías detectadas
duration_seconds FLOAT     Tiempo de ejecución
status           STRING    pending | running | completed | failed
error_message    STRING    Detalle si status=failed
created_at       DATETIME  Inicio del batch
completed_at     DATETIME  Fin del batch
```

### Cómo se calcula el score de riesgo (decisión de arquitectura clave)

```
score_combinado = (|anomaly_score| × 200) + reputation_score

Ejemplo con 185.220.101.5:
  anomaly_score   = -0.45  →  |−0.45| × 200 = 90  (comportamiento muy anómalo)
  reputation_score = 100   →  +100 (AbuseIPDB: Tor exit node conocido)
  score_combinado  = 190   →  CRITICO (umbral: > 110)

Por qué combinar dos señales:
  - ML solo: puede dar falsos positivos (tráfico inusual pero legítimo)
  - Reputación sola: solo detecta amenazas conocidas (pierde zero-days)
  - Combinado: tráfico anómalo de IP maliciosa conocida = prioridad máxima sin discusión
```

---

## 6. GUÍA DE DEMO EN LA ENTREVISTA

### Preparación (antes de entrar)

- Tener abiertos en pestañas: dashboard, Swagger, GitHub
- Tener preparado el CSV `ataque_fuerza_bruta.csv` en el escritorio
- Verificar que el backend responde: https://threatscope-uoza.onrender.com/docs
  - **Nota:** Render.com pone el servicio en sleep si no hay actividad. Si la primera llamada tarda 30-60 segundos, es normal — Render está arrancando el contenedor. Decirle al entrevistador "el backend está en plan gratuito, el cold start puede tardar un momento".

### Secuencia de demo — 10 minutos

**Minuto 1-2: Contexto**
> "ThreatScope detecta amenazas en tráfico de red en tiempo real. Combina Machine Learning con inteligencia de reputación real de IPs y mapeo MITRE ATT&CK. Está desplegado y funcionando ahora mismo."

Abrir el dashboard: https://threatscope-three.vercel.app
Mostrar la tabla de detecciones si hay datos. Explicar las columnas: IP, nivel de riesgo, score ML, reputación, técnicas MITRE.

**Minuto 3-4: El escenario de ataque**
> "Voy a analizar un CSV que simula un ataque de fuerza bruta real. La IP 185.220.101.5 es un nodo Tor real — si la buscas en AbuseIPDB ahora mismo, tiene 100/100 de puntuación."

Abrir Swagger: https://threatscope-uoza.onrender.com/docs
Buscar el endpoint `POST /analyze`

**Minuto 5-6: Ejecutar el análisis**
Hacer el upload del CSV en Swagger (o desde el dashboard si el UI lo permite).
Mientras procesa:
> "El pipeline primero valida las columnas del CSV. Luego Isolation Forest analiza el comportamiento de cada IP contra el patrón del batch. Las IPs anómalas se enriquecen con AbuseIPDB — estamos haciendo una llamada real a su API ahora mismo."

**Minuto 7-8: Mostrar el resultado**
Resultado esperado:
```
IP: 185.220.101.5
Nivel: CRITICO
Score ML: -0.45 (muy anómalo)
AbuseIPDB: 100/100
Técnicas: T1110 (Brute Force), T1078 (Valid Accounts)
Acción: Bloquear inmediatamente en firewall.
```

> "El score combinado es altísimo: el ML ya la marcó como anómala porque tiene 537 intentos de login con 531 fallos. Y AbuseIPDB confirma que es un nodo Tor con score 100/100 — la comunidad de seguridad lleva meses reportando esta IP."

**Minuto 9: Slack**
> "En paralelo, el sistema envió esta alerta a nuestro canal de Slack automáticamente."
Mostrar el canal #alertas-seguridad (si hay acceso al móvil o captura de pantalla preparada).

**Minuto 10: Arquitectura y código**
Abrir GitHub: https://github.com/maikonaline/threatscope
> "El código está completamente documentado. 38 tests pasando al 100%. Docker incluido. El pipeline tiene 5 fases claramente separadas — cada módulo tiene una única responsabilidad."

### Los tres CSVs de demo y qué demuestran cada uno

| CSV | Escenario | IP principal | Técnica MITRE | Lo que demuestra |
|---|---|---|---|---|
| `ataque_fuerza_bruta.csv` | 537 intentos de login, 531 fallos | 185.220.101.5 (Tor) | T1110 Brute Force + T1078 | Detección de credential stuffing + enriquecimiento AbuseIPDB |
| `escaneo_puertos.csv` | Exploración de 74 puertos distintos | 80.82.77.33 (Shodan scanner) | T1046 Network Service Scanning | Detección de reconnaissance / reconocimiento previo al ataque |
| `exfiltracion_datos.csv` | 1.85 GB descargados a las 3am | IP interna sospechosa | T1041 Exfiltration Over C2 | Detección de exfiltración por horario anómalo + volumen |

### Qué decir si algo falla

**Si el backend no responde:**
> "Render.com en plan gratuito hace cold start si no hay actividad reciente. Le doy 30-60 segundos." Mientras espera, explicar la arquitectura desde el código en GitHub.

**Si AbuseIPDB devuelve score diferente al esperado:**
> "AbuseIPDB es datos en tiempo real de la comunidad — la reputación de una IP puede cambiar. El sistema tiene fallback automático a heurísticas locales si la API no responde o cambia."

**Si el entrevistador pide ver el código:**
Abrir directamente `pipeline.py` en GitHub — es el módulo más representativo: muestra el flujo completo, manejo de errores, logging, separación de responsabilidades.

---

## 7. CONCEPTOS CLAVE PARA EXPLICAR

### Isolation Forest

**Definición simple:** Un algoritmo de Machine Learning que detecta "rarezas" sin necesitar ejemplos de ataques anteriores. Aprende cómo es el tráfico normal y señala lo que se desvía.

**Cómo funciona técnicamente:** Construye árboles de decisión aleatoriamente. Los puntos "normales" necesitan muchas particiones para quedar aislados (porque están rodeados de otros puntos normales). Los puntos "anómalos" quedan aislados en muy pocas particiones, porque están solos en el espacio de features. El score de anomalía indica cuántas particiones necesitó: más negativo = más raro = más anómalo.

**Por qué es ideal para ciberseguridad:** Los ataques son raros y evolucionan constantemente. Los modelos supervisados necesitan datos etiquetados ("esto es un ataque, esto no lo es"), que normalmente no existen o están desactualizados. Isolation Forest solo necesita tráfico normal para aprender — y detecta cualquier desviación, incluso ataques nuevos no vistos antes.

**En ThreatScope:** Usa 5 features numéricas: intentos_login, fallos_login, bytes_descargados, horas_actividad, puertos_distintos. El parámetro `contamination=0.05` indica que esperamos ~5% de datos anómalos en cada batch.

### MITRE ATT&CK

**Definición simple:** Una enciclopedia pública y gratuita de todas las técnicas que usan los atacantes reales. Cada técnica tiene un código (T seguido de números), un nombre, y documentación de cómo defenderse.

**Por qué importa:** Cuando el sistema detecta una IP haciendo 531 fallos de login, no dice solo "es sospechoso" — dice "está usando T1110 (Brute Force), que es Credential Access, y la mitigación recomendada es MFA y rate limiting". Eso convierte una alerta genérica en acción concreta.

**Técnicas implementadas en ThreatScope:**

| ID | Nombre | Táctica MITRE | Cuándo se mapea |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | fallos_login > 30 |
| T1046 | Network Service Scanning | Discovery | puertos_distintos > 15 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | bytes_descargados > 100.000 |
| T1078 | Valid Accounts (anomalía horaria) | Defense Evasion | actividad antes de las 6am o después de las 10pm |
| T1090.003 | Proxy: Multi-hop Proxy (Tor) | Command and Control | IP identificada como nodo Tor |

### AbuseIPDB

**Definición simple:** Una base de datos colaborativa donde la comunidad de seguridad reporta IPs maliciosas. Cualquier empresa puede reportar "esta IP nos atacó" y cualquier empresa puede consultar "¿esta IP tiene historial de ataques?".

**En ThreatScope:** Se consulta la API v2 con la clave configurada en Render. Devuelve: `abuseConfidenceScore` (0-100, construido sobre miles de reportes), `totalReports` (cuántas veces ha sido reportada), `countryCode` (país de origen). La IP 185.220.101.5 tiene score 100/100 y cientos de reportes como nodo Tor.

**Diseño del fallback:** Si AbuseIPDB no responde (timeout, rate limit, sin API key), el sistema cae automáticamente a ipwho.is para geolocalización + heurísticas locales. El pipeline nunca se rompe por dependencias externas.

### Webhook (Slack)

**Definición simple:** Una URL que Slack te da. Cuando tu sistema hace un POST a esa URL con un JSON, Slack publica el mensaje en el canal que configuraste. Sin autenticación compleja, sin SDK — solo HTTP.

**En ThreatScope:** `notifier.py` usa `urllib.request` (sin dependencias externas) para hacer el POST al webhook. El diseño clave es que el notifier tiene "fallo silencioso" — si Slack no responde, el pipeline continúa sin crashear. Una alerta perdida es mejor que una detección perdida.

### SIEM (Security Information and Event Management)

**Definición simple:** Plataforma centralizada que recopila logs de todos los sistemas de una empresa (firewalls, servidores, aplicaciones), los correlaciona, y genera alertas. Ejemplos: Splunk, Microsoft Sentinel, IBM QRadar.

**Relación con ThreatScope:** ThreatScope puede actuar como un detector ML que alimenta un SIEM. El código de integración con Splunk HEC (HTTP Event Collector) y Microsoft Sentinel ya está implementado en `notifier.py`, pendiente de configurar credenciales en producción.

### SOC (Security Operations Center)

**Definición simple:** El equipo (y la sala) donde los analistas de seguridad monitorean las alertas, investigan incidentes, y responden a amenazas. Un SOC utiliza SIEMs, herramientas de threat intelligence, y playbooks de respuesta.

**Relación con ThreatScope:** ThreatScope automatiza el primer nivel de triage del SOC — el análisis inicial que determina si un evento merece atención humana. En lugar de que un analista revise 10.000 eventos manualmente, ThreatScope le presenta 5 alertas priorizadas con nivel CRÍTICO o ALTO, cada una ya enriquecida con reputación y técnica MITRE.

### Anomaly Detection vs. Signature-based Detection

**Signature-based (tradicional):** Busca patrones conocidos. "Si ves este payload exacto, es un ataque". Ventaja: cero falsos positivos para ataques conocidos. Desventaja: incapaz de detectar ataques nuevos (zero-days).

**Anomaly-based (ThreatScope):** Aprende el comportamiento normal y detecta desviaciones. Ventaja: puede detectar ataques nuevos, nunca vistos. Desventaja: puede generar falsos positivos (comportamiento inusual pero legítimo). ThreatScope mitiga esto combinando el score ML con reputación externa.

---

## 8. PREGUNTAS FRECUENTES DE ENTREVISTA — CON RESPUESTAS

### P1: ¿Por qué Isolation Forest y no otro algoritmo?

> "En ciberseguridad hay dos problemas que hacen difícil el ML supervisado: primero, los ataques son eventos raros — en un dataset con 10.000 eventos, quizás 50 son ataques, lo que crea un desbalance severo. Segundo, los atacantes adaptan sus técnicas constantemente — un modelo entrenado sobre ataques de hace seis meses puede no reconocer los de hoy. Isolation Forest resuelve ambos problemas: es no supervisado (no necesita ejemplos de ataques), funciona bien con datasets desbalanceados, y detecta cualquier comportamiento estadísticamente inusual independientemente de si ese patrón existía antes. El tradeoff es que puede generar falsos positivos para tráfico legítimo pero inusual — por eso ThreatScope combina el score ML con reputación externa de AbuseIPDB para reducir esa tasa."

### P2: ¿Cómo sabes que no hay falsos positivos?

> "No puedo garantizar cero falsos positivos — ningún sistema de detección puede. Lo que sí hice fue diseñar el sistema para minimizarlos: el score final combina dos señales independientes. Una IP necesita ser anómala para el modelo Y tener reputación alta para llegar a nivel CRÍTICO. Si solo es anómala pero tiene reputación 0 (IP limpia), llega a MEDIO o BAJO, lo que indica 'monitorizar' en lugar de 'bloquear inmediatamente'. El parámetro `contamination=0.05` también es ajustable — en redes con más ruido se puede bajar para ser más conservador con las alertas."

### P3: ¿Qué es MITRE ATT&CK y por qué lo usaste?

> "MITRE ATT&CK es el estándar de la industria para describir técnicas de ataque. Cuando digo 'detecté actividad sospechosa', eso no le dice nada concreto a un analista de seguridad. Cuando digo 'detecté T1110 Brute Force en Credential Access', el analista sabe exactamente qué está pasando, tiene documentación de mitigaciones, y puede correlacionar con otros eventos del SIEM. Usar MITRE ATT&CK hace que las alertas de ThreatScope sean accionables y comparables con el resto del ecosistema de seguridad de una empresa."

### P4: ¿Cómo escalaría esto a producción real?

> "Cuatro cambios principales: primero, cambiar SQLite por PostgreSQL con índices en `ip` y `created_at` para consultas rápidas sobre históricos de millones de eventos. Segundo, cambiar el procesamiento por batch de CSVs por streaming en tiempo real usando Kafka o un agente de Logstash que lea los logs directamente del firewall o SIEM. Tercero, usar uvicorn con múltiples workers detrás de un load balancer para el backend. Cuarto, el modelo de Isolation Forest se reentrenaría periódicamente a medida que el tráfico normal de la red evoluciona — lo que es normal en enero puede no serlo en julio. El parámetro `contamination` y las features del modelo se ajustarían según el entorno específico."

### P5: ¿Por qué no usaste un framework de frontend (React, Vue)?

> "Decisión deliberada. El dashboard es un cliente ligero que hace GET cada 30 segundos y muestra los datos. No hay estado complejo, no hay routing, no hay interacciones complejas. Añadir React habría sumado un pipeline de build, node_modules, y complejidad de deploy sin ningún beneficio funcional. HTML/JS vanilla se despliega en Vercel como archivo estático en 10 segundos, carga instantáneamente, y el código es legible por cualquier persona. La regla que apliqué: no añadir complejidad sin un problema que lo justifique."

### P6: ¿Qué vulnerabilidades tiene el sistema?

> "Varias que soy consciente de: primero, el modelo se entrena sobre el batch actual — si el primer CSV que se sube es 100% datos de ataque, el modelo aprende que eso es 'normal'. En producción se debería entrenar sobre un baseline histórico conocido-limpio. Segundo, la API no tiene autenticación — cualquiera con la URL puede subir un CSV. En producción se añadiría API key o JWT. Tercero, SQLite no es adecuado para concurrencia en producción — múltiples requests simultáneos pueden generar locks. Cuarto, los logs podrían revelar información sensible si el nivel DEBUG está activo en producción."

### P7: ¿Cómo hiciste los tests?

> "38 tests divididos en cuatro capas: unitarios para cada módulo (config, analyzer, threat_intel, database), integración para el pipeline end-to-end con un CSV real, y tests de API con el TestClient de FastAPI que simula requests HTTP sin levantar el servidor. Los tests de threat_intel usan mocks para no hacer llamadas reales a AbuseIPDB durante los tests — eso hace los tests rápidos, deterministas, y sin dependencias externas. Se ejecutan con `pytest tests.py -v` y pasan al 100%."

### P8: ¿Qué diferencia este proyecto de simplemente usar un IDS comercial?

> "Un IDS comercial como Snort o Suricata es signature-based — detecta ataques conocidos por patrones exactos. ThreatScope es anomaly-based y usa ML — puede detectar comportamientos inusuales que no coinciden con ninguna firma conocida. Además, la integración de MITRE ATT&CK y AbuseIPDB en un pipeline automatizado que termina en una alerta de Slack es algo que normalmente requiere configurar múltiples herramientas. El valor de este proyecto es demostrar que entiendo cómo conectar las piezas del ecosistema de seguridad en código, no solo usarlas como cajas negras."

### P9: ¿Qué harías diferente si lo volvieras a construir?

> "Tres cosas: primero, habría añadido autenticación a la API desde el principio en lugar de como mejora futura — la seguridad no se añade al final. Segundo, habría implementado streaming desde el inicio en lugar de batch de CSVs — en un entorno real los logs llegan en tiempo real, no en archivos. Tercero, habría añadido explicabilidad al modelo (SHAP values) para que cada alerta incluya 'la IP fue marcada principalmente porque fallos_login = 531, que es 177 veces el valor normal del batch' — eso hace que el analista confíe en el sistema en lugar de verlo como una caja negra."

### P10: ¿Puedes explicar el código del pipeline en una frase?

> "`pipeline.py` es el orquestador que en 5 pasos convierte un CSV de logs en una alerta de Slack: carga los datos, los valida, ejecuta Isolation Forest para detectar IPs anómalas, consulta AbuseIPDB para enriquecer cada anomalía con reputación real, persiste los resultados en base de datos, y dispara notificaciones para los niveles críticos — todo en un único método `run()` con manejo de errores en cada capa."

---

## 9. RUTA A PRODUCCIÓN — CÓMO ESCALARÍA EN UNA EMPRESA REAL

### Estado actual (demo/MVP)

```
CSV manual → API REST → SQLite → Slack
Capacidad: decenas de eventos por análisis
Latencia: segundos por batch
Costo: ~$0/mes (Render free tier + Vercel free)
```

### Fase 1: Producción básica (empresa pequeña, ~100 usuarios)

Cambios:
- SQLite → PostgreSQL con índices en `ip` y `created_at`
- API key authentication en todos los endpoints
- uvicorn + gunicorn multi-worker (4-8 workers)
- Variables de entorno via secrets manager (no .env)
- Alertas por email además de Slack

Costo estimado: $50-100/mes (PostgreSQL gestionado + servidor pequeño)
Capacidad: miles de eventos por análisis, múltiples batches en paralelo

### Fase 2: Integración con infraestructura real

Cambios:
- Eliminar upload de CSV manual → leer logs directamente desde:
  - Agente Logstash en el firewall
  - CloudWatch Logs (si infraestructura en AWS)
  - Azure Monitor Logs
- Activar Splunk HEC / Microsoft Sentinel (código ya está en `notifier.py`)
- Dashboard con autenticación (login)
- Reentrenamiento periódico del modelo (cron job semanal)
- Alertas con runbooks adjuntos (links a procedimientos de respuesta)

### Fase 3: Escala enterprise

Cambios:
- Kafka para streaming de eventos en tiempo real (latencia < 1 segundo)
- Modelo de ML con reentrenamiento continuo (online learning)
- Múltiples modelos por segmento de red (un modelo para servidores, otro para workstations)
- SHAP para explicabilidad de cada alerta
- API de feedback: el analista marca si la alerta fue real o falso positivo → el modelo aprende
- SOC dashboard con gestión de incidentes, asignación de tickets, SLA
- Integración bidireccional con Jira / ServiceNow para tickets automáticos

### Lo que ThreatScope demuestra ya hoy

El proyecto prueba que se comprenden los elementos fundamentales de un pipeline de detección de amenazas: ingesta de logs, análisis estadístico/ML, enriquecimiento con threat intelligence, clasificación de riesgo, persistencia, alertas y visualización. La arquitectura modular (cada módulo con responsabilidad única, fallbacks diseñados, fallo silencioso en notificaciones) refleja los patrones de un sistema diseñado para crecer, no solo para funcionar en demo.

---

*Documento generado para presentación de entrevista — ThreatScope v1.0 — Mayo 2026*
*Repo: https://github.com/maikonaline/threatscope*
