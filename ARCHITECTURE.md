# ThreatScope — Arquitectura del Sistema

## Vision general

ThreatScope es un sistema de deteccion de amenazas de red basado en ML no supervisado.
El diseno prioriza modularidad: cada modulo tiene una unica responsabilidad y puede
ser sustituido o escalado de forma independiente.

---

## Flujo de datos completo

```
                        FUENTES DE ENTRADA
                      ┌─────────────────────┐
                      │  CSV de eventos red  │
                      │  (o BD externa SQL)  │
                      └──────────┬──────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │     pipeline.py         │
                    │   (Orquestador)         │
                    │                         │
                    │  1. Ingesta             │
                    │  2. Validacion          │
                    │  3. ML                  │
                    │  4. Enriquecimiento     │
                    │  5. Persistencia        │
                    └────────────────────────┘
                          │          │
              ┌───────────┘          └────────────┐
              ▼                                   ▼
  ┌──────────────────────┐          ┌─────────────────────────┐
  │      analyzer.py      │          │      threat_intel.py     │
  │  (Motor ML)           │          │  (Enriquecimiento)       │
  │                       │          │                          │
  │  Isolation Forest     │          │  ipwho.is (geoip)        │
  │  - predict()          │          │  AbuseIPDB (reputacion)  │
  │  - anomaly_score      │          │  VirusTotal (malware)    │
  │  - es_anomalia        │          │  MITRE ATT&CK mapping    │
  └──────────────────────┘          └─────────────────────────┘
              │                                   │
              └──────────────┬────────────────────┘
                             ▼
              ┌───────────────────────────┐
              │        database.py         │
              │  (Capa de persistencia)    │
              │                            │
              │  SQLAlchemy ORM            │
              │  SQLite (dev)              │
              │  PostgreSQL (prod)         │
              │                            │
              │  Tablas:                   │
              │  - detections              │
              │  - analysis_batches        │
              └───────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
  ┌──────────────────┐         ┌──────────────────────┐
  │      api.py       │         │       main.py         │
  │  (FastAPI REST)   │         │  (CLI)                │
  │                   │         │                        │
  │  POST /analyze    │         │  analyze --csv         │
  │  GET  /status     │         │  stats                 │
  │  GET  /detections │         │  health                │
  └──────────────────┘         └──────────────────────┘
              │
              ▼
  ┌──────────────────────┐
  │  Frontend / Cliente   │
  │  (dashboard HTML,     │
  │   curl, Postman)      │
  └──────────────────────┘
```

---

## Modulos — Responsabilidades

| Modulo | Responsabilidad unica | Dependencias |
|---|---|---|
| `config.py` | Configuracion centralizada via env vars | ninguna |
| `logger.py` | Logging estructurado con rotacion | config |
| `database.py` | ORM, CRUD, queries | config, logger, SQLAlchemy |
| `analyzer.py` | Isolation Forest: train, predict, persist | config, logger, scikit-learn |
| `threat_intel.py` | Reputacion IP + mapeo MITRE ATT&CK | config, logger, requests |
| `pipeline.py` | Orquestacion end-to-end | todos los anteriores |
| `api.py` | API REST (FastAPI) | pipeline, database, logger |
| `main.py` | CLI (argparse) | pipeline, database, logger |
| `tests.py` | Suite de tests | todos los modulos |

---

## Modelo de datos

### Tabla `detections`

```
id               INTEGER  PK autoincrement
ip               STRING   IP analizada (indexada)
risk_level       STRING   CRITICO | ALTO | MEDIO | BAJO
anomaly_score    FLOAT    Score ML (-0.5 a 0.5, mas negativo = mas anomalo)
reputation_score FLOAT    Reputacion externa (0-100)
is_known_malicious BOOL   True si aparece en DBs maliciosas
country          STRING   Pais de origen (ISO 3166-1 alpha-2)
isp              STRING   Proveedor de internet
mitre_techniques STRING   JSON: ["T1110", "T1046"]
summary          STRING   Descripcion en lenguaje natural
batch_id         STRING   UUID del lote (indexado)
created_at       DATETIME Timestamp UTC (indexado)
```

### Tabla `analysis_batches`

```
id               STRING   UUID (PK)
source           STRING   csv | postgresql | api
total_events     INTEGER  Eventos procesados
anomalies_found  INTEGER  Anomalias detectadas
duration_seconds FLOAT    Tiempo de ejecucion
status           STRING   pending | running | completed | failed
error_message    STRING   Detalle si status=failed
created_at       DATETIME Inicio del batch
completed_at     DATETIME Fin del batch
```

---

## Decision de arquitectura: Isolation Forest

**Por que no supervisado:**
En ciberseguridad, los ataques son raros y evolucionan constantemente.
Los modelos supervisados requieren etiquetas (datos de ataque previos), que
normalmente no existen o estan desactualizados.

Isolation Forest aisle anomalias construyendo arboles de aislamiento aleatorios.
Los puntos que se aisman en pocas particiones son estadisticamente anomalos —
exactamente el comportamiento de un atacante en una red normal.

**Score de anomalia:**
- Valor positivo cercano a 0.5: trafico muy normal
- Valor cerca de 0: ambiguo
- Valor negativo (hasta -0.5): altamente anomalo

**Contamination:**
Parametro `contamination=0.05` significa que esperamos ~5% de datos anomalos.
Ajustar segun el entorno (redes con mas ataques: subir a 0.10).

---

## Decision de arquitectura: scoring combinado

El nivel de riesgo final combina dos senales:

```
score_combinado = (|anomaly_score| * 200) + reputation_score

> 110  →  CRITICO
> 70   →  ALTO
> 40   →  MEDIO
<= 40  →  BAJO
```

**Por que combinar:**
- ML solo: puede generar falsos positivos (trafico inusual pero legitimo)
- Reputacion sola: solo detecta amenazas conocidas (no zero-days)
- Combinado: trafico anomalo de IP conocida maliciosa = prioridad maxima

---

## Escalabilidad

| Componente | Dev | Produccion |
|---|---|---|
| BD | SQLite (archivo local) | PostgreSQL con indices en `ip` y `created_at` |
| Modelo ML | Isolation Forest en memoria | Mismo, con refit periodico |
| API | uvicorn single process | uvicorn + gunicorn multi-worker |
| Procesamiento | Secuencial por batch | Paralelo con `WORKERS=N` |
| Ingesta | CSV manual | Kafka/Logstash para streaming |

---

## Integraciones externas

| API | Dato que provee | Fallback si falla |
|---|---|---|
| ipwho.is | Geoloc, ISP, org | Heuristicas por rango de IP |
| AbuseIPDB | Reputacion (opcional) | Score 0 (neutro) |
| VirusTotal | Deteccion malware (opcional) | Score 0 (neutro) |

El sistema funciona sin ninguna API key externa. Las integraciones mejoran la
precision pero no son requisito para operar.

---

## Seguridad del diseno

- **Sin credenciales en codigo**: toda configuracion via env vars
- **SQL injection imposible**: SQLAlchemy ORM con parametrizacion automatica
- **Sin ejecucion de codigo externo**: el CSV se parsea con pandas, no se evalua
- **Timeout en APIs externas**: `IPWHOIS_TIMEOUT=10s` por defecto
- **Error handling en cada capa**: ninguna excepcion propaga silenciosamente
