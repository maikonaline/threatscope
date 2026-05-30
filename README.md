# ThreatScope — Sistema de Detección de Amenazas en Tiempo Real

## Descripción

ThreatScope es un sistema de análisis y detección de anomalías de seguridad en tráfico de red. Combina **Machine Learning no supervisado** (Isolation Forest) con **Threat Intelligence** para identificar patrones de ataque (fuerza bruta, escaneo de puertos, exfiltración de datos) y mapearlos a técnicas de **MITRE ATT&CK**.

### Stack tecnológico

- **Backend**: Python 3.11+ (pandas, scikit-learn, SQLAlchemy)
- **ML**: Isolation Forest (no supervisado, ideal para datasets desbalanceados)
- **BD**: SQLite (dev) / PostgreSQL (prod)
- **Threat Intel**: ipwho.is, AbuseIPDB, VirusTotal (opcionales)
- **Frontend**: HTML5 + Chart.js (dashboards interactivos)
- **DevOps**: Docker, pytest, logging estructurado

---

## Características

✅ **Detección de anomalías** — Aísla comportamiento sospechoso sin etiquetas previas
✅ **Enriquecimiento en tiempo real** — Reputación de IP, geolocalización, país
✅ **Mapeo MITRE ATT&CK** — Correlaciona patrones con técnicas reales de atacantes
✅ **Persistencia** — Histórico completo en BD para auditoría y tendencias
✅ **Logging estructurado** — Trazabilidad de cada paso del pipeline
✅ **Tests** — Cobertura unitaria e integración
✅ **Dockerizable** — Despliegue fácil en contenedores
✅ **CLI + Web** — Interfaz por terminal y dashboards interactivos

---

## Instalación

### 1. Clonar y dependencias

```bash
git clone <tu-repo>
cd threatscope
pip install -r requirements.txt
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
# Edita .env según tu entorno
```

### 3. Inicializar BD

```bash
python main.py health
# Esto crea las tablas automáticamente
```

---

## Uso rápido

### Desde CLI

```bash
# Analizar un CSV
python main.py analyze --csv escenario_incidente.csv

# Ver estadísticas
python main.py stats

# Health check
python main.py health --debug
```

### Desde Python (programático)

```python
from pipeline import pipeline
from database import db

# Ejecutar análisis
result = pipeline.run("datos.csv", source="csv")
print(f"Anomalías: {result['anomalies_found']} de {result['total_events']}")

# Consultar BD
detections = db.get_recent_detections(hours=24, limit=10)
for d in detections:
    print(f"{d.ip} | {d.risk_level} | {d.summary}")
```

---

## Arquitectura modular

```
threatscope_prod/
├── config.py              # Configuración centralizada
├── logger.py              # Logging estructurado
├── database.py            # Capa de persistencia (SQLAlchemy)
├── analyzer.py            # Motor ML (Isolation Forest)
├── threat_intel.py        # Enriquecimiento + MITRE ATT&CK
├── pipeline.py            # Orquestador (ingesta → ML → enriquecimiento)
├── main.py                # CLI principal
├── tests.py               # Tests unitarios e integración
├── requirements.txt       # Dependencias Python
├── Dockerfile             # Containerización
├── .env.example           # Plantilla de variables de entorno
└── README.md              # Este archivo
```

### Flujo de datos

```
CSV/BD → [Ingesta] → [Validación] → [ML] → [Enriquecimiento] → [BD] → [CLI/Dashboard]
                                       ↓
                            Isolation Forest
                            (anomalía_score)
                                       ↓
                         [Threat Intel API]
                         (reputación IP)
                                       ↓
                          [Mapeo MITRE ATT&CK]
                          (técnicas asociadas)
                                       ↓
                            [Nivel de Riesgo]
                         (CRÍTICO/ALTO/MEDIO/BAJO)
```

---

## Módulos

### `config.py`
Configuración centralizada. Lee desde `.env` o variables de entorno del sistema.
```python
from config import settings
print(settings.DB_PATH)
print(settings.LOG_LEVEL)
```

### `logger.py`
Logging estructurado con rotación de archivos.
```python
from logger import get_logger
log = get_logger(__name__)
log.info("Mensaje")
log.error("Error")
```

### `database.py`
Capa de persistencia con SQLAlchemy. Agnóstica a la BD (SQLite/PostgreSQL).
```python
from database import db, Detection
detection = Detection(ip="192.168.1.1", risk_level="ALTO", ...)
db.save_detection(detection)
stats = db.get_stats()
```

### `analyzer.py`
Motor de ML. Isolation Forest para detección de anomalías sin supervisión.
```python
from analyzer import detector
df = detector.predict(datos)  # Añade columnas: score_anomalia, es_anomalia
```

### `threat_intel.py`
Enriquecimiento de IPs con reputación real y mapeo a MITRE ATT&CK.
```python
from threat_intel import query_reputation, map_mitre, evaluate_threat_level
rep = query_reputation("185.220.101.5")  # → Reputation(score=92, is_known=True, ...)
tecnicas = map_mitre(row)                # → [MitreTechnique(...), ...]
nivel, score = evaluate_threat_level(-5.0, rep)  # → ("CRITICO", 112.5)
```

### `pipeline.py`
Orquestador end-to-end. Integra todos los módulos.
```python
from pipeline import pipeline
result = pipeline.run("datos.csv", source="csv")
# → {"batch_id": "...", "total_events": 52, "anomalies_found": 11, ...}
```

### `main.py`
CLI con subcomandos para análisis, estadísticas y health checks.
```bash
python main.py analyze --csv datos.csv
python main.py stats
python main.py health --debug
```

---

## Testing

```bash
# Ejecutar todos los tests
pytest tests.py -v

# Con cobertura
pytest tests.py --cov=. --cov-report=html
```

Tests incluyen:
- ✓ Carga y validación de datos
- ✓ Predicción del modelo ML
- ✓ Detección de IPs maliciosas (Tor, proxy)
- ✓ Mapeo a técnicas MITRE
- ✓ Pipeline end-to-end

---

## Despliegue con Docker

### Build

```bash
docker build -t threatscope .
```

### Run

```bash
docker run -it \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -e THREATSCOPE_ENV=production \
  threatscope python main.py analyze --csv /app/data/datos.csv
```

### Con Docker Compose (opcional)

```yaml
# docker-compose.yml
version: '3.8'
services:
  threatscope:
    build: .
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      THREATSCOPE_ENV: production
      THREATSCOPE_DB_ENGINE: sqlite
  
  # Opcional: PostgreSQL
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: threatscope
      POSTGRES_USER: threatscope
      POSTGRES_PASSWORD: secret
```

---

## Documentación de API

### Detection (BD)

```python
Detection(
    ip: str,                    # "192.168.1.1"
    risk_level: str,            # "CRITICO" | "ALTO" | "MEDIO" | "BAJO"
    anomaly_score: float,       # -0.5 a 0.5 (más negativo = más raro)
    reputation_score: float,    # 0-100
    is_known_malicious: bool,   # True si IP ya es conocida
    country: str,               # "ES", "DE", etc.
    isp: str,                   # ISP de la IP
    mitre_techniques: str,      # JSON ["T1110", "T1046"]
    summary: str,               # Resumen en lenguaje natural
    batch_id: str,              # UUID del lote de análisis
    created_at: DateTime,       # Automático
)
```

### Reputation

```python
Reputation(
    score: float,               # 0-100 (100 = muy maliciosa)
    is_known: bool,             # Está en bases de datos maliciosas
    country: str,               # País de origen
    is_proxy: bool,             # ¿Es un proxy/VPN?
    is_hosting: bool,           # ¿Es un datacenter/hosting?
)
```

### MitreTechnique

```python
MitreTechnique(
    id: str,                    # "T1110"
    name: str,                  # "Brute Force"
    tactic: str,                # "Credential Access"
)
```

---

## Mejoras futuras

- [ ] Integración con SIEM real (Splunk, QRadar)
- [ ] API REST para automatización
- [ ] Dashboard web avanzado con filtros y exportación
- [ ] Entrenamiento reentrenable (refit periódico del modelo)
- [ ] Streaming con Kafka para eventos en tiempo real
- [ ] Alerting: email, Slack, webhook
- [ ] Validación contra datasets públicos (CICIDS2017, UNSW-NB15)
- [ ] Explicabilidad de decisiones (SHAP, LIME)

---

## Notas de producción

### BD
- **Development**: SQLite (por defecto, archivo local)
- **Production**: PostgreSQL recomendado. Configura en `.env`:
  ```env
  THREATSCOPE_DB_ENGINE=postgresql
  THREATSCOPE_DB_HOST=db.empresa.com
  THREATSCOPE_DB_USER=threatscope
  THREATSCOPE_DB_PASS=<contraseña>
  ```

### Threat Intel
Para máxima precisión, registra claves de API:
```env
ABUSEIPDB_API_KEY=<tu_clave>
VIRUSTOTAL_API_KEY=<tu_clave>
```
Sin ellas, el sistema usa heurísticas simples (pero funciona).

### Logging
- En dev: `LOG_LEVEL=DEBUG` + consola
- En prod: `LOG_LEVEL=INFO` + rotación de archivos (max 10MB, 5 backups)

### Escalado
Para volúmenes altos:
1. Usa PostgreSQL en lugar de SQLite
2. Paraleliza con `THREATSCOPE_WORKERS=8`
3. Considera Kafka para streaming de eventos
4. Crea índices en BD por `ip` y `created_at`

---

## Licencia

MIT (libre para usar, modificar y distribuir)

---

## Autor

Proyecto de detección de amenazas para entrevista técnica — junior ciberseguridad.
