"""
api.py
------
API REST con FastAPI para ThreatScope.

Expone los tres endpoints principales:
  POST /analyze   — analiza un CSV de eventos de red
  GET  /status    — health check del sistema
  GET  /detections — consulta detecciones historicas

Inicio rapido:
    uvicorn api:app --reload --port 8000

Documentacion interactiva disponible en:
    http://localhost:8000/docs   (Swagger UI)
    http://localhost:8000/redoc  (ReDoc)
"""

import asyncio
import json
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from config import settings
from database import db
from logger import get_logger
from pipeline import AnalysisPipeline

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Autenticación por API key
# ---------------------------------------------------------------------------

async def verify_api_key(x_api_key: str = Header(default="")) -> None:
    """
    Valida el header X-API-Key.
    Si THREATSCOPE_API_KEY no está configurada, el acceso es libre (modo demo).
    """
    if settings.API_KEY and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o ausente")


# ---------------------------------------------------------------------------
# Schemas de respuesta
# ---------------------------------------------------------------------------


class DetectionSchema(BaseModel):
    """Representa una deteccion de amenaza individual."""

    id: int = Field(..., description="ID unico de la deteccion en BD")
    ip: str = Field(..., description="Direccion IP analizada")
    risk_level: str = Field(..., description="Nivel de riesgo: CRITICO, ALTO, MEDIO, BAJO")
    anomaly_score: float = Field(
        ..., description="Score del modelo ML. Mas negativo = mas anomalo"
    )
    reputation_score: float = Field(..., description="Reputacion de la IP (0-100)")
    is_known_malicious: bool = Field(..., description="True si la IP esta en bases de datos maliciosas")
    country: str = Field(default="??", description="Pais de origen de la IP")
    mitre_techniques: List[str] = Field(
        default=[], description="Lista de IDs de tecnicas MITRE ATT&CK detectadas"
    )
    summary: str = Field(..., description="Resumen en lenguaje natural de la amenaza")
    created_at: str = Field(..., description="Timestamp ISO 8601 de la deteccion")


class AnalysisResult(BaseModel):
    """Resultado de un analisis de batch."""

    batch_id: str = Field(..., description="UUID del lote de analisis")
    total_events: int = Field(..., description="Total de eventos procesados")
    anomalies_found: int = Field(..., description="Numero de anomalias detectadas")
    duration_seconds: float = Field(..., description="Tiempo de procesamiento en segundos")
    detections: List[dict] = Field(default=[], description="Lista de detecciones del batch")


class StatusResponse(BaseModel):
    """Respuesta del health check."""

    status: str = Field(..., description="'ok' o 'degraded'")
    environment: str = Field(..., description="Entorno actual: development, production")
    database: dict = Field(..., description="Estado y estadisticas de la BD")
    model: dict = Field(..., description="Estado del modelo ML")
    timestamp: str = Field(..., description="Timestamp ISO 8601 del check")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Ciclo de vida de la aplicacion.
    Ejecuta inicializacion al arrancar y limpieza al cerrar.
    """
    # Startup
    log.info("ThreatScope API arrancando...")
    db.init_db()
    log.info("BD inicializada. API lista.")
    yield
    # Shutdown (si fuera necesario cerrar conexiones, etc.)
    log.info("ThreatScope API cerrando.")


app = FastAPI(
    title="ThreatScope API",
    description=(
        "API REST para el sistema de deteccion de amenazas ThreatScope. "
        "Combina Machine Learning (Isolation Forest) con Threat Intelligence "
        "para identificar comportamiento anomalo en trafico de red y mapearlo "
        "a tecnicas MITRE ATT&CK."
    ),
    version="1.0.0",
    lifespan=lifespan,
    contact={
        "name": "ThreatScope",
        "url": "https://github.com/tu-usuario/threatscope",
    },
    license_info={"name": "MIT"},
)

# CORS — dominios permitidos desde config (variable ALLOWED_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/analyze",
    response_model=AnalysisResult,
    summary="Analiza un CSV de eventos de red",
    description=(
        "Recibe un archivo CSV con eventos de red y ejecuta el pipeline completo: "
        "validacion → ML (Isolation Forest) → Threat Intelligence → persistencia en BD.\n\n"
        "**Columnas requeridas en el CSV:**\n"
        "- `ip` — direccion IP\n"
        "- `intentos_login` — total de intentos de autenticacion\n"
        "- `fallos_login` — intentos fallidos\n"
        "- `bytes_descargados` — volumen de datos descargados\n"
        "- `horas_actividad` — hora del dia de la actividad (0-23)\n"
        "- `puertos_distintos` — numero de puertos distintos accedidos\n\n"
        "**Ejemplo de CSV:** ver `/examples/escenario_incidente.csv` en el repositorio."
    ),
    tags=["Analysis"],
)
async def analyze(
    file: UploadFile = File(..., description="Archivo CSV con eventos de red"),
    _: None = Depends(verify_api_key),
) -> AnalysisResult:
    """
    Ejecuta el pipeline de deteccion sobre un archivo CSV.

    Args:
        file: archivo CSV subido via multipart/form-data.

    Returns:
        AnalysisResult con estadisticas del batch y lista de detecciones.

    Raises:
        HTTPException 400: si el archivo no es CSV, supera el límite de tamaño, o faltan columnas.
        HTTPException 401: si la API key es inválida.
        HTTPException 500: si el pipeline falla por error interno.
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail=f"Solo se aceptan archivos CSV. Recibido: {file.filename}",
        )

    # Guardar el CSV en un archivo temporal para que el pipeline lo lea
    try:
        content = await file.read()

        if len(content) > settings.MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"Archivo demasiado grande: {len(content):,} bytes. Máximo: {settings.MAX_UPLOAD_BYTES:,} bytes (10 MB).",
            )

        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".csv", delete=False
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        log.info(f"CSV recibido: {file.filename} ({len(content)} bytes) → {tmp_path}")

        # Ejecutar pipeline en un thread para no bloquear el event loop de FastAPI
        pipe = AnalysisPipeline()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: pipe.run(tmp_path, source="csv"))

        return AnalysisResult(**result)

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Error en /analyze: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno del pipeline: {str(e)}")
    finally:
        # Limpiar archivo temporal
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@app.get(
    "/status",
    response_model=StatusResponse,
    summary="Health check del sistema",
    description=(
        "Verifica el estado de todos los componentes del sistema: "
        "base de datos, modelo ML y configuracion. "
        "Retorna 200 si todo funciona, 503 si algun componente falla."
    ),
    tags=["System"],
)
async def status() -> StatusResponse:
    """
    Verifica el estado de salud del sistema.

    Returns:
        StatusResponse con estado de BD, modelo ML y configuracion.

    Raises:
        HTTPException 503: si la BD no responde o el modelo no esta listo.
    """
    errors = []
    db_info = {}
    model_info = {}

    # Verificar BD
    try:
        stats = db.get_stats()
        db_info = {
            "status": "ok",
            "engine": settings.DB_ENGINE,
            "total_detections": stats["total"],
            "critical": stats["criticos"],
            "high": stats["altos"],
        }
    except Exception as e:
        errors.append(f"BD: {e}")
        db_info = {"status": "error", "detail": str(e)}

    # Verificar modelo ML
    try:
        from analyzer import detector
        model_info = {
            "status": "ok",
            "fitted": detector.is_fitted(),
            "algorithm": "IsolationForest",
            "contamination": settings.ML_CONTAMINATION,
            "n_estimators": settings.ML_N_ESTIMATORS,
        }
    except Exception as e:
        errors.append(f"Modelo: {e}")
        model_info = {"status": "error", "detail": str(e)}

    overall_status = "ok" if not errors else "degraded"

    response = StatusResponse(
        status=overall_status,
        environment=settings.ENV,
        database=db_info,
        model=model_info,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )

    if errors:
        return JSONResponse(status_code=503, content=response.model_dump())

    return response


@app.get(
    "/detections",
    response_model=List[DetectionSchema],
    summary="Consulta detecciones historicas",
    description=(
        "Retorna las detecciones almacenadas en BD. "
        "Se puede filtrar por ventana temporal y nivel de riesgo, "
        "y paginar con `limit`."
    ),
    tags=["Detections"],
)
async def get_detections(
    hours: int = Query(
        default=24,
        ge=1,
        le=8760,  # max 1 anho
        description="Ventana temporal: detecciones de las ultimas N horas",
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=500,
        description="Numero maximo de detecciones a retornar",
    ),
    risk_level: Optional[str] = Query(
        default=None,
        description="Filtrar por nivel de riesgo: CRITICO, ALTO, MEDIO, BAJO",
    ),
) -> List[DetectionSchema]:
    """
    Consulta el historico de detecciones con filtros opcionales.

    Args:
        hours: ventana temporal en horas (1-8760). Default: 24.
        limit: maximo de resultados (1-500). Default: 50.
        risk_level: filtro por nivel de riesgo (opcional).

    Returns:
        Lista de DetectionSchema ordenada por fecha descendente.

    Raises:
        HTTPException 400: si el risk_level no es valido.
        HTTPException 500: si falla la consulta a BD.
    """
    valid_levels = {"CRITICO", "ALTO", "MEDIO", "BAJO"}
    if risk_level and risk_level.upper() not in valid_levels:
        raise HTTPException(
            status_code=400,
            detail=f"Nivel de riesgo invalido: '{risk_level}'. Validos: {valid_levels}",
        )

    try:
        detections = db.get_recent_detections(hours=hours, limit=limit)

        # Filtro opcional por nivel de riesgo (en memoria — dataset pequeno)
        if risk_level:
            detections = [d for d in detections if d.risk_level == risk_level.upper()]

        result = []
        for d in detections:
            # Deserializar JSON de tecnicas MITRE (guardado como string)
            try:
                mitre = json.loads(d.mitre_techniques) if d.mitre_techniques else []
            except (json.JSONDecodeError, TypeError):
                mitre = []

            result.append(
                DetectionSchema(
                    id=d.id,
                    ip=d.ip,
                    risk_level=d.risk_level,
                    anomaly_score=d.anomaly_score,
                    reputation_score=d.reputation_score,
                    is_known_malicious=bool(d.is_known_malicious),
                    country=d.country or "??",
                    mitre_techniques=mitre,
                    summary=d.summary or "",
                    created_at=d.created_at.isoformat() + "Z" if d.created_at else "",
                )
            )

        return result

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error en /detections: {e}")
        raise HTTPException(status_code=500, detail=f"Error consultando BD: {str(e)}")


# ---------------------------------------------------------------------------
# Schemas de integraciones
# ---------------------------------------------------------------------------


class IntegrationTestRequest(BaseModel):
    """Peticion de prueba de integracion."""

    channel: str = Field(
        ...,
        description="Canal a probar: slack, splunk, sentinel, teams",
    )
    config: Dict[str, Any] = Field(
        default={},
        description=(
            "Configuracion opcional del canal. Si no se envia, "
            "se usan las variables de entorno del servidor."
        ),
    )


class IntegrationTestResponse(BaseModel):
    """Respuesta de prueba de integracion."""

    channel: str
    success: bool
    detail: str


class IntegrationStatusItem(BaseModel):
    """Estado de una integracion individual."""

    configured: bool
    status: Optional[str] = None


class IntegrationsStatusResponse(BaseModel):
    """Estado de todas las integraciones."""

    slack:    IntegrationStatusItem
    splunk:   IntegrationStatusItem
    sentinel: IntegrationStatusItem
    teams:    IntegrationStatusItem


# ---------------------------------------------------------------------------
# Endpoints de integraciones
# ---------------------------------------------------------------------------


@app.post(
    "/integrations/test",
    response_model=IntegrationTestResponse,
    summary="Prueba una integracion externa",
    description=(
        "Envia un mensaje de prueba al canal indicado y devuelve si fue exitoso. "
        "Permite validar la configuracion desde el dashboard sin realizar un analisis real."
    ),
    tags=["Integrations"],
)
async def test_integration(body: IntegrationTestRequest, _: None = Depends(verify_api_key)) -> IntegrationTestResponse:
    """
    Prueba la conexion con un canal de notificacion externo.

    Args:
        body: canal ('slack' | 'splunk' | 'sentinel' | 'teams') y config opcional.

    Returns:
        IntegrationTestResponse con resultado del envio.

    Raises:
        HTTPException 400: si el canal es desconocido.
    """
    valid_channels = {"slack", "splunk", "sentinel", "teams"}
    if body.channel not in valid_channels:
        raise HTTPException(
            status_code=400,
            detail=f"Canal desconocido: '{body.channel}'. Validos: {valid_channels}",
        )

    try:
        from notifier import send_test
        result = send_test(body.channel, body.config)
        return IntegrationTestResponse(
            channel=body.channel,
            success=result["success"],
            detail=result["detail"],
        )
    except Exception as e:
        log.error(f"Error en /integrations/test [{body.channel}]: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


@app.get(
    "/integrations/status",
    response_model=IntegrationsStatusResponse,
    summary="Estado de integraciones externas",
    description=(
        "Devuelve que integraciones estan configuradas en el servidor. "
        "No expone secrets ni credenciales."
    ),
    tags=["Integrations"],
)
async def integrations_status() -> IntegrationsStatusResponse:
    """
    Consulta el estado de configuracion de cada integracion.

    Returns:
        IntegrationsStatusResponse con flag 'configured' por canal.
    """
    try:
        from notifier import get_integrations_status
        raw = get_integrations_status()

        def _item(data: dict) -> IntegrationStatusItem:
            return IntegrationStatusItem(
                configured=data["configured"],
                status="ok" if data["configured"] else None,
            )

        return IntegrationsStatusResponse(
            slack=_item(raw["slack"]),
            splunk=_item(raw["splunk"]),
            sentinel=_item(raw["sentinel"]),
            teams=_item(raw["teams"]),
        )
    except Exception as e:
        log.error(f"Error en /integrations/status: {e}")
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")


# ---------------------------------------------------------------------------
# Raiz
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root():
    """Redirect informativo a la documentacion."""
    return {
        "name": "ThreatScope API",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "/status",
        "endpoints": ["/analyze", "/status", "/detections", "/integrations/status", "/integrations/test"],
    }
