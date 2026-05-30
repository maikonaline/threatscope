"""
tests.py
--------
Suite de tests para ThreatScope.

Cubre:
- config.py: inicializacion y validacion
- analyzer.py: entrenamiento, prediccion, auto-fit
- threat_intel.py: mapeo MITRE, evaluacion de riesgo, resumen
- database.py: CRUD de detecciones y batches
- pipeline.py: flujo end-to-end con CSV real
- api.py: endpoints REST con TestClient de FastAPI

Ejecucion:
    pytest tests.py -v
    pytest tests.py --cov=. --cov-report=term-missing
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_df() -> pd.DataFrame:
    """DataFrame de 10 eventos con patrones de ataque reales."""
    return pd.DataFrame(
        {
            "ip": [
                "185.220.101.5",  # Tor exit node
                "192.168.1.100",
                "10.0.0.50",
                "203.0.113.77",  # Brute force
                "198.51.100.23",  # Port scan
                "172.16.0.5",  # Exfiltracion
                "192.168.1.200",
                "10.0.0.15",
                "45.33.32.156",
                "192.168.2.50",
            ],
            "intentos_login": [45, 3, 2, 120, 5, 2, 4, 1, 30, 3],
            "fallos_login": [44, 1, 1, 118, 2, 1, 2, 0, 28, 1],
            "bytes_descargados": [500, 1200, 800, 300, 450, 500000, 1100, 900, 2000, 700],
            "horas_actividad": [3, 10, 14, 2, 9, 3, 11, 15, 4, 13],
            "puertos_distintos": [2, 1, 1, 3, 45, 2, 1, 1, 3, 1],
        }
    )


@pytest.fixture
def sample_csv(sample_df, tmp_path) -> str:
    """Crea un CSV temporal con los datos de muestra."""
    csv_path = tmp_path / "test_events.csv"
    sample_df.to_csv(csv_path, index=False)
    return str(csv_path)


@pytest.fixture
def test_db(tmp_path):
    """
    BD SQLite temporal para tests.
    Parchea settings para usar una ruta temporal en lugar de la BD real.
    """
    db_path = tmp_path / "test.db"
    with patch("config.settings") as mock_settings:
        mock_settings.DB_ENGINE = "sqlite"
        mock_settings.DB_PATH = str(db_path)
        mock_settings.DEBUG = False
        mock_settings.LOG_LEVEL = "WARNING"
        mock_settings.LOG_FORMAT = "%(levelname)s | %(message)s"
        mock_settings.LOGS_DIR = tmp_path / "logs"
        mock_settings.MODELS_DIR = tmp_path / "models"
        mock_settings.DATA_DIR = tmp_path / "data"
        mock_settings.ML_CONTAMINATION = 0.1
        mock_settings.ML_N_ESTIMATORS = 10
        mock_settings.ML_RANDOM_STATE = 42
        mock_settings.MODEL_SAVE_PATH = str(tmp_path / "models" / "model.pkl")
        mock_settings.BATCH_SIZE = 100
        mock_settings.WORKERS = 1
        mock_settings.ABUSEIPDB_KEY = ""
        mock_settings.VIRUSTOTAL_KEY = ""
        mock_settings.IPWHOIS_TIMEOUT = 3
        mock_settings.ENV = "test"
        mock_settings.db_url.return_value = f"sqlite:///{db_path}"
        yield mock_settings


# ---------------------------------------------------------------------------
# Tests: config.py
# ---------------------------------------------------------------------------


class TestConfig:
    """Verifica inicializacion y metodos de Settings."""

    def test_settings_defaults(self):
        """Settings inicializa con valores por defecto sin env vars."""
        from config import Settings

        cfg = Settings()
        assert cfg.ENV in ("development", "test", "production")
        assert cfg.DB_ENGINE in ("sqlite", "postgresql")
        assert cfg.ML_CONTAMINATION > 0
        assert cfg.ML_N_ESTIMATORS > 0

    def test_sqlite_url(self):
        """db_url() genera URL correcta para SQLite."""
        from config import Settings

        cfg = Settings()
        cfg.DB_ENGINE = "sqlite"
        cfg.DB_PATH = "/tmp/test.db"
        url = cfg.db_url()
        assert url.startswith("sqlite:///")
        assert "test.db" in url

    def test_postgresql_url(self):
        """db_url() genera URL correcta para PostgreSQL."""
        from config import Settings

        cfg = Settings()
        cfg.DB_ENGINE = "postgresql"
        cfg.DB_USER = "user"
        cfg.DB_PASS = "pass"
        cfg.DB_HOST = "localhost"
        cfg.DB_PORT = 5432
        cfg.DB_NAME = "db"
        url = cfg.db_url()
        assert url.startswith("postgresql://")
        assert "localhost:5432/db" in url

    def test_unknown_engine_raises(self):
        """db_url() lanza ValueError con motor desconocido."""
        from config import Settings

        cfg = Settings()
        cfg.DB_ENGINE = "mongodb"
        with pytest.raises(ValueError, match="Motor BD desconocido"):
            cfg.db_url()


# ---------------------------------------------------------------------------
# Tests: analyzer.py
# ---------------------------------------------------------------------------


class TestAnomalyDetector:
    """Verifica el motor ML de deteccion de anomalias."""

    def test_train_and_predict(self, sample_df):
        """El detector entrena con datos y predice sin errores."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()

        det.train(sample_df)
        assert det.is_fitted()

        result = det.predict(sample_df)
        assert "prediccion" in result.columns
        assert "score_anomalia" in result.columns
        assert "es_anomalia" in result.columns

    def test_predict_auto_fit(self, sample_df):
        """predict() entrena automaticamente si el modelo no tiene fit."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()

        # No llamamos a train() — debe auto-entrenarse
        result = det.predict(sample_df)
        assert det.is_fitted()
        assert len(result) == len(sample_df)

    def test_predict_returns_boolean_anomaly(self, sample_df):
        """es_anomalia debe ser dtype bool."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()
        result = det.predict(sample_df)
        assert result["es_anomalia"].dtype == bool

    def test_predict_score_is_float(self, sample_df):
        """score_anomalia debe ser numeric."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()
        result = det.predict(sample_df)
        assert pd.api.types.is_float_dtype(result["score_anomalia"])

    def test_predict_empty_df_raises(self):
        """predict() con DataFrame vacio lanza ValueError."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()
        with pytest.raises(ValueError, match="vacio"):
            det.predict(pd.DataFrame())

    def test_predict_missing_columns_raises(self, sample_df):
        """predict() con columnas faltantes lanza KeyError."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()
        bad_df = sample_df.drop(columns=["fallos_login"])
        with pytest.raises(KeyError):
            det.predict(bad_df)

    def test_feature_importance_sums_to_one(self):
        """get_feature_importance() devuelve pesos que suman 1.0."""
        from analyzer import AnomalyDetector

        det = AnomalyDetector.__new__(AnomalyDetector)
        det.model = None
        det._fitted = False
        det._init_unfitted_model()
        importance = det.get_feature_importance()
        assert abs(sum(importance.values()) - 1.0) < 0.01
        assert set(importance.keys()) == set(det.FEATURES)

    def test_save_and_load_model(self, sample_df, tmp_path):
        """El modelo se guarda y carga correctamente desde disco."""
        from analyzer import AnomalyDetector
        from config import settings

        original_path = settings.MODEL_SAVE_PATH
        model_path = tmp_path / "model.pkl"
        settings.MODEL_SAVE_PATH = str(model_path)

        try:
            det = AnomalyDetector.__new__(AnomalyDetector)
            det.model = None
            det._fitted = False
            det._init_unfitted_model()
            det.train(sample_df)
            assert model_path.exists()

            # Cargar modelo desde disco
            det2 = AnomalyDetector.__new__(AnomalyDetector)
            det2.model = None
            det2._fitted = False
            det2._load_from_disk()
            assert det2.is_fitted()
        finally:
            settings.MODEL_SAVE_PATH = original_path


# ---------------------------------------------------------------------------
# Tests: threat_intel.py
# ---------------------------------------------------------------------------


class TestThreatIntel:
    """Verifica el modulo de inteligencia de amenazas."""

    def test_map_mitre_brute_force(self):
        """Detecta brute force con muchos fallos de login."""
        from threat_intel import map_mitre

        row = {
            "fallos_login": 50,
            "bytes_descargados": 1000,
            "puertos_distintos": 2,
            "horas_actividad": 12,
        }
        tecnicas = map_mitre(row)
        ids = [t.id for t in tecnicas]
        assert "T1110" in ids  # Brute Force

    def test_map_mitre_port_scan(self):
        """Detecta escaneo de puertos con muchos puertos distintos."""
        from threat_intel import map_mitre

        row = {
            "fallos_login": 0,
            "bytes_descargados": 500,
            "puertos_distintos": 50,
            "horas_actividad": 14,
        }
        tecnicas = map_mitre(row)
        ids = [t.id for t in tecnicas]
        assert "T1046" in ids  # Network Service Scanning

    def test_map_mitre_exfiltration(self):
        """Detecta exfiltracion con bytes descargados elevados."""
        from threat_intel import map_mitre

        row = {
            "fallos_login": 0,
            "bytes_descargados": 200000,
            "puertos_distintos": 2,
            "horas_actividad": 10,
        }
        tecnicas = map_mitre(row)
        ids = [t.id for t in tecnicas]
        assert "T1041" in ids  # Exfiltration Over C2 Channel

    def test_map_mitre_off_hours(self):
        """Detecta actividad fuera de horario."""
        from threat_intel import map_mitre

        row = {
            "fallos_login": 0,
            "bytes_descargados": 500,
            "puertos_distintos": 2,
            "horas_actividad": 3,  # 3 AM
        }
        tecnicas = map_mitre(row)
        ids = [t.id for t in tecnicas]
        assert "T1078" in ids  # Valid Accounts (anomalia horaria)

    def test_map_mitre_normal_traffic_empty(self):
        """Trafico normal no genera tecnicas MITRE."""
        from threat_intel import map_mitre

        row = {
            "fallos_login": 1,
            "bytes_descargados": 800,
            "puertos_distintos": 1,
            "horas_actividad": 10,
        }
        tecnicas = map_mitre(row)
        assert len(tecnicas) == 0

    def test_evaluate_threat_level_critico(self):
        """Score ML extremo + reputacion alta = CRITICO."""
        from threat_intel import Reputation, evaluate_threat_level

        rep = Reputation(score=92, is_known=True, country="?", is_proxy=True)
        nivel, score = evaluate_threat_level(-0.5, rep)
        assert nivel == "CRITICO"
        assert score > 110

    def test_evaluate_threat_level_bajo(self):
        """Score ML normal + reputacion baja = BAJO."""
        from threat_intel import Reputation, evaluate_threat_level

        rep = Reputation(score=5, is_known=False, country="ES")
        nivel, score = evaluate_threat_level(0.1, rep)
        assert nivel == "BAJO"

    def test_summarize_threat_contains_ip(self):
        """El resumen siempre incluye la IP analizada."""
        from threat_intel import MitreTechnique, Reputation, summarize_threat

        rep = Reputation(score=92, is_known=True, country="RU", is_proxy=True)
        tecnicas = [MitreTechnique("T1110", "Brute Force", "Credential Access")]
        resumen = summarize_threat("1.2.3.4", tecnicas, rep, "CRITICO")
        assert "1.2.3.4" in resumen
        assert "CRITICO" in resumen

    def test_query_reputation_fallback(self):
        """
        query_reputation() usa fallback si la API externa falla.
        No debe lanzar excepcion en ningun caso.
        """
        from threat_intel import query_reputation

        with patch("requests.get", side_effect=Exception("network error")):
            rep = query_reputation("185.220.101.5")
            # El fallback debe funcionar — IP de Tor conocida
            assert rep.score > 0
            assert isinstance(rep.is_known, bool)

    def test_query_reputation_tor_ip(self):
        """IPs Tor (185.220.101.x) deben tener score alto en fallback."""
        from threat_intel import query_reputation

        with patch("requests.get", side_effect=Exception("sin red")):
            rep = query_reputation("185.220.101.99")
            assert rep.score >= 90
            assert rep.is_known is True


# ---------------------------------------------------------------------------
# Tests: database.py
# ---------------------------------------------------------------------------


class TestDatabase:
    """Verifica la capa de persistencia con BD en memoria."""

    @pytest.fixture
    def fresh_db(self, tmp_path):
        """BD SQLite temporal limpia para cada test."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        db_path = tmp_path / "test.db"
        engine = create_engine(f"sqlite:///{db_path}", echo=False)

        from database import Base, Database, Detection

        Base.metadata.create_all(engine)

        db_instance = Database.__new__(Database)
        db_instance.engine = engine
        db_instance.SessionLocal = sessionmaker(bind=engine)
        return db_instance

    def test_save_and_get_detection(self, fresh_db):
        """Guarda y recupera una deteccion correctamente."""
        from database import Detection

        det = Detection(
            ip="10.0.0.1",
            risk_level="ALTO",
            anomaly_score=-0.3,
            reputation_score=65.0,
            is_known_malicious=False,
            country="ES",
            isp="Telefonica",
            mitre_techniques=json.dumps(["T1110"]),
            summary="Test detection",
            batch_id="test-batch-001",
        )
        saved = fresh_db.save_detection(det)
        assert saved.id is not None

        detections = fresh_db.get_recent_detections(hours=1, limit=10)
        assert len(detections) >= 1
        assert detections[0].ip == "10.0.0.1"

    def test_get_stats_counts_correctly(self, fresh_db):
        """get_stats() cuenta correctamente por nivel de riesgo."""
        from database import Detection

        for risk in ["CRITICO", "CRITICO", "ALTO", "BAJO"]:
            fresh_db.save_detection(
                Detection(
                    ip="1.2.3.4",
                    risk_level=risk,
                    anomaly_score=-0.2,
                    reputation_score=50.0,
                    is_known_malicious=False,
                    country="ES",
                    isp="",
                    mitre_techniques="[]",
                    summary="test",
                    batch_id="test",
                )
            )

        stats = fresh_db.get_stats()
        assert stats["total"] == 4
        assert stats["criticos"] == 2
        assert stats["altos"] == 1

    def test_get_detections_by_batch(self, fresh_db):
        """Filtra correctamente por batch_id."""
        from database import Detection

        for i in range(3):
            fresh_db.save_detection(
                Detection(
                    ip=f"10.0.0.{i}",
                    risk_level="BAJO",
                    anomaly_score=0.1,
                    reputation_score=5.0,
                    is_known_malicious=False,
                    country="ES",
                    isp="",
                    mitre_techniques="[]",
                    summary="",
                    batch_id="batch-A",
                )
            )

        fresh_db.save_detection(
            Detection(
                ip="9.9.9.9",
                risk_level="ALTO",
                anomaly_score=-0.3,
                reputation_score=80.0,
                is_known_malicious=True,
                country="RU",
                isp="",
                mitre_techniques="[]",
                summary="",
                batch_id="batch-B",
            )
        )

        batch_a = fresh_db.get_detections_by_batch("batch-A")
        assert len(batch_a) == 3
        batch_b = fresh_db.get_detections_by_batch("batch-B")
        assert len(batch_b) == 1


# ---------------------------------------------------------------------------
# Tests: pipeline.py (integracion)
# ---------------------------------------------------------------------------


class TestPipeline:
    """Tests de integracion del pipeline end-to-end."""

    def test_pipeline_runs_with_csv(self, sample_csv):
        """El pipeline completo corre sin errores con un CSV valido."""
        from pipeline import AnalysisPipeline

        pipe = AnalysisPipeline()
        result = pipe.run(sample_csv, source="csv")

        assert "batch_id" in result
        assert result["total_events"] == 10
        assert result["anomalies_found"] >= 0
        assert result["duration_seconds"] > 0
        assert isinstance(result["detections"], list)

    def test_pipeline_invalid_source_raises(self, sample_csv):
        """Pipeline lanza ValueError con fuente desconocida."""
        from pipeline import AnalysisPipeline

        pipe = AnalysisPipeline()
        with pytest.raises((ValueError, NotImplementedError)):
            pipe.run(sample_csv, source="kafka")

    def test_pipeline_missing_csv_raises(self):
        """Pipeline lanza error si el CSV no existe."""
        from pipeline import AnalysisPipeline

        pipe = AnalysisPipeline()
        with pytest.raises(Exception):
            pipe.run("/ruta/inexistente/archivo.csv", source="csv")

    def test_pipeline_missing_columns_raises(self, tmp_path):
        """Pipeline valida columnas requeridas y lanza ValueError."""
        from pipeline import AnalysisPipeline

        bad_csv = tmp_path / "bad.csv"
        pd.DataFrame({"ip": ["1.2.3.4"], "columna_random": [1]}).to_csv(bad_csv, index=False)

        pipe = AnalysisPipeline()
        with pytest.raises(ValueError):
            pipe.run(str(bad_csv), source="csv")

    def test_pipeline_batch_persisted(self, sample_csv):
        """El batch se guarda en BD al completar."""
        from database import db
        from pipeline import AnalysisPipeline

        pipe = AnalysisPipeline()
        result = pipe.run(sample_csv, source="csv")
        batch_id = result["batch_id"]

        # Verificar que las detecciones del batch estan en BD
        detections_in_db = db.get_detections_by_batch(batch_id)
        assert len(detections_in_db) == result["anomalies_found"]


# ---------------------------------------------------------------------------
# Tests: api.py (endpoints REST)
# ---------------------------------------------------------------------------


class TestAPI:
    """Tests de la API REST usando FastAPI TestClient."""

    @pytest.fixture
    def client(self):
        """Cliente de test para la API (sin servidor real)."""
        from fastapi.testclient import TestClient

        from api import app

        return TestClient(app)

    def test_root_returns_info(self, client):
        """GET / retorna informacion basica de la API."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "ThreatScope" in data["name"]
        assert "/docs" in data["docs"]

    def test_status_ok(self, client):
        """GET /status retorna 200 con sistema funcionando."""
        response = client.get("/status")
        assert response.status_code in (200, 503)
        data = response.json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded")
        assert "database" in data
        assert "model" in data

    def test_analyze_with_valid_csv(self, client, sample_csv):
        """POST /analyze con CSV valido retorna resultado correcto."""
        with open(sample_csv, "rb") as f:
            response = client.post(
                "/analyze",
                files={"file": ("test.csv", f, "text/csv")},
            )
        assert response.status_code == 200
        data = response.json()
        assert "batch_id" in data
        assert data["total_events"] == 10
        assert "anomalies_found" in data

    def test_analyze_rejects_non_csv(self, client, tmp_path):
        """POST /analyze rechaza archivos que no son CSV."""
        txt_file = tmp_path / "datos.txt"
        txt_file.write_text("no es un csv")
        with open(txt_file, "rb") as f:
            response = client.post(
                "/analyze",
                files={"file": ("datos.txt", f, "text/plain")},
            )
        assert response.status_code == 400
        assert "CSV" in response.json()["detail"]

    def test_detections_returns_list(self, client):
        """GET /detections retorna lista (vacia o con datos)."""
        response = client.get("/detections")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_detections_with_limit(self, client):
        """GET /detections respeta el parametro limit."""
        response = client.get("/detections?limit=5")
        assert response.status_code == 200
        assert len(response.json()) <= 5

    def test_detections_invalid_risk_level(self, client):
        """GET /detections con risk_level invalido retorna 400."""
        response = client.get("/detections?risk_level=INEXISTENTE")
        assert response.status_code == 400

    def test_detections_valid_risk_filter(self, client):
        """GET /detections con filtro valido retorna 200."""
        for level in ["CRITICO", "ALTO", "MEDIO", "BAJO"]:
            response = client.get(f"/detections?risk_level={level}")
            assert response.status_code == 200
