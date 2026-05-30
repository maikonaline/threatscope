"""
database.py
-----------
Capa de persistencia. Guarda histórico de detecciones y eventos.
Usa SQLAlchemy para ser agnóstico a la BD (SQLite, PostgreSQL, etc.)
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings
from logger import get_logger

log = get_logger(__name__)

Base = declarative_base()


class Detection(Base):
    """Modelo: una detección de anomalía."""

    __tablename__ = "detections"

    id = Column(Integer, primary_key=True)
    ip = Column(String(15), nullable=False, index=True)
    risk_level = Column(String(10), nullable=False)  # CRITICO, ALTO, MEDIO, BAJO
    anomaly_score = Column(Float, nullable=False)
    reputation_score = Column(Float, nullable=False)
    is_known_malicious = Column(Boolean, default=False)
    country = Column(String(100), nullable=True)
    isp = Column(String(100), nullable=True)
    mitre_techniques = Column(String(500), nullable=True)  # JSON string
    summary = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    batch_id = Column(String(50), nullable=True, index=True)  # para agrupar análisis

    def __repr__(self):
        return f"<Detection ip={self.ip} risk={self.risk_level} score={self.anomaly_score:.2f}>"


class AnalysisBatch(Base):
    """Modelo: un lote de análisis (ejecutable una sola vez o programado)."""

    __tablename__ = "analysis_batches"

    id = Column(String(50), primary_key=True)  # UUID
    source = Column(String(100), nullable=False)  # csv, siem_splunk, api, etc.
    total_events = Column(Integer, default=0)
    anomalies_found = Column(Integer, default=0)
    duration_seconds = Column(Float, nullable=True)
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    error_message = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<AnalysisBatch id={self.id} status={self.status} anomalies={self.anomalies_found}>"


class Database:
    """Interfaz para la base de datos."""

    def __init__(self):
        self.engine = create_engine(settings.db_url(), echo=settings.DEBUG)
        self.SessionLocal = sessionmaker(bind=self.engine)
        log.info(f"BD conectada: {settings.DB_ENGINE} en {settings.DB_PATH}")

    def init_db(self):
        """Crea las tablas."""
        Base.metadata.create_all(self.engine)
        log.info("Tablas de BD inicializadas")

    def get_session(self):
        """Context manager para sesiones."""
        return self.SessionLocal()

    def save_detection(self, detection: Detection) -> Detection:
        """Guarda una detección."""
        session = self.get_session()
        try:
            session.add(detection)
            session.commit()
            log.debug(f"Detección guardada: {detection.ip} ({detection.risk_level})")
            return detection
        except Exception as e:
            session.rollback()
            log.error(f"Error guardando detección: {e}")
            raise
        finally:
            session.close()

    def save_batch(self, batch: AnalysisBatch):
        """Guarda metadatos de un lote de análisis."""
        session = self.get_session()
        try:
            session.add(batch)
            session.commit()
            return batch
        except Exception as e:
            session.rollback()
            log.error(f"Error guardando batch: {e}")
            raise
        finally:
            session.close()

    def get_detections_by_batch(self, batch_id: str) -> List[Detection]:
        """Obtiene todas las detecciones de un batch."""
        session = self.get_session()
        try:
            return session.query(Detection).filter_by(batch_id=batch_id).all()
        finally:
            session.close()

    def get_recent_detections(self, hours: int = 24, limit: int = 100) -> List[Detection]:
        """Obtiene detecciones recientes."""
        from datetime import timedelta
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            return (
                session.query(Detection)
                .filter(Detection.created_at >= since)
                .order_by(Detection.created_at.desc())
                .limit(limit)
                .all()
            )
        finally:
            session.close()

    def get_stats(self) -> dict:
        """Estadísticas generales."""
        session = self.get_session()
        try:
            total = session.query(Detection).count()
            criticos = session.query(Detection).filter_by(risk_level="CRITICO").count()
            altos = session.query(Detection).filter_by(risk_level="ALTO").count()
            return {"total": total, "criticos": criticos, "altos": altos}
        finally:
            session.close()


# Instancia global
db = Database()
