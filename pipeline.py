"""
pipeline.py
-----------
Orquestador del análisis: ingesta -> ML -> enriquecimiento -> persistencia.
Manejo robusto de errores y logging detallado.
"""

import uuid
import time
import json
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd
from pathlib import Path

from config import settings
from logger import get_logger
from database import db, Detection, AnalysisBatch
from analyzer import detector
from threat_intel import (
    query_reputation, map_mitre, evaluate_threat_level, summarize_threat
)

log = get_logger(__name__)


class AnalysisPipeline:
    """Pipeline end-to-end de detección de amenazas."""

    def __init__(self):
        self.batch_id = None
        self.df = None

    def load_csv(self, filepath: str) -> pd.DataFrame:
        """Carga un CSV de eventos."""
        try:
            self.df = pd.read_csv(filepath)
            log.info(f"CSV cargado: {filepath} ({len(self.df)} filas)")
            return self.df
        except Exception as e:
            log.error(f"Error cargando CSV {filepath}: {e}")
            raise

    def load_sql(self, query: str, connection_string: str = None) -> pd.DataFrame:
        """Carga eventos desde BD (PostgreSQL, MySQL, etc.)"""
        try:
            if connection_string is None:
                connection_string = settings.db_url()
            self.df = pd.read_sql(query, connection_string)
            log.info(f"Datos cargados desde SQL: {len(self.df)} filas")
            return self.df
        except Exception as e:
            log.error(f"Error cargando desde SQL: {e}")
            raise

    def validate_data(self) -> bool:
        """Valida que el DataFrame tiene las columnas requeridas."""
        required = ["ip", "intentos_login", "fallos_login", "bytes_descargados",
                   "horas_actividad", "puertos_distintos"]
        if not all(col in self.df.columns for col in required):
            missing = [c for c in required if c not in self.df.columns]
            log.error(f"Columnas faltantes en datos: {missing}")
            raise ValueError(f"Columnas requeridas: {required}")
        return True

    def run(self, filepath: str = None, source: str = "csv") -> Dict:
        """
        Ejecuta el pipeline completo.
        
        Args:
            filepath: ruta del CSV o conexión
            source: tipo de fuente (csv, postgresql, etc.)
        
        Returns:
            dict con resultados y estadísticas
        """
        start = time.time()
        self.batch_id = str(uuid.uuid4())
        batch = AnalysisBatch(id=self.batch_id, source=source, status="running")
        db.save_batch(batch)

        try:
            # 1. INGESTA
            log.info(f"[{self.batch_id}] Iniciando análisis...")
            if source == "csv":
                self.load_csv(filepath)
            elif source == "sql":
                # Por implementar: conexión real a BD
                raise NotImplementedError("SQL source no implementado aún")
            else:
                raise ValueError(f"Fuente desconocida: {source}")

            # 2. VALIDACIÓN
            self.validate_data()
            batch.total_events = len(self.df)

            # 3. ANÁLISIS ML
            log.info(f"[{self.batch_id}] Ejecutando Isolation Forest...")
            self.df = detector.predict(self.df)

            # 4. ENRIQUECIMIENTO
            log.info(f"[{self.batch_id}] Enriqueciendo con Threat Intel...")
            detections = []
            for idx, row in self.df[self.df["es_anomalia"]].iterrows():
                try:
                    rep = query_reputation(row["ip"])
                    tecnicas = map_mitre(row)
                    nivel, score = evaluate_threat_level(row["score_anomalia"], rep)
                    resumen = summarize_threat(row["ip"], tecnicas, rep, nivel)

                    det = Detection(
                        ip=row["ip"],
                        risk_level=nivel,
                        anomaly_score=float(row["score_anomalia"]),
                        reputation_score=rep.score,
                        is_known_malicious=rep.is_known,
                        country=rep.country,
                        isp="",
                        mitre_techniques=json.dumps([t.id for t in tecnicas]),
                        summary=resumen,
                        batch_id=self.batch_id,
                    )
                    db.save_detection(det)
                    detections.append(det)

                    # Disparar notificaciones para niveles CRITICO y ALTO
                    if det.risk_level in ("CRITICO", "ALTO"):
                        try:
                            from notifier import send_alerts
                            detection_dict = {
                                "ip":               det.ip,
                                "risk_level":       det.risk_level,
                                "anomaly_score":    det.anomaly_score,
                                "reputation_score": det.reputation_score,
                                "is_known_malicious": det.is_known_malicious,
                                "country":          det.country,
                                "mitre_techniques": json.loads(det.mitre_techniques)
                                                    if det.mitre_techniques else [],
                                "summary":          det.summary,
                                "batch_id":         self.batch_id,
                            }
                            send_alerts(detection_dict)
                        except Exception as notify_err:
                            # El notifier no puede crashear el pipeline
                            log.warning(f"Error disparando notificaciones para IP {det.ip}: {notify_err}")

                except Exception as e:
                    log.warning(f"Error procesando IP {row['ip']}: {e}")
                    continue

            # 5. GUARDAR BATCH
            batch.anomalies_found = len(detections)
            batch.status = "completed"
            batch.completed_at = datetime.utcnow()
            duration = time.time() - start
            batch.duration_seconds = duration
            db.save_batch(batch)

            log.info(f"[{self.batch_id}] Análisis completado en {duration:.2f}s: "
                    f"{len(detections)} anomalías de {len(self.df)} eventos")

            return {
                "batch_id": self.batch_id,
                "total_events": len(self.df),
                "anomalies_found": len(detections),
                "duration_seconds": duration,
                "detections": [
                    {
                        "ip": d.ip,
                        "risk": d.risk_level,
                        "score": d.anomaly_score,
                        "summary": d.summary,
                    }
                    for d in detections
                ],
            }

        except Exception as e:
            batch.status = "failed"
            batch.error_message = str(e)
            batch.completed_at = datetime.utcnow()
            db.save_batch(batch)
            log.error(f"[{self.batch_id}] Pipeline falló: {e}")
            raise


# Instancia global
pipeline = AnalysisPipeline()
