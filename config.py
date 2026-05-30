"""
config.py
---------
Configuración centralizada. Lee desde variables de entorno.
Uso: from config import Settings; cfg = Settings()
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    """Configuración del sistema ThreatScope."""

    # ENTORNO
    ENV: str = os.getenv("THREATSCOPE_ENV", "development")
    DEBUG: bool = os.getenv("THREATSCOPE_DEBUG", "false").lower() == "true"

    # RUTAS
    PROJECT_ROOT: Path = Path(__file__).parent
    DATA_DIR: Path = PROJECT_ROOT / "data"
    LOGS_DIR: Path = PROJECT_ROOT / "logs"
    MODELS_DIR: Path = PROJECT_ROOT / "models"

    # BASE DE DATOS
    DB_ENGINE: str = os.getenv("THREATSCOPE_DB_ENGINE", "sqlite")  # sqlite, postgresql
    DB_PATH: str = os.getenv("THREATSCOPE_DB_PATH", str(DATA_DIR / "threatscope.db"))
    DB_HOST: str = os.getenv("THREATSCOPE_DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("THREATSCOPE_DB_PORT", "5432"))
    DB_USER: str = os.getenv("THREATSCOPE_DB_USER", "threatscope")
    DB_PASS: str = os.getenv("THREATSCOPE_DB_PASS", "")
    DB_NAME: str = os.getenv("THREATSCOPE_DB_NAME", "threatscope")

    # THREAT INTELLIGENCE
    ABUSEIPDB_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    IPWHOIS_TIMEOUT: int = int(os.getenv("IPWHOIS_TIMEOUT", "10"))

    # MODELO ML
    ML_CONTAMINATION: float = float(os.getenv("ML_CONTAMINATION", "0.05"))
    ML_N_ESTIMATORS: int = int(os.getenv("ML_N_ESTIMATORS", "100"))
    ML_RANDOM_STATE: int = int(os.getenv("ML_RANDOM_STATE", "42"))
    MODEL_SAVE_PATH: str = str(MODELS_DIR / "isolation_forest.pkl")

    # LOGGING
    LOG_LEVEL: str = os.getenv("THREATSCOPE_LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"

    # EJECUCIÓN
    BATCH_SIZE: int = int(os.getenv("THREATSCOPE_BATCH_SIZE", "1000"))
    WORKERS: int = int(os.getenv("THREATSCOPE_WORKERS", "4"))

    def __post_init__(self):
        """Crear directorios si no existen."""
        for d in [self.DATA_DIR, self.LOGS_DIR, self.MODELS_DIR]:
            d.mkdir(parents=True, exist_ok=True)

    def db_url(self) -> str:
        """Genera URL de conexión a BD según tipo."""
        if self.DB_ENGINE == "sqlite":
            return f"sqlite:///{self.DB_PATH}"
        elif self.DB_ENGINE == "postgresql":
            return f"postgresql://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        else:
            raise ValueError(f"Motor BD desconocido: {self.DB_ENGINE}")


# Instancia global
settings = Settings()
