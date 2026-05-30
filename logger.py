"""
logger.py
---------
Logging estructurado con rotacion de archivos.
Proporciona un logger consistente para todos los modulos del sistema.

Uso:
    from logger import get_logger, setup_logging
    log = get_logger(__name__)
    log.info("Mensaje informativo")
    log.warning("Advertencia")
    log.error("Error critico")
"""

import logging
import logging.handlers
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_dir: str = None) -> None:
    """
    Configura el sistema de logging global.

    Configura dos handlers:
    - StreamHandler: salida a consola (stdout)
    - RotatingFileHandler: archivo con rotacion (max 10MB, 5 backups)

    Args:
        level: nivel de log ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
               Por defecto 'INFO'.
        log_dir: directorio donde guardar el archivo de log.
                 Si es None, intenta leer desde settings.

    Returns:
        None

    Raises:
        ValueError: si el nivel de log no es valido.
    """
    try:
        from config import settings
        effective_level = settings.LOG_LEVEL if level == "INFO" else level
        log_format = settings.LOG_FORMAT
        if log_dir is None:
            log_dir = str(settings.LOGS_DIR)
    except Exception:
        effective_level = level
        log_format = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
        if log_dir is None:
            log_dir = "logs"

    numeric_level = getattr(logging, effective_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Nivel de log invalido: {effective_level}")

    # Crear directorio si no existe
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_file = Path(log_dir) / "threatscope.log"

    formatter = logging.Formatter(log_format)

    # Handler: consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)

    # Handler: archivo con rotacion
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(numeric_level)

    # Configurar root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Limpiar handlers existentes para evitar duplicados
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Obtiene un logger con el nombre dado.

    Llama a setup_logging() si el root logger no tiene handlers configurados,
    garantizando que siempre haya al menos un handler activo.

    Args:
        name: nombre del logger, tipicamente __name__ del modulo llamador.

    Returns:
        logging.Logger: instancia de logger configurada.

    Example:
        log = get_logger(__name__)
        log.info("Sistema iniciado")
        log.error("Fallo al conectar a BD: %s", error)
    """
    # Auto-inicializar si no hay handlers configurados
    if not logging.getLogger().handlers:
        setup_logging()
    return logging.getLogger(name)
