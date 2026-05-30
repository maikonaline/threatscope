"""
analyzer.py
-----------
Motor de deteccion de anomalias con Isolation Forest (no supervisado).

Isolation Forest es ideal para ciberseguridad porque:
- No necesita datos etiquetados (ataques son raros y no siempre conocidos)
- Funciona bien con datasets desbalanceados (pocos ataques vs. mucho trafico normal)
- Score continuo permite priorizar alertas por severidad

Uso:
    from analyzer import detector
    df_con_scores = detector.predict(df)
    # df ahora tiene columnas: prediccion, score_anomalia, es_anomalia
"""

import pickle
from pathlib import Path
from typing import Dict
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
from config import settings
from logger import get_logger

log = get_logger(__name__)


class AnomalyDetector:
    """
    Detector de anomalias con Isolation Forest.

    Ciclo de vida del modelo:
    1. Al inicializar: intenta cargar modelo serializado desde disco.
    2. Si no existe modelo guardado: se inicializa sin entrenar (lazy training).
    3. En predict(): si el modelo no esta entrenado, lo entrena con los datos
       recibidos (auto-fit). Esto permite funcionar desde el primer uso.
    4. Tras entrenar: persiste el modelo a disco para sesiones futuras.

    Attributes:
        model: instancia de IsolationForest de sklearn.
        FEATURES: lista de columnas numericas que usa el modelo.
    """

    FEATURES = [
        "intentos_login",
        "fallos_login",
        "bytes_descargados",
        "horas_actividad",
        "puertos_distintos",
    ]

    def __init__(self):
        """Inicializa el detector e intenta cargar modelo existente."""
        self.model = None
        self._fitted = False
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        """
        Intenta cargar un modelo previamente entrenado desde disco.

        Si el archivo existe y es valido, lo carga. Si falla (corrupcion,
        version incompatible), registra el warning y continua sin modelo.

        Returns:
            None
        """
        model_path = Path(settings.MODEL_SAVE_PATH)
        if not model_path.exists():
            log.info("No hay modelo guardado en disco. Se entrenara al primer uso.")
            self._init_unfitted_model()
            return

        try:
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            self._fitted = True
            log.info(f"Modelo cargado desde {model_path}")
        except Exception as e:
            log.warning(f"No se pudo cargar modelo guardado ({e}). Se entrenara de nuevo.")
            self._init_unfitted_model()

    def _init_unfitted_model(self) -> None:
        """Crea instancia de IsolationForest sin entrenar."""
        self.model = IsolationForest(
            n_estimators=settings.ML_N_ESTIMATORS,
            contamination=settings.ML_CONTAMINATION,
            random_state=settings.ML_RANDOM_STATE,
        )
        self._fitted = False

    def train(self, df: pd.DataFrame) -> None:
        """
        Entrena el modelo con un DataFrame de eventos de red.

        El modelo aprende la distribucion normal del trafico. Los eventos
        que se alejan de esa distribucion seran marcados como anomalias.

        Args:
            df: DataFrame con columnas en FEATURES. Debe tener al menos
                2 filas para que IsolationForest funcione correctamente.

        Returns:
            None

        Raises:
            KeyError: si el DataFrame no tiene las columnas requeridas.
            ValueError: si el DataFrame esta vacio o tiene datos invalidos.
        """
        try:
            X = df[self.FEATURES].astype(float)
            self.model = IsolationForest(
                n_estimators=settings.ML_N_ESTIMATORS,
                contamination=settings.ML_CONTAMINATION,
                random_state=settings.ML_RANDOM_STATE,
            )
            self.model.fit(X)
            self._fitted = True
            self._save()
            log.info(f"Modelo entrenado con {len(df)} muestras y guardado en disco.")
        except KeyError as e:
            log.error(f"Columna requerida no encontrada: {e}")
            raise
        except Exception as e:
            log.error(f"Error entrenando modelo: {e}")
            raise

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analiza un DataFrame y agrega columnas de anomalia.

        Si el modelo no esta entrenado, lo entrena con los mismos datos
        recibidos (auto-fit). Esto es aceptable porque IsolationForest
        es no supervisado: aprende la normalidad del batch actual.

        Args:
            df: DataFrame con columnas en FEATURES mas columna 'ip'.

        Returns:
            DataFrame original con tres columnas adicionales:
            - prediccion (int): -1 = anomalia, 1 = normal
            - score_anomalia (float): mas negativo = mas anomalo (rango tipico -0.5 a 0.5)
            - es_anomalia (bool): True si prediccion == -1

        Raises:
            KeyError: si el DataFrame no tiene las columnas requeridas.
            ValueError: si el DataFrame esta vacio.
        """
        if df.empty:
            raise ValueError("El DataFrame esta vacio. No hay datos para analizar.")

        # Auto-fit si el modelo no ha sido entrenado aun
        if not self._fitted:
            log.info("Modelo sin entrenar. Entrenando con datos del batch actual...")
            self.train(df)

        try:
            X = df[self.FEATURES].astype(float)
            df = df.copy()  # no mutar el DataFrame original
            df["prediccion"] = self.model.predict(X)       # -1=anomalia, 1=normal
            df["score_anomalia"] = self.model.decision_function(X)  # mas negativo = mas anomalo
            df["es_anomalia"] = df["prediccion"] == -1
            n_anomalias = int(df["es_anomalia"].sum())
            log.info(f"Analisis completado: {n_anomalias} anomalias de {len(df)} eventos "
                     f"({n_anomalias/len(df)*100:.1f}%)")
            return df
        except KeyError as e:
            log.error(f"Columna requerida no encontrada en datos: {e}")
            raise
        except Exception as e:
            log.error(f"Error en prediccion: {e}")
            raise

    def _save(self) -> None:
        """
        Persiste el modelo entrenado a disco en formato pickle.

        Args:
            None

        Returns:
            None — falla silenciosamente si no puede escribir (loggea el error).
        """
        try:
            model_path = Path(settings.MODEL_SAVE_PATH)
            model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            log.info(f"Modelo guardado en {model_path}")
        except Exception as e:
            log.error(f"Error guardando modelo (no critico): {e}")

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Retorna una aproximacion uniforme de importancia de features.

        Isolation Forest no provee importancia de features nativa.
        Se retorna distribucion uniforme como placeholder. En produccion
        se puede usar SHAP para interpretabilidad real.

        Returns:
            Dict con nombre de feature como clave y peso como valor.
            Todos los pesos suman 1.0.
        """
        n = len(self.FEATURES)
        return {feat: round(1.0 / n, 4) for feat in self.FEATURES}

    def is_fitted(self) -> bool:
        """
        Indica si el modelo ha sido entrenado.

        Returns:
            bool: True si el modelo tiene un fit() aplicado.
        """
        return self._fitted


# Instancia global — compartida entre modulos
detector = AnomalyDetector()
