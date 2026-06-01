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

import joblib
from pathlib import Path
from typing import Dict, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
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
        """Inicializa el detector. Carga modelo de disco o entrena con baseline sintético."""
        self.model = None
        self._fitted = False
        self._training_sample: Optional[pd.DataFrame] = None
        self._load_from_disk()
        if not self._fitted:
            self._train_baseline()

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
            self.model = joblib.load(model_path)
            self._fitted = True
            log.info(f"Modelo cargado desde {model_path}")
        except Exception as e:
            log.warning(f"No se pudo cargar modelo guardado ({e}). Se entrenará con baseline.")
            self._init_unfitted_model()

    def _init_unfitted_model(self) -> None:
        """Crea instancia de IsolationForest sin entrenar."""
        self.model = IsolationForest(
            n_estimators=settings.ML_N_ESTIMATORS,
            contamination=settings.ML_CONTAMINATION,
            random_state=settings.ML_RANDOM_STATE,
        )
        self._fitted = False

    def _train_baseline(self) -> None:
        """
        Entrena el modelo con tráfico de red sintético y normal como referencia.

        Esto es crítico: el modelo debe aprender qué es "normal" antes de ver
        datos reales. Si entrenamos con el CSV de análisis, un batch de puro
        tráfico malicioso sería clasificado como "normal". El baseline garantiza
        que el modelo tiene una distribución de referencia correcta.
        """
        rng = np.random.default_rng(settings.ML_RANDOM_STATE)
        n = 500
        baseline = pd.DataFrame({
            "intentos_login":    rng.poisson(lam=3, size=n).clip(0, 20).astype(float),
            "fallos_login":      rng.poisson(lam=1, size=n).clip(0, 5).astype(float),
            "bytes_descargados": rng.lognormal(mean=8.5, sigma=1.2, size=n),   # ~5KB median
            "horas_actividad":   rng.integers(8, 19, size=n).astype(float),    # horario laboral
            "puertos_distintos": rng.choice([1, 1, 1, 2, 2, 3], size=n).astype(float),
        })
        self.train(baseline)
        log.info("Modelo inicializado con baseline sintético (500 muestras de tráfico normal).")

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
            self._training_sample = X.sample(min(100, len(X)), random_state=settings.ML_RANDOM_STATE)
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

        if not self._fitted:
            raise RuntimeError("El modelo no está entrenado. Llama a train() o _train_baseline() primero.")

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
            joblib.dump(self.model, model_path)
            log.info(f"Modelo guardado en {model_path}")
        except Exception as e:
            log.error(f"Error guardando modelo (no critico): {e}")

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Calcula importancia real de features usando SHAP (SHapley Additive exPlanations).

        SHAP mide cuánto contribuye cada feature a la decisión del modelo para cada
        muestra del training set. El valor absoluto promedio es la importancia global.

        Si SHAP no está instalado, usa distribución uniforme como fallback.
        """
        if not self._fitted or self._training_sample is None:
            n = len(self.FEATURES)
            return {feat: round(1.0 / n, 4) for feat in self.FEATURES}

        try:
            import shap
            explainer = shap.TreeExplainer(self.model)
            shap_values = explainer.shap_values(self._training_sample)
            importances = np.abs(shap_values).mean(axis=0)
            total = importances.sum()
            if total > 0:
                normalized = importances / total
            else:
                normalized = np.ones(len(self.FEATURES)) / len(self.FEATURES)
            return {feat: round(float(val), 4) for feat, val in zip(self.FEATURES, normalized)}
        except Exception as e:
            log.warning(f"SHAP no disponible ({e}). Usando distribución uniforme.")
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
