"""
threat_intel.py
---------------
Enriquecimiento de IPs con reputación externa y MITRE ATT&CK.
Incluye manejo de errores, caché, y fallback a datos simulados.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import requests
from config import settings
from logger import get_logger

log = get_logger(__name__)


@dataclass
class Reputation:
    """Resultado de consulta de reputación."""
    score: float  # 0-100
    is_known: bool
    country: str
    is_proxy: bool = False
    is_hosting: bool = False


@dataclass
class MitreTechnique:
    """Una técnica de MITRE ATT&CK."""
    id: str
    name: str
    tactic: str


# Base de datos de técnicas (simplificada; en prod. se consultaría a la API de MITRE)
MITRE_DB = {
    "T1110": MitreTechnique("T1110", "Brute Force", "Credential Access"),
    "T1046": MitreTechnique("T1046", "Network Service Scanning", "Discovery"),
    "T1041": MitreTechnique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    "T1078": MitreTechnique("T1078", "Valid Accounts (anomalía horaria)", "Defense Evasion"),
    "T1090.003": MitreTechnique("T1090.003", "Proxy: Multi-hop Proxy (Tor)", "Command and Control"),
}


def query_reputation(ip: str) -> Reputation:
    """
    Consulta reputación de una IP.
    En producción: AbuseIPDB, VirusTotal, etc.
    Aquí: lógica heurística + simulación para funcionar sin API key.
    """
    try:
        # Intenta consultar ipwho.is para datos reales de red
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=settings.IPWHOIS_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            org = ((data.get("connection", {}).get("org", "") + " " +
                   data.get("connection", {}).get("isp", "")).lower())
            country = data.get("country", "??")

            # Heurísticas basadas en el tipo de red
            is_tor = ip.startswith("185.220.101.") or "tor" in org
            is_proxy = "proxy" in org or "vpn" in org or data.get("proxy") == True
            is_hosting = any(x in org for x in ["host", "cloud", "server", "datacenter", "ovh", "digital", "aws"])

            score = 92 if is_tor else (65 if is_proxy else (45 if is_hosting else 5))
            return Reputation(
                score=score,
                is_known=is_tor or is_proxy,
                country=country,
                is_proxy=is_proxy,
                is_hosting=is_hosting,
            )
    except requests.Timeout:
        log.warning(f"Timeout consultando ipwho.is para {ip}")
    except Exception as e:
        log.warning(f"Error consultando threat intel para {ip}: {e}")

    # Fallback: lógica simple sin API
    is_tor = ip.startswith("185.220.101.")
    is_proxy = ip.startswith(("45.", "193.", "194."))
    score = 92 if is_tor else (60 if is_proxy else 5)
    return Reputation(
        score=score,
        is_known=is_tor or is_proxy,
        country="??" if is_proxy else "ES",
        is_proxy=is_proxy,
        is_hosting=False,
    )


def map_mitre(row: dict) -> List[MitreTechnique]:
    """
    Mapea el comportamiento de una IP a técnicas MITRE.
    row debe tener: fallos_login, bytes_descargados, puertos_distintos, horas_actividad
    """
    tecnicas = []

    fallos = float(row.get("fallos_login", 0))
    bytes_down = float(row.get("bytes_descargados", 0))
    puertos = float(row.get("puertos_distintos", 0))
    hora = float(row.get("horas_actividad", 12))

    if fallos > 30:
        tecnicas.append(MITRE_DB["T1110"])
    if puertos > 15:
        tecnicas.append(MITRE_DB["T1046"])
    if bytes_down > 100000:
        tecnicas.append(MITRE_DB["T1041"])
    if hora < 6 or hora > 22:
        tecnicas.append(MITRE_DB["T1078"])

    return tecnicas


def evaluate_threat_level(anomaly_score: float, rep: Reputation) -> Tuple[str, float]:
    """
    Combina score ML + reputación para obtener nivel de riesgo final.
    Devuelve (nivel: str, score: float)
    """
    combined = (abs(min(anomaly_score, 0)) * 200) + rep.score

    if combined > 110:
        return "CRITICO", combined
    elif combined > 70:
        return "ALTO", combined
    elif combined > 40:
        return "MEDIO", combined
    else:
        return "BAJO", combined


def summarize_threat(ip: str, tecnicas: List[MitreTechnique], rep: Reputation, nivel: str) -> str:
    """Genera un resumen descriptivo de la alerta."""
    tecnicas_txt = ", ".join(f"{t.id} ({t.name})" for t in tecnicas) or "comportamiento anómalo"
    accion = "Bloquear inmediatamente en firewall." if nivel in ("CRITICO", "ALTO") else "Monitorizar."
    return (
        f"IP {ip} presenta riesgo {nivel} (reputación {rep.score:.0f}/100, "
        f"conocida maliciosa: {'SÍ' if rep.is_known else 'NO'}, "
        f"país: {rep.country}). Patrones: {tecnicas_txt}. Acción: {accion}"
    )
