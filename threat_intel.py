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


# Base de datos de técnicas MITRE ATT&CK
MITRE_DB = {
    # Credential Access
    "T1110":     MitreTechnique("T1110",     "Brute Force",                       "Credential Access"),
    "T1110.001": MitreTechnique("T1110.001", "Brute Force: Password Guessing",    "Credential Access"),
    "T1110.003": MitreTechnique("T1110.003", "Brute Force: Password Spraying",    "Credential Access"),
    # Discovery
    "T1046":     MitreTechnique("T1046",     "Network Service Scanning",          "Discovery"),
    "T1018":     MitreTechnique("T1018",     "Remote System Discovery",           "Discovery"),
    "T1595":     MitreTechnique("T1595",     "Active Scanning",                   "Reconnaissance"),
    "T1595.001": MitreTechnique("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"),
    # Exfiltration
    "T1041":     MitreTechnique("T1041",     "Exfiltration Over C2 Channel",      "Exfiltration"),
    "T1048":     MitreTechnique("T1048",     "Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1071":     MitreTechnique("T1071",     "Application Layer Protocol",        "Command and Control"),
    # Defense Evasion / Persistence
    "T1078":     MitreTechnique("T1078",     "Valid Accounts",                    "Defense Evasion"),
    "T1078.003": MitreTechnique("T1078.003", "Valid Accounts: Local Accounts",    "Persistence"),
    # Command and Control
    "T1090.003": MitreTechnique("T1090.003", "Proxy: Multi-hop Proxy (Tor)",      "Command and Control"),
    "T1071.001": MitreTechnique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    # Impact
    "T1486":     MitreTechnique("T1486",     "Data Encrypted for Impact",         "Impact"),
    "T1485":     MitreTechnique("T1485",     "Data Destruction",                  "Impact"),
    # Collection
    "T1005":     MitreTechnique("T1005",     "Data from Local System",            "Collection"),
}


def _query_abuseipdb(ip: str) -> Optional[Reputation]:
    """
    Consulta AbuseIPDB API v2 para obtener reputación real de una IP.

    Solo se invoca si ABUSEIPDB_API_KEY está configurada en el entorno.
    Devuelve None en cualquier condición de error para permitir fallback.

    Args:
        ip: Dirección IP a consultar.

    Returns:
        Reputation con datos reales de AbuseIPDB, o None si falla o no hay key.
    """
    api_key = settings.ABUSEIPDB_KEY
    if not api_key:
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=settings.IPWHOIS_TIMEOUT,
        )

        if resp.status_code == 429:
            log.warning("AbuseIPDB: límite de requests diario alcanzado. Usando fallback.")
            return None

        if resp.status_code != 200:
            log.warning(f"AbuseIPDB respondió {resp.status_code} para {ip}. Usando fallback.")
            return None

        data = resp.json().get("data", {})
        abuse_score = float(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        country = data.get("countryCode") or "??"
        is_whitelisted = bool(data.get("isWhitelisted", False))

        # IP en whitelist de AbuseIPDB → reputación limpia
        if is_whitelisted:
            return Reputation(score=0.0, is_known=False, country=country)

        is_known_malicious = total_reports > 0

        log.info(
            f"AbuseIPDB [{ip}]: score={abuse_score:.0f}/100, "
            f"reports={total_reports}, country={country}, malicious={is_known_malicious}"
        )

        return Reputation(
            score=abuse_score,
            is_known=is_known_malicious,
            country=country,
            is_proxy=False,   # AbuseIPDB no expone este campo en v2/check básico
            is_hosting=False,
        )

    except requests.Timeout:
        log.warning(f"AbuseIPDB: timeout consultando {ip}. Usando fallback.")
        return None
    except Exception as e:
        log.warning(f"AbuseIPDB: error inesperado para {ip}: {e}. Usando fallback.")
        return None


def query_reputation(ip: str) -> Reputation:
    """
    Consulta reputación de una IP.

    Prioridad:
    1. AbuseIPDB (si ABUSEIPDB_API_KEY está configurada) — datos reales
    2. ipwho.is — geolocalización + heurísticas de red
    3. Fallback estático — lógica local sin dependencias externas
    """
    # --- Nivel 1: AbuseIPDB con datos reales ---
    abuseipdb_result = _query_abuseipdb(ip)
    if abuseipdb_result is not None:
        return abuseipdb_result

    # --- Nivel 2: ipwho.is + heurísticas ---
    try:
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

    # --- Nivel 3: fallback estático sin dependencias externas ---
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
    Mapea el comportamiento de una IP a técnicas MITRE ATT&CK.
    row debe tener: fallos_login, intentos_login, bytes_descargados, puertos_distintos, horas_actividad
    """
    tecnicas: List[MitreTechnique] = []

    fallos = float(row.get("fallos_login", 0))
    intentos = float(row.get("intentos_login", 0))
    bytes_down = float(row.get("bytes_descargados", 0))
    puertos = float(row.get("puertos_distintos", 0))
    hora = float(row.get("horas_actividad", 12))

    # Credential Access — Brute Force
    if fallos > 100:
        tecnicas.append(MITRE_DB["T1110.001"])  # Password Guessing intensivo
    elif fallos > 30:
        tecnicas.append(MITRE_DB["T1110"])      # Brute Force genérico
    elif intentos > 20 and fallos < intentos * 0.3:
        tecnicas.append(MITRE_DB["T1110.003"])  # Password Spraying (muchos intentos, pocos fallos)

    # Reconnaissance / Discovery — Escaneo de red
    if puertos > 50:
        tecnicas.append(MITRE_DB["T1595.001"])  # Active Scanning: IP Blocks
        tecnicas.append(MITRE_DB["T1046"])      # Network Service Scanning
    elif puertos > 15:
        tecnicas.append(MITRE_DB["T1046"])      # Network Service Scanning
        tecnicas.append(MITRE_DB["T1018"])      # Remote System Discovery

    # Exfiltration — Transferencia de datos anómala
    if bytes_down > 500_000_000:  # >500MB
        tecnicas.append(MITRE_DB["T1048"])      # Exfiltration Over Alternative Protocol
        tecnicas.append(MITRE_DB["T1005"])      # Data from Local System
    elif bytes_down > 100_000:    # >100KB
        tecnicas.append(MITRE_DB["T1041"])      # Exfiltration Over C2 Channel

    # Defense Evasion — Actividad fuera de horario laboral
    if hora < 6 or hora > 22:
        tecnicas.append(MITRE_DB["T1078"])      # Valid Accounts

    # C2 — Comunicación sospechosa (actividad fuera de horario + descarga)
    if (hora < 6 or hora > 22) and bytes_down > 10_000:
        tecnicas.append(MITRE_DB["T1071.001"])  # Application Layer Protocol: Web

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
