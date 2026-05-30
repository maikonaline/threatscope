"""
notifier.py
-----------
Sistema de notificaciones multi-canal para ThreatScope.
Envia alertas a Slack, Splunk, Azure Sentinel y Microsoft Teams.

Principio de diseno:
- Fallo silencioso: nunca crashea el pipeline
- Threading: no bloquea requests
- Skip automatico si la variable de entorno no esta configurada
"""

import hashlib
import hmac
import base64
import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List

import urllib.request
import urllib.error

from logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Colores por nivel de riesgo
# ---------------------------------------------------------------------------
_LEVEL_COLORS = {
    "CRITICO": "#FF0000",
    "ALTO":    "#FF8C00",
    "MEDIO":   "#FFD700",
    "BAJO":    "#00AA00",
}

_LEVEL_EMOJI = {
    "CRITICO": "🚨",
    "ALTO":    "⚠️",
    "MEDIO":   "🟡",
    "BAJO":    "🟢",
}

_DASHBOARD_URL = "https://threatscope.vercel.app"
_TIMEOUT_SECONDS = 5


# ---------------------------------------------------------------------------
# Helpers HTTP (sin dependencias externas como requests)
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: dict, headers: dict = None) -> dict:
    """
    POST JSON simple usando urllib. Timeout de _TIMEOUT_SECONDS.
    Devuelve dict con 'ok' (bool) y 'status' (int) o 'error' (str).
    """
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Canal: Slack
# ---------------------------------------------------------------------------

def _send_slack(data: dict) -> None:
    """Envia alerta formateada a Slack usando Incoming Webhooks."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        log.debug("Slack: SLACK_WEBHOOK_URL no configurada, skip")
        return

    level   = data.get("risk_level", "DESCONOCIDO")
    ip      = data.get("ip", "—")
    country = data.get("country", "??")
    rep     = data.get("reputation_score", 0)
    reports = data.get("abuse_reports", 0)
    summary = data.get("summary", "Sin resumen disponible")
    mitre   = data.get("mitre_techniques", [])
    color   = _LEVEL_COLORS.get(level, "#888888")
    emoji   = _LEVEL_EMOJI.get(level, "🔔")

    # Formatear tecnicas MITRE
    if isinstance(mitre, str):
        try:
            mitre = json.loads(mitre)
        except Exception:
            mitre = [mitre]
    mitre_str = " | ".join(mitre) if mitre else "N/A"

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} ThreatScope — {level}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*IP:* `{ip}`"},
                            {"type": "mrkdwn", "text": f"*Pais:* {country}"},
                            {"type": "mrkdwn", "text": f"*AbuseIPDB:* {rep}/100 | Reportes: {reports}"},
                            {"type": "mrkdwn", "text": f"*Tecnicas MITRE:* {mitre_str}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Resumen:* {summary}",
                        },
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Ver dashboard → <{_DASHBOARD_URL}|ThreatScope>",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    result = _post_json(webhook_url, payload)
    if result["ok"]:
        log.info(f"Slack: alerta enviada para IP {ip} (nivel {level})")
    else:
        log.error(f"Slack: error enviando alerta — {result.get('error') or result.get('status')}")


# ---------------------------------------------------------------------------
# Canal: Slack — mensaje de prueba
# ---------------------------------------------------------------------------

def _send_slack_test(webhook_url: str) -> dict:
    """Envia mensaje de prueba a Slack. Devuelve dict ok/error."""
    payload = {
        "text": "🧪 ThreatScope — Test de conexion exitoso",
        "attachments": [
            {
                "color": "#3b82f6",
                "text": "La integracion con Slack esta correctamente configurada.",
            }
        ],
    }
    return _post_json(webhook_url, payload)


# ---------------------------------------------------------------------------
# Canal: Splunk HEC
# ---------------------------------------------------------------------------

def _send_splunk(data: dict) -> None:
    """Envia evento a Splunk via HTTP Event Collector."""
    hec_url   = os.getenv("SPLUNK_HEC_URL", "").strip()
    hec_token = os.getenv("SPLUNK_HEC_TOKEN", "").strip()

    if not hec_url or not hec_token:
        log.debug("Splunk: SPLUNK_HEC_URL o SPLUNK_HEC_TOKEN no configurados, skip")
        return

    ip    = data.get("ip", "—")
    level = data.get("risk_level", "DESCONOCIDO")

    # Formato estandar Splunk HEC
    payload = {
        "time":       time.time(),
        "host":       "threatscope",
        "source":     "threatscope:detections",
        "sourcetype": "threatscope:alert",
        "index":      "security",
        "event": {
            "severity":         level,
            "ip":               ip,
            "country":          data.get("country", "??"),
            "reputation_score": data.get("reputation_score", 0),
            "anomaly_score":    data.get("anomaly_score", 0),
            "is_known_malicious": data.get("is_known_malicious", False),
            "mitre_techniques": data.get("mitre_techniques", []),
            "summary":          data.get("summary", ""),
            "batch_id":         data.get("batch_id", ""),
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        },
    }

    headers = {"Authorization": f"Splunk {hec_token}"}
    result  = _post_json(hec_url, payload, headers=headers)

    if result["ok"]:
        log.info(f"Splunk: evento enviado para IP {ip} (nivel {level})")
    else:
        log.error(f"Splunk: error enviando evento — {result.get('error') or result.get('status')}")


def _send_splunk_test(hec_url: str, hec_token: str) -> dict:
    """Envia evento de prueba a Splunk HEC."""
    payload = {
        "time":       time.time(),
        "host":       "threatscope",
        "source":     "threatscope:test",
        "sourcetype": "threatscope:test",
        "event": {
            "message":   "ThreatScope — Test de conexion exitoso",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    }
    headers = {"Authorization": f"Splunk {hec_token}"}
    return _post_json(hec_url, payload, headers=headers)


# ---------------------------------------------------------------------------
# Canal: Azure Sentinel (Log Analytics Workspace)
# ---------------------------------------------------------------------------

def _build_sentinel_signature(workspace_id: str, primary_key: str, date: str, content_length: int) -> str:
    """Construye la firma HMAC-SHA256 para Azure Monitor Data Collector API."""
    string_to_hash = (
        f"POST\n{content_length}\napplication/json\n"
        f"x-ms-date:{date}\n/api/logs"
    )
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key   = base64.b64decode(primary_key)
    signature     = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{signature}"


def _send_sentinel(data: dict) -> None:
    """Envia log a Azure Sentinel via Azure Monitor Data Collector API."""
    workspace_id  = os.getenv("SENTINEL_WORKSPACE_ID", "").strip()
    primary_key   = os.getenv("SENTINEL_PRIMARY_KEY", "").strip()

    if not workspace_id or not primary_key:
        log.debug("Sentinel: SENTINEL_WORKSPACE_ID o SENTINEL_PRIMARY_KEY no configurados, skip")
        return

    ip    = data.get("ip", "—")
    level = data.get("risk_level", "DESCONOCIDO")

    log_type = "ThreatScopeDetection"
    url      = (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        f"/api/logs?api-version=2016-04-01"
    )

    body = json.dumps([{
        "Severity":          level,
        "IP":                ip,
        "Country":           data.get("country", "??"),
        "ReputationScore":   data.get("reputation_score", 0),
        "AnomalyScore":      data.get("anomaly_score", 0),
        "IsKnownMalicious":  str(data.get("is_known_malicious", False)),
        "MitreTechniques":   json.dumps(data.get("mitre_techniques", [])),
        "Summary":           data.get("summary", ""),
        "BatchId":           data.get("batch_id", ""),
        "TimeGenerated":     datetime.now(timezone.utc).isoformat(),
    }]).encode("utf-8")

    rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature    = _build_sentinel_signature(
        workspace_id, primary_key, rfc1123_date, len(body)
    )

    headers = {
        "Authorization": signature,
        "Log-Type":      log_type,
        "x-ms-date":     rfc1123_date,
        "time-generated-field": "TimeGenerated",
    }

    # _post_json asume dict payload; para Sentinel necesitamos bytes directos
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            log.info(f"Sentinel: log enviado para IP {ip} (nivel {level}), status {resp.status}")
    except urllib.error.HTTPError as e:
        log.error(f"Sentinel: error HTTP {e.code} enviando log — {e.reason}")
    except Exception as e:
        log.error(f"Sentinel: error enviando log — {e}")


def _send_sentinel_test(workspace_id: str, primary_key: str) -> dict:
    """Envia log de prueba a Azure Sentinel."""
    log_type = "ThreatScopeTest"
    url      = (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        f"/api/logs?api-version=2016-04-01"
    )
    body = json.dumps([{
        "Message":       "ThreatScope — Test de conexion exitoso",
        "TimeGenerated": datetime.now(timezone.utc).isoformat(),
    }]).encode("utf-8")

    rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature    = _build_sentinel_signature(workspace_id, primary_key, rfc1123_date, len(body))

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", signature)
    req.add_header("Log-Type", log_type)
    req.add_header("x-ms-date", rfc1123_date)
    req.add_header("time-generated-field", "TimeGenerated")

    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SECONDS) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Canal: Microsoft Teams
# ---------------------------------------------------------------------------

def _send_teams(data: dict) -> None:
    """Envia alerta a Microsoft Teams via Incoming Webhook (MessageCard)."""
    webhook_url = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook_url:
        log.debug("Teams: TEAMS_WEBHOOK_URL no configurada, skip")
        return

    level   = data.get("risk_level", "DESCONOCIDO")
    ip      = data.get("ip", "—")
    country = data.get("country", "??")
    rep     = data.get("reputation_score", 0)
    summary = data.get("summary", "Sin resumen disponible")
    mitre   = data.get("mitre_techniques", [])
    color   = _LEVEL_COLORS.get(level, "888888").lstrip("#")
    emoji   = _LEVEL_EMOJI.get(level, "🔔")

    if isinstance(mitre, str):
        try:
            mitre = json.loads(mitre)
        except Exception:
            mitre = [mitre]
    mitre_str = ", ".join(mitre) if mitre else "N/A"

    # MessageCard format (compatible con conectores clasicos)
    payload = {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": color,
        "summary":    f"ThreatScope — {level} — {ip}",
        "sections": [
            {
                "activityTitle":    f"{emoji} **ThreatScope — {level}**",
                "activitySubtitle": f"IP: `{ip}` | Pais: {country}",
                "facts": [
                    {"name": "Nivel de riesgo",   "value": level},
                    {"name": "IP",                "value": ip},
                    {"name": "Pais",              "value": country},
                    {"name": "Reputacion",        "value": f"{rep}/100"},
                    {"name": "Tecnicas MITRE",    "value": mitre_str},
                    {"name": "Resumen",           "value": summary},
                ],
                "markdown": True,
            }
        ],
        "potentialAction": [
            {
                "@type":   "OpenUri",
                "name":    "Ver dashboard",
                "targets": [{"os": "default", "uri": _DASHBOARD_URL}],
            }
        ],
    }

    result = _post_json(webhook_url, payload)
    if result["ok"]:
        log.info(f"Teams: alerta enviada para IP {ip} (nivel {level})")
    else:
        log.error(f"Teams: error enviando alerta — {result.get('error') or result.get('status')}")


def _send_teams_test(webhook_url: str) -> dict:
    """Envia mensaje de prueba a Teams."""
    payload = {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": "3b82f6",
        "summary":    "ThreatScope — Test de conexion",
        "sections": [
            {
                "activityTitle":    "🧪 **ThreatScope — Test de conexion exitoso**",
                "activitySubtitle": "La integracion con Microsoft Teams esta correctamente configurada.",
                "markdown": True,
            }
        ],
    }
    return _post_json(webhook_url, payload)


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

def send_alerts(detection_data: dict) -> None:
    """
    Dispara todos los canales activos en paralelo usando threading.
    No bloquea. Falla silenciosamente en caso de error.

    Args:
        detection_data: dict con campos de la deteccion (ip, risk_level, etc.)
    """
    channels: List[callable] = [
        _send_slack,
        _send_splunk,
        _send_sentinel,
        _send_teams,
    ]

    threads = []
    for fn in channels:
        t = threading.Thread(
            target=_safe_call,
            args=(fn, detection_data),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # No join — daemon=True, el pipeline no espera
    log.debug(f"Notifier: {len(threads)} hilos lanzados para IP {detection_data.get('ip', '?')}")


def send_test(channel: str, config: dict) -> dict:
    """
    Envia un mensaje de prueba para el canal indicado.
    Usado desde el endpoint POST /integrations/test.

    Args:
        channel: 'slack' | 'splunk' | 'sentinel' | 'teams'
        config:  dict con las variables de configuracion del canal

    Returns:
        dict con 'success' (bool) y 'detail' (str)
    """
    try:
        if channel == "slack":
            url = config.get("webhook_url") or os.getenv("SLACK_WEBHOOK_URL", "").strip()
            if not url:
                return {"success": False, "detail": "SLACK_WEBHOOK_URL no configurada"}
            result = _send_slack_test(url)

        elif channel == "splunk":
            url   = config.get("hec_url")   or os.getenv("SPLUNK_HEC_URL", "").strip()
            token = config.get("hec_token")  or os.getenv("SPLUNK_HEC_TOKEN", "").strip()
            if not url or not token:
                return {"success": False, "detail": "SPLUNK_HEC_URL o SPLUNK_HEC_TOKEN no configurados"}
            result = _send_splunk_test(url, token)

        elif channel == "sentinel":
            ws_id = config.get("workspace_id") or os.getenv("SENTINEL_WORKSPACE_ID", "").strip()
            key   = config.get("primary_key")   or os.getenv("SENTINEL_PRIMARY_KEY", "").strip()
            if not ws_id or not key:
                return {"success": False, "detail": "SENTINEL_WORKSPACE_ID o SENTINEL_PRIMARY_KEY no configurados"}
            result = _send_sentinel_test(ws_id, key)

        elif channel == "teams":
            url = config.get("webhook_url") or os.getenv("TEAMS_WEBHOOK_URL", "").strip()
            if not url:
                return {"success": False, "detail": "TEAMS_WEBHOOK_URL no configurada"}
            result = _send_teams_test(url)

        else:
            return {"success": False, "detail": f"Canal desconocido: {channel}"}

        if result.get("ok"):
            return {"success": True, "detail": "Mensaje de prueba enviado correctamente"}
        else:
            return {
                "success": False,
                "detail":  result.get("error") or f"HTTP {result.get('status')}",
            }

    except Exception as e:
        log.error(f"Notifier test [{channel}]: {e}")
        return {"success": False, "detail": str(e)}


def get_integrations_status() -> dict:
    """
    Devuelve el estado de cada integracion (configurada o no).
    No expone keys ni secrets.
    """
    return {
        "slack": {
            "configured": bool(os.getenv("SLACK_WEBHOOK_URL", "").strip()),
        },
        "splunk": {
            "configured": (
                bool(os.getenv("SPLUNK_HEC_URL", "").strip())
                and bool(os.getenv("SPLUNK_HEC_TOKEN", "").strip())
            ),
        },
        "sentinel": {
            "configured": (
                bool(os.getenv("SENTINEL_WORKSPACE_ID", "").strip())
                and bool(os.getenv("SENTINEL_PRIMARY_KEY", "").strip())
            ),
        },
        "teams": {
            "configured": bool(os.getenv("TEAMS_WEBHOOK_URL", "").strip()),
        },
    }


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _safe_call(fn: callable, data: dict) -> None:
    """Wrapper que absorbe cualquier excepcion para no crashear el pipeline."""
    try:
        fn(data)
    except Exception as e:
        log.error(f"Notifier [{fn.__name__}]: excepcion no controlada — {e}")
