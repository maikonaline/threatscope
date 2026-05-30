"""
misobras_connector.py
---------------------
Conector entre misobras (Supabase Auth) y ThreatScope.

Extrae logs de autenticacion de Supabase, los transforma al formato
CSV que espera ThreatScope, envia el archivo para analisis y muestra
las detecciones resultantes.

Uso:
    python misobras_connector.py
    python misobras_connector.py --hours 48
    python misobras_connector.py --hours 6 --dry-run

Requisitos:
    pip install requests supabase

IMPORTANTE — Acceso a auth.audit_log_entries:
    La tabla auth.audit_log_entries solo es accesible con SERVICE_ROLE_KEY.
    Con la ANON_KEY el acceso esta bloqueado por RLS de Supabase.
    Si no tienes la service role key, obtenla en:
    Supabase Dashboard -> Project Settings -> API -> service_role
    y ponla en SUPABASE_KEY abajo (o en variable de entorno).
"""

import argparse
import csv
import io
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from supabase import create_client, Client

# =============================================================================
# CONFIGURACION — editar estos valores o usar variables de entorno
# =============================================================================

SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://ygvlslmazjegfxzmncms.supabase.co"
)

# CRITICO: usar SERVICE_ROLE_KEY para acceder a auth.audit_log_entries.
# La anon key NO tiene permisos sobre el schema auth.
# Obtener en: Supabase Dashboard -> Project Settings -> API -> service_role
SUPABASE_KEY = os.environ.get(
    "SUPABASE_SERVICE_ROLE_KEY",
    # Fallback a anon key (solo para queries sobre tablas publicas con RLS)
    os.environ.get("SUPABASE_ANON_KEY", "sb_publishable_lelw3fzQlL3-Q-RWpbho4w_j_SYxwpy")
)

THREATSCOPE_API = os.environ.get(
    "THREATSCOPE_API",
    "https://threatscope-uoza.onrender.com"
)

EXPORTS_DIR = Path(r"D:\Downloads\seguridad\exports")

# =============================================================================
# CONSTANTES
# =============================================================================

# Tipos de evento de Supabase Auth que se consideran fallos de login
AUTH_FAILURE_EVENTS = {
    "login_failed",
    "signup_failed",
    "otp_disabled",
    "token_refreshed_denied",
    "password_recovery_requested",  # puede indicar fuerza bruta de recovery
}

# Puerto unico para trafico HTTPS/auth web
PUERTO_HTTPS = 1

# Bytes estimados por evento de auth (handshake TLS + payload JWT tipico)
BYTES_POR_AUTH_EVENT = 4096  # ~4KB por request de autenticacion


# =============================================================================
# EXTRACCION DE LOGS
# =============================================================================


def get_auth_logs(client: Client, hours: int) -> list[dict]:
    """
    Extrae logs de auth.audit_log_entries de Supabase.

    Supabase expone esta tabla solo con service_role key.
    Si el acceso falla, lanza RuntimeError con instrucciones claras.

    Args:
        client: cliente Supabase inicializado con service_role key.
        hours: ventana temporal en horas hacia atras desde ahora.

    Returns:
        Lista de dicts con campos: ip_address, created_at, payload (dict).

    Raises:
        RuntimeError: si el acceso esta denegado o la tabla no existe.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    try:
        response = (
            client
            .schema("auth")
            .table("audit_log_entries")
            .select("ip_address, created_at, payload")
            .gte("created_at", since)
            .order("created_at", desc=False)
            .execute()
        )
    except Exception as e:
        raise RuntimeError(
            f"Error accediendo a auth.audit_log_entries: {e}\n"
            "Verifica que SUPABASE_KEY sea la SERVICE_ROLE_KEY, no la anon key.\n"
            "Obtenerla en: Supabase Dashboard -> Project Settings -> API -> service_role"
        ) from e

    if not response.data:
        return []

    # Filtrar registros sin IP (eventos de sistema internos)
    logs = [
        row for row in response.data
        if row.get("ip_address") and row["ip_address"] != "127.0.0.1"
    ]

    print(f"  Logs extraidos: {len(response.data)} totales, {len(logs)} con IP valida")
    return logs


# =============================================================================
# TRANSFORMACION
# =============================================================================


def parse_event_type(payload: dict | str | None) -> str:
    """
    Extrae el tipo de evento del payload de audit_log_entries.

    El campo payload puede venir como dict o como string JSON segun la version
    de Supabase. Normaliza ambos casos.

    Args:
        payload: campo payload del registro de audit_log.

    Returns:
        String con el tipo de evento (ej: "login", "login_failed", etc.)
        o "unknown" si no se puede determinar.
    """
    if payload is None:
        return "unknown"

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return "unknown"

    if not isinstance(payload, dict):
        return "unknown"

    # Supabase guarda el action en payload.action o en payload.event
    return payload.get("action", payload.get("event", "unknown")).lower()


def aggregate_logs_to_csv_rows(logs: list[dict]) -> list[dict]:
    """
    Agrega logs por IP y construye las filas del CSV para ThreatScope.

    Logica de agregacion:
    - ip: IP de origen del evento
    - intentos_login: total de eventos de auth de esa IP
    - fallos_login: eventos con tipo en AUTH_FAILURE_EVENTS
    - bytes_descargados: intentos_login * BYTES_POR_AUTH_EVENT (estimacion)
    - horas_actividad: hora del primer evento de esa IP (0-23)
    - puertos_distintos: siempre 1 (solo HTTPS/443 en auth web)

    Args:
        logs: lista de dicts de audit_log_entries.

    Returns:
        Lista de dicts con las columnas del CSV de ThreatScope.
    """
    # Estructura por IP: {ip: {intentos, fallos, primer_timestamp}}
    per_ip: dict[str, dict] = defaultdict(lambda: {
        "intentos": 0,
        "fallos": 0,
        "primer_ts": None,
    })

    for log_entry in logs:
        ip = log_entry["ip_address"]
        event_type = parse_event_type(log_entry.get("payload"))
        created_at = log_entry.get("created_at", "")

        per_ip[ip]["intentos"] += 1

        if event_type in AUTH_FAILURE_EVENTS:
            per_ip[ip]["fallos"] += 1

        # Registrar el timestamp mas temprano para calcular hora de actividad
        if per_ip[ip]["primer_ts"] is None or created_at < per_ip[ip]["primer_ts"]:
            per_ip[ip]["primer_ts"] = created_at

    rows = []
    for ip, stats in per_ip.items():
        # Extraer hora del primer evento (0-23)
        hora_actividad = 0
        if stats["primer_ts"]:
            try:
                ts = datetime.fromisoformat(
                    stats["primer_ts"].replace("Z", "+00:00")
                )
                hora_actividad = ts.hour
            except (ValueError, AttributeError):
                hora_actividad = 0

        rows.append({
            "ip": ip,
            "intentos_login": stats["intentos"],
            "fallos_login": stats["fallos"],
            "bytes_descargados": stats["intentos"] * BYTES_POR_AUTH_EVENT,
            "horas_actividad": hora_actividad,
            "puertos_distintos": PUERTO_HTTPS,
        })

    # Ordenar por intentos descendente para facilitar lectura del output
    rows.sort(key=lambda r: r["intentos_login"], reverse=True)
    return rows


def build_csv_content(rows: list[dict]) -> str:
    """
    Serializa las filas agregadas al formato CSV que ThreatScope espera.

    Args:
        rows: lista de dicts con columnas del CSV.

    Returns:
        String CSV con cabecera.
    """
    if not rows:
        return ""

    fieldnames = [
        "ip", "intentos_login", "fallos_login",
        "bytes_descargados", "horas_actividad", "puertos_distintos"
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


# =============================================================================
# EXPORTACION LOCAL
# =============================================================================


def save_csv_locally(csv_content: str) -> Path:
    """
    Guarda el CSV en D:/Downloads/seguridad/exports/ con timestamp.

    Nombre: misobras_YYYYMMDD_HH.csv

    Args:
        csv_content: string CSV a guardar.

    Returns:
        Path del archivo guardado.
    """
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H")
    filename = f"misobras_{timestamp}.csv"
    filepath = EXPORTS_DIR / filename

    filepath.write_text(csv_content, encoding="utf-8")
    print(f"  CSV guardado en: {filepath}")
    return filepath


# =============================================================================
# ENVIO A THREATSCOPE
# =============================================================================


def send_to_threatscope(csv_content: str, filepath: Path) -> dict:
    """
    Envia el CSV a ThreatScope via POST /analyze (multipart/form-data).

    ThreatScope espera el archivo como UploadFile con nombre *.csv.
    El endpoint valida la extension antes de procesar.

    Args:
        csv_content: contenido del CSV como string.
        filepath: path local del archivo (para usar como nombre en el upload).

    Returns:
        Dict con la respuesta JSON de ThreatScope (AnalysisResult schema).

    Raises:
        requests.HTTPError: si el servidor responde con error HTTP.
        RuntimeError: si la conexion falla o la respuesta no es JSON valido.
    """
    url = f"{THREATSCOPE_API.rstrip('/')}/analyze"
    print(f"  Enviando a: {url}")

    files = {
        "file": (filepath.name, csv_content.encode("utf-8"), "text/csv")
    }

    try:
        response = requests.post(url, files=files, timeout=120)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            f"No se pudo conectar con ThreatScope en {url}\n"
            f"Verifica que el servidor este activo: {e}"
        ) from e
    except requests.exceptions.Timeout:
        raise RuntimeError(
            f"ThreatScope no respondio en 120 segundos. "
            "El servidor en Render puede estar en cold start (esperar ~30s y reintentar)."
        )
    except requests.exceptions.HTTPError as e:
        error_detail = ""
        try:
            error_detail = response.json().get("detail", "")
        except Exception:
            error_detail = response.text[:200]
        raise requests.HTTPError(
            f"ThreatScope respondio con error {response.status_code}: {error_detail}"
        ) from e

    try:
        return response.json()
    except (json.JSONDecodeError, ValueError) as e:
        raise RuntimeError(
            f"Respuesta invalida de ThreatScope (no es JSON): {response.text[:200]}"
        ) from e


# =============================================================================
# PRESENTACION DE RESULTADOS
# =============================================================================


def print_results(result: dict, rows: list[dict]) -> None:
    """
    Imprime el resumen del analisis en consola.

    Args:
        result: dict con la respuesta de ThreatScope (AnalysisResult).
        rows: filas CSV enviadas (para calcular IPs analizadas).
    """
    sep = "=" * 60

    print(f"\n{sep}")
    print("  RESULTADO DEL ANALISIS — ThreatScope")
    print(sep)

    total_ips = len(rows)
    total_events = result.get("total_events", total_ips)
    anomalies = result.get("anomalies_found", 0)
    duration = result.get("duration_seconds", 0)
    batch_id = result.get("batch_id", "N/A")

    print(f"  Batch ID       : {batch_id}")
    print(f"  IPs analizadas : {total_ips}")
    print(f"  Eventos totales: {total_events}")
    print(f"  Anomalias      : {anomalies}")
    print(f"  Duracion       : {duration:.2f}s")

    detections = result.get("detections", [])
    if not detections:
        print("\n  Sin anomalias detectadas en la ventana analizada.")
        print(sep)
        return

    # Agrupar por nivel de riesgo para el resumen
    by_risk: dict[str, list] = defaultdict(list)
    for d in detections:
        risk = d.get("risk", d.get("risk_level", "DESCONOCIDO"))
        by_risk[risk].append(d)

    risk_order = ["CRITICO", "ALTO", "MEDIO", "BAJO"]
    risk_labels = {
        "CRITICO": "[!!!] CRITICO",
        "ALTO":    "[ ! ] ALTO   ",
        "MEDIO":   "[ ~ ] MEDIO  ",
        "BAJO":    "[   ] BAJO   ",
    }

    print(f"\n  Resumen por nivel de riesgo:")
    for level in risk_order:
        if level in by_risk:
            count = len(by_risk[level])
            label = risk_labels.get(level, level)
            print(f"    {label}: {count} IP(s)")

    print(f"\n  IPs sospechosas detectadas:")
    print(f"  {'IP':<20} {'RIESGO':<10} {'SCORE':<10} DESCRIPCION")
    print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*30}")

    for level in risk_order:
        for d in by_risk.get(level, []):
            ip = d.get("ip", "N/A")
            risk = d.get("risk", d.get("risk_level", "?"))
            score = d.get("score", d.get("anomaly_score", 0))
            summary = d.get("summary", "")[:50]
            print(f"  {ip:<20} {risk:<10} {score:<10.4f} {summary}")

    print(sep)


# =============================================================================
# MAIN
# =============================================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Conector misobras-ThreatScope. "
            "Extrae logs de auth de Supabase y los analiza con ThreatScope."
        )
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        metavar="N",
        help="Analizar las ultimas N horas de logs (default: 24)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Generar y guardar el CSV pero NO enviarlo a ThreatScope. "
            "Util para verificar la extraccion antes del analisis."
        ),

    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(f"\nmisobras -> ThreatScope Connector")
    print(f"Ventana temporal: ultimas {args.hours} horas")
    print(f"Proyecto Supabase: {SUPABASE_URL}")
    print(f"ThreatScope API: {THREATSCOPE_API}")
    if args.dry_run:
        print("MODO: dry-run (no se enviara a ThreatScope)")
    print()

    # --- 1. CONEXION A SUPABASE ---
    print("[1/4] Conectando a Supabase...")
    try:
        client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"ERROR: No se pudo crear el cliente Supabase: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 2. EXTRACCION DE LOGS ---
    print(f"[2/4] Extrayendo logs de auth (ultimas {args.hours}h)...")
    try:
        logs = get_auth_logs(client, args.hours)
    except RuntimeError as e:
        print(f"\nERROR de acceso a Supabase:\n{e}", file=sys.stderr)
        print(
            "\nSolucion: establece la variable de entorno SUPABASE_SERVICE_ROLE_KEY\n"
            "con la service role key de tu proyecto Supabase.\n"
            "Ejemplo:\n"
            "  $env:SUPABASE_SERVICE_ROLE_KEY='eyJ...'  (PowerShell)\n"
            "  set SUPABASE_SERVICE_ROLE_KEY=eyJ...     (CMD)\n"
            "  export SUPABASE_SERVICE_ROLE_KEY=eyJ...  (bash)",
            file=sys.stderr
        )
        sys.exit(1)

    if not logs:
        print(f"  Sin logs en las ultimas {args.hours} horas. Nada que analizar.")
        sys.exit(0)

    # --- 3. TRANSFORMACION Y EXPORT ---
    print("[3/4] Transformando datos al formato ThreatScope...")
    rows = aggregate_logs_to_csv_rows(logs)
    print(f"  IPs unicas encontradas: {len(rows)}")

    csv_content = build_csv_content(rows)
    if not csv_content:
        print("  CSV vacio tras agregacion. Nada que enviar.")
        sys.exit(0)

    filepath = save_csv_locally(csv_content)

    if args.dry_run:
        print(f"\nDry-run completado. CSV disponible en:\n  {filepath}")
        print("\nPrimeras filas del CSV:")
        for line in csv_content.splitlines()[:6]:
            print(f"  {line}")
        sys.exit(0)

    # --- 4. ANALISIS EN THREATSCOPE ---
    print("[4/4] Enviando a ThreatScope para analisis...")
    try:
        result = send_to_threatscope(csv_content, filepath)
    except (RuntimeError, requests.HTTPError) as e:
        print(f"\nERROR enviando a ThreatScope:\n{e}", file=sys.stderr)
        print(f"\nEl CSV se guardo localmente en:\n  {filepath}", file=sys.stderr)
        print(
            "Puedes enviarlo manualmente con:\n"
            f"  curl -X POST {THREATSCOPE_API}/analyze -F 'file=@{filepath}'",
            file=sys.stderr
        )
        sys.exit(1)

    # --- RESULTADOS ---
    print_results(result, rows)


if __name__ == "__main__":
    main()
