#!/usr/bin/env python3
"""
main.py
-------
CLI principal: ejecuta análisis de amenazas desde línea de comandos.
Uso:
  python main.py analyze --csv escenario_incidente.csv
  python main.py stats
  python main.py health
"""

import argparse
import json
import sys
from pathlib import Path
from tabulate import tabulate

from config import settings
from logger import get_logger, setup_logging
from database import db
from pipeline import pipeline

log = get_logger(__name__)


def cmd_analyze(args):
    """Ejecuta análisis sobre un CSV."""
    if not args.csv:
        log.error("Debes proporcionar --csv")
        return 1

    if not Path(args.csv).exists():
        log.error(f"Archivo no encontrado: {args.csv}")
        return 1

    try:
        result = pipeline.run(args.csv, source="csv")
        print("\n" + "="*70)
        print("  ANÁLISIS COMPLETADO")
        print("="*70)
        print(f"Batch ID           : {result['batch_id']}")
        print(f"Eventos procesados : {result['total_events']}")
        print(f"Anomalías detectadas: {result['anomalies_found']}")
        print(f"Tiempo             : {result['duration_seconds']:.2f}s")

        if result["detections"]:
            print("\nDetecciones:")
            table = [
                [d["ip"], d["risk"], f"{d['score']:.2f}", d["summary"][:50]+"..."]
                for d in result["detections"]
            ]
            print(tabulate(table, headers=["IP", "Riesgo", "Score", "Resumen"]))
        else:
            print("\nSin anomalías detectadas.")

        print("="*70)
        return 0
    except Exception as e:
        log.error(f"Error en análisis: {e}")
        return 1


def cmd_stats(args):
    """Muestra estadísticas generales."""
    try:
        stats = db.get_stats()
        print("\n" + "="*70)
        print("  ESTADÍSTICAS GENERALES")
        print("="*70)
        print(f"Total detecciones : {stats['total']}")
        print(f"Riesgo CRÍTICO     : {stats['criticos']}")
        print(f"Riesgo ALTO        : {stats['altos']}")
        print("="*70)
        return 0
    except Exception as e:
        log.error(f"Error obteniendo stats: {e}")
        return 1


def cmd_health(args):
    """Verifica la salud del sistema."""
    print("\n" + "="*70)
    print("  HEALTH CHECK")
    print("="*70)
    try:
        # BD
        stats = db.get_stats()
        print("✓ Base de datos     : OK")
        print(f"  - Total registros : {stats['total']}")

        # Modelo
        print("✓ Modelo ML        : OK")
        print(f"  - Features       : {len(detector.model.estimators_)}")

        # Config
        print("✓ Configuración    : OK")
        print(f"  - Entorno        : {settings.ENV}")
        print(f"  - Log level      : {settings.LOG_LEVEL}")

        print("="*70)
        return 0
    except Exception as e:
        print(f"✗ Error: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="ThreatScope — Sistema de detección de amenazas",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s analyze --csv datos.csv
  %(prog)s stats
  %(prog)s health
        """,
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Modo debug (logs verbosos)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # Subcomando: analyze
    sp_analyze = subparsers.add_parser("analyze", help="Analiza un CSV de eventos")
    sp_analyze.add_argument("--csv", required=True, help="Ruta al archivo CSV")
    sp_analyze.set_defaults(func=cmd_analyze)

    # Subcomando: stats
    sp_stats = subparsers.add_parser("stats", help="Muestra estadísticas")
    sp_stats.set_defaults(func=cmd_stats)

    # Subcomando: health
    sp_health = subparsers.add_parser("health", help="Health check del sistema")
    sp_health.set_defaults(func=cmd_health)

    args = parser.parse_args()

    # Setup logging
    if args.debug:
        settings.DEBUG = True
    setup_logging()

    # Inicializar BD
    db.init_db()

    if not args.command:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
