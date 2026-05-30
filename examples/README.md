# Ejemplos de uso — ThreatScope

Esta carpeta contiene datasets de ejemplo para demostrar las capacidades del sistema.

## Archivos

### `escenario_incidente.csv`

10 eventos de red con patron mixto: trafico normal + ataques aislados.

Patrones incluidos:
- `185.220.101.5` — nodo de salida Tor (brute force + horario nocturno)
- `203.0.113.77` — brute force intenso (120 intentos, 118 fallidos)
- `198.51.100.23` — escaneo de puertos (45 puertos distintos)
- `172.16.0.5` — exfiltracion (500,000 bytes descargados a las 3 AM)

### `escenario_ransomware.csv`

12 eventos simulando un ataque de ransomware en progreso:
- Callback de C2 via Tor (185.220.101.x)
- Movimiento lateral entre hosts internos
- Exfiltracion masiva antes del cifrado
- 3 hosts comprometidos con brute force simultaneo

## Formato requerido

El sistema acepta CSVs con estas columnas:

| Columna | Tipo | Descripcion |
|---|---|---|
| `ip` | string | Direccion IP de origen |
| `intentos_login` | int | Total de intentos de autenticacion |
| `fallos_login` | int | Intentos de login fallidos |
| `bytes_descargados` | int | Bytes transferidos en la sesion |
| `horas_actividad` | int | Hora del dia (0-23) de la actividad |
| `puertos_distintos` | int | Numero de puertos distintos accedidos |

## Uso

```bash
# CLI
python main.py analyze --csv examples/escenario_incidente.csv
python main.py analyze --csv examples/escenario_ransomware.csv

# API REST (servidor corriendo en puerto 8000)
curl -X POST http://localhost:8000/analyze \
  -F "file=@examples/escenario_incidente.csv"
```
