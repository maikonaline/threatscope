FROM python:3.11-slim

WORKDIR /app

# Dependencias del sistema (gcc necesario para algunas libs de numpy/scipy)
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependencias Python primero (capa cacheada si requirements no cambia)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar codigo
COPY . .

# Crear directorios de runtime
RUN mkdir -p data logs models examples

# Variables de entorno por defecto (sobreescribibles en runtime)
ENV THREATSCOPE_ENV=production
ENV THREATSCOPE_LOG_LEVEL=INFO
ENV THREATSCOPE_DB_ENGINE=sqlite
ENV THREATSCOPE_DB_PATH=/app/data/threatscope.db

# Puerto de la API
EXPOSE 8000

# Health check via API
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/status')" || exit 1

# Por defecto: arrancar la API REST
# Para CLI: docker run threatscope python main.py analyze --csv /app/data/archivo.csv
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
