# Guia de Deploy — ThreatScope

## 1. Subir a GitHub

### Crear repositorio en GitHub

1. Ir a https://github.com/new
2. Nombre: `threatscope`
3. Descripcion: "Sistema de deteccion de amenazas con ML + MITRE ATT&CK"
4. Visibilidad: **Public** (necesario para mostrar en entrevista)
5. NO inicializar con README (ya tenemos nuestros archivos)
6. Click **Create repository**

### Conectar y hacer push

```bash
# En D:\Downloads\seguridad — el repositorio ya esta inicializado
git remote add origin https://github.com/TU-USUARIO/threatscope.git
git branch -M main
git push -u origin main
```

Verificar en GitHub que aparecen los 4 commits y todos los archivos.

---

## 2. Deploy en Render.com

### Por que Render y no Vercel

- **Vercel descartado**: scikit-learn + numpy + pandas + scipy superan 400MB descomprimidos.
  Vercel Serverless tiene limite de 250MB. Ademas, SQLite no funciona con filesystem efimero.
- **Render.com**: servidor Python persistente, plan free disponible, deploy directo desde GitHub.

### Pasos

1. Ir a https://render.com y crear cuenta (gratis, puede usar GitHub OAuth)

2. Click **New** → **Web Service**

3. Conectar el repositorio `TU-USUARIO/threatscope`

4. Configurar el servicio:
   - **Name**: `threatscope-api`
   - **Region**: Frankfurt EU (o la mas cercana)
   - **Branch**: `main`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn api:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free

5. Click **Create Web Service**

El primer deploy tarda ~3-5 minutos (instala las dependencias).

### URLs que quedaran disponibles

```
https://threatscope-api.onrender.com/           → info de la API
https://threatscope-api.onrender.com/docs        → Swagger UI (interactivo)
https://threatscope-api.onrender.com/status      → health check
https://threatscope-api.onrender.com/detections  → detecciones historicas
```

### Probar el deploy

```bash
# Health check
curl https://threatscope-api.onrender.com/status

# Analizar un CSV
curl -X POST https://threatscope-api.onrender.com/analyze \
  -F "file=@examples/escenario_incidente.csv"
```

---

## 3. Nota sobre el plan free de Render

El plan free de Render tiene un limite: el servicio se "duerme" tras 15 minutos de inactividad
y tarda ~30 segundos en arrancar la primera peticion.

Para la entrevista: hacer una peticion a `/status` 2 minutos antes para que este despierto.

---

## 4. Verificacion final

Checklist antes de la entrevista:

- [ ] `git push` hecho — todos los commits en GitHub
- [ ] Render muestra "Live" (verde)
- [ ] `https://tu-app.onrender.com/status` retorna `{"status": "ok", ...}`
- [ ] `https://tu-app.onrender.com/docs` carga el Swagger UI
- [ ] Puedes ejecutar `/analyze` desde el Swagger UI con el CSV de ejemplo
- [ ] `pytest tests.py -v` → 38/38 pasando localmente
