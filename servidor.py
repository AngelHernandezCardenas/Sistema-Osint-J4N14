"""
servidor.py — Backend FastAPI para Recon365 OSINT/ASM.

Proporciona una API REST para interactuar con la base de datos
y lanzar escaneos. Sirve la interfaz web estática.

Uso:
    uvicorn servidor:app --reload
"""

import asyncio
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from utilidades.base_datos import BaseDatos
from utilidades.logger import obtener_logger
from motores.osint_engine import motor_osint
from motores.threat_intel_engine import motor_amenazas
from motores.risk_engine import motor_riesgo
from motores.correlation_engine import motor_correlacion

log = obtener_logger(__name__)

# Configuración de FastAPI
app = FastAPI(
    title="Recon365 OSINT/ASM",
    description="API para la plataforma de Attack Surface Management",
    version="2.0.0"
)

# CORS (para desarrollo local)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base de datos compartida
db = BaseDatos()

# Montar archivos estáticos
WEB_DIR = Path(__file__).parent / "web"
WEB_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

# ============================================================================
# RUTAS DE LA API
# ============================================================================

@app.get("/api/organizaciones")
async def listar_organizaciones():
    """Lista todas las organizaciones analizadas."""
    return db.listar_organizaciones()

@app.post("/api/scan")
async def iniciar_escaneo(nombre: str, dominio: str, background_tasks: BackgroundTasks):
    """
    Inicia un escaneo completo de una organización en segundo plano.
    """
    # 1. Crear organización en BD
    org_id = db.crear_organizacion(nombre, dominio)
    
    # 2. Definir tarea de fondo
    async def tarea_escaneo(org_id_task: int, dominio_task: str):
        log.info(f"Escaneo en segundo plano iniciado para {dominio_task}")
        try:
            # Fase OSINT
            await motor_osint.analizar_organizacion(org_id_task, dominio_task)
            
            # Fase Inteligencia de Amenazas
            await motor_amenazas.enriquecer_tecnologias(org_id_task)
            
            # Fase Riesgo
            motor_riesgo.evaluar_organizacion(org_id_task)
            
            log.info(f"Escaneo completado con éxito para {dominio_task}")
        except Exception as e:
            log.error(f"Error en escaneo de {dominio_task}: {e}")
            
    # 3. Lanzar tarea
    background_tasks.add_task(tarea_escaneo, org_id, dominio)
    
    return {"mensaje": "Escaneo iniciado", "org_id": org_id, "dominio": dominio}

@app.get("/api/resultados/{org_id}")
async def obtener_resultados(org_id: int):
    """Obtiene un resumen de resultados para una organización."""
    org = db.obtener_organizacion(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organización no encontrada")
        
    stats = db.obtener_estadisticas(org_id)
    dominios = db.obtener_dominios(org_id)
    tecnologias = db.obtener_tecnologias(org_id)
    secretos = db.obtener_secretos(org_id)
    vulnerabilidades = db.obtener_vulnerabilidades(org_id)
    alertas = db.obtener_alertas(org_id)
    
    return {
        "organizacion": org,
        "estadisticas": stats,
        "dominios_count": len(dominios),
        "tecnologias": tecnologias,
        "secretos": secretos,
        "vulnerabilidades": vulnerabilidades,
        "alertas": alertas,
    }

@app.get("/api/grafo/{org_id}")
async def obtener_grafo(org_id: int):
    """Obtiene el grafo de correlación para visualización."""
    org = db.obtener_organizacion(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organización no encontrada")
        
    return motor_correlacion.construir_grafo(org_id)

@app.get("/api/riesgo/{org_id}")
async def obtener_riesgo(org_id: int):
    """Obtiene la última evaluación de riesgo."""
    # Obtenemos la última evaluación de la BD (si existe)
    conn = db._conectar()
    row = conn.execute(
        "SELECT * FROM evaluaciones_riesgo WHERE org_id = ? ORDER BY creado_en DESC LIMIT 1",
        (org_id,)
    ).fetchone()
    
    if row:
        import json
        res = dict(row)
        res["factores"] = json.loads(res["factores"])
        return res
        
    # Si no hay, forzamos cálculo
    return motor_riesgo.evaluar_organizacion(org_id)

@app.get("/api/diff/{org_id}")
async def obtener_diff(org_id: int):
    """Obtiene diferencias con el escaneo anterior."""
    return db.comparar_snapshots(org_id)

# ============================================================================
# RUTAS DEL FRONTEND
# ============================================================================

@app.get("/")
async def index():
    """Sirve la página principal (dashboard)."""
    index_path = WEB_DIR / "index.html"
    if not index_path.exists():
        return {"mensaje": "Frontend no disponible. Ejecute el sistema completo o revise web/index.html"}
    return FileResponse(index_path)

if __name__ == "__main__":
    import uvicorn
    log.info("Iniciando servidor FastAPI en http://127.0.0.1:8000")
    uvicorn.run("servidor:app", host="127.0.0.1", port=8000, reload=True)
