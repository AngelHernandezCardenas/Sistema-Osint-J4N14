"""
configuracion.py — Variables globales y configuración del sistema Recon365.

Este módulo centraliza todas las constantes, rutas y parámetros
de configuración utilizados por los distintos módulos del sistema.
Optimizado para ejecución local con GPU NVIDIA de 8 GB VRAM.
"""

from pathlib import Path
from typing import Final

# RUTAS DEL PROYECTO

RUTA_BASE: Final[Path] = Path(__file__).parent
RUTA_DATOS: Final[Path] = RUTA_BASE / "data"
RUTA_INPUTS: Final[Path] = RUTA_DATOS / "inputs"
RUTA_OUTPUTS: Final[Path] = RUTA_DATOS / "outputs"
RUTA_CAPTURAS: Final[Path] = RUTA_OUTPUTS / "capturas"
RUTA_DB: Final[Path] = RUTA_DATOS / "db"

# CONFIGURACIÓN DEL MODELO DE IA (Motor J4N14)

# API local — Ollama (para mock y compatibilidad)
API_BASE_URL: Final[str] = "http://localhost:11434"
API_ENDPOINT_CHAT: Final[str] = f"{API_BASE_URL}/api/chat"
API_ENDPOINT_GENERAR: Final[str] = f"{API_BASE_URL}/api/generate"

# API local — LM Studio (formato OpenAI, Dolphin real)
LMSTUDIO_BASE_URL: Final[str] = "http://localhost:1234"
LMSTUDIO_ENDPOINT_CHAT: Final[str] = f"{LMSTUDIO_BASE_URL}/v1/chat/completions"
LMSTUDIO_ENDPOINT_MODELS: Final[str] = f"{LMSTUDIO_BASE_URL}/v1/models"

# Modelo LLM — optimizado para 8 GB VRAM
MODELO_IA: Final[str] = "dolphin-2.9.4-llama3.1-8b"

# Parámetros de generación
TEMPERATURA: Final[float] = 0.3          # Baja para respuestas determinísticas
TOP_P: Final[float] = 0.9
MAX_TOKENS: Final[int] = 2048
GPU_LAYERS: Final[int] = 35             # Capas cargadas en VRAM (8 GB)
CONTEXTO_VENTANA: Final[int] = 4096     # Tokens de contexto

# Control de IA generativa (J4N14 en generador_ataques y recolector)
USAR_IA_GENERATIVA: Final[bool] = True   # Habilitar J4N14 en todos los módulos
TIMEOUT_IA_GENERACION: Final[int] = 120  # Timeout para generación de correos (seg)
TIMEOUT_IA_REFINAMIENTO: Final[int] = 90  # Timeout para refinamiento de texto (seg)

# CONFIGURACIÓN DEL NAVEGADOR (Playwright)

NAVEGADOR_HEADLESS: Final[bool] = True
TIMEOUT_NAVEGADOR: Final[int] = 30_000   # 30 segundos en milisegundos
TIMEOUT_ESPERA: Final[int] = 10_000      # Espera de elementos (ms)
MAX_REINTENTOS: Final[int] = 3
DELAY_ENTRE_REINTENTOS: Final[float] = 2.0  # Segundos entre reintentos

# User-Agent para evitar detección básica
USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# CONFIGURACIÓN DE LOGGING

LOG_NIVEL: Final[str] = "DEBUG"
LOG_ARCHIVO: Final[str] = "recon365.log"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024   # 5 MB por archivo de log
LOG_BACKUP_COUNT: Final[int] = 3               # Archivos de log rotados

# CONFIGURACIÓN DEL SISTEMA

VERSION: Final[str] = "2.0.0-osint"
NOMBRE_SISTEMA: Final[str] = "Recon365"
NOMBRE_MOTOR: Final[str] = "J4N14"

# Categorías predictivas del motor J4N14
CATEGORIAS_PREDICTIVAS: Final[list[str]] = [
    "JERARQUIA",
    "ESTILO_VIDA",
    "TECNOLOGICO",
]

# Extensiones de archivo de entrada soportadas
EXTENSIONES_ENTRADA: Final[list[str]] = [".txt", ".csv"]

# ── MODO LIGHT (sin GPU, sin IA local) ──────────────────────────────────────
# Rama 'light': para máquinas sin GPU / sin LM Studio instalado.
# Cuando es True, el sistema salta automáticamente la generación con IA y usa
# el pipeline de plantillas estáticas que ya existe en generador_ataques.py.
# En la rama 'main' (GPU disponible), este flag es False.
MODO_LIGHT: Final[bool] = True

# ── OPTIMIZADOR GP (Programación Genética con DEAP) ─────────────────────────
# Motor evolutivo que aprende a seleccionar la plantilla óptima para cada perfil.
# Corre 100% en CPU — sin GPU, sin IA local. Requiere: pip install deap numpy
# En rama 'light' se incluye desactivado por defecto; activar cuando DEAP esté
# instalado y se quiera experimentar con optimización dinámica de plantillas.
USAR_GP_OPTIMIZER: Final[bool] = False   # ← Cambiar a True para activar el GP
GP_NUM_FASES: Final[int] = 10            # Entornos distintos a recorrer
GP_GEN_POR_FASE: Final[int] = 5         # Generaciones por fase
GP_TAM_POBLACION: Final[int] = 50       # Individuos por generación
GP_TAM_ELITE: Final[int] = 10           # Semilla elite entre fases
GP_MAX_TREE_HEIGHT: Final[int] = 8      # Límite de altura del árbol (control bloat)