"""
configuracion.py — Variables globales y configuración del sistema Recon365.

Este módulo centraliza todas las constantes, rutas y parámetros
de configuración utilizados por los distintos módulos del sistema.
Optimizado para ejecución local con GPU NVIDIA de 8 GB VRAM.
"""

from pathlib import Path
from typing import Final

# ============================================================================
# RUTAS DEL PROYECTO
# ============================================================================

RUTA_BASE: Final[Path] = Path(__file__).parent
RUTA_DATOS: Final[Path] = RUTA_BASE / "data"
RUTA_INPUTS: Final[Path] = RUTA_DATOS / "inputs"
RUTA_OUTPUTS: Final[Path] = RUTA_DATOS / "outputs"
RUTA_CAPTURAS: Final[Path] = RUTA_OUTPUTS / "capturas"
RUTA_DB: Final[Path] = RUTA_DATOS / "db"

# ============================================================================
# CONFIGURACIÓN DEL MODELO DE IA (Motor J4N14)
# ============================================================================

# API local compatible con Ollama / LM Studio
API_BASE_URL: Final[str] = "http://localhost:11434"
API_ENDPOINT_CHAT: Final[str] = f"{API_BASE_URL}/api/chat"
API_ENDPOINT_GENERAR: Final[str] = f"{API_BASE_URL}/api/generate"

# Modelo LLM — optimizado para 8 GB VRAM
MODELO_IA: Final[str] = "llama3.1:8b"

# Parámetros de generación
TEMPERATURA: Final[float] = 0.3          # Baja para respuestas determinísticas
TOP_P: Final[float] = 0.9
MAX_TOKENS: Final[int] = 2048
GPU_LAYERS: Final[int] = 35             # Capas cargadas en VRAM (8 GB)
CONTEXTO_VENTANA: Final[int] = 4096     # Tokens de contexto

# ============================================================================
# CONFIGURACIÓN DEL NAVEGADOR (Playwright)
# ============================================================================

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

# ============================================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================================

LOG_NIVEL: Final[str] = "DEBUG"
LOG_ARCHIVO: Final[str] = "recon365.log"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024   # 5 MB por archivo de log
LOG_BACKUP_COUNT: Final[int] = 3               # Archivos de log rotados

# ============================================================================
# CONFIGURACIÓN DEL SISTEMA
# ============================================================================

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