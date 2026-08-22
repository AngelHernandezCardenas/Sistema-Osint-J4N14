<![CDATA["""
utilidades/logger.py — Sistema de logging centralizado para Recon365.

Proporciona un logger profesional con salida dual:
    - Consola: Coloreada con Rich para legibilidad
    - Archivo: Rotativo para persistencia

Uso:
    from utilidades.logger import obtener_logger
    log = obtener_logger(__name__)
    log.info("Operación completada")
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from configuracion import (
    LOG_ARCHIVO,
    LOG_BACKUP_COUNT,
    LOG_MAX_BYTES,
    LOG_NIVEL,
    NOMBRE_SISTEMA,
    RUTA_BASE,
)

# ============================================================================
# TEMA PERSONALIZADO PARA RICH
# ============================================================================

_TEMA_RECON365 = Theme({
    "info": "cyan",
    "warning": "yellow bold",
    "error": "red bold",
    "critical": "white on red bold",
    "success": "green bold",
    "motor": "magenta bold",         # Para mensajes del Motor J4N14
    "recolector": "blue bold",       # Para mensajes del recolector
    "ataque": "red italic",          # Para mensajes del generador
})

_consola = Console(theme=_TEMA_RECON365)

# ============================================================================
# REGISTRO DE LOGGERS CREADOS (evitar duplicados)
# ============================================================================

_loggers_registrados: dict[str, logging.Logger] = {}


def obtener_logger(
    nombre: str,
    nivel: Optional[str] = None,
) -> logging.Logger:
    """
    Crea o recupera un logger configurado para Recon365.

    Args:
        nombre: Nombre del módulo (usualmente __name__).
        nivel: Nivel de logging override. Si None, usa LOG_NIVEL de configuración.

    Returns:
        Logger configurado con salida a consola (Rich) y archivo rotativo.
    """
    # Evitar crear loggers duplicados
    if nombre in _loggers_registrados:
        return _loggers_registrados[nombre]

    nivel_log: str = nivel or LOG_NIVEL
    logger = logging.getLogger(f"{NOMBRE_SISTEMA}.{nombre}")
    logger.setLevel(getattr(logging, nivel_log.upper(), logging.DEBUG))

    # Evitar propagación al logger root
    logger.propagate = False

    # --- Handler de consola con Rich ---
    handler_consola = RichHandler(
        console=_consola,
        show_time=True,
        show_level=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        log_time_format="[%H:%M:%S]",
    )
    handler_consola.setLevel(getattr(logging, nivel_log.upper(), logging.DEBUG))
    formato_consola = logging.Formatter(
        fmt="%(message)s",
        datefmt="[%X]",
    )
    handler_consola.setFormatter(formato_consola)

    # --- Handler de archivo rotativo ---
    ruta_log: Path = RUTA_BASE / LOG_ARCHIVO
    handler_archivo = RotatingFileHandler(
        filename=str(ruta_log),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler_archivo.setLevel(logging.DEBUG)  # Archivo captura TODO
    formato_archivo = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] [%(name)s] — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler_archivo.setFormatter(formato_archivo)

    # Agregar handlers solo si no existen
    if not logger.handlers:
        logger.addHandler(handler_consola)
        logger.addHandler(handler_archivo)

    _loggers_registrados[nombre] = logger
    return logger


def imprimir_banner() -> None:
    """Imprime el banner de inicio de Recon365 en consola."""
    _consola.print()
    _consola.print(
        "[bold magenta]"
        "╔══════════════════════════════════════════════════╗\n"
        "║        🗺️  M.A.P.A. — Recon365 × J4N14          ║\n"
        "║   Módulo de Análisis de Perfiles Abiertos       ║\n"
        "║   Motor de Inferencia de IA Local               ║\n"
        "╚══════════════════════════════════════════════════╝"
        "[/bold magenta]"
    )
    _consola.print(
        "[dim]⚠️  Solo para auditorías de seguridad autorizadas.[/dim]"
    )
    _consola.print()


def imprimir_separador(titulo: str = "") -> None:
    """Imprime un separador visual en consola."""
    if titulo:
        _consola.rule(f"[bold cyan]{titulo}[/bold cyan]")
    else:
        _consola.rule()


def imprimir_exito(mensaje: str) -> None:
    """Imprime un mensaje de éxito destacado."""
    _consola.print(f"[success]✅ {mensaje}[/success]")


def imprimir_error(mensaje: str) -> None:
    """Imprime un mensaje de error destacado."""
    _consola.print(f"[error]❌ {mensaje}[/error]")


def imprimir_motor(mensaje: str) -> None:
    """Imprime un mensaje del Motor J4N14."""
    _consola.print(f"[motor]🧠 [J4N14] {mensaje}[/motor]")
]]>
