<![CDATA["""
utilidades/gestor_archivos.py — Gestión de archivos I/O para Recon365.

Funciones auxiliares para:
    - Leer listas de objetivos desde archivos .txt y .csv
    - Guardar reportes finales en formato .json
    - Guardar capturas de pantalla
    - Asegurar que existan los directorios necesarios

Uso:
    from utilidades.gestor_archivos import leer_objetivos, guardar_reporte
    objetivos = leer_objetivos("data/inputs/objetivos.txt")
    guardar_reporte(datos, "reporte_objetivo_1")
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utilidades.logger import obtener_logger

from configuracion import (
    EXTENSIONES_ENTRADA,
    RUTA_CAPTURAS,
    RUTA_INPUTS,
    RUTA_OUTPUTS,
)

log = obtener_logger(__name__)


def asegurar_directorios() -> None:
    """
    Crea los directorios necesarios si no existen.

    Directorios creados:
        - data/inputs/
        - data/outputs/
        - data/outputs/capturas/
    """
    directorios: list[Path] = [RUTA_INPUTS, RUTA_OUTPUTS, RUTA_CAPTURAS]

    for directorio in directorios:
        directorio.mkdir(parents=True, exist_ok=True)
        log.debug(f"Directorio verificado: {directorio}")

    log.info("Estructura de directorios verificada correctamente.")


def leer_objetivos(ruta: str | Path) -> list[dict[str, str]]:
    """
    Lee una lista de objetivos desde un archivo .txt o .csv.

    Formatos soportados:
        - .txt: Una URL por línea. Se genera un nombre automático.
        - .csv: Columnas esperadas: nombre, url, empresa.

    Args:
        ruta: Ruta al archivo de objetivos (relativa o absoluta).

    Returns:
        Lista de diccionarios con claves: nombre, url, empresa.

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ValueError: Si la extensión no es soportada.
    """
    ruta_archivo: Path = Path(ruta)

    if not ruta_archivo.exists():
        raise FileNotFoundError(f"Archivo de objetivos no encontrado: {ruta_archivo}")

    extension: str = ruta_archivo.suffix.lower()
    if extension not in EXTENSIONES_ENTRADA:
        raise ValueError(
            f"Extensión '{extension}' no soportada. "
            f"Use: {', '.join(EXTENSIONES_ENTRADA)}"
        )

    objetivos: list[dict[str, str]] = []

    if extension == ".txt":
        objetivos = _leer_txt(ruta_archivo)
    elif extension == ".csv":
        objetivos = _leer_csv(ruta_archivo)

    log.info(f"Objetivos cargados: {len(objetivos)} desde '{ruta_archivo.name}'")
    return objetivos


def _leer_txt(ruta: Path) -> list[dict[str, str]]:
    """
    Lee objetivos desde un archivo .txt (una URL por línea).

    Args:
        ruta: Ruta al archivo .txt.

    Returns:
        Lista de diccionarios con nombre auto-generado.
    """
    objetivos: list[dict[str, str]] = []

    with open(ruta, "r", encoding="utf-8") as archivo:
        for indice, linea in enumerate(archivo, start=1):
            url: str = linea.strip()
            if url and not url.startswith("#"):  # Ignorar vacías y comentarios
                objetivos.append({
                    "nombre": f"objetivo_{indice:03d}",
                    "url": url,
                    "empresa": "no_especificada",
                })

    return objetivos


def _leer_csv(ruta: Path) -> list[dict[str, str]]:
    """
    Lee objetivos desde un archivo .csv con columnas: nombre, url, empresa.

    Args:
        ruta: Ruta al archivo .csv.

    Returns:
        Lista de diccionarios con las columnas del CSV.
    """
    objetivos: list[dict[str, str]] = []

    with open(ruta, "r", encoding="utf-8", newline="") as archivo:
        lector = csv.DictReader(archivo)

        # Validar columnas requeridas
        columnas_requeridas: set[str] = {"nombre", "url", "empresa"}
        columnas_archivo: set[str] = set(lector.fieldnames or [])

        if not columnas_requeridas.issubset(columnas_archivo):
            faltantes: set[str] = columnas_requeridas - columnas_archivo
            raise ValueError(
                f"Columnas faltantes en CSV: {', '.join(faltantes)}. "
                f"Columnas requeridas: {', '.join(columnas_requeridas)}"
            )

        for fila in lector:
            if fila.get("url", "").strip():
                objetivos.append({
                    "nombre": fila["nombre"].strip(),
                    "url": fila["url"].strip(),
                    "empresa": fila.get("empresa", "no_especificada").strip(),
                })

    return objetivos


def guardar_reporte(
    datos: dict[str, Any],
    nombre_archivo: str,
) -> Path:
    """
    Guarda un reporte en formato JSON en la carpeta de outputs.

    Args:
        datos: Diccionario con los datos del reporte.
        nombre_archivo: Nombre base del archivo (sin extensión).

    Returns:
        Path al archivo JSON creado.
    """
    # Agregar timestamp al reporte
    datos["_metadata"] = {
        "generado_por": "Recon365 × J4N14",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    # Sanitizar nombre de archivo
    nombre_limpio: str = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in nombre_archivo
    )
    ruta_salida: Path = RUTA_OUTPUTS / f"{nombre_limpio}.json"

    with open(ruta_salida, "w", encoding="utf-8") as archivo:
        json.dump(datos, archivo, ensure_ascii=False, indent=2)

    log.info(f"Reporte guardado: {ruta_salida}")
    return ruta_salida


def guardar_captura(
    contenido: bytes,
    nombre: str,
) -> Path:
    """
    Guarda una captura de pantalla como archivo PNG.

    Args:
        contenido: Bytes de la imagen PNG.
        nombre: Nombre base del archivo (sin extensión).

    Returns:
        Path al archivo PNG creado.
    """
    nombre_limpio: str = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in nombre
    )
    ruta_captura: Path = RUTA_CAPTURAS / f"{nombre_limpio}.png"

    with open(ruta_captura, "wb") as archivo:
        archivo.write(contenido)

    log.info(f"Captura guardada: {ruta_captura}")
    return ruta_captura
]]>
