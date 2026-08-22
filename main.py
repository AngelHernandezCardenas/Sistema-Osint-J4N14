"""
main.py — Orquestador principal de Recon365 × Motor J4N14.

Pipeline de ejecución:
    1. Leer lista de objetivos desde data/inputs/
    2. Para cada objetivo:
        a. Recolectar datos públicos (Playwright headless)
        b. Perfilar con Motor J4N14 (IA local vía Ollama)
        c. Generar vector de Spear Phishing personalizado
        d. Guardar reporte JSON en data/outputs/
    3. Resumen estadístico en consola

Uso:
    python main.py
    python main.py --archivo objetivos.csv
    python main.py --archivo lista.txt

⚠️ DISCLAIMER: Solo para auditorías de seguridad autorizadas.
"""

import argparse
import asyncio
import io
import sys
import time
from pathlib import Path
from typing import Any

# Forzar UTF-8 en la terminal de Windows antes de cualquier salida
if sys.stdout and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table

from configuracion import (
    NOMBRE_MOTOR,
    NOMBRE_SISTEMA,
    RUTA_INPUTS,
    VERSION,
)
from modulos.perfilador_ia import analizar_perfil, inicializar_motor
from modulos.recolector import recolectar_objetivo
from modulos.generador_ataques import crear_pretexto, generar_reporte_final
from utilidades.gestor_archivos import (
    asegurar_directorios,
    guardar_reporte,
    leer_objetivos,
)
from utilidades.logger import (
    imprimir_banner,
    imprimir_error,
    imprimir_exito,
    imprimir_separador,
    obtener_logger,
)

log = obtener_logger(__name__)
consola = Console()


def parsear_argumentos() -> argparse.Namespace:
    """
    Parsea argumentos de la línea de comandos.

    Returns:
        Namespace con los argumentos parseados.
    """
    parser = argparse.ArgumentParser(
        prog="Recon365",
        description=(
            f"{NOMBRE_SISTEMA} × {NOMBRE_MOTOR} — "
            "Módulo de reconocimiento OSINT con perfilamiento IA."
        ),
        epilog="⚠️  Solo para auditorías de seguridad autorizadas.",
    )
    parser.add_argument(
        "--archivo",
        "-a",
        type=str,
        default=None,
        help=(
            "Nombre del archivo de objetivos en data/inputs/ "
            "(ej: objetivos.txt, lista.csv). Si no se especifica, "
            "se usa el primer archivo encontrado."
        ),
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"{NOMBRE_SISTEMA} v{VERSION}",
    )
    parser.add_argument(
        "--skip-motor",
        action="store_true",
        default=False,
        help="Omitir verificación del motor de IA (para testing).",
    )

    return parser.parse_args()


def encontrar_archivo_objetivos(nombre_archivo: str | None = None) -> Path:
    """
    Encuentra el archivo de objetivos a procesar.

    Args:
        nombre_archivo: Nombre específico del archivo, o None para autodetección.

    Returns:
        Path al archivo de objetivos.

    Raises:
        FileNotFoundError: Si no se encuentra ningún archivo válido.
    """
    if nombre_archivo:
        ruta: Path = RUTA_INPUTS / nombre_archivo
        if ruta.exists():
            return ruta
        raise FileNotFoundError(
            f"Archivo no encontrado: {ruta}\n"
            f"Asegúrese de colocarlo en: {RUTA_INPUTS}"
        )

    # Autodetección: buscar el primer .txt o .csv en inputs/
    archivos_validos: list[Path] = sorted(
        [
            f for f in RUTA_INPUTS.iterdir()
            if f.is_file() and f.suffix.lower() in (".txt", ".csv")
        ]
    )

    if not archivos_validos:
        raise FileNotFoundError(
            f"No se encontraron archivos de objetivos en: {RUTA_INPUTS}\n"
            f"Coloque un archivo .txt o .csv con las URLs a analizar."
        )

    log.info(f"Archivo autodetectado: {archivos_validos[0].name}")
    return archivos_validos[0]


def mostrar_resumen(
    resultados: list[dict[str, Any]],
    tiempo_total: float,
) -> None:
    """
    Muestra un resumen estadístico de la ejecución en consola.

    Args:
        resultados: Lista de reportes finales generados.
        tiempo_total: Tiempo total de ejecución en segundos.
    """
    imprimir_separador("RESUMEN DE EJECUCIÓN")

    # Contadores
    total: int = len(resultados)
    exitosos: int = sum(1 for r in resultados if r.get("_exitoso", False))
    fallidos: int = total - exitosos

    # Tabla de resultados
    tabla = Table(
        title=f"🗺️ {NOMBRE_SISTEMA} × {NOMBRE_MOTOR} — Resultados",
        show_header=True,
        header_style="bold cyan",
    )
    tabla.add_column("Objetivo", style="white", min_width=20)
    tabla.add_column("Categoría", style="magenta", justify="center")
    tabla.add_column("Confianza", justify="center")
    tabla.add_column("Vector", style="yellow", min_width=20)
    tabla.add_column("Estado", justify="center")

    for resultado in resultados:
        nombre: str = resultado.get("objetivo", {}).get("nombre", "?")
        perfil: dict = resultado.get("perfil_psicografico", {})
        vector: dict = resultado.get("vector_ataque", {})
        exitoso: bool = resultado.get("_exitoso", False)

        categoria: str = perfil.get("categoria_predictiva", "—")
        confianza: float = perfil.get("confianza", 0.0)
        tipo_vector: str = vector.get("tipo", "—")

        # Colorear confianza
        if confianza >= 0.7:
            conf_str: str = f"[green]{confianza:.0%}[/green]"
        elif confianza >= 0.4:
            conf_str = f"[yellow]{confianza:.0%}[/yellow]"
        else:
            conf_str = f"[red]{confianza:.0%}[/red]"

        estado_str: str = "[green]✅[/green]" if exitoso else "[red]❌[/red]"

        tabla.add_row(nombre, categoria, conf_str, tipo_vector, estado_str)

    consola.print(tabla)
    consola.print()

    # Estadísticas
    consola.print(f"[bold]📊 Estadísticas:[/bold]")
    consola.print(f"   Total de objetivos: {total}")
    consola.print(f"   Exitosos: [green]{exitosos}[/green]")
    consola.print(f"   Fallidos: [red]{fallidos}[/red]")
    consola.print(f"   Tiempo total: {tiempo_total:.1f}s")
    consola.print(
        f"   Tiempo promedio: {tiempo_total / max(total, 1):.1f}s por objetivo"
    )
    consola.print()


async def procesar_objetivo(
    objetivo: dict[str, str],
    indice: int,
    total: int,
) -> dict[str, Any]:
    """
    Procesa un objetivo completo a través del pipeline.

    Pipeline: Recolectar → Perfilar (J4N14) → Generar Vector → Guardar.

    Args:
        objetivo: Diccionario con nombre, url, empresa.
        indice: Número del objetivo actual (1-indexed).
        total: Total de objetivos a procesar.

    Returns:
        Reporte final del objetivo.
    """
    nombre: str = objetivo.get("nombre", "desconocido")

    imprimir_separador(f"Objetivo {indice}/{total}: {nombre}")

    try:
        # === FASE 1: RECOLECCIÓN ===
        log.info("📡 Fase 1: Recolección de datos...")
        datos_recolectados: dict[str, Any] = await recolectar_objetivo(objetivo)

        if not datos_recolectados.get("exitoso", False):
            log.warning(
                f"Recolección parcial/fallida para '{nombre}'. "
                f"Errores: {datos_recolectados.get('errores', [])}"
            )
            # Continuar con lo que se tenga

        texto: str = datos_recolectados.get("texto_extraido", "")

        # === FASE 2: PERFILAMIENTO IA (Motor J4N14) ===
        log.info("🧠 Fase 2: Perfilamiento con Motor J4N14...")
        perfil: dict[str, Any] = analizar_perfil(texto, nombre)

        if perfil.get("error"):
            log.warning(
                f"Error en perfilamiento de '{nombre}': {perfil['error']}"
            )

        # === FASE 3: GENERACIÓN DE VECTOR ===
        log.info("⚔️  Fase 3: Generación de vector de ataque...")
        # Agregar empresa al perfil para el generador
        perfil["empresa"] = objetivo.get("empresa", "la empresa")
        vector: dict[str, Any] = crear_pretexto(perfil)

        # === FASE 4: REPORTE FINAL ===
        log.info("📄 Fase 4: Generando reporte final...")
        reporte: dict[str, Any] = generar_reporte_final(
            objetivo, perfil, vector
        )
        reporte["_exitoso"] = True

        # Guardar en disco
        nombre_archivo: str = f"reporte_{nombre}"
        ruta_guardado: Path = guardar_reporte(reporte, nombre_archivo)

        imprimir_exito(
            f"Objetivo '{nombre}' procesado — "
            f"Categoría: {perfil.get('categoria_predictiva', '?')} — "
            f"Reporte: {ruta_guardado.name}"
        )

        return reporte

    except Exception as error:
        log.error(f"Error procesando objetivo '{nombre}': {error}")
        imprimir_error(f"Falló el procesamiento de '{nombre}': {error}")

        reporte_error: dict[str, Any] = {
            "objetivo": objetivo,
            "perfil_psicografico": {},
            "vector_ataque": {},
            "error": str(error),
            "_exitoso": False,
        }
        return reporte_error


async def ejecutar_pipeline(args: argparse.Namespace) -> None:
    """
    Ejecuta el pipeline completo de Recon365.

    Args:
        args: Argumentos de línea de comandos.
    """
    tiempo_inicio: float = time.time()

    # === INICIALIZACIÓN ===
    imprimir_banner()
    asegurar_directorios()

    # === VERIFICAR MOTOR DE IA ===
    if not args.skip_motor:
        motor_listo: bool = inicializar_motor()
        if not motor_listo:
            imprimir_error(
                "Motor J4N14 no disponible. "
                "Ejecute 'ollama serve' e intente de nuevo. "
                "O use --skip-motor para testing."
            )
            sys.exit(1)
    else:
        log.warning("Verificación del motor de IA omitida (--skip-motor).")

    # === CARGAR OBJETIVOS ===
    try:
        ruta_archivo: Path = encontrar_archivo_objetivos(args.archivo)
        objetivos: list[dict[str, str]] = leer_objetivos(str(ruta_archivo))
    except (FileNotFoundError, ValueError) as error:
        imprimir_error(str(error))
        sys.exit(1)

    if not objetivos:
        imprimir_error("No se encontraron objetivos válidos en el archivo.")
        sys.exit(1)

    log.info(f"Objetivos a procesar: {len(objetivos)}")

    # === PROCESAR OBJETIVOS ===
    resultados: list[dict[str, Any]] = []
    total: int = len(objetivos)

    for indice, objetivo in enumerate(objetivos, start=1):
        resultado: dict[str, Any] = await procesar_objetivo(
            objetivo, indice, total
        )
        resultados.append(resultado)

    # === RESUMEN ===
    tiempo_total: float = time.time() - tiempo_inicio
    mostrar_resumen(resultados, tiempo_total)

    imprimir_exito(
        f"Pipeline completado en {tiempo_total:.1f}s — "
        f"{len(resultados)} objetivos procesados."
    )


def main() -> None:
    """Punto de entrada principal."""
    args: argparse.Namespace = parsear_argumentos()

    try:
        asyncio.run(ejecutar_pipeline(args))
    except KeyboardInterrupt:
        consola.print("\n[yellow]Ejecucion interrumpida por el usuario.[/yellow]")
        sys.exit(0)
    except Exception as error:
        consola.print(f"\n[red bold]Error fatal: {error}[/red bold]")
        log.critical(f"Error fatal: {error}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()