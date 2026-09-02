"""
main.py — Orquestador principal de Recon365 OSINT/ASM.

Pipeline de ejecución:
    - Modo Phishing (--archivo): Reconocimiento y perfilamiento (Motor J4N14)
    - Modo Organización (--org): Escaneo OSINT pasivo completo
    - Modo Servidor (--server): Levanta la interfaz web y API REST

Uso:
    python main.py --archivo objetivos.csv
    python main.py --org "Empresa X" --dominio "example.com"
    python main.py --server
"""

import argparse
import asyncio
import io
import sys
import time
from pathlib import Path
from typing import Any
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Forzar UTF-8 en la terminal de Windows
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

# Módulos Legacy (Perfilamiento)
from modulos.perfilador_ia import analizar_perfil, inicializar_motor
from modulos.recolector import recolectar_objetivo
from modulos.generador_ataques import crear_pretexto, generar_reporte_final

# Módulos Nuevos (OSINT / ASM)
from motores.osint_engine import motor_osint
from motores.threat_intel_engine import motor_amenazas
from motores.risk_engine import motor_riesgo
from motores.correlation_engine import motor_correlacion
from utilidades.base_datos import BaseDatos

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
db = BaseDatos()


def parsear_argumentos() -> argparse.Namespace:
    """Parsea argumentos de la línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="Recon365",
        description=(
            f"{NOMBRE_SISTEMA} v{VERSION} - "
            "Plataforma de Attack Surface Management & Threat Intel."
        ),
        epilog="ADVERTENCIA: Solo para auditorías autorizadas.",
    )
    
    # Grupo excluyente: ¿qué queremos hacer?
    grupo = parser.add_mutually_exclusive_group(required=True)
    
    grupo.add_argument(
        "--archivo",
        "-a",
        type=str,
        help="Archivo de objetivos (modo perfilamiento y spear phishing).",
    )
    
    grupo.add_argument(
        "--org",
        "-o",
        type=str,
        help="Nombre de la organización (modo escaneo OSINT pasivo).",
    )
    
    grupo.add_argument(
        "--server",
        "-s",
        action="store_true",
        help="Inicia la interfaz web y la API REST.",
    )
    
    # Argumentos adicionales
    parser.add_argument(
        "--dominio",
        "-d",
        type=str,
        help="Dominio principal (requerido con --org).",
    )

    parser.add_argument(
        "--skip-motor",
        action="store_true",
        default=False,
        help="Omitir verificación del motor de IA en modo archivo.",
    )

    return parser.parse_args()


# MODO: PERFILAMIENTO (LEGACY / SPEAR PHISHING)

def encontrar_archivo_objetivos(nombre_archivo: str | None = None) -> Path:
    if nombre_archivo:
        ruta: Path = RUTA_INPUTS / nombre_archivo
        if ruta.exists():
            return ruta
        raise FileNotFoundError(f"Archivo no encontrado: {ruta}")

    archivos_validos: list[Path] = sorted(
        [f for f in RUTA_INPUTS.iterdir() if f.is_file() and f.suffix.lower() in (".txt", ".csv")]
    )

    if not archivos_validos:
        raise FileNotFoundError("No se encontraron archivos en data/inputs/")
    return archivos_validos[0]

def mostrar_resumen_perfiles(resultados: list[dict[str, Any]], tiempo_total: float) -> None:
    imprimir_separador("RESUMEN DE PERFILAMIENTO")
    
    total = len(resultados)
    exitosos = sum(1 for r in resultados if r.get("_exitoso", False))
    
    tabla = Table(title="Resultados de Perfilamiento", show_header=True, header_style="bold cyan")
    tabla.add_column("Objetivo", style="white")
    tabla.add_column("Categoría", style="magenta")
    tabla.add_column("Confianza")
    tabla.add_column("Vector", style="yellow")
    
    for r in resultados:
        perfil = r.get("perfil_psicografico", {})
        confianza = perfil.get("confianza", 0.0)
        conf_str = f"[green]{confianza:.0%}[/green]" if confianza >= 0.7 else f"[red]{confianza:.0%}[/red]"
        tabla.add_row(
            r.get("objetivo", {}).get("nombre", "?"),
            perfil.get("categoria_predictiva", "—"),
            conf_str,
            r.get("vector_ataque", {}).get("tipo", "—")
        )
        
    consola.print(tabla)
    consola.print(f"\nExitosos: {exitosos}/{total} en {tiempo_total:.1f}s")

async def procesar_objetivo(objetivo: dict[str, str], indice: int, total: int) -> dict[str, Any]:
    nombre = objetivo.get("nombre", "desconocido")
    imprimir_separador(f"Objetivo {indice}/{total}: {nombre}")

    try:
        log.info("Fase 1: Recolección de datos...")
        datos = await recolectar_objetivo(objetivo)

        # Usar texto refinado por J4N14 si está disponible, sino texto bruto
        texto = datos.get("texto_refinado") or datos.get("texto_extraido", "")

        log.info("Fase 2: Perfilamiento J4N14...")
        perfil = analizar_perfil(texto, nombre)

        log.info("Fase 3: Vector de ataque...")
        perfil["empresa"] = objetivo.get("empresa", "la empresa")
        vector = crear_pretexto(perfil)

        log.info("Fase 4: Reporte final...")
        reporte = generar_reporte_final(objetivo, perfil, vector)
        reporte["_exitoso"] = True
        
        guardar_reporte(reporte, f"reporte_{nombre}")
        return reporte
    except Exception as e:
        log.error(f"Error procesando {nombre}: {e}")
        return {"error": str(e), "_exitoso": False}

async def ejecutar_modo_archivo(args: argparse.Namespace) -> None:
    tiempo_inicio = time.time()
    
    if not args.skip_motor:
        if not inicializar_motor():
            imprimir_error("Motor J4N14 no disponible. Use --skip-motor para pruebas.")
            sys.exit(1)

    ruta = encontrar_archivo_objetivos(args.archivo)
    objetivos = leer_objetivos(str(ruta))
    
    resultados = []
    for i, obj in enumerate(objetivos, 1):
        res = await procesar_objetivo(obj, i, len(objetivos))
        resultados.append(res)

    mostrar_resumen_perfiles(resultados, time.time() - tiempo_inicio)


# MODO: ORGANIZACIÓN (NUEVO OSINT / ASM)

async def ejecutar_modo_org(args: argparse.Namespace) -> None:
    if not args.dominio:
        imprimir_error("Se requiere --dominio cuando se usa --org")
        sys.exit(1)
        
    org_nombre = args.org
    dominio = args.dominio
    tiempo_inicio = time.time()
    
    imprimir_separador(f"ESCANEO OSINT/ASM: {org_nombre} ({dominio})")
    
    # 1. Crear/Obtener org en DB
    org_id = db.crear_organizacion(org_nombre, dominio)
    
    # 2. Motor OSINT
    consola.print("[cyan]Iniciando fase de recolección OSINT (esto tomará varios minutos)...[/cyan]")
    stats_osint = await motor_osint.analizar_organizacion(org_id, dominio)
    
    # 3. Threat Intel
    consola.print("[yellow]Buscando vulnerabilidades conocidas (CVEs)...[/yellow]")
    vulns_count = await motor_amenazas.enriquecer_tecnologias(org_id)
    
    # 4. Evaluacion de riesgo
    consola.print("[magenta]Evaluando postura de riesgo...[/magenta]")
    riesgo = motor_riesgo.evaluar_organizacion(org_id)
    
    # Resumen
    tiempo_total = time.time() - tiempo_inicio
    imprimir_separador("RESUMEN DE ESCANEO")
    
    tabla = Table(title=f"Resultados OSINT: {org_nombre}", show_header=True)
    tabla.add_column("Métrica", style="cyan")
    tabla.add_column("Valor", style="white bold")
    
    tabla.add_row("Subdominios Descubiertos", str(stats_osint.get("total_subdominios", 0)))
    tabla.add_row("Tecnologías Detectadas", str(stats_osint.get("total_tecnologias", 0)))
    tabla.add_row("Certificados (CT Logs)", str(stats_osint.get("total_certificados", 0)))
    tabla.add_row("Secretos Expuestos", str(stats_osint.get("total_secretos", 0)))
    tabla.add_row("Repositorios (GitHub)", str(stats_osint.get("total_repositorios", 0)))
    tabla.add_row("Vulnerabilidades (CVE)", str(vulns_count))
    tabla.add_row("Nivel de Riesgo", f"{riesgo['score']:.1f}/100 ({riesgo['nivel']})")
    
    consola.print(tabla)
    consola.print(f"\n[green]Escaneo completado en {tiempo_total:.1f}s[/green]")
    consola.print("\nPara visualizar los resultados y el grafo de relaciones:")
    consola.print("  [bold]python main.py --server[/bold]")

# MODO: SERVIDOR

def ejecutar_modo_servidor() -> None:
    try:
        import uvicorn
        imprimir_separador("INICIANDO SERVIDOR WEB")
        consola.print("Dashboard disponible en: [bold underline cyan]http://127.0.0.1:8000[/bold underline cyan]")
        consola.print("API disponible en: [bold underline yellow]http://127.0.0.1:8000/docs[/bold underline yellow]")
        consola.print("Presiona Ctrl+C para detener.")
        
        uvicorn.run("servidor:app", host="127.0.0.1", port=8000, reload=False, log_level="warning")
    except ImportError:
        imprimir_error("No se pudo importar uvicorn o fastapi. Ejecuta: pip install -r requirements.txt")

# PUNTO DE ENTRADA

def main() -> None:
    args = parsear_argumentos()
    imprimir_banner()
    asegurar_directorios()
    
    try:
        if args.server:
            ejecutar_modo_servidor()
        elif args.org:
            asyncio.run(ejecutar_modo_org(args))
        elif args.archivo:
            asyncio.run(ejecutar_modo_archivo(args))
            
    except KeyboardInterrupt:
        consola.print("\n[yellow]Interrumpido por el usuario.[/yellow]")
        sys.exit(0)
    except Exception as e:
        consola.print(f"\n[red bold]Error fatal: {e}[/red bold]")
        log.critical(f"Error fatal: {e}", exc_info=True)
        sys.exit(1)
if __name__ == "__main__":
    main()