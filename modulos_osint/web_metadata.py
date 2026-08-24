"""
modulos_osint/web_metadata.py — Recopilación de metadata web para Recon365.

Analiza archivos y metadata públicos de un sitio web:
    - robots.txt (rutas ocultas/bloqueadas)
    - sitemap.xml (estructura del sitio)
    - security.txt (contacto de seguridad)
    - Metadata de la página (título, descripción, Open Graph)

Uso:
    from modulos_osint.web_metadata import analizar_metadata_web
    metadata = await analizar_metadata_web("https://example.com")
"""

import re
from typing import Any
from urllib.parse import urljoin

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


async def obtener_robots_txt(base_url: str) -> dict[str, Any]:
    """
    Analiza el archivo robots.txt de un sitio.

    Detecta:
        - Rutas bloqueadas (Disallow) — posibles áreas sensibles
        - Sitemaps referenciados
        - User-agents específicos

    Args:
        base_url: URL base del sitio.

    Returns:
        Diccionario con rutas interesantes descubiertas.
    """
    resultado: dict[str, Any] = {
        "encontrado": False,
        "rutas_bloqueadas": [],
        "rutas_interesantes": [],
        "sitemaps": [],
        "user_agents": [],
        "raw": "",
    }

    url = urljoin(base_url, "/robots.txt")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                if resp.status == 200:
                    texto = await resp.text()
                    resultado["encontrado"] = True
                    resultado["raw"] = texto[:2000]

                    for linea in texto.split("\n"):
                        linea = linea.strip()
                        if linea.lower().startswith("disallow:"):
                            ruta = linea.split(":", 1)[1].strip()
                            if ruta and ruta != "/":
                                resultado["rutas_bloqueadas"].append(ruta)
                                # Detectar rutas interesantes
                                if any(kw in ruta.lower() for kw in [
                                    "admin", "login", "dashboard", "api", "backup",
                                    "private", "secret", "internal", "dev", "staging",
                                    "test", "debug", "config", "panel", ".env",
                                    "phpmyadmin", "wp-admin", "console",
                                ]):
                                    resultado["rutas_interesantes"].append(ruta)
                        elif linea.lower().startswith("sitemap:"):
                            sitemap_url = linea.split(":", 1)[1].strip()
                            resultado["sitemaps"].append(sitemap_url)
                        elif linea.lower().startswith("user-agent:"):
                            ua = linea.split(":", 1)[1].strip()
                            if ua != "*":
                                resultado["user_agents"].append(ua)

    except Exception as error:
        log.debug(f"Error obteniendo robots.txt de {base_url}: {error}")

    return resultado


async def obtener_sitemap(base_url: str, sitemap_urls: list[str] = None) -> dict[str, Any]:
    """
    Analiza el sitemap.xml de un sitio.

    Args:
        base_url: URL base del sitio.
        sitemap_urls: URLs de sitemaps encontradas en robots.txt.

    Returns:
        Diccionario con URLs descubiertas del sitemap.
    """
    resultado: dict[str, Any] = {
        "encontrado": False,
        "urls": [],
        "total_urls": 0,
    }

    urls_a_probar = sitemap_urls or []
    urls_a_probar.append(urljoin(base_url, "/sitemap.xml"))
    urls_a_probar.append(urljoin(base_url, "/sitemap_index.xml"))

    try:
        async with aiohttp.ClientSession() as session:
            for sitemap_url in urls_a_probar:
                try:
                    async with session.get(
                        sitemap_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False
                    ) as resp:
                        if resp.status == 200:
                            texto = await resp.text()
                            if "<url>" in texto or "<sitemap>" in texto:
                                resultado["encontrado"] = True
                                # Extraer URLs con regex simple
                                locs = re.findall(r"<loc>(.*?)</loc>", texto)
                                resultado["urls"] = locs[:100]  # Limitar
                                resultado["total_urls"] = len(locs)
                                break
                except Exception:
                    continue

    except Exception as error:
        log.debug(f"Error obteniendo sitemap de {base_url}: {error}")

    return resultado


async def obtener_security_txt(base_url: str) -> dict[str, Any]:
    """
    Busca y analiza el archivo security.txt (RFC 9116).

    Args:
        base_url: URL base del sitio.

    Returns:
        Diccionario con información de contacto de seguridad.
    """
    resultado: dict[str, Any] = {
        "encontrado": False,
        "contacto": [],
        "encryption": "",
        "policy": "",
        "acknowledgments": "",
    }

    urls_a_probar = [
        urljoin(base_url, "/.well-known/security.txt"),
        urljoin(base_url, "/security.txt"),
    ]

    try:
        async with aiohttp.ClientSession() as session:
            for url in urls_a_probar:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        if resp.status == 200:
                            texto = await resp.text()
                            if "contact:" in texto.lower():
                                resultado["encontrado"] = True
                                for linea in texto.split("\n"):
                                    linea = linea.strip()
                                    if linea.lower().startswith("contact:"):
                                        resultado["contacto"].append(
                                            linea.split(":", 1)[1].strip()
                                        )
                                    elif linea.lower().startswith("encryption:"):
                                        resultado["encryption"] = linea.split(":", 1)[1].strip()
                                    elif linea.lower().startswith("policy:"):
                                        resultado["policy"] = linea.split(":", 1)[1].strip()
                                    elif linea.lower().startswith("acknowledgments:"):
                                        resultado["acknowledgments"] = linea.split(":", 1)[1].strip()
                                break
                except Exception:
                    continue

    except Exception as error:
        log.debug(f"Error buscando security.txt en {base_url}: {error}")

    return resultado


async def analizar_metadata_web(url: str) -> dict[str, Any]:
    """
    Análisis completo de metadata web de un sitio.

    Args:
        url: URL del sitio a analizar.

    Returns:
        Diccionario completo con robots, sitemap, security.txt y metadata.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    log.info(f"Análisis de metadata web: {url}")

    # Ejecutar todo en paralelo
    robots_task = obtener_robots_txt(url)
    security_task = obtener_security_txt(url)

    robots, security = await __import__("asyncio").gather(
        robots_task, security_task
    )

    # Sitemap con URLs encontradas en robots
    sitemap = await obtener_sitemap(url, robots.get("sitemaps", []))

    resultado: dict[str, Any] = {
        "url": url,
        "robots_txt": robots,
        "sitemap": sitemap,
        "security_txt": security,
        "problemas": [],
    }

    # Detectar problemas
    if robots["rutas_interesantes"]:
        resultado["problemas"].append(
            f"robots.txt revela {len(robots['rutas_interesantes'])} rutas sensibles: "
            f"{', '.join(robots['rutas_interesantes'][:5])}"
        )

    if not security["encontrado"]:
        resultado["problemas"].append(
            "No se encontró security.txt — sin canal público de reporte de vulnerabilidades"
        )

    log.info(f"Metadata web completada para {url}")

    return resultado
