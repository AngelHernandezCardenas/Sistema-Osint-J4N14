"""
modulos/recolector.py — Módulo de scraping y recolección visual para Recon365.

Utiliza Playwright en modo headless para:
    - Validar accesibilidad de URLs públicas
    - Extraer texto relevante (biografías, descripciones) del DOM
    - Tomar capturas de pantalla full-page
    - Refinar texto extraído con J4N14 (Dolphin) para filtrar ruido

Manejo de errores con reintentos y backoff exponencial.

Uso:
    from modulos.recolector import recolectar_objetivo
    datos = await recolectar_objetivo({"nombre": "test", "url": "https://...", "empresa": "X"})
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Optional

import requests as http_requests

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
    TimeoutError as PlaywrightTimeoutError,
)

from utilidades.logger import obtener_logger
from utilidades.gestor_archivos import guardar_captura

from configuracion import (
    DELAY_ENTRE_REINTENTOS,
    LMSTUDIO_ENDPOINT_CHAT,
    MAX_REINTENTOS,
    MODELO_IA,
    NAVEGADOR_HEADLESS,
    TEMPERATURA,
    TIMEOUT_ESPERA,
    TIMEOUT_IA_REFINAMIENTO,
    TIMEOUT_NAVEGADOR,
    TOP_P,
    USAR_IA_GENERATIVA,
    USER_AGENT,
)

log = obtener_logger(__name__)


# SELECTORES CSS COMUNES PARA BIOGRAFÍAS / DESCRIPCIONES

SELECTORES_BIOGRAFA: list[str] = [
    # Genéricos
    "[class*='bio']",
    "[class*='about']",
    "[class*='description']",
    "[class*='summary']",
    "[class*='profile']",
    "[id*='bio']",
    "[id*='about']",
    "[id*='description']",
    # Metadatos
    "meta[name='description']",
    "meta[property='og:description']",
    # Semánticos
    "article",
    "main",
    ".content",
    "#content",
]


# SYSTEM PROMPT PARA REFINAMIENTO DE TEXTO CON J4N14

SYSTEM_PROMPT_EXTRACTOR: str = """Eres J4N14, el motor de extracción inteligente del \
sistema Recon365. Tu función es limpiar y filtrar texto extraído de páginas web \
para dejar SOLO la información relevante para perfilamiento OSINT.

═══════════════════════════════════════════════════════════
REGLAS
═══════════════════════════════════════════════════════════

1. FORMATO: Responde ÚNICAMENTE con un JSON:
   {"texto_refinado": "...", "elementos_detectados": ["..."]}

2. CONSERVAR: Biografía, rol profesional, cargo, empresa, industria, educación,
   habilidades, certificaciones, intereses, hobbies, logros, publicaciones,
   actividad profesional, idiomas, ubicación.

3. ELIMINAR: Menús de navegación, footers, cookies, banners, publicidad,
   scripts, botones, términos legales, políticas de privacidad, código HTML/CSS,
   contadores de seguidores/likes (conservar solo si son relevantes),
   texto repetido, URLs sin contexto.

4. ESTRUCTURA: Organiza el texto refinado en párrafos coherentes.
   Mantiene el idioma original del texto.

5. "elementos_detectados" debe listar qué tipos de información encontraste:
   ej: ["biografía", "rol_profesional", "empresa", "intereses", "educación"]

RESPONDE SOLO CON EL JSON. NADA MÁS."""


# FUNCIÓN DE REFINAMIENTO CON IA

def _refinar_texto_con_ia(
    texto_bruto: str,
    nombre: str,
    url: str,
) -> Optional[dict[str, Any]]:
    """
    Envía el texto bruto extraído del DOM a J4N14 para que filtre ruido
    y devuelva solo la información relevante para perfilamiento OSINT.

    Args:
        texto_bruto: Texto crudo extraído de la página web.
        nombre: Nombre del objetivo.
        url: URL de origen.

    Returns:
        Diccionario con texto_refinado y elementos_detectados, o None si falla.
    """
    if not USAR_IA_GENERATIVA:
        log.debug("IA generativa deshabilitada. Saltando refinamiento.")
        return None

    if not texto_bruto or len(texto_bruto.strip()) < 30:
        log.debug("Texto demasiado corto para refinar.")
        return None

    prompt_usuario = (
        f"Limpia y filtra el siguiente texto extraído de la página web de "
        f"'{nombre}' ({url}). Conserva SOLO la información útil para "
        f"perfilamiento OSINT.\n\n"
        f"═══ TEXTO BRUTO ═══\n\n"
        f"{texto_bruto[:3000]}\n\n"
        f"═══ FIN TEXTO ═══\n\n"
        f"Responde SOLO con JSON: {{\"texto_refinado\": \"...\", \"elementos_detectados\": [...]}}"
    )

    payload = {
        "model": MODELO_IA,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_EXTRACTOR},
            {"role": "user", "content": prompt_usuario},
        ],
        "temperature": 0.2,  # Más determinista para extracción
        "top_p": TOP_P,
        "max_tokens": 1500,
        "stream": False,
    }

    try:
        log.info("J4N14 refinando texto extraído...")
        respuesta = http_requests.post(
            LMSTUDIO_ENDPOINT_CHAT,
            json=payload,
            timeout=TIMEOUT_IA_REFINAMIENTO,
        )

        if respuesta.status_code != 200:
            log.warning(
                f"LM Studio respondió HTTP {respuesta.status_code} en refinamiento. "
                f"Usando texto bruto."
            )
            return None

        data = respuesta.json()
        contenido = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )

        if not contenido:
            log.warning("Respuesta vacía de J4N14 en refinamiento.")
            return None

        # Parsear JSON
        contenido_limpio = contenido.strip()
        try:
            resultado = json.loads(contenido_limpio)
        except json.JSONDecodeError:
            import re
            match = re.search(r"\{.*\}", contenido_limpio, re.DOTALL)
            if match:
                try:
                    resultado = json.loads(match.group(0))
                except json.JSONDecodeError:
                    log.warning("JSON inválido en refinamiento. Usando texto bruto.")
                    return None
            else:
                log.warning("No se encontró JSON en refinamiento.")
                return None

        texto_refinado = resultado.get("texto_refinado", "")
        elementos = resultado.get("elementos_detectados", [])

        if texto_refinado:
            log.info(
                f"Texto refinado por J4N14: {len(texto_bruto)} → {len(texto_refinado)} chars. "
                f"Elementos: {', '.join(elementos) if elementos else 'ninguno'}"
            )
            return {
                "texto_refinado": texto_refinado,
                "elementos_detectados": elementos,
            }

        return None

    except http_requests.ConnectionError:
        log.warning("LM Studio no disponible para refinamiento. Usando texto bruto.")
        return None
    except http_requests.Timeout:
        log.warning(
            f"Timeout de J4N14 en refinamiento (>{TIMEOUT_IA_REFINAMIENTO}s). "
            f"Usando texto bruto."
        )
        return None
    except Exception as error:
        log.warning(f"Error en refinamiento con IA: {error}. Usando texto bruto.")
        return None


async def validar_perfil(url: str) -> bool:
    """
    Verifica que una URL sea accesible mediante navegación headless.

    Args:
        url: URL pública a validar.

    Returns:
        True si la URL responde con status 200-399, False en caso contrario.
    """
    try:
        async with async_playwright() as p:
            navegador: Browser = await p.chromium.launch(headless=NAVEGADOR_HEADLESS)
            contexto: BrowserContext = await navegador.new_context(
                user_agent=USER_AGENT,
            )
            pagina: Page = await contexto.new_page()

            respuesta = await pagina.goto(
                url,
                timeout=TIMEOUT_NAVEGADOR,
                wait_until="domcontentloaded",
            )

            status: int = respuesta.status if respuesta else 0
            await navegador.close()

            accesible: bool = 200 <= status < 400
            log.info(
                f"Validación de '{url}': "
                f"{'[OK] Accesible' if accesible else '[FAIL] No accesible'} "
                f"(HTTP {status})"
            )
            return accesible

    except PlaywrightTimeoutError:
        log.warning(f"Timeout al validar URL: {url}")
        return False
    except Exception as error:
        log.error(f"Error inesperado al validar '{url}': {error}")
        return False


async def extraer_texto(url: str) -> str:
    """
    Navega a una URL y extrae texto relevante de biografía/descripción.

    Estrategia de extracción:
        1. Busca elementos con selectores CSS comunes (bio, about, description)
        2. Si no encuentra, extrae meta tags (og:description, description)
        3. Como fallback, extrae el texto del <body> (primeros 3000 chars)

    Args:
        url: URL pública del perfil a analizar.

    Returns:
        Texto extraído de la página. Cadena vacía si falla.
    """
    texto_extraido: str = ""

    try:
        async with async_playwright() as p:
            navegador: Browser = await p.chromium.launch(headless=NAVEGADOR_HEADLESS)
            contexto: BrowserContext = await navegador.new_context(
                user_agent=USER_AGENT,
            )
            pagina: Page = await contexto.new_page()

            await pagina.goto(
                url,
                timeout=TIMEOUT_NAVEGADOR,
                wait_until="networkidle",
            )

            # Esperar a que el contenido se cargue
            await pagina.wait_for_timeout(2000)

            # --- Estrategia 1: Selectores específicos ---
            for selector in SELECTORES_BIOGRAFA:
                try:
                    elementos = await pagina.query_selector_all(selector)
                    for elemento in elementos:
                        texto: Optional[str] = await elemento.text_content()
                        if texto and len(texto.strip()) > 20:
                            texto_extraido += texto.strip() + "\n\n"
                except Exception:
                    continue

            # --- Estrategia 2: Meta tags ---
            if len(texto_extraido) < 50:
                meta_selectores: list[str] = [
                    "meta[name='description']",
                    "meta[property='og:description']",
                    "meta[name='twitter:description']",
                ]
                for meta_sel in meta_selectores:
                    try:
                        meta = await pagina.query_selector(meta_sel)
                        if meta:
                            contenido: Optional[str] = await meta.get_attribute("content")
                            if contenido:
                                texto_extraido += contenido.strip() + "\n\n"
                    except Exception:
                        continue

            # --- Estrategia 3: Título de la página ---
            titulo: str = await pagina.title()
            if titulo:
                texto_extraido = f"Título: {titulo}\n\n" + texto_extraido

            # --- Estrategia 4: Fallback al body ---
            if len(texto_extraido.strip()) < 50:
                body = await pagina.query_selector("body")
                if body:
                    texto_body: Optional[str] = await body.text_content()
                    if texto_body:
                        # Limitar a 3000 caracteres para no sobrecargar el LLM
                        texto_extraido = texto_body.strip()[:3000]

            await navegador.close()

            # Limpiar texto: eliminar espacios excesivos
            lineas: list[str] = [
                linea.strip()
                for linea in texto_extraido.split("\n")
                if linea.strip()
            ]
            texto_extraido = "\n".join(lineas)

            log.info(
                f"Texto extraído de '{url}': {len(texto_extraido)} caracteres"
            )

    except PlaywrightTimeoutError:
        log.error(f"Timeout al extraer texto de: {url}")
    except Exception as error:
        log.error(f"Error al extraer texto de '{url}': {error}")

    return texto_extraido


async def tomar_captura(url: str, nombre: str) -> Optional[Path]:
    """
    Toma una captura de pantalla full-page de una URL.

    Args:
        url: URL pública a capturar.
        nombre: Nombre base para el archivo de captura.

    Returns:
        Path al archivo PNG guardado, o None si falla.
    """
    try:
        async with async_playwright() as p:
            navegador: Browser = await p.chromium.launch(headless=NAVEGADOR_HEADLESS)
            contexto: BrowserContext = await navegador.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1920, "height": 1080},
            )
            pagina: Page = await contexto.new_page()

            await pagina.goto(
                url,
                timeout=TIMEOUT_NAVEGADOR,
                wait_until="networkidle",
            )

            # Esperar renderizado completo
            await pagina.wait_for_timeout(2000)

            # Captura full-page
            contenido_captura: bytes = await pagina.screenshot(
                full_page=True,
                type="png",
            )

            await navegador.close()

            # Guardar usando el gestor de archivos
            ruta: Path = guardar_captura(contenido_captura, nombre)
            log.info(f"Captura tomada para '{nombre}': {ruta}")
            return ruta

    except PlaywrightTimeoutError:
        log.error(f"Timeout al capturar '{url}'")
        return None
    except Exception as error:
        log.error(f"Error al capturar '{url}': {error}")
        return None


async def recolectar_objetivo(
    objetivo: dict[str, str],
) -> dict[str, Any]:
    """
    Orquesta la recolección completa de un objetivo.

    Ejecuta: validación → extracción de texto → captura de pantalla.
    Incluye reintentos con backoff exponencial.

    Args:
        objetivo: Diccionario con claves: nombre, url, empresa.

    Returns:
        Diccionario con los datos recolectados:
            - nombre: str
            - url: str
            - empresa: str
            - texto_extraido: str
            - ruta_captura: str | None
            - exitoso: bool
            - errores: list[str]
    """
    nombre: str = objetivo.get("nombre", "desconocido")
    url: str = objetivo.get("url", "")
    empresa: str = objetivo.get("empresa", "no_especificada")

    log.info(f"{'='*50}")
    log.info(f"Iniciando recolección: {nombre} ({url})")
    log.info(f"{'='*50}")

    resultado: dict[str, Any] = {
        "nombre": nombre,
        "url": url,
        "empresa": empresa,
        "texto_extraido": "",
        "texto_refinado": "",
        "elementos_detectados": [],
        "ruta_captura": None,
        "exitoso": False,
        "errores": [],
    }

    # --- Paso 1: Validar accesibilidad ---
    for intento in range(1, MAX_REINTENTOS + 1):
        log.info(f"Intento {intento}/{MAX_REINTENTOS} — Validando URL...")

        accesible: bool = await validar_perfil(url)
        if accesible:
            break

        if intento < MAX_REINTENTOS:
            espera: float = DELAY_ENTRE_REINTENTOS * (2 ** (intento - 1))
            log.warning(f"Reintentando en {espera:.1f}s...")
            await asyncio.sleep(espera)
    else:
        error_msg: str = f"URL no accesible tras {MAX_REINTENTOS} intentos: {url}"
        log.error(error_msg)
        resultado["errores"].append(error_msg)
        return resultado

    # --- Paso 2: Extraer texto ---
    try:
        texto: str = await extraer_texto(url)
        resultado["texto_extraido"] = texto
        if not texto:
            resultado["errores"].append("No se pudo extraer texto relevante.")
    except Exception as error:
        error_msg = f"Error en extracción de texto: {error}"
        log.error(error_msg)
        resultado["errores"].append(error_msg)

    # --- Paso 3: Refinar texto con J4N14 ---
    if resultado["texto_extraido"]:
        refinamiento = _refinar_texto_con_ia(
            resultado["texto_extraido"], nombre, url
        )
        if refinamiento:
            resultado["texto_refinado"] = refinamiento["texto_refinado"]
            resultado["elementos_detectados"] = refinamiento["elementos_detectados"]
        else:
            # Fallback: usar texto bruto como refinado también
            resultado["texto_refinado"] = resultado["texto_extraido"]

    # --- Paso 4: Captura de pantalla ---
    try:
        ruta_captura: Optional[Path] = await tomar_captura(url, nombre)
        resultado["ruta_captura"] = str(ruta_captura) if ruta_captura else None
    except Exception as error:
        error_msg = f"Error en captura de pantalla: {error}"
        log.error(error_msg)
        resultado["errores"].append(error_msg)

    # Marcar como exitoso si al menos el texto fue extraído
    resultado["exitoso"] = bool(resultado["texto_extraido"])

    estado: str = "[OK] EXITOSO" if resultado["exitoso"] else "[WARN] PARCIAL"
    log.info(f"Recolección de '{nombre}': {estado}")

    return resultado