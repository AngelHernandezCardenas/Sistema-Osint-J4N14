"""
modulos_osint/tech_fingerprint.py — Fingerprinting tecnológico para Recon365.

Identifica tecnologías usadas en un sitio web:
    - Headers HTTP (Server, X-Powered-By, X-Generator)
    - Meta tags HTML (generator)
    - Patrones en HTML/JS/CSS (CMS, frameworks, librerías)
    - Configuración TLS
    - Cookies conocidas
    - Headers de seguridad

Uso:
    from modulos_osint.tech_fingerprint import fingerprint_tecnologico
    techs = await fingerprint_tecnologico("https://example.com")
"""

import re
import ssl
import socket
import asyncio
from typing import Any, Optional

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)


# Patrones de detección de tecnologías en HTML
PATRONES_HTML: list[dict[str, Any]] = [
    # CMS
    {"nombre": "WordPress", "categoria": "CMS", "patron": r"wp-content|wp-includes|wordpress", "confianza": 0.9},
    {"nombre": "Joomla", "categoria": "CMS", "patron": r"/media/jui/|com_content|Joomla!", "confianza": 0.9},
    {"nombre": "Drupal", "categoria": "CMS", "patron": r"Drupal\.settings|drupal\.js|sites/default", "confianza": 0.9},
    {"nombre": "Shopify", "categoria": "E-commerce", "patron": r"cdn\.shopify\.com|Shopify\.theme", "confianza": 0.9},
    {"nombre": "Wix", "categoria": "CMS", "patron": r"wix\.com|wixstatic\.com", "confianza": 0.9},
    {"nombre": "Squarespace", "categoria": "CMS", "patron": r"squarespace\.com|sqsp\.net", "confianza": 0.9},
    # Frameworks JS
    {"nombre": "React", "categoria": "Framework JS", "patron": r"react\.production|__NEXT_DATA__|_next/static|reactroot", "confianza": 0.8},
    {"nombre": "Next.js", "categoria": "Framework JS", "patron": r"__NEXT_DATA__|_next/static|next/dist", "confianza": 0.9},
    {"nombre": "Vue.js", "categoria": "Framework JS", "patron": r"vue\.js|vue\.min\.js|vue\.runtime|v-bind|v-on", "confianza": 0.8},
    {"nombre": "Angular", "categoria": "Framework JS", "patron": r"ng-app|ng-controller|angular\.js|angular\.min", "confianza": 0.8},
    {"nombre": "jQuery", "categoria": "Librería JS", "patron": r"jquery\.js|jquery\.min\.js|jquery-\d", "confianza": 0.9},
    {"nombre": "Bootstrap", "categoria": "CSS Framework", "patron": r"bootstrap\.css|bootstrap\.min\.|bootstrap\.bundle", "confianza": 0.9},
    {"nombre": "Tailwind CSS", "categoria": "CSS Framework", "patron": r"tailwindcss|tailwind\.min", "confianza": 0.8},
    # Analytics
    {"nombre": "Google Analytics", "categoria": "Analytics", "patron": r"google-analytics\.com|gtag|UA-\d{4,10}", "confianza": 0.9},
    {"nombre": "Google Tag Manager", "categoria": "Analytics", "patron": r"googletagmanager\.com|GTM-", "confianza": 0.9},
    {"nombre": "Cloudflare", "categoria": "CDN/Security", "patron": r"cloudflare|cf-ray|__cf_bm", "confianza": 0.8},
]

# Patrones de detección en headers HTTP
PATRONES_HEADERS: dict[str, list[dict[str, str]]] = {
    "server": [
        {"patron": r"Apache/?(\S*)", "nombre": "Apache"},
        {"patron": r"nginx/?(\S*)", "nombre": "Nginx"},
        {"patron": r"Microsoft-IIS/?(\S*)", "nombre": "IIS"},
        {"patron": r"LiteSpeed", "nombre": "LiteSpeed"},
        {"patron": r"cloudflare", "nombre": "Cloudflare"},
        {"patron": r"AmazonS3", "nombre": "Amazon S3"},
        {"patron": r"gunicorn/?(\S*)", "nombre": "Gunicorn"},
    ],
    "x-powered-by": [
        {"patron": r"PHP/?(\S*)", "nombre": "PHP"},
        {"patron": r"ASP\.NET", "nombre": "ASP.NET"},
        {"patron": r"Express", "nombre": "Express.js"},
        {"patron": r"Next\.js", "nombre": "Next.js"},
        {"patron": r"Servlet", "nombre": "Java Servlet"},
    ],
}

# Cookies conocidas
COOKIES_CONOCIDAS: dict[str, str] = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "connect.sid": "Express.js",
    "_rails_session": "Ruby on Rails",
    "laravel_session": "Laravel",
    "ci_session": "CodeIgniter",
    "CFID": "ColdFusion",
    "wp_logged_in": "WordPress",
}

# Headers de seguridad a verificar
HEADERS_SEGURIDAD: dict[str, str] = {
    "Strict-Transport-Security": "Fuerza HTTPS — protege contra ataques downgrade",
    "Content-Security-Policy": "Previene XSS y inyección de contenido",
    "X-Frame-Options": "Previene clickjacking",
    "X-Content-Type-Options": "Previene MIME sniffing",
    "X-XSS-Protection": "Filtro XSS del navegador (legacy)",
    "Referrer-Policy": "Controla información enviada en Referer",
    "Permissions-Policy": "Controla acceso a APIs del navegador",
    "Cross-Origin-Opener-Policy": "Aislamiento de contexto de navegación",
    "Cross-Origin-Resource-Policy": "Controla carga de recursos cross-origin",
}


async def fingerprint_tecnologico(url: str) -> dict[str, Any]:
    """
    Realiza fingerprinting tecnológico completo de una URL.

    Args:
        url: URL del sitio a analizar.

    Returns:
        Diccionario con tecnologías detectadas y análisis de seguridad.
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    log.info(f"Fingerprinting: {url}")

    resultado: dict[str, Any] = {
        "url": url,
        "tecnologias": [],
        "headers_seguridad": [],
        "tls_info": {},
        "cookies": [],
        "problemas": [],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=20),
                allow_redirects=True,
                ssl=False,  # No verificar SSL para análisis
            ) as resp:
                headers = dict(resp.headers)
                html = await resp.text(errors="replace")
                cookies_resp = resp.cookies

                # 1. Analizar headers del servidor
                _detectar_por_headers(headers, resultado)

                # 2. Analizar HTML
                _detectar_por_html(html, resultado)

                # 3. Analizar meta tags
                _detectar_por_metatags(html, resultado)

                # 4. Analizar cookies
                _detectar_por_cookies(cookies_resp, resultado)

                # 5. Analizar headers de seguridad
                _analizar_headers_seguridad(headers, resultado)

    except aiohttp.ClientError as error:
        log.warning(f"Error HTTP al analizar {url}: {error}")
        resultado["problemas"].append(f"Error de conexión: {type(error).__name__}")
    except Exception as error:
        log.warning(f"Error en fingerprinting de {url}: {error}")

    # 6. Analizar TLS (separado porque usa socket directo)
    resultado["tls_info"] = await _analizar_tls(url)

    # Deduplicar tecnologías
    vistos: set[str] = set()
    techs_unicas: list[dict] = []
    for tech in resultado["tecnologias"]:
        key = tech["nombre"]
        if key not in vistos:
            vistos.add(key)
            techs_unicas.append(tech)
    resultado["tecnologias"] = techs_unicas

    log.info(f"Fingerprinting completado: {len(resultado['tecnologias'])} tecnologías detectadas")

    return resultado


def _detectar_por_headers(headers: dict, resultado: dict) -> None:
    """Detecta tecnologías a partir de headers HTTP."""
    for header_name, patrones in PATRONES_HEADERS.items():
        valor = headers.get(header_name, "")
        if not valor:
            # Case-insensitive search
            for h, v in headers.items():
                if h.lower() == header_name.lower():
                    valor = v
                    break

        if valor:
            for patron_info in patrones:
                match = re.search(patron_info["patron"], valor, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    resultado["tecnologias"].append({
                        "nombre": patron_info["nombre"],
                        "version": version.strip("/"),
                        "categoria": "Servidor" if header_name == "server" else "Backend",
                        "fuente": f"header:{header_name}",
                        "confianza": 0.9,
                    })


def _detectar_por_html(html: str, resultado: dict) -> None:
    """Detecta tecnologías por patrones en el HTML."""
    for patron_info in PATRONES_HTML:
        if re.search(patron_info["patron"], html, re.IGNORECASE):
            resultado["tecnologias"].append({
                "nombre": patron_info["nombre"],
                "version": "",
                "categoria": patron_info["categoria"],
                "fuente": "html_pattern",
                "confianza": patron_info["confianza"],
            })


def _detectar_por_metatags(html: str, resultado: dict) -> None:
    """Detecta tecnologías por meta tags (generator, etc.)."""
    # meta generator
    match = re.search(
        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    )
    if match:
        generator = match.group(1)
        nombre = generator.split()[0] if generator else "Unknown"
        version = generator.split()[1] if len(generator.split()) > 1 else ""
        resultado["tecnologias"].append({
            "nombre": nombre,
            "version": version,
            "categoria": "CMS/Framework",
            "fuente": "meta:generator",
            "confianza": 0.95,
        })


def _detectar_por_cookies(cookies: Any, resultado: dict) -> None:
    """Detecta tecnologías por cookies conocidas."""
    if not cookies:
        return
    for cookie_name, tech_name in COOKIES_CONOCIDAS.items():
        for cookie in cookies:
            if cookie.lower() == cookie_name.lower():
                resultado["tecnologias"].append({
                    "nombre": tech_name,
                    "version": "",
                    "categoria": "Backend",
                    "fuente": f"cookie:{cookie_name}",
                    "confianza": 0.7,
                })
                resultado["cookies"].append(cookie)
                break


def _analizar_headers_seguridad(headers: dict, resultado: dict) -> None:
    """Analiza la presencia de headers de seguridad."""
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, descripcion in HEADERS_SEGURIDAD.items():
        presente = header.lower() in headers_lower
        valor = headers_lower.get(header.lower(), "")

        resultado["headers_seguridad"].append({
            "header": header,
            "presente": presente,
            "valor": valor if presente else "",
            "recomendacion": descripcion,
        })

        if not presente:
            resultado["problemas"].append(
                f"Header de seguridad ausente: {header} — {descripcion}"
            )


async def _analizar_tls(url: str) -> dict[str, Any]:
    """Analiza la configuración TLS de un sitio."""
    info: dict[str, Any] = {"exitoso": False}

    if not url.startswith("https://"):
        info["nota"] = "Sitio no usa HTTPS"
        return info

    try:
        hostname = url.replace("https://", "").split("/")[0].split(":")[0]

        def _get_tls_info():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(10)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
                return cert, cipher, version

        cert, cipher, version = await asyncio.get_event_loop().run_in_executor(
            None, _get_tls_info
        )

        info = {
            "exitoso": True,
            "version_tls": version,
            "cipher_suite": cipher[0] if cipher else "",
            "bits": cipher[2] if cipher else 0,
            "subject": dict(x[0] for x in cert.get("subject", []) if x),
            "issuer": dict(x[0] for x in cert.get("issuer", []) if x),
            "valid_from": cert.get("notBefore", ""),
            "valid_until": cert.get("notAfter", ""),
            "sans": [
                san[1] for san in cert.get("subjectAltName", [])
                if san[0] == "DNS"
            ],
        }

    except Exception as error:
        info["error"] = str(error)

    return info
