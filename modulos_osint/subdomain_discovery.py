"""
modulos_osint/subdomain_discovery.py — Descubrimiento de subdominios para Recon365.

Fuentes de descubrimiento (todas gratuitas, sin API keys):
    - Certificate Transparency (crt.sh)
    - Wordlist de subdominios comunes
    - Validación DNS de subdominios descubiertos

Uso:
    from modulos_osint.subdomain_discovery import descubrir_subdominios
    subs = await descubrir_subdominios("example.com")
"""

import asyncio
import socket
from typing import Any, Optional

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

# Wordlist de subdominios comunes para bruteforce básico
SUBDOMINIOS_COMUNES: list[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "vpn", "remote", "gateway", "proxy",
    "admin", "panel", "dashboard", "portal", "login", "sso",
    "api", "api-v1", "api-v2", "graphql", "rest",
    "dev", "staging", "test", "qa", "uat", "sandbox", "beta", "demo",
    "app", "apps", "web", "mobile",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "email", "correo",
    "cdn", "static", "assets", "media", "img", "images", "files",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "ci", "cd", "jenkins", "drone", "travis", "build",
    "monitor", "monitoring", "grafana", "prometheus", "kibana", "elk",
    "docs", "documentation", "wiki", "help", "support", "status",
    "blog", "news", "press",
    "shop", "store", "ecommerce", "pay", "payment", "billing",
    "crm", "erp", "hr", "jira", "confluence",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "extranet", "corp", "corporate",
    "cloud", "aws", "azure", "gcp",
    "mx-verification", "autodiscover", "autoconfig",
    "m", "wap",
]


async def buscar_crtsh(dominio: str) -> list[str]:
    """
    Busca subdominios en Certificate Transparency via crt.sh.

    Args:
        dominio: Dominio base a buscar.

    Returns:
        Lista de subdominios únicos encontrados.
    """
    subdominios: set[str] = set()
    url = f"https://crt.sh/?q=%.{dominio}&output=json"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    datos = await resp.json(content_type=None)
                    for entrada in datos:
                        nombre = entrada.get("name_value", "")
                        # crt.sh puede devolver múltiples nombres separados por \n
                        for sub in nombre.split("\n"):
                            sub = sub.strip().lower()
                            # Filtrar wildcards y verificar que sea del dominio
                            if sub and not sub.startswith("*") and sub.endswith(dominio):
                                subdominios.add(sub)

        log.info(f"crt.sh: {len(subdominios)} subdominios encontrados para {dominio}")

    except asyncio.TimeoutError:
        log.warning(f"Timeout consultando crt.sh para {dominio}")
    except Exception as error:
        log.warning(f"Error en crt.sh para {dominio}: {error}")

    return list(subdominios)


async def resolver_subdominio(subdominio: str) -> Optional[str]:
    """
    Intenta resolver un subdominio a una IP.

    Returns:
        IP resuelta o None si no resuelve.
    """
    try:
        resultado = await asyncio.get_event_loop().run_in_executor(
            None, lambda: socket.getaddrinfo(subdominio, None, socket.AF_INET)
        )
        if resultado:
            return resultado[0][4][0]
    except (socket.gaierror, socket.timeout, OSError):
        pass
    return None


async def bruteforce_subdominios(
    dominio: str,
    wordlist: Optional[list[str]] = None,
    max_concurrente: int = 20,
) -> list[dict[str, str]]:
    """
    Descubre subdominios por fuerza bruta con una wordlist.

    Args:
        dominio: Dominio base.
        wordlist: Lista de prefijos a probar.
        max_concurrente: Máximo de resoluciones concurrentes.

    Returns:
        Lista de subdominios resueltos con sus IPs.
    """
    if wordlist is None:
        wordlist = SUBDOMINIOS_COMUNES

    resultados: list[dict[str, str]] = []
    semaforo = asyncio.Semaphore(max_concurrente)

    async def probar_subdominio(prefijo: str) -> Optional[dict[str, str]]:
        async with semaforo:
            subdominio = f"{prefijo}.{dominio}"
            ip = await resolver_subdominio(subdominio)
            if ip:
                return {"subdominio": subdominio, "ip": ip}
            return None

    tareas = [probar_subdominio(prefijo) for prefijo in wordlist]
    resultados_raw = await asyncio.gather(*tareas)

    for r in resultados_raw:
        if r is not None:
            resultados.append(r)

    log.info(f"Bruteforce: {len(resultados)}/{len(wordlist)} subdominios resolvieron para {dominio}")

    return resultados


async def descubrir_subdominios(dominio: str) -> dict[str, Any]:
    """
    Ejecuta descubrimiento completo de subdominios usando múltiples fuentes.

    Args:
        dominio: Dominio base a analizar.

    Returns:
        Diccionario con todos los subdominios descubiertos y validados.
    """
    log.info(f"Descubrimiento de subdominios: {dominio}")

    resultado: dict[str, Any] = {
        "dominio": dominio,
        "subdominios": [],
        "total": 0,
        "fuentes": {
            "crt_sh": 0,
            "bruteforce": 0,
        },
    }

    # Fase 1: Certificate Transparency (crt.sh)
    subs_crtsh = await buscar_crtsh(dominio)
    resultado["fuentes"]["crt_sh"] = len(subs_crtsh)

    # Fase 2: Bruteforce con wordlist
    subs_brute = await bruteforce_subdominios(dominio)
    resultado["fuentes"]["bruteforce"] = len(subs_brute)

    # Combinar y deduplicar
    todos_los_subdominios: dict[str, Optional[str]] = {}

    # De crt.sh (sin IP aún)
    for sub in subs_crtsh:
        if sub not in todos_los_subdominios:
            todos_los_subdominios[sub] = None

    # De bruteforce (ya tienen IP)
    for sub_info in subs_brute:
        todos_los_subdominios[sub_info["subdominio"]] = sub_info["ip"]

    # Resolver IPs faltantes de crt.sh (en paralelo, limitado)
    subs_sin_ip = [s for s, ip in todos_los_subdominios.items() if ip is None]
    if subs_sin_ip:
        log.info(f"Resolviendo {len(subs_sin_ip)} subdominios de crt.sh...")
        semaforo = asyncio.Semaphore(20)

        async def resolver_con_semaforo(sub: str) -> tuple[str, Optional[str]]:
            async with semaforo:
                ip = await resolver_subdominio(sub)
                return sub, ip

        tareas = [resolver_con_semaforo(s) for s in subs_sin_ip[:100]]  # Limitar a 100
        resoluciones = await asyncio.gather(*tareas)

        for sub, ip in resoluciones:
            todos_los_subdominios[sub] = ip

    # Construir resultado final
    for sub, ip in sorted(todos_los_subdominios.items()):
        resultado["subdominios"].append({
            "subdominio": sub,
            "ip": ip,
            "activo": ip is not None,
        })

    resultado["total"] = len(resultado["subdominios"])
    activos = sum(1 for s in resultado["subdominios"] if s["activo"])

    log.info(
        f"Descubrimiento completado para {dominio}: "
        f"{resultado['total']} subdominios ({activos} activos)"
    )

    return resultado
