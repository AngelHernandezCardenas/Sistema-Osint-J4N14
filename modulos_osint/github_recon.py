"""
modulos_osint/github_recon.py — Reconocimiento de GitHub para Recon365.

Busca información pública en GitHub:
    - Repositorios de una organización/usuario
    - Posibles secretos en código (API keys, tokens, passwords)
    - Archivos de configuración expuestos
    - Información de contribuidores

Usa la API pública de GitHub (sin autenticación: 60 req/hora).

Uso:
    from modulos_osint.github_recon import recon_github
    repos = await recon_github("organizacion")
"""

import re
from typing import Any, Optional

import aiohttp

from utilidades.logger import obtener_logger

log = obtener_logger(__name__)

GITHUB_API = "https://api.github.com"

# Patrones de secretos a buscar en código
PATRONES_SECRETOS: list[dict[str, str]] = [
    {"tipo": "aws_access_key", "patron": r"AKIA[0-9A-Z]{16}", "severidad": "critica"},
    {"tipo": "aws_secret_key", "patron": r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]', "severidad": "critica"},
    {"tipo": "github_token", "patron": r"ghp_[a-zA-Z0-9]{36}", "severidad": "critica"},
    {"tipo": "github_oauth", "patron": r"gho_[a-zA-Z0-9]{36}", "severidad": "alta"},
    {"tipo": "google_api_key", "patron": r"AIza[0-9A-Za-z\-_]{35}", "severidad": "alta"},
    {"tipo": "slack_token", "patron": r"xox[baprs]-[0-9a-zA-Z]{10,}", "severidad": "alta"},
    {"tipo": "stripe_key", "patron": r"sk_live_[0-9a-zA-Z]{24}", "severidad": "critica"},
    {"tipo": "jwt_token", "patron": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+", "severidad": "alta"},
    {"tipo": "private_key", "patron": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "severidad": "critica"},
    {"tipo": "password_inline", "patron": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{4,}[\'"]', "severidad": "alta"},
    {"tipo": "connection_string", "patron": r"(?i)(mongodb|mysql|postgres|redis|jdbc)://[^\s]+", "severidad": "alta"},
    {"tipo": "api_key_generic", "patron": r'(?i)(api[_-]?key|apikey|api_secret)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]', "severidad": "media"},
    {"tipo": "ip_privada", "patron": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "severidad": "baja"},
]

# Archivos de configuración sensibles
ARCHIVOS_SENSIBLES: list[str] = [
    ".env", ".env.local", ".env.production", ".env.development",
    "config.yml", "config.yaml", "config.json",
    "secrets.yml", "secrets.yaml", "secrets.json",
    "credentials.json", "service-account.json",
    "docker-compose.yml", "Dockerfile",
    ".htaccess", ".htpasswd",
    "wp-config.php", "settings.py", "application.properties",
    "database.yml", "web.config",
]


async def buscar_repos_organizacion(nombre: str) -> list[dict[str, Any]]:
    """
    Busca repositorios públicos de una organización/usuario en GitHub.

    Args:
        nombre: Nombre de la organización o usuario.

    Returns:
        Lista de repositorios con metadata.
    """
    repos: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession() as session:
            # Intentar primero como organización
            url = f"{GITHUB_API}/orgs/{nombre}/repos?per_page=100&sort=updated"
            headers = {"Accept": "application/vnd.github.v3+json"}

            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    datos = await resp.json()
                elif resp.status == 404:
                    # Intentar como usuario
                    url = f"{GITHUB_API}/users/{nombre}/repos?per_page=100&sort=updated"
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp2:
                        if resp2.status == 200:
                            datos = await resp2.json()
                        else:
                            log.warning(f"GitHub: No se encontró org/usuario '{nombre}'")
                            return repos
                else:
                    log.warning(f"GitHub API respondió {resp.status} para '{nombre}'")
                    return repos

            for repo in datos:
                repos.append({
                    "nombre": repo.get("name", ""),
                    "url": repo.get("html_url", ""),
                    "descripcion": repo.get("description", "") or "",
                    "lenguaje": repo.get("language", "") or "",
                    "es_fork": repo.get("fork", False),
                    "estrellas": repo.get("stargazers_count", 0),
                    "ultimo_push": repo.get("pushed_at", ""),
                    "tamaño_kb": repo.get("size", 0),
                    "default_branch": repo.get("default_branch", "main"),
                    "topics": repo.get("topics", []),
                })

        log.info(f"GitHub: {len(repos)} repos encontrados para '{nombre}'")

    except Exception as error:
        log.warning(f"Error buscando repos de '{nombre}': {error}")

    return repos


async def buscar_secretos_en_repo(
    owner: str, repo: str, branch: str = "main"
) -> list[dict[str, Any]]:
    """
    Busca secretos expuestos en un repositorio usando la API de búsqueda.

    Args:
        owner: Propietario del repo.
        repo: Nombre del repo.
        branch: Branch a analizar.

    Returns:
        Lista de posibles secretos encontrados.
    """
    secretos_encontrados: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"Accept": "application/vnd.github.v3+json"}

            # Buscar archivos de configuración sensibles
            for archivo in ARCHIVOS_SENSIBLES[:10]:  # Limitar para no exceder rate limit
                url = f"{GITHUB_API}/search/code?q=filename:{archivo}+repo:{owner}/{repo}"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        datos = await resp.json()
                        if datos.get("total_count", 0) > 0:
                            for item in datos.get("items", [])[:3]:
                                secretos_encontrados.append({
                                    "tipo": "archivo_sensible",
                                    "archivo": item.get("path", ""),
                                    "repo": f"{owner}/{repo}",
                                    "url": item.get("html_url", ""),
                                    "severidad": "media",
                                    "confianza": 0.7,
                                })
                    elif resp.status == 403:
                        log.debug("GitHub API rate limit alcanzado")
                        break

    except Exception as error:
        log.debug(f"Error buscando secretos en {owner}/{repo}: {error}")

    return secretos_encontrados


async def recon_github(nombre_org: str) -> dict[str, Any]:
    """
    Ejecuta reconocimiento completo de GitHub para una organización.

    Args:
        nombre_org: Nombre de la organización/usuario de GitHub.

    Returns:
        Diccionario con repos, secretos y análisis.
    """
    log.info(f"Reconocimiento GitHub: {nombre_org}")

    resultado: dict[str, Any] = {
        "organizacion": nombre_org,
        "repositorios": [],
        "secretos_potenciales": [],
        "estadisticas": {},
        "problemas": [],
    }

    # Buscar repositorios
    repos = await buscar_repos_organizacion(nombre_org)
    resultado["repositorios"] = repos

    # Buscar secretos en los repos más activos (top 5)
    repos_activos = sorted(repos, key=lambda r: r.get("estrellas", 0), reverse=True)[:5]
    for repo in repos_activos:
        secretos = await buscar_secretos_en_repo(
            nombre_org, repo["nombre"], repo.get("default_branch", "main")
        )
        resultado["secretos_potenciales"].extend(secretos)

    # Estadísticas
    resultado["estadisticas"] = {
        "total_repos": len(repos),
        "repos_originales": sum(1 for r in repos if not r["es_fork"]),
        "repos_fork": sum(1 for r in repos if r["es_fork"]),
        "lenguajes": list(set(r["lenguaje"] for r in repos if r["lenguaje"])),
        "secretos_encontrados": len(resultado["secretos_potenciales"]),
    }

    if resultado["secretos_potenciales"]:
        resultado["problemas"].append(
            f"Se encontraron {len(resultado['secretos_potenciales'])} "
            "posibles archivos sensibles en repositorios públicos"
        )

    log.info(
        f"GitHub recon completado: {len(repos)} repos, "
        f"{len(resultado['secretos_potenciales'])} secretos potenciales"
    )

    return resultado
