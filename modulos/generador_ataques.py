"""
modulos/generador_ataques.py — Generador de vectores de Spear Phishing para Recon365.

Toma el perfil psicográfico generado por el Motor J4N14 y redacta
correos de Spear Phishing altamente persuasivos basados en los
intereses y vulnerabilidades detectadas del objetivo.

Modos de operación:
    - IA GENERATIVA (J4N14 + Dolphin): Genera correos dinámicos y únicos
      usando el perfil psicográfico completo como contexto.
    - PLANTILLAS (fallback): Si la IA no está disponible, usa plantillas
      estáticas predefinidas con variables.

Modelos Predictivos:
    - JERARQUIA: Correo urgente con autoridad (directivos)
    - ESTILO_VIDA: Premio falso o promoción (intereses personales)
    - TECNOLOGICO: Falsa actualización de seguridad (técnicos)

Uso:
    from modulos.generador_ataques import crear_pretexto, generar_reporte_final
    vector = crear_pretexto(perfil_j4n14)
    reporte = generar_reporte_final(objetivo, perfil, vector)
"""

import json
import random
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from utilidades.logger import obtener_logger

from configuracion import (
    LMSTUDIO_ENDPOINT_CHAT,
    MODELO_IA,
    MODO_LIGHT,
    NOMBRE_MOTOR,
    TEMPERATURA,
    TIMEOUT_IA_GENERACION,
    TOP_P,
    USAR_GP_OPTIMIZER,
    USAR_IA_GENERATIVA,
    VERSION,
)

log = obtener_logger(__name__)


# PLANTILLAS DE VECTORES DE ATAQUE

PLANTILLAS_JERARQUIA: list[dict[str, str]] = [
    {
        "tipo": "urgencia_financiera",
        "asunto": "[URGENTE] Revisión inmediata requerida — Presupuesto Q{quarter} {year}",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Se ha detectado una discrepancia en los números del presupuesto "
            "del Q{quarter} que requiere su aprobación inmediata antes del "
            "cierre de hoy.\n\n"
            "El equipo de finanzas ha preparado un resumen ejecutivo con las "
            "correcciones necesarias. Por favor, revise el documento adjunto "
            "y confirme su aprobación.\n\n"
            "[ADJUNTO] Documento: Presupuesto_Q{quarter}_{year}_Revisado.pdf\n\n"
            "Necesitamos su respuesta antes de las 17:00 hrs.\n\n"
            "Saludos cordiales,\n"
            "Departamento de Finanzas\n"
            "{empresa}"
        ),
    },
    {
        "tipo": "auditoria_compliance",
        "asunto": "[ALERTA] Auditoría de Compliance — Acción requerida de {rol}",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Como parte de la auditoría anual de compliance, necesitamos "
            "que verifique y confirme los accesos de su equipo a los "
            "sistemas internos.\n\n"
            "Este proceso es obligatorio para todos los {rol} y debe "
            "completarse en las próximas 24 horas para evitar la "
            "suspensión temporal de credenciales.\n\n"
            "[ENLACE] Portal de verificación: [enlace]\n\n"
            "Si tiene preguntas, contacte al equipo de Seguridad TI.\n\n"
            "Atentamente,\n"
            "Oficina de Compliance\n"
            "{empresa}"
        ),
    },
    {
        "tipo": "reunion_directiva",
        "asunto": "[DOC] Agenda confidencial — Reunión de directiva {date}",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Adjunto la agenda confidencial para la reunión de directiva "
            "programada para el {date}. Se incluyen puntos sensibles sobre "
            "reestructuración y proyecciones del próximo trimestre.\n\n"
            "Por favor, revise el documento antes de la sesión y prepare "
            "sus comentarios sobre la sección 3 (Inversiones Estratégicas).\n\n"
            "[ADJUNTO] Agenda_Directiva_Confidencial_{date}.docx\n\n"
            "Este documento es estrictamente confidencial.\n\n"
            "Cordialmente,\n"
            "Asistente de Dirección\n"
            "{empresa}"
        ),
    },
]

PLANTILLAS_ESTILO_VIDA: list[dict[str, str]] = [
    {
        "tipo": "premio_sorteo",
        "asunto": "¡Felicidades {nombre}! Has sido seleccionado/a — {interes}",
        "cuerpo": (
            "¡Hola {nombre}!\n\n"
            "Nos complace informarte que has sido seleccionado/a como "
            "ganador/a de nuestro sorteo exclusivo relacionado con "
            "{interes}.\n\n"
            "Tu premio incluye:\n"
            "Premio: {premio}\n\n"
            "Para reclamar tu premio, solo necesitas confirmar tus datos "
            "en el siguiente enlace antes del {date}:\n\n"
            "[ENLACE] Confirmar premio: [enlace]\n\n"
            "¡No dejes pasar esta oportunidad!\n\n"
            "El equipo de Premios Exclusivos"
        ),
    },
    {
        "tipo": "descuento_exclusivo",
        "asunto": "[OFERTA] Exclusiva para ti — 70% en {interes}",
        "cuerpo": (
            "Hola {nombre},\n\n"
            "Porque sabemos que te apasiona {interes}, hemos preparado "
            "una oferta exclusiva solo para ti:\n\n"
            "Descuento: 70% en {premio}\n"
            "Tiempo: Oferta válida solo por 24 horas\n\n"
            "Hemos notado tu interés en {interes} y queremos "
            "recompensarte con esta promoción irrepetible.\n\n"
            "[ENLACE] Aprovechar oferta: [enlace]\n\n"
            "¡No te lo pierdas!\n\n"
            "Equipo de Ofertas Personalizadas"
        ),
    },
    {
        "tipo": "invitacion_evento",
        "asunto": "[INVITACION] VIP — Evento exclusivo de {interes}",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Tienes una invitación VIP para un evento exclusivo "
            "relacionado con {interes} que se celebrará el {date}.\n\n"
            "Detalles del evento:\n"
            "Ubicación: Por confirmar al registrarte\n"
            "Acceso: VIP — Solo por invitación\n"
            "Incluye: {premio}\n\n"
            "Confirma tu asistencia:\n"
            "[ENLACE] Registro VIP: [enlace]\n\n"
            "Plazas limitadas.\n\n"
            "Coordinación de Eventos"
        ),
    },
]

PLANTILLAS_TECNOLOGICO: list[dict[str, str]] = [
    {
        "tipo": "alerta_seguridad",
        "asunto": "[CRITICO] Vulnerabilidad detectada en {tech} — Actualice ahora",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Nuestro equipo de seguridad ha detectado una vulnerabilidad "
            "crítica (CVE-{year}-{cve_id}) que afecta a {tech}.\n\n"
            "Severidad: CRÍTICA (CVSS 9.8)\n"
            "Impacto: Ejecución remota de código\n"
            "Sistemas afectados: {tech}\n\n"
            "Es imperativo que actualice inmediatamente. Hemos preparado "
            "un parche de emergencia:\n\n"
            "[ADJUNTO] Parche: {tech}_Security_Patch_{year}.exe\n"
            "[ENLACE] Descarga directa: [enlace]\n\n"
            "No aplazar esta actualización puede comprometer la "
            "infraestructura de {empresa}.\n\n"
            "Equipo de Seguridad TI"
        ),
    },
    {
        "tipo": "herramienta_beta",
        "asunto": "[NUEVO] Acceso exclusivo beta — Nueva herramienta de {tech}",
        "cuerpo": (
            "Hola {nombre},\n\n"
            "Has sido seleccionado/a para el programa beta exclusivo de "
            "una nueva herramienta de desarrollo para {tech}.\n\n"
            "Características:\n"
            "- Rendimiento 10x superior\n"
            "- Integración nativa con {tech}\n"
            "- Asistente IA incorporado\n"
            "- Análisis de código avanzado\n\n"
            "Solo se han enviado 50 invitaciones. Descarga la versión "
            "beta antes de que se agoten:\n\n"
            "[ENLACE] Descargar beta: [enlace]\n\n"
            "Tu feedback como experto en {tech} es muy valioso.\n\n"
            "Equipo de Desarrollo"
        ),
    },
    {
        "tipo": "certificacion_gratuita",
        "asunto": "[EDUCACION] Certificación GRATUITA de {tech} — Cupo limitado",
        "cuerpo": (
            "Estimado/a {nombre},\n\n"
            "Nos complace informarte que has sido seleccionado/a para "
            "obtener una certificación profesional de {tech} de forma "
            "completamente gratuita.\n\n"
            "Detalles:\n"
            "Curso: {tech} Professional Advanced\n"
            "Costo: $599 USD — HOY GRATIS\n"
            "Fecha límite de registro: {date}\n"
            "Beneficio: Validez internacional\n\n"
            "Regístrate ahora:\n"
            "[ENLACE] Registro: [enlace]\n\n"
            "Solo quedan {plazas} plazas disponibles.\n\n"
            "Equipo de Formación Profesional"
        ),
    },
]

# Premios por categoría para personalización
PREMIOS_ESTILO_VIDA: dict[str, list[str]] = {
    "viajes": [
        "2 boletos de avión a cualquier destino",
        "Estancia de 5 noches en resort all-inclusive",
        "Crucero para 2 personas por el Mediterráneo",
    ],
    "deportes": [
        "Entradas VIP para la final de la Champions League",
        "Kit deportivo profesional valorado en $500",
        "Suscripción anual premium a plataforma deportiva",
    ],
    "tecnologia": [
        "iPhone 16 Pro Max último modelo",
        "MacBook Pro M4 de última generación",
        "Setup gaming completo valorado en $3,000",
    ],
    "default": [
        "Tarjeta regalo de $500 USD",
        "Suscripción premium anual a servicio exclusivo",
        "Kit de experiencias personalizadas",
    ],
}


# SYSTEM PROMPT PARA GENERACIÓN DINÁMICA CON J4N14

SYSTEM_PROMPT_GENERADOR: str = """Eres J4N14, el motor de generación de vectores de \
Spear Phishing del sistema Recon365. Tu función es redactar correos electrónicos \
de ingeniería social ALTAMENTE persuasivos y personalizados.

═══════════════════════════════════════════════════════════
REGLAS ABSOLUTAS
═══════════════════════════════════════════════════════════

1. FORMATO: Responde ÚNICAMENTE con un objeto JSON válido con las claves:
   {"asunto": "...", "cuerpo": "..."}
   NO incluyas texto conversacional, explicaciones, ni markdown. Solo JSON puro.

2. PERSONALIZACIÓN: Usa TODOS los datos del perfil proporcionado:
   - Nombre del objetivo para dirigirte a él/ella
   - Rol y empresa para establecer contexto corporativo
   - Intereses personales para crear ganchos emocionales
   - Vulnerabilidades detectadas para explotar puntos débiles psicológicos
   - Industria para usar jerga y terminología específica del sector

3. REALISMO: El correo debe parecer 100% legítimo:
   - Usa un remitente creíble (departamento interno, servicio conocido, colega)
   - Incluye detalles específicos que demuestren "conocimiento" del objetivo
   - Genera urgencia sin ser obvio
   - Incluye un CTA (call to action) con [ENLACE] o [ADJUNTO] como placeholder

4. CATEGORÍAS:
   - JERARQUIA: Correos de autoridad/urgencia corporativa (auditorías, reportes, compliance)
   - ESTILO_VIDA: Premios, sorteos, ofertas, invitaciones VIP basadas en intereses
   - TECNOLOGICO: Alertas de seguridad, actualizaciones, certificaciones, herramientas

5. IDIOMA: Siempre en español. Tono profesional adaptado a la categoría.

RESPONDE SOLO CON EL JSON. NADA MÁS."""


# FUNCIONES DE GENERACIÓN CON IA (J4N14 + DOLPHIN)

def _construir_prompt_generacion(perfil: dict[str, Any], categoria: str) -> str:
    """
    Construye el prompt de usuario para que J4N14 genere un correo personalizado.

    Args:
        perfil: Perfil psicográfico completo del objetivo.
        categoria: Categoría predictiva (JERARQUIA, ESTILO_VIDA, TECNOLOGICO).

    Returns:
        Prompt formateado con todos los datos del perfil.
    """
    intereses = perfil.get("intereses", [])
    vulnerabilidades = perfil.get("vulnerabilidades", [])
    necesidades = perfil.get("necesidades_inferidas", [])

    return (
        f"Genera un correo de Spear Phishing para la categoría: {categoria}\n\n"
        f"═══ DATOS DEL OBJETIVO ═══\n"
        f"Nombre: {perfil.get('nombre_objetivo', 'Estimado/a')}\n"
        f"Rol: {perfil.get('rol_detectado', 'no_determinado')}\n"
        f"Empresa: {perfil.get('empresa', 'no_especificada')}\n"
        f"Industria: {perfil.get('industria', 'no_determinada')}\n"
        f"Intereses: {', '.join(intereses) if intereses else 'no_determinados'}\n"
        f"Vulnerabilidades: {', '.join(vulnerabilidades) if vulnerabilidades else 'no_determinadas'}\n"
        f"Necesidades: {', '.join(necesidades) if necesidades else 'no_determinadas'}\n"
        f"═══ FIN DATOS ═══\n\n"
        f"Recuerda: JSON puro con claves 'asunto' y 'cuerpo'. NADA MÁS."
    )


def _generar_con_ia(perfil: dict[str, Any], categoria: str) -> Optional[dict[str, str]]:
    """
    Genera un correo de Spear Phishing usando J4N14 (Dolphin vía LM Studio).

    Envía el perfil psicográfico completo al LLM para que redacte un correo
    único, dinámico y altamente personalizado.

    Args:
        perfil: Perfil psicográfico del Motor J4N14.
        categoria: Categoría predictiva del objetivo.

    Returns:
        Diccionario con {asunto, cuerpo} generados, o None si falla.
    """
    # ── Modo light: saltar IA sin intentar ninguna conexión ──
    if MODO_LIGHT:
        log.info("[LIGHT] Modo light activo — saltando IA generativa, usando plantillas estáticas.")
        return None

    if not USAR_IA_GENERATIVA:
        log.debug("IA generativa deshabilitada en configuración.")
        return None

    prompt_usuario = _construir_prompt_generacion(perfil, categoria)

    payload = {
        "model": MODELO_IA,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_GENERADOR},
            {"role": "user", "content": prompt_usuario},
        ],
        "temperature": TEMPERATURA,
        "top_p": TOP_P,
        "max_tokens": 1024,
        "stream": False,
    }

    try:
        log.info("J4N14 generando correo con IA (Dolphin)...")
        respuesta = requests.post(
            LMSTUDIO_ENDPOINT_CHAT,
            json=payload,
            timeout=TIMEOUT_IA_GENERACION,
        )

        if respuesta.status_code != 200:
            log.warning(
                f"LM Studio respondió HTTP {respuesta.status_code}. "
                f"Usando plantillas como fallback."
            )
            return None

        data = respuesta.json()
        contenido = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )

        if not contenido:
            log.warning("Respuesta vacía de J4N14. Fallback a plantillas.")
            return None

        # Intentar parsear JSON de la respuesta
        contenido_limpio = contenido.strip()

        # Intento directo
        try:
            resultado = json.loads(contenido_limpio)
        except json.JSONDecodeError:
            # Buscar JSON entre llaves
            import re
            match = re.search(r"\{.*\}", contenido_limpio, re.DOTALL)
            if match:
                try:
                    resultado = json.loads(match.group(0))
                except json.JSONDecodeError:
                    log.warning("JSON inválido de J4N14. Fallback a plantillas.")
                    return None
            else:
                log.warning("No se encontró JSON en respuesta de J4N14.")
                return None

        # Validar que tenga las claves necesarias
        if "asunto" not in resultado or "cuerpo" not in resultado:
            log.warning("Respuesta de J4N14 sin claves requeridas (asunto/cuerpo).")
            return None

        log.info("J4N14 generó correo exitosamente con IA.")
        return {
            "asunto": resultado["asunto"],
            "cuerpo": resultado["cuerpo"],
        }

    except requests.ConnectionError:
        log.warning(
            "LM Studio no disponible. Fallback a plantillas estáticas."
        )
        return None
    except requests.Timeout:
        log.warning(
            f"Timeout de J4N14 (>{TIMEOUT_IA_GENERACION}s). Fallback a plantillas."
        )
        return None
    except Exception as error:
        log.warning(f"Error en generación con IA: {error}. Fallback a plantillas.")
        return None


# FUNCIONES DE GENERACIÓN POR PLANTILLAS (FALLBACK)

def _obtener_datos_dinamicos() -> dict[str, str]:
    """
    Genera datos dinámicos para personalizar las plantillas.

    Returns:
        Diccionario con valores dinámicos: quarter, year, date, cve_id, plazas.
    """
    ahora: datetime = datetime.now(timezone.utc)
    quarter: int = (ahora.month - 1) // 3 + 1

    return {
        "quarter": str(quarter),
        "year": str(ahora.year),
        "date": ahora.strftime("%d/%m/%Y"),
        "cve_id": str(random.randint(10000, 99999)),
        "plazas": str(random.randint(3, 15)),
    }


def _seleccionar_premio(intereses: list[str]) -> str:
    """
    Selecciona un premio relevante basado en los intereses del objetivo.

    Args:
        intereses: Lista de intereses detectados por J4N14.

    Returns:
        Premio personalizado como string.
    """
    for interes in intereses:
        interes_lower: str = interes.lower()
        for categoria, premios in PREMIOS_ESTILO_VIDA.items():
            if categoria in interes_lower:
                return random.choice(premios)

    return random.choice(PREMIOS_ESTILO_VIDA["default"])


def _generar_vector_jerarquia(perfil: dict[str, Any]) -> dict[str, str]:
    """
    Genera un vector de Spear Phishing para objetivos de JERARQUÍA.

    Correos urgentes con tono de autoridad dirigidos a directivos.

    Args:
        perfil: Perfil psicográfico del Motor J4N14.

    Returns:
        Diccionario con: tipo, asunto, cuerpo.
    """
    plantilla: dict[str, str] = random.choice(PLANTILLAS_JERARQUIA)
    datos: dict[str, str] = _obtener_datos_dinamicos()

    variables: dict[str, str] = {
        "nombre": perfil.get("nombre_objetivo", "Estimado/a"),
        "rol": perfil.get("rol_detectado", "Director/a"),
        "empresa": perfil.get("empresa", "la empresa"),
        **datos,
    }

    return {
        "tipo_vector": f"JERARQUIA — {plantilla['tipo']}",
        "asunto": plantilla["asunto"].format(**variables),
        "cuerpo": plantilla["cuerpo"].format(**variables),
    }


def _generar_vector_estilo_vida(perfil: dict[str, Any]) -> dict[str, str]:
    """
    Genera un vector de Spear Phishing para objetivos de ESTILO_VIDA.

    Premios falsos y promociones basados en intereses personales.

    Args:
        perfil: Perfil psicográfico del Motor J4N14.

    Returns:
        Diccionario con: tipo, asunto, cuerpo.
    """
    plantilla: dict[str, str] = random.choice(PLANTILLAS_ESTILO_VIDA)
    datos: dict[str, str] = _obtener_datos_dinamicos()
    intereses: list[str] = perfil.get("intereses", ["actividades exclusivas"])

    interes_principal: str = intereses[0] if intereses else "actividades exclusivas"
    premio: str = _seleccionar_premio(intereses)

    variables: dict[str, str] = {
        "nombre": perfil.get("nombre_objetivo", "amigo/a"),
        "interes": interes_principal,
        "premio": premio,
        **datos,
    }

    return {
        "tipo_vector": f"ESTILO_VIDA — {plantilla['tipo']}",
        "asunto": plantilla["asunto"].format(**variables),
        "cuerpo": plantilla["cuerpo"].format(**variables),
    }


def _generar_vector_tecnologico(perfil: dict[str, Any]) -> dict[str, str]:
    """
    Genera un vector de Spear Phishing para objetivos TECNOLÓGICOS.

    Falsas alertas de seguridad y actualizaciones dirigidas a técnicos.

    Args:
        perfil: Perfil psicográfico del Motor J4N14.

    Returns:
        Diccionario con: tipo, asunto, cuerpo.
    """
    plantilla: dict[str, str] = random.choice(PLANTILLAS_TECNOLOGICO)
    datos: dict[str, str] = _obtener_datos_dinamicos()
    intereses: list[str] = perfil.get("intereses", ["software"])

    # Detectar tecnología principal
    tech: str = "el sistema"
    for interes in intereses:
        if any(
            kw in interes.lower()
            for kw in [
                "python", "java", "node", "react", "docker",
                "kubernetes", "aws", "azure", "linux", "windows",
                "vscode", "git", "sql", "cloud", "devops",
            ]
        ):
            tech = interes
            break

    variables: dict[str, str] = {
        "nombre": perfil.get("nombre_objetivo", "Estimado/a"),
        "tech": tech,
        "empresa": perfil.get("empresa", "su organización"),
        **datos,
    }

    return {
        "tipo_vector": f"TECNOLOGICO — {plantilla['tipo']}",
        "asunto": plantilla["asunto"].format(**variables),
        "cuerpo": plantilla["cuerpo"].format(**variables),
    }


def crear_pretexto(perfil: dict[str, Any]) -> dict[str, Any]:
    """
    Función principal — Genera un vector de Spear Phishing personalizado
    basado en el perfil psicográfico del objetivo.

    Pipeline híbrido:
        1. Intenta generar con J4N14 + Dolphin (IA generativa dinámica)
        2. Si la IA falla, usa plantillas estáticas como fallback robusto

    Args:
        perfil: Perfil psicográfico generado por perfilador_ia.analizar_perfil().

    Returns:
        Diccionario con el vector de ataque:
            - tipo_vector: str
            - asunto: str
            - cuerpo: str
            - categoria_usada: str
            - confianza_perfil: float
            - generado_por: str ("j4n14_ia" o "plantilla_estatica")
    """
    categoria: str = perfil.get("categoria_predictiva", "ESTILO_VIDA").upper()

    log.info(f"Generando vector — Categoría predictiva: {categoria}")

    # ── Intento 0 (opcional): GP Optimizer — selección evolutiva de plantillas ──
    # Solo activo si USAR_GP_OPTIMIZER=True en configuracion.py y DEAP está instalado.
    # En modo light, este bloque es un no-op (USAR_GP_OPTIMIZER=False por defecto).
    vector: Optional[dict[str, Any]] = None
    if USAR_GP_OPTIMIZER:
        try:
            from motores.gp_optimizer import seleccionar_plantilla_con_gp
            log.info("[GP] Intentando selección de plantilla con GP Optimizer...")
            vector = seleccionar_plantilla_con_gp(perfil, categoria)
            if vector:
                vector["generado_por"] = "gp_optimizer"
                log.info("[GP] Vector seleccionado por GP Optimizer.")
        except ImportError:
            log.debug("[GP] DEAP no instalado — GP Optimizer no disponible.")
        except Exception as _gp_err:
            log.warning(f"[GP] Error en GP Optimizer: {_gp_err}. Continuando con pipeline normal.")

    # ── Intento 1: Generación dinámica con J4N14 (Dolphin) ──
    if vector is None:
        resultado_ia: Optional[dict[str, str]] = _generar_con_ia(perfil, categoria)

        if resultado_ia:
            vector = {
                "tipo_vector": f"{categoria} — j4n14_generado",
                "asunto": resultado_ia["asunto"],
                "cuerpo": resultado_ia["cuerpo"],
                "generado_por": "j4n14_ia",
            }
            log.info("Vector generado por J4N14 (IA generativa).")

    # ── Intento 2: Fallback a plantillas estáticas ──
    if vector is None:
        log.info("Usando plantillas estáticas como fallback.")
        generadores: dict[str, Any] = {
            "JERARQUIA": _generar_vector_jerarquia,
            "ESTILO_VIDA": _generar_vector_estilo_vida,
            "TECNOLOGICO": _generar_vector_tecnologico,
        }

        generador = generadores.get(categoria, _generar_vector_estilo_vida)
        vector = generador(perfil)
        vector["generado_por"] = "plantilla_estatica"

    # Agregar metadata
    vector["categoria_usada"] = categoria
    vector["confianza_perfil"] = perfil.get("confianza", 0.0)

    log.info(f"Vector generado: {vector['tipo_vector']}")
    return vector


def generar_reporte_final(
    objetivo: dict[str, str],
    perfil: dict[str, Any],
    vector: dict[str, Any],
) -> dict[str, Any]:
    """
    Empaqueta todos los datos en un reporte JSON final estructurado.

    Combina: datos del objetivo + perfil psicográfico + vector de ataque
    en un único diccionario listo para serializar.

    Args:
        objetivo: Datos originales del objetivo (nombre, url, empresa).
        perfil: Perfil psicográfico del Motor J4N14.
        vector: Vector de ataque generado.

    Returns:
        Diccionario completo del reporte final.
    """
    reporte: dict[str, Any] = {
        "sistema": {
            "nombre": "Recon365",
            "motor": NOMBRE_MOTOR,
            "version": VERSION,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        },
        "objetivo": {
            "nombre": objetivo.get("nombre", "desconocido"),
            "url": objetivo.get("url", ""),
            "empresa": objetivo.get("empresa", "no_especificada"),
        },
        "perfil_psicografico": {
            "rol_detectado": perfil.get("rol_detectado", "no_determinado"),
            "industria": perfil.get("industria", "no_determinado"),
            "intereses": perfil.get("intereses", []),
            "necesidades_inferidas": perfil.get("necesidades_inferidas", []),
            "categoria_predictiva": perfil.get("categoria_predictiva", ""),
            "vulnerabilidades": perfil.get("vulnerabilidades", []),
            "confianza": perfil.get("confianza", 0.0),
            "razonamiento": perfil.get("razonamiento", ""),
        },
        "vector_ataque": {
            "tipo": vector.get("tipo_vector", ""),
            "asunto_correo": vector.get("asunto", ""),
            "cuerpo_correo": vector.get("cuerpo", ""),
            "categoria_usada": vector.get("categoria_usada", ""),
        },
        "disclaimer": (
            "Este reporte fue generado como parte de una auditoría de "
            "seguridad AUTORIZADA. El uso no autorizado de esta información "
            "es ilegal. Solo para fines de pentesting y red teaming."
        ),
    }

    log.info(
        f"Reporte final generado para '{objetivo.get('nombre', '?')}' — "
        f"Vector: {vector.get('tipo_vector', '?')}"
    )

    return reporte