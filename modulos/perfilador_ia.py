"""
modulos/perfilador_ia.py — Motor J4N14 de perfilamiento con IA local.

Este es el CEREBRO del sistema Recon365. Conecta con un modelo de lenguaje
local (Ollama / LM Studio) para analizar texto recolectado de perfiles
públicos y generar perfiles psicográficos estructurados.

Características:
    - System Prompt estricto que fuerza salida JSON pura
    - 3 categorías predictivas: JERARQUIA, ESTILO_VIDA, TECNOLOGICO
    - Validación de esquema de salida con Pydantic
    - Procesamiento 100% offline (sin envío de datos a la nube)
    - Optimizado para GPU NVIDIA 8 GB VRAM

Uso:
    from modulos.perfilador_ia import inicializar_motor, analizar_perfil
    if inicializar_motor():
        perfil = analizar_perfil("texto del perfil...", "nombre_objetivo")
"""

import json
import re
from typing import Any, Optional

import requests
from pydantic import BaseModel, Field, field_validator

from utilidades.logger import obtener_logger, imprimir_motor

from configuracion import (
    API_ENDPOINT_CHAT,
    API_BASE_URL,
    CATEGORIAS_PREDICTIVAS,
    CONTEXTO_VENTANA,
    GPU_LAYERS,
    MAX_TOKENS,
    MODELO_IA,
    NOMBRE_MOTOR,
    TEMPERATURA,
    TOP_P,
)

log = obtener_logger(__name__)


# ============================================================================
# SYSTEM PROMPT DEL MOTOR J4N14
# ============================================================================

SYSTEM_PROMPT_J4N14: str = """Eres J4N14, un motor de análisis de inteligencia de fuentes abiertas (OSINT) \
especializado en perfilamiento psicográfico. Tu ÚNICA función es analizar texto \
extraído de perfiles públicos en internet y generar un perfil estructurado del objetivo.

═══════════════════════════════════════════════════════════
REGLAS ABSOLUTAS — VIOLACIÓN = FALLO DEL SISTEMA
═══════════════════════════════════════════════════════════

1. FORMATO: Responde ÚNICAMENTE con un objeto JSON válido. NO incluyas texto \
   conversacional, explicaciones, ni markdown. Solo JSON puro.

2. ANÁLISIS: Evalúa el texto para determinar:
   - Rol profesional y nivel jerárquico
   - Industria o sector laboral
   - Intereses personales y profesionales
   - Necesidades inferidas a partir de sus publicaciones
   - Vulnerabilidades psicológicas explotables en ingeniería social

3. CLASIFICACIÓN PREDICTIVA — Asigna UNA categoría:
   - "JERARQUIA": Si detectas palabras como CEO, Director, Gerente, Fundador, \
     VP, C-Suite, Managing Partner, Socio Director. Indica persona de alto rango \
     con poco tiempo y sensibilidad a temas de autoridad y urgencia.
   - "ESTILO_VIDA": Si detectas menciones a viajes, deportes, hobbies, mascotas, \
     familia, comida, fitness, música, entretenimiento, equipos deportivos. \
     Indica persona susceptible a ofertas, premios y promociones.
   - "TECNOLOGICO": Si detectas lenguajes de programación, certificaciones IT, \
     hardware, software, frameworks, herramientas de desarrollo, cloud, DevOps. \
     Indica persona susceptible a alertas de seguridad y actualizaciones falsas.

4. CONFIANZA: Asigna un puntaje de 0.0 a 1.0 según la cantidad de evidencia.
   - < 0.3: Datos insuficientes
   - 0.3-0.6: Perfil parcial
   - 0.6-0.8: Perfil sólido
   - > 0.8: Perfil muy detallado

5. HONESTIDAD: Si no hay evidencia para un campo, usa "no_determinado". \
   NUNCA inventes datos que no estén en el texto proporcionado.

═══════════════════════════════════════════════════════════
ESQUEMA JSON DE SALIDA (OBLIGATORIO)
═══════════════════════════════════════════════════════════

{
  "nombre_objetivo": "string",
  "rol_detectado": "string",
  "industria": "string",
  "intereses": ["string"],
  "necesidades_inferidas": ["string"],
  "categoria_predictiva": "JERARQUIA | ESTILO_VIDA | TECNOLOGICO",
  "vulnerabilidades": ["string"],
  "confianza": 0.0,
  "razonamiento": "string (breve justificación de la categoría elegida)"
}

═══════════════════════════════════════════════════════════
EJEMPLO ONE-SHOT (NIVEL DE PROFUNDIDAD ESPERADO)
═══════════════════════════════════════════════════════════
Entrada de texto hipotética: "Soy Director Regional de Ventas. Viajo constantemente cerrando tratos y necesito que mi equipo cumpla las metas trimestrales cueste lo que cueste. No tengo tiempo para reuniones inútiles."

Salida JSON Esperada:
{
  "nombre_objetivo": "Jane Doe",
  "rol_detectado": "Director Regional de Ventas",
  "industria": "Ventas / Negocios",
  "intereses": ["Cierre de negocios", "Liderazgo de equipos", "Cumplimiento de metas", "Viajes de negocios"],
  "necesidades_inferidas": [
    "Necesidad extrema de optimizar su escaso tiempo libre",
    "Presión constante por alcanzar cuotas trimestrales de ventas",
    "Deseo de proyectar autoridad y control sobre su equipo"
  ],
  "categoria_predictiva": "JERARQUIA",
  "vulnerabilidades": [
    "Reacción impulsiva ante mensajes etiquetados como 'URGENTE' o relacionados a caídas en ventas",
    "Receptividad a atajos ejecutivos o herramientas VIP que prometan ahorrar tiempo",
    "Delegación rápida sin verificar correos que parezcan órdenes corporativas estándar"
  ],
  "confianza": 0.95,
  "razonamiento": "El perfil revela un alto cargo gerencial (Director), enfoque agresivo en resultados trimestrales y falta de tiempo, rasgos clásicos del perfil JERARQUIA."
}

RESPONDE SOLO CON EL JSON. NADA MÁS."""


# ============================================================================
# MODELO PYDANTIC PARA VALIDACIÓN DE SALIDA
# ============================================================================

class PerfilObjetivo(BaseModel):
    """Esquema de validación para la salida del Motor J4N14."""

    nombre_objetivo: str = Field(
        ..., description="Nombre del objetivo analizado"
    )
    rol_detectado: str = Field(
        default="no_determinado",
        description="Rol profesional detectado",
    )
    industria: str = Field(
        default="no_determinado",
        description="Industria o sector laboral",
    )
    intereses: list[str] = Field(
        default_factory=list,
        description="Lista de intereses detectados",
    )
    necesidades_inferidas: list[str] = Field(
        default_factory=list,
        description="Necesidades deducidas del perfil",
    )
    categoria_predictiva: str = Field(
        ..., description="Categoría predictiva del objetivo"
    )
    vulnerabilidades: list[str] = Field(
        default_factory=list,
        description="Vulnerabilidades psicológicas explotables",
    )
    confianza: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Nivel de confianza del análisis (0.0-1.0)",
    )
    razonamiento: str = Field(
        default="",
        description="Justificación de la categoría elegida",
    )

    @field_validator("categoria_predictiva")
    @classmethod
    def validar_categoria(cls, valor: str) -> str:
        """Valida que la categoría sea una de las permitidas."""
        valor_upper: str = valor.upper().strip()
        if valor_upper not in CATEGORIAS_PREDICTIVAS:
            # Intentar mapeo fuzzy
            mapeo: dict[str, str] = {
                "JERARQUÍA": "JERARQUIA",
                "HIERARQUIA": "JERARQUIA",
                "HIERARCHY": "JERARQUIA",
                "LIFESTYLE": "ESTILO_VIDA",
                "ESTILO DE VIDA": "ESTILO_VIDA",
                "TECH": "TECNOLOGICO",
                "TECNOLOGÍA": "TECNOLOGICO",
                "TECHNOLOGY": "TECNOLOGICO",
                "TECNOLÓGICO": "TECNOLOGICO",
            }
            valor_upper = mapeo.get(valor_upper, "ESTILO_VIDA")
        return valor_upper


# ============================================================================
# FUNCIONES PRINCIPALES
# ============================================================================

def inicializar_motor() -> bool:
    """
    Verifica la conectividad con el servidor de IA local (Ollama/LM Studio).

    Comprueba:
        1. Que el servidor esté ejecutándose
        2. Que el modelo configurado esté disponible

    Returns:
        True si el motor está listo para operar, False en caso contrario.
    """
    imprimir_motor("Inicializando Motor J4N14...")

    # --- Verificar servidor ---
    try:
        respuesta = requests.get(
            API_BASE_URL,
            timeout=10,
        )
        if respuesta.status_code == 200:
            log.info(f"Servidor de IA detectado en {API_BASE_URL}")
        else:
            log.error(
                f"Servidor respondió con código {respuesta.status_code}. "
                f"Verifique que Ollama esté ejecutándose."
            )
            return False
    except requests.ConnectionError:
        log.error(
            f"No se puede conectar a {API_BASE_URL}. "
            f"Asegúrese de que Ollama esté ejecutándose: 'ollama serve'"
        )
        return False
    except requests.Timeout:
        log.error(f"Timeout al conectar con {API_BASE_URL}")
        return False

    # --- Verificar modelo ---
    try:
        respuesta_modelos = requests.get(
            f"{API_BASE_URL}/api/tags",
            timeout=10,
        )
        if respuesta_modelos.status_code == 200:
            modelos_data: dict = respuesta_modelos.json()
            modelos_disponibles: list[str] = [
                m.get("name", "") for m in modelos_data.get("models", [])
            ]

            # Verificar si nuestro modelo está disponible
            modelo_encontrado: bool = any(
                MODELO_IA in modelo for modelo in modelos_disponibles
            )

            if modelo_encontrado:
                imprimir_motor(f"Modelo '{MODELO_IA}' cargado y listo.")
                log.info(f"Motor {NOMBRE_MOTOR} inicializado correctamente.")
                return True
            else:
                log.warning(
                    f"Modelo '{MODELO_IA}' no encontrado. "
                    f"Modelos disponibles: {modelos_disponibles}. "
                    f"Ejecute: 'ollama pull {MODELO_IA}'"
                )
                # Intentar continuar de todas formas (Ollama descarga bajo demanda)
                imprimir_motor(
                    f"Modelo '{MODELO_IA}' no pre-cargado. "
                    f"Se descargará en la primera consulta."
                )
                return True
    except Exception as error:
        log.warning(f"No se pudo verificar modelos: {error}. Continuando...")
        return True

    return False


def _construir_prompt(
    texto_perfil: str,
    nombre_objetivo: str,
) -> list[dict[str, str]]:
    """
    Construye la lista de mensajes (system + user) para enviar al LLM.

    Args:
        texto_perfil: Texto extraído del perfil público.
        nombre_objetivo: Nombre del objetivo para incluir en el análisis.

    Returns:
        Lista de mensajes en formato compatible con Ollama/OpenAI.
    """
    mensaje_usuario: str = (
        f"Analiza el siguiente texto extraído del perfil público de "
        f"'{nombre_objetivo}' y genera el perfil psicográfico en JSON.\n\n"
        f"═══ TEXTO DEL PERFIL ═══\n\n"
        f"{texto_perfil[:3000]}\n\n"  # Limitar a 3000 chars
        f"═══ FIN DEL TEXTO ═══\n\n"
        f"Recuerda: nombre_objetivo debe ser '{nombre_objetivo}'. "
        f"Responde SOLO con JSON válido."
    )

    mensajes: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT_J4N14},
        {"role": "user", "content": mensaje_usuario},
    ]

    return mensajes


def _extraer_json_de_respuesta(texto: str) -> Optional[dict[str, Any]]:
    """
    Extrae y parsea un objeto JSON de la respuesta del LLM.

    Maneja casos donde el modelo incluye texto adicional o
    bloques de código markdown alrededor del JSON.

    Args:
        texto: Respuesta cruda del modelo.

    Returns:
        Diccionario parseado o None si no se pudo extraer JSON.
    """
    texto_limpio: str = texto.strip()

    # Intento 1: Parseo directo
    try:
        return json.loads(texto_limpio)
    except json.JSONDecodeError:
        pass

    # Intento 2: Extraer JSON de bloques de código markdown
    patron_code_block = re.compile(
        r"```(?:json)?\s*\n?(.*?)\n?\s*```",
        re.DOTALL,
    )
    match_code = patron_code_block.search(texto_limpio)
    if match_code:
        try:
            return json.loads(match_code.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Intento 3: Buscar el primer {...} en el texto
    patron_json = re.compile(r"\{.*\}", re.DOTALL)
    match_json = patron_json.search(texto_limpio)
    if match_json:
        try:
            return json.loads(match_json.group(0))
        except json.JSONDecodeError:
            pass

    log.error(f"No se pudo extraer JSON de la respuesta del LLM: {texto[:200]}...")
    return None


def _validar_esquema(datos: dict[str, Any]) -> Optional[PerfilObjetivo]:
    """
    Valida los datos contra el esquema Pydantic del perfil.

    Args:
        datos: Diccionario con los datos del perfil.

    Returns:
        Instancia de PerfilObjetivo validada, o None si falla.
    """
    try:
        perfil: PerfilObjetivo = PerfilObjetivo(**datos)
        log.debug(f"Esquema validado — Categoría: {perfil.categoria_predictiva}")
        return perfil
    except Exception as error:
        log.error(f"Error de validación de esquema: {error}")
        return None


def analizar_perfil(
    texto_perfil: str,
    nombre_objetivo: str,
) -> dict[str, Any]:
    """
    Función principal del Motor J4N14. Analiza texto de un perfil público
    y genera un perfil psicográfico estructurado.

    Pipeline:
        1. Construye el prompt (system + user)
        2. Envía al LLM local vía API HTTP
        3. Extrae JSON de la respuesta
        4. Valida contra el esquema Pydantic
        5. Retorna diccionario limpio

    Args:
        texto_perfil: Texto extraído del perfil público del objetivo.
        nombre_objetivo: Nombre identificador del objetivo.

    Returns:
        Diccionario con el perfil psicográfico. Contiene un campo
        'error' si el análisis falló.
    """
    imprimir_motor(f"Analizando perfil de '{nombre_objetivo}'...")

    # Verificar que hay texto suficiente
    if not texto_perfil or len(texto_perfil.strip()) < 20:
        log.warning(
            f"Texto insuficiente para analizar '{nombre_objetivo}' "
            f"({len(texto_perfil)} chars). Se requieren al menos 20."
        )
        return {
            "nombre_objetivo": nombre_objetivo,
            "error": "texto_insuficiente",
            "categoria_predictiva": "ESTILO_VIDA",
            "confianza": 0.0,
            "intereses": [],
            "necesidades_inferidas": [],
            "vulnerabilidades": [],
            "razonamiento": "Datos insuficientes para análisis.",
        }

    # Construir prompt
    mensajes: list[dict[str, str]] = _construir_prompt(
        texto_perfil, nombre_objetivo
    )

    # Enviar al LLM
    payload: dict[str, Any] = {
        "model": MODELO_IA,
        "messages": mensajes,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": TEMPERATURA,
            "top_p": TOP_P,
            "num_predict": MAX_TOKENS,
            "num_gpu": GPU_LAYERS,
            "num_ctx": CONTEXTO_VENTANA,
        },
    }

    try:
        log.info(f"Enviando consulta al modelo '{MODELO_IA}'...")
        respuesta = requests.post(
            API_ENDPOINT_CHAT,
            json=payload,
            timeout=120,  # 2 minutos para generación con GPU
        )

        if respuesta.status_code != 200:
            log.error(
                f"Error del servidor de IA: HTTP {respuesta.status_code} — "
                f"{respuesta.text[:300]}"
            )
            return {
                "nombre_objetivo": nombre_objetivo,
                "error": f"http_{respuesta.status_code}",
                "confianza": 0.0,
            }

        # Extraer contenido de la respuesta
        respuesta_json: dict = respuesta.json()
        contenido: str = (
            respuesta_json
            .get("message", {})
            .get("content", "")
        )

        if not contenido:
            log.error("Respuesta vacía del modelo de IA.")
            return {
                "nombre_objetivo": nombre_objetivo,
                "error": "respuesta_vacia",
                "confianza": 0.0,
            }

        log.debug(f"Respuesta cruda del LLM ({len(contenido)} chars)")

        # Extraer JSON
        datos_perfil: Optional[dict[str, Any]] = _extraer_json_de_respuesta(contenido)
        if datos_perfil is None:
            return {
                "nombre_objetivo": nombre_objetivo,
                "error": "json_invalido",
                "respuesta_cruda": contenido[:500],
                "confianza": 0.0,
            }

        # Asegurar nombre del objetivo
        datos_perfil["nombre_objetivo"] = nombre_objetivo

        # Validar esquema
        perfil_validado: Optional[PerfilObjetivo] = _validar_esquema(datos_perfil)
        if perfil_validado is None:
            log.warning(
                "Esquema no válido. Retornando datos sin validar."
            )
            return datos_perfil

        resultado: dict[str, Any] = perfil_validado.model_dump()

        imprimir_motor(
            f"Perfil generado — Categoría: {resultado['categoria_predictiva']} "
            f"| Confianza: {resultado['confianza']:.1%}"
        )

        return resultado

    except requests.ConnectionError:
        log.error(
            "No se puede conectar al servidor de IA. "
            "Verifique que Ollama esté ejecutándose."
        )
        return {
            "nombre_objetivo": nombre_objetivo,
            "error": "conexion_fallida",
            "confianza": 0.0,
        }
    except requests.Timeout:
        log.error("Timeout esperando respuesta del modelo de IA (>120s).")
        return {
            "nombre_objetivo": nombre_objetivo,
            "error": "timeout",
            "confianza": 0.0,
        }
    except Exception as error:
        log.error(f"Error inesperado en Motor J4N14: {error}")
        return {
            "nombre_objetivo": nombre_objetivo,
            "error": str(error),
            "confianza": 0.0,
        }