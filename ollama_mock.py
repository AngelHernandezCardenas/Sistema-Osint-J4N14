"""
ollama_mock.py — Servidor mock de Ollama para pruebas sin GPU.

Simula la API de Ollama en http://localhost:11434 respondiendo
con perfiles psicográficos generados por reglas (sin LLM real).

Endpoints implementados:
    GET  /            → "Ollama is running"
    GET  /api/tags    → Lista de modelos disponibles
    POST /api/chat    → Análisis mock del perfil (respuesta instantánea)
    POST /api/generate → Alias de /api/chat

Uso:
    python ollama_mock.py
    # En otra terminal:
    python main.py

Dependencias: Solo stdlib de Python (http.server, json, re)
"""

import json
import re
import random
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

# ============================================================================
# CONFIGURACIÓN DEL MOCK
# ============================================================================

HOST = "localhost"
PORT = 11434
MODELO_MOCK = "llama3.1:8b"

# Simular un pequeño delay para que parezca que "piensa" (en segundos)
DELAY_SIMULADO = 0.3

# ============================================================================
# MOTOR DE ANÁLISIS POR REGLAS (reemplaza al LLM real)
# ============================================================================

# Palabras clave por categoría
PALABRAS_JERARQUIA = [
    "ceo", "director", "gerente", "fundador", "founder", "vp", "vice",
    "presidente", "partner", "socio", "managing", "chief", "head",
    "lider", "líder", "executive", "ejecutivo", "c-suite", "coo", "cto",
    "encargado", "supervisor", "coordinador", "jefe"
]

PALABRAS_TECNOLOGICO = [
    "python", "java", "javascript", "developer", "desarrollador", "dev",
    "software", "hardware", "cloud", "aws", "azure", "devops", "linux",
    "programador", "código", "codigo", "frontend", "backend", "fullstack",
    "react", "docker", "kubernetes", "git", "github", "cybersecurity",
    "seguridad", "networking", "datos", "data", "ml", "ia", "ai",
    "certificación", "certificacion", "cisco", "comptia", "hack",
    "servidor", "sistema", "base de datos", "sql", "api", "framework"
]

PALABRAS_ESTILO_VIDA = [
    "viaje", "viajes", "travel", "playa", "montaña", "deporte", "fitness",
    "gym", "música", "musica", "food", "comida", "foto", "fotografia",
    "mascota", "perro", "gato", "familia", "hijo", "hija", "bebé",
    "bebe", "hobby", "hobbies", "running", "futbol", "fútbol", "basket",
    "netflix", "gaming", "juego", "cocina", "cocinando", "premio",
    "sorteo", "ganador", "vacaciones", "moda", "fashion", "compras"
]

# Vectores de ataque por categoría
VECTORES = {
    "JERARQUIA":    "urgencia_financiera",
    "TECNOLOGICO":  "alerta_seguridad",
    "ESTILO_VIDA":  "premio_sorteo",
}

# Vulnerabilidades por categoría
VULNERABILIDADES_MOCK = {
    "JERARQUIA": [
        "Reacciona rápidamente a mensajes etiquetados como 'URGENTE' de supuestos superiores",
        "Susceptible a correos con tono corporativo y terminología financiera",
        "Presión por resultados puede llevarlo a saltarse protocolos de verificación",
    ],
    "TECNOLOGICO": [
        "Mayor confianza en mensajes técnicos (alertas de sistemas, actualizaciones críticas)",
        "Puede ser víctima de phishing disfrazado de notificaciones de plataformas técnicas",
        "Tendencia a hacer clic en links de 'vulnerabilidades detectadas' en sus sistemas",
    ],
    "ESTILO_VIDA": [
        "Susceptible a ofertas de premios, sorteos o descuentos personalizados",
        "Comparte información personal fácilmente en redes sociales",
        "Alta probabilidad de participar en concursos o formularios en línea",
    ],
}

NECESIDADES_MOCK = {
    "JERARQUIA": [
        "Optimización del tiempo y productividad ejecutiva",
        "Mantenimiento de imagen de autoridad y liderazgo",
        "Información estratégica para toma de decisiones",
    ],
    "TECNOLOGICO": [
        "Actualización constante sobre nuevas herramientas y tecnologías",
        "Soluciones que automaticen tareas técnicas repetitivas",
        "Validación de conocimientos técnicos por pares",
    ],
    "ESTILO_VIDA": [
        "Reconocimiento social por estilo de vida aspiracional",
        "Ofertas exclusivas y experiencias personalizadas",
        "Conexión con comunidades de intereses afines",
    ],
}


def analizar_texto_mock(texto: str, nombre_objetivo: str) -> dict:
    """
    Analiza el texto usando reglas de palabras clave.
    Simula la salida del Motor J4N14 sin usar un LLM real.
    """
    texto_lower = texto.lower()

    # Contar coincidencias por categoría
    score_jerarquia  = sum(1 for w in PALABRAS_JERARQUIA    if w in texto_lower)
    score_tecnologico = sum(1 for w in PALABRAS_TECNOLOGICO  if w in texto_lower)
    score_estilo_vida = sum(1 for w in PALABRAS_ESTILO_VIDA  if w in texto_lower)

    scores = {
        "JERARQUIA":    score_jerarquia,
        "TECNOLOGICO":  score_tecnologico,
        "ESTILO_VIDA":  score_estilo_vida,
    }

    # Categoría ganadora
    categoria = max(scores, key=scores.get)

    # Si empate o sin datos, default a ESTILO_VIDA
    if scores[categoria] == 0:
        categoria = "ESTILO_VIDA"

    # Calcular confianza basada en cantidad de evidencia
    total_matches = sum(scores.values())
    if total_matches == 0:
        confianza = round(random.uniform(0.25, 0.40), 2)
    elif total_matches <= 2:
        confianza = round(random.uniform(0.40, 0.60), 2)
    elif total_matches <= 5:
        confianza = round(random.uniform(0.60, 0.80), 2)
    else:
        confianza = round(random.uniform(0.80, 0.95), 2)

    # Detectar rol e industria con heurísticas simples
    rol_detectado = "no_determinado"
    for palabra in PALABRAS_JERARQUIA:
        if palabra in texto_lower:
            # Intentar extraer contexto alrededor de la palabra
            idx = texto_lower.find(palabra)
            fragmento = texto[max(0, idx-10):min(len(texto), idx+40)]
            rol_detectado = fragmento.strip().split("\n")[0][:50]
            break

    # Industria
    industria = "no_determinado"
    industrias_map = {
        "tecnología": ["software", "developer", "programador", "tech", "cloud", "data"],
        "finanzas":   ["banco", "finanzas", "inversión", "inversion", "financiero"],
        "salud":      ["médico", "medico", "doctor", "enfermero", "salud", "hospital"],
        "educación":  ["profesor", "docente", "educación", "universidad", "escuela"],
        "negocios":   ["ventas", "marketing", "negocios", "empresa", "startup"],
        "arte/entretenimiento": ["música", "musica", "arte", "diseño", "diseño", "fotografía"],
    }
    for ind, palabras in industrias_map.items():
        if any(p in texto_lower for p in palabras):
            industria = ind
            break

    # Intereses extraídos de palabras clave encontradas
    palabras_pool = PALABRAS_JERARQUIA + PALABRAS_TECNOLOGICO + PALABRAS_ESTILO_VIDA
    intereses = list({w.replace("_", " ").title() for w in palabras_pool if w in texto_lower})[:4]
    if not intereses:
        intereses = ["no_determinado"]

    razonamiento = (
        f"[MOCK] Análisis por reglas: scores={scores}. "
        f"Categoría '{categoria}' seleccionada con {scores[categoria]} coincidencias. "
        f"Confianza calculada en base a {total_matches} indicadores totales."
    )

    return {
        "nombre_objetivo":    nombre_objetivo,
        "rol_detectado":      rol_detectado,
        "industria":          industria,
        "intereses":          intereses,
        "necesidades_inferidas": NECESIDADES_MOCK[categoria],
        "categoria_predictiva":  categoria,
        "vulnerabilidades":   VULNERABILIDADES_MOCK[categoria],
        "confianza":          confianza,
        "razonamiento":       razonamiento,
    }


def extraer_nombre_y_texto(mensajes: list) -> tuple[str, str]:
    """Extrae el nombre del objetivo y el texto del perfil del prompt."""
    nombre = "objetivo_mock"
    texto  = ""

    for msg in mensajes:
        if msg.get("role") == "user":
            contenido = msg.get("content", "")
            # Buscar nombre entre comillas simples
            match_nombre = re.search(r"de '([^']+)'", contenido)
            if match_nombre:
                nombre = match_nombre.group(1)
            # Extraer texto del perfil entre los separadores
            match_texto = re.search(
                r"═══ TEXTO DEL PERFIL ═══\s*(.*?)\s*═══ FIN DEL TEXTO ═══",
                contenido, re.DOTALL
            )
            if match_texto:
                texto = match_texto.group(1).strip()
            else:
                texto = contenido

    return nombre, texto


# ============================================================================
# SERVIDOR HTTP MOCK
# ============================================================================

class OllamaMockHandler(BaseHTTPRequestHandler):
    """Handler que simula la API REST de Ollama."""

    def log_message(self, format, *args):
        """Override para formato de log más limpio."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{ts}] [MOCK] {self.path} → {args[1] if len(args) > 1 else ''}")

    def _send_json(self, data: dict, status: int = 200):
        """Envía una respuesta JSON."""
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, status: int = 200):
        """Envía una respuesta de texto plano."""
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _leer_body(self) -> dict:
        """Lee y parsea el body JSON de la request."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ── GET handlers ─────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/":
            self._send_text("Ollama is running")

        elif self.path == "/api/tags":
            # Simular lista de modelos disponibles
            self._send_json({
                "models": [
                    {
                        "name":        MODELO_MOCK,
                        "model":       MODELO_MOCK,
                        "modified_at": datetime.now().isoformat(),
                        "size":        4661211136,
                        "digest":      "mock_digest_abc123",
                        "details": {
                            "format":             "gguf",
                            "family":             "llama",
                            "parameter_size":     "8B",
                            "quantization_level": "Q4_0",
                        }
                    }
                ]
            })

        else:
            self._send_json({"error": "endpoint no implementado"}, 404)

    # ── POST handlers ─────────────────────────────────────────────────────────

    def do_POST(self):
        body = self._leer_body()

        if self.path in ("/api/chat", "/api/generate"):
            self._handle_chat(body)
        else:
            self._send_json({"error": "endpoint no implementado"}, 404)

    def _handle_chat(self, body: dict):
        """Simula una respuesta del LLM con análisis por reglas."""

        # Extraer mensajes del body
        mensajes = body.get("messages", [])

        # Si viene de /api/generate (prompt string en lugar de messages)
        if not mensajes and "prompt" in body:
            mensajes = [{"role": "user", "content": body["prompt"]}]

        # Analizar
        nombre, texto = extraer_nombre_y_texto(mensajes)

        time.sleep(DELAY_SIMULADO)  # Simular tiempo de procesamiento

        perfil = analizar_texto_mock(texto, nombre)
        perfil_json_str = json.dumps(perfil, ensure_ascii=False, indent=2)

        # Responder en formato compatible con Ollama /api/chat
        self._send_json({
            "model":      MODELO_MOCK,
            "created_at": datetime.now().isoformat() + "Z",
            "message": {
                "role":    "assistant",
                "content": perfil_json_str,
            },
            "done":              True,
            "done_reason":       "stop",
            "total_duration":    int(DELAY_SIMULADO * 1e9),
            "load_duration":     50000000,
            "prompt_eval_count": len(str(mensajes)),
            "eval_count":        len(perfil_json_str),
        })


# ============================================================================
# ENTRADA PRINCIPAL
# ============================================================================

if __name__ == "__main__":
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║       Ollama MOCK Server — Recon365             ║")
    print("  ║       Modo prueba sin GPU ni instalaciones      ║")
    print("  ╠══════════════════════════════════════════════════╣")
    print(f"  ║  Escuchando en: http://{HOST}:{PORT}              ║")
    print(f"  ║  Modelo simulado: {MODELO_MOCK}               ║")
    print("  ║                                                  ║")
    print("  ║  Presiona Ctrl+C para detener.                  ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    print("  Esperando solicitudes de Recon365...\n")

    server = HTTPServer((HOST, PORT), OllamaMockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n  [MOCK] Servidor detenido.")
        server.server_close()
