# Recon365 — Guía de Instalación Rápida

> **Solo para auditorías de seguridad autorizadas.**

## Requisitos Previos

### 1. Python 3.11 o superior
- Descarga desde: https://www.python.org/downloads/
- ⚠️ **IMPORTANTE**: Durante la instalación, marca la casilla **"Add Python to PATH"**

### 2. Ollama (Motor de IA Local)
- Descarga desde: https://ollama.com
- Tras instalarlo, abre una terminal y ejecuta:
  ```
  ollama pull llama3.1:8b
  ```
  *(Descarga ~4.7 GB, requiere conexión a internet)*
- Asegúrate de que Ollama esté corriendo antes de usar Recon365

---

## Instalación (una sola vez)

1. Descomprime el `.zip` en cualquier carpeta de tu PC
2. Abre la carpeta y haz **doble clic en `instalar.bat`**
3. Espera a que termine (instala dependencias de Python y el navegador Chromium)

---

## Uso

Cada vez que quieras usar Recon365:

1. **Doble clic en `ejecutar.bat`**

O desde una terminal (dentro de la carpeta del proyecto):
```bash
# Activar entorno virtual
.venv\Scripts\activate

# Correr el programa
python main.py
```

---

## Estructura del Proyecto

```
recon365/
├── instalar.bat          ← Ejecuta primero (solo una vez)
├── ejecutar.bat          ← Ejecuta cada vez que uses el programa
├── main.py               ← Punto de entrada principal
├── configuracion.py      ← Parámetros del sistema
├── requirements.txt      ← Dependencias Python
├── modulos/
│   ├── perfilador_ia.py  ← Motor J4N14 (análisis con LLM)
│   ├── recolector.py     ← Módulo de recolección
│   └── generador_ataques.py ← Generador de vectores
├── utilidades/
│   ├── logger.py         ← Sistema de logging
│   └── gestor_archivos.py ← Gestión de archivos
└── data/
    ├── inputs/           ← Pon aquí tus archivos de objetivos (.txt, .csv)
    └── outputs/          ← Reportes generados automáticamente
```

---

## Configuración de Objetivos

Edita el archivo `data/inputs/objetivos.txt` con tus objetivos (uno por línea).

---

## Solución de Problemas

| Problema | Solución |
|----------|----------|
| `Python no encontrado` | Reinstala Python marcando "Add to PATH" |
| `Ollama no responde` | Abre Ollama desde el menú de inicio o ejecuta `ollama serve` |
| `Modelo no encontrado` | Ejecuta `ollama pull llama3.1:8b` en una terminal |
| `Error de Playwright` | Ejecuta manualmente: `.venv\Scripts\activate` → `playwright install chromium` |

---

*Recon365 v1.0.0-mvp — Motor J4N14*
