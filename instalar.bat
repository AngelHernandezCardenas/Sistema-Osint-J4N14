@echo off
chcp 65001 >nul
cls
echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║         Recon365 — Instalador Automático          ║
echo  ║         Motor de Inferencia J4N14                 ║
echo  ╚═══════════════════════════════════════════════════╝
echo.

REM ── Verificar Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python no encontrado en PATH.
    echo  Por favor instala Python 3.11+ desde https://www.python.org/downloads/
    echo  IMPORTANTE: Marca la casilla "Add Python to PATH" durante la instalacion.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo  [OK] Python detectado: %PY_VER%

REM ── Crear entorno virtual ──────────────────────────────────────────────────────
echo.
echo  [1/4] Creando entorno virtual (.venv)...
if exist ".venv" (
    echo  [INFO] Entorno virtual ya existe, omitiendo creacion.
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
    echo  [OK] Entorno virtual creado.
)

REM ── Activar entorno virtual ────────────────────────────────────────────────────
call .venv\Scripts\activate.bat
echo  [OK] Entorno virtual activado.

REM ── Actualizar pip ────────────────────────────────────────────────────────────
echo.
echo  [2/4] Actualizando pip...
python -m pip install --upgrade pip --quiet
echo  [OK] pip actualizado.

REM ── Instalar dependencias ──────────────────────────────────────────────────────
echo.
echo  [3/4] Instalando dependencias (puede tomar varios minutos)...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  [ERROR] Fallo al instalar dependencias.
    echo  Revisa tu conexion a internet e intenta de nuevo.
    pause
    exit /b 1
)
echo  [OK] Dependencias instaladas correctamente.

REM ── Instalar browsers de Playwright ───────────────────────────────────────────
echo.
echo  [4/4] Instalando navegador Chromium para Playwright...
echo  (Descarga ~150 MB, puede demorar segun tu internet)
playwright install chromium
if errorlevel 1 (
    echo  [ADVERTENCIA] No se pudo instalar Chromium automaticamente.
    echo  Ejecuta manualmente: playwright install chromium
)
echo  [OK] Chromium instalado.

REM ── Verificar Ollama ──────────────────────────────────────────────────────────
echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║       PASO MANUAL REQUERIDO: Ollama               ║
echo  ╠═══════════════════════════════════════════════════╣
echo  ║  1. Instala Ollama desde: https://ollama.com      ║
echo  ║  2. Abre una terminal y ejecuta:                  ║
echo  ║       ollama pull llama3.1:8b                     ║
echo  ║  3. Asegurate que Ollama este corriendo antes     ║
echo  ║     de ejecutar Recon365.                         ║
echo  ╚═══════════════════════════════════════════════════╝
echo.
echo  ════════════════════════════════════════════════════
echo  [OK] Instalacion completada. Usa ejecutar.bat para iniciar.
echo  ════════════════════════════════════════════════════
echo.
pause
