@echo off
chcp 65001 >nul
cls
echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║         Recon365 — Iniciando Sistema              ║
echo  ║         Motor de Inferencia J4N14                 ║
echo  ╚═══════════════════════════════════════════════════╝
echo.

REM ── Verificar entorno virtual ──────────────────────────────────────────────────
if not exist ".venv\Scripts\activate.bat" (
    echo  [ERROR] Entorno virtual no encontrado.
    echo  Por favor ejecuta primero: instalar.bat
    echo.
    pause
    exit /b 1
)

REM ── Activar entorno virtual ────────────────────────────────────────────────────
call .venv\Scripts\activate.bat

REM ── Verificar Ollama ──────────────────────────────────────────────────────────
echo  Verificando servidor Ollama en http://localhost:11434 ...
curl -s http://localhost:11434 >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ┌─────────────────────────────────────────────────────┐
    echo  │  [ADVERTENCIA] Ollama no parece estar corriendo.    │
    echo  │  Asegurate de:                                      │
    echo  │    1. Tener Ollama instalado (https://ollama.com)   │
    echo  │    2. Haber descargado el modelo:                   │
    echo  │         ollama pull llama3.1:8b                     │
    echo  │    3. Que el servicio Ollama este activo.           │
    echo  └─────────────────────────────────────────────────────┘
    echo.
    set /p CONTINUAR="  Continuar de todas formas? (s/n): "
    if /i not "%CONTINUAR%"=="s" (
        echo  Saliendo...
        pause
        exit /b 0
    )
)

echo.
echo  Iniciando Recon365...
echo  ════════════════════════════════════════════════════
echo.
python ejecutables\main.py

echo.
echo  ════════════════════════════════════════════════════
echo  Ejecucion finalizada.
echo.
pause
