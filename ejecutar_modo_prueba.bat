@echo off
chcp 65001 >nul
cls
echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║       Recon365 — MODO PRUEBA                     ║
echo  ║       Motor J4N14 [MOCK] activado                ║
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

REM ── Verificar que el puerto 11434 esté libre ───────────────────────────────────
netstat -ano | findstr ":11434" >nul 2>&1
if not errorlevel 1 (
    echo  [ADVERTENCIA] El puerto 11434 ya esta en uso.
    echo  Puede que Ollama real este corriendo, o el mock ya este activo.
    echo  El sistema usara el servidor que ya esta en ese puerto.
    echo.
    goto :iniciar_main
)

REM ── Iniciar servidor mock en background ───────────────────────────────────────
echo  [1/2] Iniciando servidor Ollama MOCK...
start /B "" python ejecutables\ollama_mock.py > mock_server.log 2>&1

REM ── Esperar que el mock levante ────────────────────────────────────────────────
echo  [INFO] Esperando que el mock inicie (2 segundos)...
timeout /t 2 /nobreak >nul

REM ── Verificar que levantó ──────────────────────────────────────────────────────
curl -s http://localhost:11434 >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] El servidor mock no pudo iniciar.
    echo  Revisa mock_server.log para ver el error.
    pause
    exit /b 1
)
echo  [OK] Servidor mock activo en http://localhost:11434

:iniciar_main
REM ── Ejecutar Recon365 ──────────────────────────────────────────────────────────
start cmd /k "title Ollama Mock Server && python ejecutables\ollama_mock.py"

echo.
echo  Iniciando Recon365 en modo prueba...
echo  ================================================
echo.
python ejecutables\main.py --archivo %ARCHIVO_OBJETIVOS% --skip-motor 
echo.
echo  ════════════════════════════════════════════════════
echo  Ejecucion finalizada. Cerrando servidor mock...

REM ── Detener servidor mock ──────────────────────────────────────────────────────
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":11434" ^| findstr "LISTENING"') do (
    taskkill /PID %%p /F >nul 2>&1
)
echo  [OK] Servidor mock detenido.
echo.
pause
