@echo off
echo ==============================================
echo   AI Code Review & Security Analysis Agent
echo ==============================================
echo Starting Backend (FastAPI)...
start "Backend" cmd /c "cd backend && .\.venv\Scripts\uvicorn.exe main:app --reload --host 127.0.0.1 --port 8000"

echo Starting Frontend (Vite)...
start "Frontend" cmd /c "cd frontend && npm run dev"

echo.
echo Both servers have been started in new windows!
echo Frontend is available at: http://localhost:5173
echo Backend API is at: http://localhost:8000
echo.
pause
