import threading
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, SessionLocal
from routers import submission, kb, chat, reports

# Load .env manually to ensure GROQ_API_KEY and other keys are available
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
if os.path.exists(env_path):
    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                key, val = line.split('=', 1)
                os.environ.setdefault(key.strip(), val.strip())

app = FastAPI(title="AI Code Review & Security Analysis Agent – Milestone 2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _bg_ingest():
    """Run KB ingestion in a background thread so startup is not blocked."""
    try:
        from services.rag import is_kb_populated, ingest_all_kb_sources
        db = SessionLocal()
        if not is_kb_populated(db):
            print("[startup] KB is empty — starting ingestion in background...")
            ingest_all_kb_sources(db)
        else:
            print("[startup] KB already populated — skipping ingestion.")
        db.close()
    except Exception as e:
        print(f"[startup] KB ingestion error: {e}")


@app.on_event("startup")
def on_startup():
    init_db()
    # Ingest KB sources in background (model download can take a few minutes on first run)
    threading.Thread(target=_bg_ingest, daemon=True).start()


app.include_router(submission.router, prefix="/api/v1/submit", tags=["submission"])
app.include_router(kb.router, prefix="/api/kb", tags=["kb"])
app.include_router(chat.router, prefix="/api/scans", tags=["chat"])
app.include_router(reports.router, prefix="/api/scans", tags=["reports"])

@app.get("/health")
def health_check():
    return {"status": "ok"}
