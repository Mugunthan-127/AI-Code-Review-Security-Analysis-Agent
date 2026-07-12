import threading
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import init_db, SessionLocal
from routers import submission

app = FastAPI(title="AI Code Review & Security Analysis Agent – Milestone 1")

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


@app.get("/health")
def health_check():
    return {"status": "ok"}
