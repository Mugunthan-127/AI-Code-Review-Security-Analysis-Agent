import os
import sys

# Add backend to path so we can import from database/models
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database import SessionLocal
from services.rag import ingest_all_kb_sources
from models import KBDocument, KBChunk

def ingest_all():
    db = SessionLocal()
    try:
        # Clear existing KB data to avoid duplicates during re-ingestion
        print("Clearing existing KB data...")
        db.query(KBChunk).delete()
        db.query(KBDocument).delete()
        db.commit()
        
        ingest_all_kb_sources(db)
    finally:
        db.close()

if __name__ == "__main__":
    print("Starting ingestion...")
    ingest_all()
    print("Ingestion complete.")
