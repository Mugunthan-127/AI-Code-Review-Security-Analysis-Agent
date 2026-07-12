import os
import sys

# Add backend to path so we can import from database/models
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database import SessionLocal
from services.rag import ingest_document

def ingest_all():
    db = SessionLocal()
    kb_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'kb_sources')
    
    if not os.path.exists(kb_dir):
        print(f"Directory {kb_dir} not found.")
        return
        
    for filename in os.listdir(kb_dir):
        if filename.endswith(".md") or filename.endswith(".txt"):
            filepath = os.path.join(kb_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Dummy category mapping
            category = "guideline"
            if "cheat_sheet" in filename:
                category = "cheat_sheet"
                
            ingest_document(
                db=db,
                source_name=filename,
                category=category,
                content=content
            )
            
    db.close()

if __name__ == "__main__":
    print("Starting ingestion...")
    ingest_all()
    print("Ingestion complete.")
