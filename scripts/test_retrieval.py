import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database import SessionLocal
from services.rag import retrieve

def test_retrieval(query: str):
    db = SessionLocal()
    print(f"Query: '{query}'\n")
    
    results = retrieve(db, query, k=3)
    
    if not results:
        print("No results found.")
    
    for i, chunk in enumerate(results):
        print(f"--- Result {i+1} ---")
        print(f"Source: {chunk.source_name} | Category: {chunk.category}")
        print(f"Chunk Text: {chunk.chunk_text[:150]}...")
        print()
        
    db.close()

if __name__ == "__main__":
    query = "how to prevent SQL injection in Python"
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        
    test_retrieval(query)
