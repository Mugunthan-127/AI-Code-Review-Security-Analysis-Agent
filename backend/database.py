import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://pguser:pgpassword@localhost:5432/agent_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from pgvector.sqlalchemy import Vector
    # Ensure vector extension is created
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.commit()

    # Create all tables (no-op if they already exist)
    Base.metadata.create_all(bind=engine)

    # Safe migration: add new enum values
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        try:
            conn.execute(text("ALTER TYPE statusenum ADD VALUE IF NOT EXISTS 'analyzed'"))
            conn.execute(text("ALTER TYPE statusenum ADD VALUE IF NOT EXISTS 'completed'"))
        except Exception:
            pass

    # Safe migration: add session_id column if missing (for existing DBs)
    with engine.connect() as conn:
        conn.execute(text("""
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS session_id VARCHAR
        """))
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS ix_scans_session_id ON scans (session_id)
        """))
        # Safe migration: add summary_text column if missing
        conn.execute(text("""
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS summary_text TEXT
        """))
        conn.execute(text("""
            ALTER TABLE scans
            ADD COLUMN IF NOT EXISTS risk_score INTEGER
        """))
        # Safe migration: add agent_source and owasp_type columns on findings
        conn.execute(text("""
            ALTER TABLE findings
            ADD COLUMN IF NOT EXISTS agent_source VARCHAR
        """))
        conn.execute(text("""
            ALTER TABLE findings
            ADD COLUMN IF NOT EXISTS owasp_type VARCHAR
        """))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_score VARCHAR;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS detected_by VARCHAR;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS language VARCHAR;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS severity VARCHAR;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_score FLOAT;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS original_code TEXT;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_status VARCHAR;"))
        conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'OPEN';"))
        
        conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS commit_id UUID;"))
        
        # Safe migration: add language and severity columns on kb_documents and kb_chunks
        for table in ["kb_documents", "kb_chunks"]:
            conn.execute(text(f"""
                ALTER TABLE {table}
                ADD COLUMN IF NOT EXISTS language VARCHAR
            """))
            conn.execute(text(f"""
                ALTER TABLE {table}
                ADD COLUMN IF NOT EXISTS severity VARCHAR
            """))
        conn.commit()
