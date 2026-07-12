from sqlalchemy import Column, String, Text, DateTime, Integer, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime
from database import Base
from pgvector.sqlalchemy import Vector
import enum

class User(Base):
    __tablename__ = "users"
    
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="user")

class LanguageEnum(str, enum.Enum):
    python = "python"
    java = "java"

class SourceTypeEnum(str, enum.Enum):
    paste = "paste"
    upload = "upload"

class StatusEnum(str, enum.Enum):
    validated = "validated"
    rejected = "rejected"

class Scan(Base):
    __tablename__ = "scans"
    
    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True) # nullable for simple testing
    session_id = Column(String, nullable=True, index=True)  # anonymous browser session
    language = Column(Enum(LanguageEnum))
    source_type = Column(Enum(SourceTypeEnum))
    raw_code_ref = Column(Text)
    status = Column(Enum(StatusEnum))
    validation_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")

class KBDocument(Base):
    __tablename__ = "kb_documents"
    
    kb_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_name = Column(String)
    category = Column(String)
    owasp_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    raw_content_ref = Column(Text)
    ingested_at = Column(DateTime, default=datetime.utcnow)

    chunks = relationship("KBChunk", back_populates="document")

class KBChunk(Base):
    __tablename__ = "kb_chunks"
    
    chunk_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kb_id = Column(UUID(as_uuid=True), ForeignKey("kb_documents.kb_id"))
    chunk_text = Column(Text)
    # Using 384 dimensions for all-MiniLM-L6-v2 embedding model
    embedding = Column(Vector(384))
    source_name = Column(String)
    category = Column(String)
    owasp_id = Column(String, nullable=True)
    cwe_id = Column(String, nullable=True)
    token_count = Column(Integer)

    document = relationship("KBDocument", back_populates="chunks")
