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
    summary_text = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    chat_sessions = relationship("ChatSession", back_populates="scan")
    token_usages = relationship("TokenUsage", back_populates="scan")

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

class Finding(Base):
    __tablename__ = "findings"
    
    finding_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    agent_source = Column(String, nullable=True)  # 'code_analysis' | 'security_vulnerability'
    line = Column(Integer, nullable=True)
    column_num = Column(Integer, nullable=True)
    tool = Column(String)
    rule_id = Column(String, nullable=True)
    severity = Column(String)
    category = Column(String)
    owasp_type = Column(String, nullable=True)     # e.g. 'SQL Injection', 'XSS'
    title = Column(String)
    explanation = Column(Text, nullable=True)
    suggested_fix = Column(Text, nullable=True)
    cwe_id = Column(String, nullable=True)
    grounding_source = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")

class ChatSession(Base):
    __tablename__ = "chat_sessions"
    
    session_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="chat_sessions")
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    message_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("chat_sessions.session_id"))
    role = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    session = relationship("ChatSession", back_populates="messages")

class TokenUsage(Base):
    __tablename__ = "token_usage"
    
    usage_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"), nullable=True)
    agent_name = Column(String)
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="token_usages")
