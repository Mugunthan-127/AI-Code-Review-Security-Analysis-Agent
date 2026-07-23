from sqlalchemy import Column, String, Text, DateTime, Integer, Enum, ForeignKey, Float
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

    projects = relationship("Project", back_populates="owner")
    scans = relationship("Scan", back_populates="user")

class Project(Base):
    __tablename__ = "projects"
    
    project_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, index=True)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"))
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    repositories = relationship("Repository", back_populates="project")

class Repository(Base):
    __tablename__ = "repositories"
    
    repo_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.project_id"))
    name = Column(String, index=True)
    url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="repositories")
    commits = relationship("Commit", back_populates="repository")

class Commit(Base):
    __tablename__ = "commits"
    
    commit_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    repo_id = Column(UUID(as_uuid=True), ForeignKey("repositories.repo_id"))
    commit_hash = Column(String, index=True)
    message = Column(Text, nullable=True)
    author = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="commits")
    scans = relationship("Scan", back_populates="commit")

class LanguageEnum(str, enum.Enum):
    python = "python"
    java = "java"

class SourceTypeEnum(str, enum.Enum):
    paste = "paste"
    upload = "upload"

class StatusEnum(str, enum.Enum):
    analyzed = "analyzed"
    validated = "validated"
    completed = "completed"
    rejected = "rejected"

class Scan(Base):
    __tablename__ = "scans"
    
    scan_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True) # nullable for simple testing
    commit_id = Column(UUID(as_uuid=True), ForeignKey("commits.commit_id"), nullable=True) # GitHub integration
    session_id = Column(String, nullable=True, index=True)  # anonymous browser session
    language = Column(Enum(LanguageEnum))
    source_type = Column(Enum(SourceTypeEnum))
    raw_code_ref = Column(Text)
    status = Column(Enum(StatusEnum))
    validation_error = Column(Text, nullable=True)
    summary_text = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="scans")
    commit = relationship("Commit", back_populates="scans")
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
    language = Column(String, nullable=True)
    severity = Column(String, nullable=True)
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
    language = Column(String, nullable=True)
    severity = Column(String, nullable=True)
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
    cvss_score = Column(Float, nullable=True)
    category = Column(String)
    owasp_type = Column(String, nullable=True)     # e.g. 'SQL Injection', 'XSS'
    title = Column(String)
    explanation = Column(Text, nullable=True)
    suggested_fix = Column(Text, nullable=True)
    cwe_id = Column(String, nullable=True)         # e.g. 'CWE-89'
    grounding_source = Column(String, nullable=True) # e.g. 'owasp_a01.md'
    confidence_score = Column(String, nullable=True) # e.g. '96%'
    detected_by = Column(String, nullable=True)      # e.g. '["SpotBugs", "LLM Validation"]'
    original_code = Column(String, nullable=True)
    validation_status = Column(String, nullable=True)
    status = Column(String, default='OPEN')          # 'OPEN', 'FIXED', 'IGNORED'

    scan = relationship("Scan", back_populates="findings")
    fixes = relationship("Fix", back_populates="finding")

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

class Fix(Base):
    __tablename__ = "fixes"
    
    fix_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.finding_id"))
    patched_code = Column(Text)
    status = Column(String, default='PENDING') # 'PENDING', 'APPLIED', 'REJECTED'
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="fixes")
    history = relationship("FixHistory", back_populates="fix")

class FixHistory(Base):
    __tablename__ = "fix_history"
    
    history_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fix_id = Column(UUID(as_uuid=True), ForeignKey("fixes.fix_id"))
    action = Column(String) # 'GENERATED', 'APPLIED_TO_PR', 'REJECTED'
    timestamp = Column(DateTime, default=datetime.utcnow)

    fix = relationship("Fix", back_populates="history")
