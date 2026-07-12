# Data Schemas (Milestone 1)

These schemas define the underlying data model for the application. In Milestone 1, they are designed as PostgreSQL tables (using SQLAlchemy ORM). Some tables are included as placeholders for future milestones.

## 1. User
*(Minimal user for scan ownership)*
- `user_id`: UUID (Primary Key)
- `name`: String
- `email`: String (Unique)
- `created_at`: DateTime

## 2. Scan
- `scan_id`: UUID (Primary Key)
- `user_id`: UUID (Foreign Key to User)
- `language`: Enum ('python', 'java')
- `source_type`: Enum ('paste', 'upload')
- `raw_code_ref`: Text (The raw code snippet)
- `status`: Enum ('validated', 'rejected')
- `validation_error`: Text (Nullable, for syntax errors)
- `created_at`: DateTime

## 3. KBDocument
- `kb_id`: UUID (Primary Key)
- `source_name`: String (e.g., 'OWASP Top 10')
- `category`: String (e.g., 'guideline', 'cheat_sheet')
- `owasp_id`: String (Nullable)
- `cwe_id`: String (Nullable)
- `raw_content_ref`: Text (Original markdown/text content)
- `ingested_at`: DateTime

## 4. KBChunk
- `chunk_id`: UUID (Primary Key)
- `kb_id`: UUID (Foreign Key to KBDocument)
- `chunk_text`: Text
- `embedding`: Vector (pgvector, e.g., 384 dims for `all-MiniLM-L6-v2`)
- `source_name`: String (Inherited)
- `category`: String (Inherited)
- `owasp_id`: String (Nullable, Inherited)
- `cwe_id`: String (Nullable, Inherited)
- `token_count`: Integer

---
*Note: `Finding`, `ChatSession`, `ChatMessage`, and `Report` tables are defined at the design level but are deferred until future milestones.*
