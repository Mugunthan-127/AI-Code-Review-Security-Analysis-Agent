# Architecture Diagram and Agent Responsibility Matrix (Milestone 1 Design)

## Architecture Diagram

```mermaid
graph TD
    subgraph Client
        UI[User Interface]
    end

    subgraph "Code Submission Module"
        API[FastAPI Backend]
        API --> V[Validation Service (ast, javalang)]
        V --> DB[(PostgreSQL)]
    end

    subgraph "RAG Pipeline Module"
        Ingest[Ingestion Script]
        Ingest --> Chunk[Chunker]
        Chunk --> Embed[Embedding Model]
        Embed --> PG[(pgvector)]
        Retrieve[Retrieve Function]
        PG --> Retrieve
    end

    subgraph "Future Agents (Deferred to M2+)"
        A1[Code Analysis Agent]
        A2[Security Vulnerability Agent]
        A3[Remediation Agent]
        A4[PR Summary Agent]
        A5[Conversational Code Assistant]
    end

    UI --> API
    Retrieve -.-> A1
    Retrieve -.-> A2
    Retrieve -.-> A5
```

## Agent Responsibility Matrix

*(Note: Agents are NOT implemented in Milestone 1, this is a design artifact)*

| Agent | Input | Process | Output |
|---|---|---|---|
| **Code Analysis Agent** | Validated AST/Code, user requirements | Analyzes code structure, logic flow, and adherence to clean code principles. | Code quality review comments, logic flaws. |
| **Security Vulnerability Agent** | Validated Code, chunks from RAG Pipeline | Identifies security flaws, matches against OWASP/CWE using retrieved RAG context. | Security findings with severity and CWE/OWASP references. |
| **Remediation Agent** | Security findings, raw code | Generates secure code replacements and patches for identified vulnerabilities. | Patch diffs, suggested fixed code blocks. |
| **PR Summary Agent** | All findings, patches, code diffs | Summarizes the review into a structured report for PR integration. | Markdown report, PR comments. |
| **Conversational Code Assistant** | User natural language queries, RAG context, scan context | Answers user queries about the code or security findings interactively. | Chat responses, ad-hoc explanations. |
