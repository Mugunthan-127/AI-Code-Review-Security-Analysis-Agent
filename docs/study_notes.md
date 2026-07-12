# Milestone 1 Study Notes

## 1. OWASP Top 10 Summary
The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.

1. **A01:2021-Broken Access Control**: Restrictions on what authenticated users are allowed to do are not properly enforced.
2. **A02:2021-Cryptographic Failures**: Failures related to cryptography (or lack thereof), leading to sensitive data exposure.
3. **A03:2021-Injection**: Untrusted data sent to an interpreter as part of a command or query. E.g., SQL Injection, OS Command Injection.
4. **A04:2021-Insecure Design**: Missing or ineffective control design.
5. **A05:2021-Security Misconfiguration**: Insecure default settings, incomplete or ad hoc configurations, open cloud storage.
6. **A06:2021-Vulnerable and Outdated Components**: Using components with known vulnerabilities.
7. **A07:2021-Identification and Authentication Failures**: Improper confirmation of user identity, authentication, and session management.
8. **A08:2021-Software and Data Integrity Failures**: Code and infrastructure that does not protect against integrity violations (e.g., CI/CD pipelines without validation).
9. **A09:2021-Security Logging and Monitoring Failures**: Without logging and monitoring, breaches cannot be detected.
10. **A10:2021-Server-Side Request Forgery (SSRF)**: Fetching a remote resource without validating the user-supplied URL.

## 2. CWE Top 25 Detectability Notes
The Common Weakness Enumeration (CWE) Top 25 highlights the most dangerous software errors. From a static code analysis perspective, these are highly detectable using AST parsing and semantic searches:
- **CWE-79 (Cross-site Scripting)**: Often detected by finding unsanitized outputs rendered in templates.
- **CWE-89 (SQL Injection)**: Detectable by looking for string concatenation in SQL execution methods instead of parameterized queries.
- **CWE-22 (Path Traversal)**: Detectable by finding user input being concatenated to file paths (e.g., `open(input_dir + user_file)`).
- **CWE-78 (OS Command Injection)**: Detectable by tracing user input to functions like `os.system()` or `subprocess.run(..., shell=True)`.

*Note for AI Agents:* LLMs have high accuracy in identifying these patterns in code snippets if prompted with the exact CWE definitions via RAG.

## 3. RAG Primer Notes
Retrieval-Augmented Generation (RAG) is an architectural pattern that improves LLM generation by providing it with external knowledge.
- **Ingestion**: Raw documents (OWASP PDFs, Markdown guides) are parsed and split into smaller "chunks" (300-500 tokens).
- **Embedding**: A model (e.g. `text-embedding-3-small` or `all-MiniLM-L6-v2`) converts each chunk into a dense vector representing its semantic meaning.
- **Storage**: Vectors are stored in a database optimized for similarity search (e.g., PostgreSQL with `pgvector`).
- **Retrieval**: When a query is made, it is embedded using the same model. The database performs a cosine-similarity search to find the closest matching chunks.
- **Generation**: The retrieved chunks are appended to the LLM prompt as context.
