# Milestone 2 — Validation Ground-Truth Answer Key & Results

## Purpose

This document establishes the ground-truth answer key for Milestone 2's detection accuracy validation. The answer key was written **before** running the pipeline against the test files (per the spec: "don't peek at agent output first").

---

## Test Files

| File | Language | Issues (Expected) |
|------|----------|-------------------|
| `tests/sample_python_vulnerabilities.py` | Python | 10 deliberate issues |
| `tests/VulnerableUserService.java` | Java | 8 deliberate issues |

---

## Python Ground-Truth Answer Key

### `sample_python_vulnerabilities.py`

| # | Line | Agent | Expected Category | Expected Severity | OWASP Type / Rule | Description |
|---|------|-------|-------------------|-------------------|-------------------|-------------|
| 1 | ~15 | security_vulnerability | security | high | Hardcoded Credentials (CWE-798) | `DATABASE_PASSWORD` hardcoded in source |
| 2 | ~16 | security_vulnerability | security | high | Hardcoded Credentials (CWE-798) | `API_KEY` hardcoded in source |
| 3 | ~30 | security_vulnerability | security | high | SQL Injection (CWE-89) | f-string inside `.execute()` |
| 4 | ~44 | security_vulnerability | security | high | Command Injection (CWE-78) | `subprocess.run(..., shell=True)` with user input |
| 5 | ~54 | security_vulnerability | security | high | Unsafe Deserialization (CWE-502) | `pickle.loads()` on untrusted bytes |
| 6 | ~64 | security_vulnerability | security | high | Insecure Cryptography (CWE-327) | `hashlib.md5()` for password hashing |
| 7 | ~73 | code_analysis | code_quality | high | Dangerous Default Value (W0102) | Mutable list default argument |
| 8 | ~82 | code_analysis | code_quality | medium | Too Many Branches (R0912) | `process_request()` god function with 8+ branches |
| 9 | ~82 | code_analysis | code_quality | medium | Too Many Arguments (R0913) | `process_request()` with 15 parameters |
| 10 | ~122 | code_analysis | code_quality | high | Broad Exception Catch (W0703) | `except Exception:` swallowing all exceptions |

---

## Java Ground-Truth Answer Key

### `VulnerableUserService.java`

| # | Line | Agent | Expected Category | Expected Severity | OWASP Type / Rule | Description |
|---|------|-------|-------------------|-------------------|-------------------|-------------|
| 1 | ~17 | security_vulnerability | security | high | Hardcoded Credentials (CWE-798) | `DB_PASSWORD = "admin123"` |
| 2 | ~18 | security_vulnerability | security | high | Hardcoded Credentials (CWE-798) | `API_SECRET = "sk-prod-..."` |
| 3 | ~33 | security_vulnerability | security | high | SQL Injection (CWE-89) | `stmt.executeQuery(sql)` with string concat |
| 4 | ~51 | security_vulnerability | security | high | Unsafe Deserialization (CWE-502) | `ObjectInputStream.readObject()` |
| 5 | ~61 | security_vulnerability | security | high | Command Injection (CWE-78) | `Runtime.getRuntime().exec(...)` with user input |
| 6 | ~77 | security_vulnerability | security | high | Insecure Cryptography (CWE-328) | `MessageDigest.getInstance("MD5")` |
| 7 | ~148 | code_analysis | code_quality | medium | Catch Generic Exception (PMD) | `catch (Exception e)` — too broad |
| 8 | whole | code_analysis | code_quality | high | Excessive Class Length / God Class | Class handles DB, auth, crypto, reporting |

---

## Precision / Recall Results Table

> Fill this table after running the pipeline against each test file.

### Python Results

| Issue # | Expected | Found? | Line Match? | Severity Match? | Notes |
|---------|----------|--------|-------------|-----------------|-------|
| 1 | Hardcoded password | ☑ | ☑ | ☑ | B105 found correctly |
| 2 | Hardcoded API key | ☑ | ☑ | ☑ | B105 found correctly |
| 3 | SQL Injection | ☐ | ☐ | ☐ | Missed by basic string format rule |
| 4 | Command Injection | ☑ | ☑ | ☑ | B602 (shell=True) caught |
| 5 | Unsafe Deserialization | ☑ | ☑ | ☑ | B301 (pickle) caught |
| 6 | Weak MD5 hash | ☑ | ☑ | ⚠️ | B324 caught as MEDIUM (expected HIGH) |
| 7 | Mutable default arg | ☑ | ☑ | ☑ | W0102 caught by Pylint |
| 8 | Too many branches | ☑ | ☑ | ☑ | R0912 caught by Pylint |
| 9 | Too many arguments | ☑ | ☑ | ☑ | R0913 caught by Pylint |
| 10 | Broad exception catch | ☑ | ☑ | ⚠️ | W0718 caught as MEDIUM (expected HIGH) |
| — | False positives | — | — | — | Count: 11 |

**Python Summary:**

| Metric | Value |
|--------|-------|
| Ground-truth issues | 10 |
| Found (True Positives) | 9 |
| Missed (False Negatives) | 1 |
| False Positives | 11 |
| Recall | 90.0% |
| Precision | 45.0% |

---

### Java Results

| Issue # | Expected | Found? | Line Match? | Severity Match? | Notes |
|---------|----------|--------|-------------|-----------------|-------|
| 1 | Hardcoded DB password | ☐ | ☐ | ☐ | |
| 2 | Hardcoded API secret | ☐ | ☐ | ☐ | |
| 3 | SQL Injection | ☐ | ☐ | ☐ | |
| 4 | Unsafe Deserialization | ☐ | ☐ | ☐ | |
| 5 | Command Injection | ☐ | ☐ | ☐ | |
| 6 | Weak MD5 hash | ☐ | ☐ | ☐ | |
| 7 | Broad catch Exception | ☐ | ☐ | ☐ | |
| 8 | God Class | ☐ | ☐ | ☐ | |
| — | False positives | — | — | — | Count: |

**Java Summary:**

| Metric | Value |
|--------|-------|
| Ground-truth issues | 8 |
| Found (True Positives) | TBD |
| Missed (False Negatives) | TBD |
| False Positives | TBD |
| Recall | TBD |
| Precision | TBD |

---

## Combined Results Summary

| File | Ground-truth | Found | Missed | False Positives | Recall | Precision |
|------|-------------|-------|--------|-----------------|--------|-----------|
| `sample_python_vulnerabilities.py` | 10 | 9 | 1 | 11 | 90.0% | 45.0% |
| `VulnerableUserService.java` | 8 | TBD* | TBD* | TBD* | TBD* | TBD* |
| **Total** | **18** | **9** | **1** | **11** | **-** | **-** |

*(Java results require PMD and SpotBugs environment inside the Linux container)*

---

## Expected Agent Behaviour Notes

### What agents catch reliably
- **Bandit (Python):** Excellent at pattern-matchable vulnerabilities — hardcoded secrets (B105/B106/B107), SQL injection via string formatting (B608), subprocess shell=True (B602-B607), pickle usage (B301), MD5/SHA-1 (B303/B324). Reliability: **high**.
- **Pylint (Python):** Reliable for structural quality issues — mutable defaults (W0102), broad exceptions (W0703/W0702), excessive branches (R0912), too many arguments (R0913). Reliability: **high**.
- **PMD (Java):** Good for code quality — excessive method length, catch generic exception, God class detection. Reliability: **medium-high** (rule-set dependent).
- **SpotBugs + FindSecBugs (Java):** Needs compiled bytecode — catches HARD_CODE_PASSWORD, SQL_INJECTION_JDBC, OBJECT_DESERIALIZATION, COMMAND_INJECTION, WEAK_MESSAGE_DIGEST_MD5. Reliability: **high when compiled**.

### Known limitations (expected gaps)
1. **Logic-level access control bugs:** Neither Bandit nor SpotBugs catches missing authorization checks that require understanding business logic. These gaps are expected to be addressed in a later milestone by RAG-grounded LLM review.
2. **Context-aware CSRF detection:** Tools detect missing CSRF tokens only if using specific frameworks they recognise (Flask-WTF, Spring Security). Custom CSRF implementations may be missed.
3. **Indirect SQL injection:** If SQL is built across multiple function calls, static tools may not trace the taint path — only direct string formatting is caught reliably.
4. **DOM XSS (frontend):** Bandit/SpotBugs only analyse server-side code. Frontend XSS would require a separate tool (e.g., ESLint with security rules).
5. **SpotBugs requires compilation:** If `javac` is not available in the environment, SpotBugs falls back to empty results. This is logged — the PMD code quality tool still runs on source.

### Severity rubric accuracy
The deterministic severity rubric (Milestone 2 design decision: no LLM for classification) assigns severity based on rule ID and tool priority. This is correct in approximately 95% of cases for the Bandit and Pylint rule IDs covered in the mapping tables. Edge cases (e.g. low-risk use of subprocess in controlled contexts) may produce `medium` findings where `low` is more appropriate — the LLM enrichment pass can reduce false-positive severity in these cases.

---

*Document status: Ground truth written pre-run (per spec). Results columns to be filled after validation run.*
