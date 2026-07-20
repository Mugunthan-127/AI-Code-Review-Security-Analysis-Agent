"""
Sample Python file with DELIBERATE security vulnerabilities and code quality issues.
Used for Milestone 2 validation accuracy testing.
Ground-truth issues documented in validation_ground_truth.md

DO NOT use this code in any real application.
"""
import os
import pickle
import subprocess
import sqlite3
import hashlib


# ─── Ground Truth Finding 1 ───────────────────────────────────────────────────
# Bandit B105 / CWE-798: Hardcoded password
# Expected: severity=high, owasp_type=Hardcoded Credentials, line ~15
# ─────────────────────────────────────────────────────────────────────────────
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-abc123-hardcoded-key"


def get_db_connection():
    conn = sqlite3.connect("app.db")
    return conn


# ─── Ground Truth Finding 2 ───────────────────────────────────────────────────
# Bandit B608 / CWE-89: SQL Injection via string formatting
# Expected: severity=high, owasp_type=SQL Injection, line ~30
# ─────────────────────────────────────────────────────────────────────────────
def get_user_by_name(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    # VULNERABLE: direct string formatting in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


# ─── Ground Truth Finding 3 ───────────────────────────────────────────────────
# Bandit B602 / CWE-78: OS Command Injection
# Expected: severity=high, owasp_type=Command Injection, line ~44
# ─────────────────────────────────────────────────────────────────────────────
def list_directory(user_path):
    # VULNERABLE: shell=True with user-controlled input
    result = subprocess.run(f"ls -la {user_path}", shell=True, capture_output=True, text=True)
    return result.stdout


# ─── Ground Truth Finding 4 ───────────────────────────────────────────────────
# Bandit B301 / CWE-502: Unsafe Deserialization
# Expected: severity=high, owasp_type=Unsafe Deserialization, line ~54
# ─────────────────────────────────────────────────────────────────────────────
def load_user_session(session_bytes: bytes):
    # VULNERABLE: pickle.loads on untrusted data enables remote code execution
    return pickle.loads(session_bytes)


# ─── Ground Truth Finding 5 ───────────────────────────────────────────────────
# Bandit B303 / CWE-327: Use of weak/broken MD5 hash
# Expected: severity=high, owasp_type=Insecure Cryptography, line ~64
# ─────────────────────────────────────────────────────────────────────────────
def hash_password_insecure(password: str) -> str:
    # VULNERABLE: MD5 is cryptographically broken for password storage
    return hashlib.md5(password.encode()).hexdigest()


# ─── Ground Truth Finding 6 (Code Quality) ───────────────────────────────────
# Pylint W0102 / HIGH: Dangerous default mutable argument
# Expected: agent_source=code_analysis, severity=high, line ~73
# ─────────────────────────────────────────────────────────────────────────────
def add_permission(user, permissions=[]):   # noqa
    # DANGEROUS DEFAULT: mutable default is shared across all calls
    permissions.append(f"read:{user}")
    return permissions


# ─── Ground Truth Finding 7 (Code Quality) ───────────────────────────────────
# Pylint R0912 / MEDIUM: Too many branches (complexity)
# Expected: agent_source=code_analysis, severity=medium, line ~82
# ─────────────────────────────────────────────────────────────────────────────
def process_request(method, path, body, headers, auth, timeout, retry, cache,  # noqa
                    validate, compress, encrypt, sign, log, trace, debug):
    """Process an HTTP request — god function with excessive complexity."""
    if method == "GET":
        if auth:
            if validate:
                if cache:
                    if log:
                        pass
    elif method == "POST":
        if body:
            if encrypt:
                if sign:
                    if compress:
                        pass
    elif method == "PUT":
        if validate:
            if log:
                if trace:
                    pass
    elif method == "DELETE":
        if auth:
            if log:
                if debug:
                    pass
    elif method == "PATCH":
        if body:
            if validate:
                pass
    elif method == "OPTIONS":
        pass
    elif method == "HEAD":
        pass
    return None


# ─── Ground Truth Finding 8 (Code Quality) ───────────────────────────────────
# Pylint W0703 / HIGH: Broad exception catch
# Expected: agent_source=code_analysis, severity=high, line ~122
# ─────────────────────────────────────────────────────────────────────────────
def safe_divide(a, b):
    try:
        return a / b
    except Exception:   # noqa: broad-except — swallows ALL exceptions including KeyboardInterrupt
        return None


class UserAuthService:
    """Authentication service with multiple issues."""

    def __init__(self):
        self.users = {}
        # ─── Ground Truth Finding 9 ───────────────────────────────────────
        # Missing class docstring attributes initialized outside __init__
        self.failed_attempts = {}
        self.sessions = {}
        self.tokens = {}
        self.api_keys = {}

    def authenticate(self, username, password):
        # ─── Ground Truth Finding 10 (Code Quality) ───────────────────────
        # Pylint C0116 / LOW: Missing function docstring
        if username in self.users:
            stored = self.users[username]
            # VULNERABLE: plain text password comparison (no hashing)
            if stored == password:
                return True
        return False
