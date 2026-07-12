# OWASP A02:2021 – Cryptographic Failures & Hardcoded Secrets (CWE-798, CWE-321, CWE-327, CWE-326)

## Overview
Cryptographic failures refer to weaknesses in how sensitive data is protected.
This includes weak encryption algorithms, hardcoded secrets, improper key management,
and transmission of data in cleartext. Previously known as "Sensitive Data Exposure."

---

## Hardcoded Credentials and Secrets (CWE-798, CWE-259)

One of the most dangerous and common vulnerabilities is embedding passwords, API keys,
tokens, or cryptographic keys directly in source code.

### Vulnerable Python Example
```python
# DANGEROUS: Hardcoded password and API key in source code
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "my_secret_jwt_token"

def connect_database():
    return psycopg2.connect(password="admin123", user="root")
```

### Secure Python Example
```python
# SAFE: Load secrets from environment variables
import os
DB_PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")
SECRET_TOKEN = os.getenv("SECRET_TOKEN")

if not all([DB_PASSWORD, API_KEY, SECRET_TOKEN]):
    raise RuntimeError("Missing required environment variables")
```

### Vulnerable Java Example
```java
// DANGEROUS: Hardcoded credentials
private static final String DB_PASSWORD = "admin123";
private static final String API_KEY = "secret-api-key-123";
String connectionUrl = "jdbc:mysql://localhost/db?password=hardcoded";
```

### Secure Java Example
```java
// SAFE: Read from environment or config service
String dbPassword = System.getenv("DB_PASSWORD");
String apiKey = System.getenv("API_KEY");
// Or use a secrets management system like HashiCorp Vault, AWS Secrets Manager
```

### Prevention Checklist
- Never commit passwords, tokens, or API keys to source control
- Use environment variables, `.env` files (excluded from git), or a secrets vault
- Scan your repository with tools like `gitleaks`, `trufflehog`, or GitHub secret scanning
- Rotate all secrets that have ever been committed to version control
- Use `.gitignore` to exclude config files containing secrets

---

## Weak Cryptographic Algorithms (CWE-327, CWE-328)

Using outdated or weak cryptographic algorithms makes encrypted data recoverable.

### Vulnerable Python Example
```python
# DANGEROUS: MD5 and SHA1 are cryptographically broken for security purposes
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # NEVER use MD5 for passwords
checksum = hashlib.sha1(data).hexdigest()  # SHA1 is deprecated for security

# DANGEROUS: DES is a broken cipher
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)  # DES has 56-bit key, trivially brute-forced
```

### Secure Python Example
```python
# SAFE: Use bcrypt, argon2, or scrypt for password hashing
import bcrypt
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode(), salt)

# SAFE: Use SHA-256+ for checksums
import hashlib
checksum = hashlib.sha256(data).hexdigest()

# SAFE: Use AES-256-GCM for symmetric encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
```

### Vulnerable Java Example
```java
// DANGEROUS: Weak algorithms
MessageDigest md = MessageDigest.getInstance("MD5");
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
```

### Secure Java Example
```java
// SAFE: Strong algorithms
MessageDigest md = MessageDigest.getInstance("SHA-256");
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// For passwords: use BCrypt
String hashed = BCrypt.hashpw(password, BCrypt.gensalt(12));
```

---

## Insecure Random Number Generation (CWE-338)

Using non-cryptographic random functions for security-sensitive operations.

### Vulnerable Python Example
```python
# DANGEROUS: random module is NOT cryptographically secure
import random
token = random.randint(100000, 999999)  # Predictable!
session_id = str(random.random())
```

### Secure Python Example
```python
# SAFE: Use secrets module for security-sensitive randomness
import secrets
token = secrets.token_urlsafe(32)     # Cryptographically secure token
otp = secrets.randbelow(1000000)      # Cryptographically secure integer
session_id = secrets.token_hex(16)    # 32-char hex string
```

---

## Transmission of Sensitive Data in Cleartext (CWE-319)

### Prevention Checklist
- Always use TLS 1.2+ for all network communications
- Never transmit passwords, tokens, or PII over HTTP
- Use HTTPS-only cookies with the `Secure` flag
- Disable older SSL/TLS versions (SSLv3, TLS 1.0, TLS 1.1)
- Implement HTTP Strict Transport Security (HSTS)

---

## Insecure Key Storage

### Vulnerable Example
```python
# DANGEROUS: Private key stored in code or unprotected file
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
```

### Secure Example
```python
# SAFE: Load key from secure location with proper permissions
with open("/etc/secrets/private.key", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
# File should have permissions 600 and be owned by the application user
```

## References
- OWASP Cryptographic Failures: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- CWE-798 Hardcoded Credentials: https://cwe.mitre.org/data/definitions/798.html
- CWE-327 Broken Crypto Algorithm: https://cwe.mitre.org/data/definitions/327.html
- NIST Cryptographic Standards and Guidelines
