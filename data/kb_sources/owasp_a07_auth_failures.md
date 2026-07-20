# OWASP A07:2021 – Identification and Authentication Failures

**Category:** Authentication & Session Management  
**OWASP ID:** A07  
**CWE References:** CWE-287, CWE-295, CWE-297, CWE-307, CWE-384, CWE-521, CWE-613, CWE-620

## Overview

Previously known as Broken Authentication, this category slipped down from second place and now includes CWEs that are more related to identification failures. This category is still an integral part of the Top 10. Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.

## Common Weaknesses

Authentication weaknesses can lead to account takeovers, session hijacking, and credential theft:

- Permits automated attacks such as credential stuffing, where the attacker has a list of valid usernames and passwords.
- Permits brute force or other automated attacks.
- Permits default, weak, or well-known passwords, such as "Password1" or "admin/admin".
- Uses weak or ineffective credential recovery and forgot-password processes, such as "knowledge-based answers" which cannot be made safe.
- Uses plain text, encrypted, or weakly hashed passwords data stores.
- Has missing or ineffective multi-factor authentication.
- Exposes session identifier in the URL.
- Reuses session identifier after successful login.
- Does not correctly invalidate session IDs. User sessions or authentication tokens (mainly SSO tokens) are not properly invalidated during logout or a period of inactivity.

## Attack Scenarios

**Scenario 1 — Credential Stuffing:**  
Credential stuffing, the use of lists of known passwords, is a common attack. Suppose an application does not implement automated threat or credential stuffing protection. In that case, the application can be used as a password oracle to determine if the credentials are valid.

**Scenario 2 — Brute Force:**  
Most authentication attacks occur due to the continued use of passwords as a sole factor. Best practice, password rotation, and complexity requirements encourage users to use and reuse weak passwords. Organizations are recommended to stop these practices and use NIST 800-63b's guidelines.

**Scenario 3 — Session Fixation:**  
Application session timeouts aren't set correctly. A user uses a public computer to access an application. Instead of selecting "logout," the user simply closes the browser tab and walks away. An attacker uses the same browser an hour later, and the user is still authenticated.

## Prevention Strategies

### Password Management
- Store passwords using strong adaptive and salted hashing functions: bcrypt, scrypt, Argon2, or PBKDF2.
- Never store passwords in plain text or using weak hashing (MD5, SHA-1 without salt).
- Implement password length minimums (at least 8 characters; prefer 12+) with no arbitrary maximum below 64 characters.
- Allow paste functionality in password fields — prevents locking out password managers.
- Do not force periodic password changes unless there is evidence of compromise.

```python
# CORRECT — Use bcrypt for password hashing
import bcrypt

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed.encode('utf-8'))

# WRONG — Never use these approaches
import hashlib
bad_hash = hashlib.md5(password.encode()).hexdigest()       # MD5 — broken
bad_hash2 = hashlib.sha1(password.encode()).hexdigest()     # SHA-1 — broken  
bad_hash3 = hashlib.sha256(password.encode()).hexdigest()   # SHA-256 without salt — weak
plain_storage = password                                     # NEVER store plain text
```

### Session Management
- Generate new session identifiers after successful authentication (prevents session fixation).
- Use cryptographically random session IDs of at least 128 bits entropy.
- Invalidate session IDs completely on logout — server side, not just client side.
- Set appropriate session timeouts (idle: 15–30 min for sensitive apps).
- Use `HttpOnly` and `Secure` cookie flags.
- Use `SameSite=Strict` or `SameSite=Lax` to prevent CSRF.

```python
# Session cookie security (Flask example)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,        # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,   # 30 minutes
)
```

```java
// Java session security
HttpSession session = request.getSession(false);  // Don't create new if not exists
if (session != null) {
    session.invalidate();  // Invalidate old session
}
HttpSession newSession = request.getSession(true);  // Create fresh session after login
newSession.setMaxInactiveInterval(1800);  // 30 minutes
```

### Brute Force Protection
- Lock accounts or add delay after N failed attempts (e.g., 5 attempts → 15-minute lockout or CAPTCHA).
- Use rate limiting on login endpoints.
- Alert users and admins of brute force attempts.
- Implement multi-factor authentication (MFA) for all users, especially privileged accounts.

```python
# Rate limiting example (with Flask-Limiter)
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Max 5 login attempts per minute per IP
def login():
    ...
```

### Multi-Factor Authentication (MFA)
- Require MFA for sensitive operations (password change, fund transfer, admin actions).
- Support TOTP (Time-based One-Time Passwords) via apps like Google Authenticator.
- Avoid SMS-based MFA when possible (SIM-swapping attacks); prefer authenticator apps or hardware keys.

## Hardcoded Credentials Anti-Pattern

Never hardcode usernames, passwords, API keys, or tokens in source code:

```python
# WRONG — Never do this
DATABASE_PASSWORD = "supersecret123"
API_KEY = "sk-abc123xyz"
ADMIN_PASSWORD = "admin"

# CORRECT — Use environment variables or secrets manager
import os
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
API_KEY = os.environ.get("API_KEY")
# Or use a secrets manager like AWS Secrets Manager, HashiCorp Vault
```

```java
// WRONG
String dbPassword = "supersecret123";
String apiKey = "sk-abc123xyz";

// CORRECT
String dbPassword = System.getenv("DATABASE_PASSWORD");
String apiKey = System.getenv("API_KEY");
```

## References
- OWASP Top 10 A07:2021 — https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- NIST SP 800-63b — Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
- CWE-287: Improper Authentication
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-521: Weak Password Requirements
- CWE-613: Insufficient Session Expiration
