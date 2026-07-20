# Secure Authentication & Session Management Cheat Sheet

**Category:** Authentication  
**OWASP ID:** A07  
**CWE References:** CWE-287, CWE-306, CWE-384, CWE-521, CWE-613, CWE-620

## Authentication Fundamentals

Authentication is the process of verifying that an individual, entity, or website is who they claim to be. Proper authentication is fundamental to application security.

## Password Security

### Password Hashing Standards

Use memory-hard, adaptive hashing algorithms. Never use MD5, SHA-1, or unsalted SHA-256 for passwords:

| Algorithm | Recommended | Notes |
|-----------|-------------|-------|
| Argon2id | ✅ Best | Winner of Password Hashing Competition |
| bcrypt | ✅ Good | Cost factor should be ≥12 |
| scrypt | ✅ Good | Good for high-memory systems |
| PBKDF2 | ✅ Acceptable | Use with SHA-256, ≥310,000 iterations |
| SHA-256 (unsalted) | ❌ Never | Rainbow table attacks |
| MD5 | ❌ Never | Broken, trivially cracked |
| SHA-1 | ❌ Never | Deprecated, unsafe |

```python
# Python — Argon2 (best choice)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    try:
        ph.verify(stored_hash, password)
        return True
    except Exception:
        return False

# Python — bcrypt (good alternative)
import bcrypt

def hash_password_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)  # Cost factor 12+
    return bcrypt.hashpw(password.encode(), salt).decode()
```

```java
// Java — BCrypt with Spring Security
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hashedPassword = encoder.encode(rawPassword);
boolean isMatch = encoder.matches(rawPassword, hashedPassword);
```

## Multi-Factor Authentication (MFA)

### TOTP Implementation

```python
# Python — TOTP with pyotp
import pyotp
import qrcode

def generate_mfa_secret(user_id: str) -> str:
    secret = pyotp.random_base32()
    # Store secret encrypted in DB associated with user
    return secret

def generate_qr_code(secret: str, user_email: str, app_name: str) -> str:
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user_email, issuer_name=app_name)
    return provisioning_uri

def verify_totp(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    # valid_window=1 allows 30 seconds of clock skew
    return totp.verify(token, valid_window=1)
```

## Session Management

### Secure Session Configuration

```python
# Flask secure session configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY'),        # Cryptographically random key
    SESSION_COOKIE_HTTPONLY=True,                    # JavaScript cannot access cookie
    SESSION_COOKIE_SECURE=True,                      # HTTPS only
    SESSION_COOKIE_SAMESITE='Lax',                   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30) # 30-minute idle timeout
)
```

### Session Fixation Prevention

Always regenerate the session ID after authentication:

```python
# Flask — Session fixation prevention
from flask import session

@app.route('/login', methods=['POST'])
def login():
    user = authenticate_user(request.form['username'], request.form['password'])
    if user:
        # Clear old session data and regenerate session ID
        session.clear()
        session['user_id'] = user.id
        session['authenticated'] = True
        # Flask automatically generates new session ID after session.clear()
        return redirect(url_for('dashboard'))
```

```java
// Java — Session fixation prevention
HttpSession oldSession = request.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();  // Destroy old session
}
HttpSession newSession = request.getSession(true);  // Create new session
newSession.setAttribute("userId", user.getId());     // Set attributes on new session
```

## Rate Limiting & Brute Force Protection

```python
# Python — Rate limiting with slowapi (FastAPI) or flask-limiter
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate(credentials.username, credentials.password, db)
    if not user:
        # Use consistent error message — don't reveal if username exists
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_token(user.id)}
```

### Account Lockout Strategy

```python
# Track failed attempts in Redis or DB
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

def check_lockout(username: str) -> bool:
    attempts = redis_client.get(f"login_attempts:{username}")
    if attempts and int(attempts) >= MAX_ATTEMPTS:
        return True  # Account locked
    return False

def record_failed_attempt(username: str):
    key = f"login_attempts:{username}"
    redis_client.incr(key)
    redis_client.expire(key, LOCKOUT_DURATION)  # Reset after lockout period

def clear_attempts(username: str):
    redis_client.delete(f"login_attempts:{username}")
```

## JWT Token Security

```python
# Python — Secure JWT handling
import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")  # Strong random key, at least 256 bits
ALGORITHM = "HS256"

def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),  # Short expiry
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
```

## Anti-Patterns to Avoid

```python
# WRONG — Timing attacks possible with == comparison
if stored_password == provided_password:  # Vulnerable to timing attacks
    login()

# CORRECT — Use constant-time comparison
import hmac
if hmac.compare_digest(stored_password.encode(), provided_password.encode()):
    login()
```

```python
# WRONG — Revealing whether username exists
if not user_exists(username):
    return "Username not found"  # User enumeration attack
if not password_correct(password):
    return "Wrong password"

# CORRECT — Generic error message
if not authenticate(username, password):
    return "Invalid credentials"  # Same message regardless of reason
```

## References
- OWASP Authentication Cheat Sheet
- OWASP Session Management Cheat Sheet  
- NIST SP 800-63b
- CWE-287, CWE-384, CWE-521, CWE-613
