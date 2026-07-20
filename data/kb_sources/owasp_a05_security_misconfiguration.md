# OWASP A05:2021 — Security Misconfiguration

**Category:** Security Misconfiguration  
**OWASP ID:** A05  
**CWE References:** CWE-16, CWE-611

## Overview

Moving up from #6 in the previous edition, 90% of applications were tested for some form of misconfiguration, with an average incidence rate of 4.%, and over 208k occurrences of CWEs were noted in this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up. Notable CWEs included are CWE-16 Configuration and CWE-611 Improper Restriction of XML External Entity Reference.

## Common Security Misconfigurations

- Missing appropriate security hardening across any part of the application stack or improperly configured permissions on cloud services.
- Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
- Default accounts and their passwords are still enabled and unchanged.
- Error handling reveals stack traces or other overly informative error messages to users.
- For upgraded systems, the latest security features are disabled or not configured securely.
- The security settings in the application servers, application frameworks (e.g., Struts, Spring, ASP.NET), libraries, databases, etc., are not set to secure values.
- The server does not send security headers or directives, or they are not set to secure values.
- The software is out of date or vulnerable.

## Prevention

A secure installation process should be implemented, including:
- A repeatable hardening process makes it fast and easy to deploy another environment that is properly locked down.
- A minimal platform without any unnecessary features, components, documentation, and samples.
- A task to review and update the configurations appropriate to all security notes, updates, and patches as part of the patch management process.
- A segmented application architecture that provides effective and secure separation between components or tenants, with segmentation, containerization, or cloud security groups.
- Sending security directives to clients, e.g., Security Headers.
- An automated process to verify the effectiveness of the configurations and settings in all environments.

## Security Headers

HTTP Security Headers are a critical part of web application security:

### Content-Security-Policy (CSP)
Prevents XSS and data injection attacks:
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none';
```

### HTTP Strict Transport Security (HSTS)
Forces HTTPS connections:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### X-Frame-Options
Prevents clickjacking:
```
X-Frame-Options: DENY
```

### X-Content-Type-Options
Prevents MIME sniffing:
```
X-Content-Type-Options: nosniff
```

### Referrer-Policy
Controls information in Referer header:
```
Referrer-Policy: strict-origin-when-cross-origin
```

### Permissions-Policy
Restricts browser features:
```
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Python/Flask Security Configuration

```python
from flask import Flask
from flask_talisman import Talisman  # pip install flask-talisman

app = Flask(__name__)

# Apply security headers automatically
talisman = Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
        'img-src': "'self' data:",
        'frame-ancestors': "'none'"
    }
)

# Debug mode must be DISABLED in production
app.config['DEBUG'] = False  # NEVER True in production
app.config['TESTING'] = False

# Secret key must be strong and random
import secrets
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
```

## FastAPI Security Configuration

```python
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(
    # Remove docs in production
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc",
    openapi_url=None if os.getenv("ENV") == "production" else "/openapi.json",
)

# HTTPS redirect in production
if os.getenv("ENV") == "production":
    app.add_middleware(HTTPSRedirectMiddleware)

# Trusted host validation
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["api.example.com", "www.api.example.com"]
)
```

## Java Spring Boot Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Security headers
            .headers()
                .frameOptions().deny()                    // X-Frame-Options: DENY
                .contentTypeOptions()                     // X-Content-Type-Options: nosniff
                .httpStrictTransportSecurity()            // HSTS
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                    .and()
                .contentSecurityPolicy("default-src 'self'")
                .and()
            // Session management
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // For REST APIs
                .and()
            // Disable default login form if using JWT
            .formLogin().disable()
            .httpBasic().disable();
    }
}
```

## Default Credentials Check

Applications must change all default credentials before deployment:

```python
# Environment-based credential validation at startup
def validate_credentials_not_default():
    dangerous_defaults = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("user", "user"),
    ]
    
    configured_user = os.environ.get("ADMIN_USERNAME", "admin")
    configured_pass = os.environ.get("ADMIN_PASSWORD", "admin")
    
    for (default_user, default_pass) in dangerous_defaults:
        if configured_user == default_user and configured_pass == default_pass:
            raise ValueError(
                f"Default credentials detected! Change ADMIN_USERNAME and ADMIN_PASSWORD "
                f"before deploying to production."
            )
```

## Error Handling — Don't Leak Stack Traces

```python
# FastAPI — Generic error responses in production
from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log full details server-side
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Return generic message to client (no stack trace)
    if os.getenv("ENV") == "production":
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred."}
        )
    else:
        # In development, return more info
        return JSONResponse(
            status_code=500,
            content={"detail": str(exc)}
        )
```

## References
- OWASP Top 10 A05:2021 — https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- OWASP Security Headers — https://owasp.org/www-project-secure-headers/
- CWE-16: Configuration
- CWE-611: XML External Entity Reference
