# CWE Top 25 Most Dangerous Software Weaknesses

**Category:** CWE Reference  
**Source:** MITRE CWE — https://cwe.mitre.org/top25/  
**Updated:** 2023 CWE Top 25 List

## Overview

The CWE Top 25 Most Dangerous Software Weaknesses is a demonstrative list of the most common and impactful issues experienced over the previous two calendar years. These weaknesses are dangerous because they are often easy to find, exploit, and can allow adversaries to completely take over a system, steal data, or prevent an application from working.

---

## Top 25 Weaknesses

### CWE-787 — Out-of-bounds Write (Rank 1)
Writing data past the end, or before the beginning, of the intended buffer. Allows attackers to execute arbitrary code.
- **Languages:** C/C++ primarily
- **Fix:** Always validate buffer boundaries before writes; use safe string functions.

### CWE-79 — Improper Neutralization of Input During Web Page Generation (XSS) (Rank 2)
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page that is served to other users.
- **Languages:** All web languages
- **Fix:** HTML-encode all user-supplied data before output; implement CSP headers.

### CWE-89 — SQL Injection (Rank 3)
The software constructs all or part of an SQL command using externally-influenced input that can modify the intended SQL command when sent to a downstream component that executes SQL commands.
- **Languages:** All languages with DB access
- **Fix:** Use parameterized queries and prepared statements; never concatenate user input into SQL.

```python
# Python — WRONG
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# Python — CORRECT
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
```

```java
// Java — WRONG
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
stmt.execute(sql);

// Java — CORRECT
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
pstmt.setString(1, username);
pstmt.executeQuery();
```

### CWE-416 — Use After Free (Rank 4)
Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.
- **Languages:** C/C++
- **Fix:** Set pointers to null after freeing; use smart pointers in C++.

### CWE-78 — OS Command Injection (Rank 5)
The software constructs all or part of an OS command using externally-influenced input that can modify the intended OS command.
- **Languages:** All languages
- **Fix:** Avoid shell=True; use process libraries with argument lists; validate and sanitize all input.

```python
# Python — WRONG
import subprocess
result = subprocess.run(f"ls {user_dir}", shell=True)  # Command injection risk

# Python — CORRECT
result = subprocess.run(["ls", user_dir], shell=False)  # Arguments as list
```

```java
// Java — WRONG
Runtime.getRuntime().exec("cmd /c dir " + userInput);

// Java — CORRECT
ProcessBuilder pb = new ProcessBuilder("ls", userInput);
pb.start();
```

### CWE-20 — Improper Input Validation (Rank 6)
The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to safely and correctly process the data.
- **Fix:** Validate type, length, format, and range; use allowlists over denylists; reject invalid input early.

### CWE-125 — Out-of-bounds Read (Rank 7)
The software reads data past the end, or before the beginning, of the intended buffer.
- **Languages:** C/C++
- **Fix:** Validate array/buffer indices; use safe memory access patterns.

### CWE-22 — Path Traversal (Rank 8)
The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize sequences within the pathname.
- **Fix:** Use realpath() or equivalent; validate paths are within expected directories; blocklist `../`.

```python
# Python — Path traversal prevention
import os

def safe_open(base_dir: str, filename: str):
    # Resolve the full path and ensure it's under base_dir
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if not full_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal attempt detected")
    return open(full_path)
```

### CWE-352 — Cross-Site Request Forgery (CSRF) (Rank 9)
The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.
- **Fix:** Use CSRF tokens; validate Origin/Referer headers; use SameSite cookie attribute.

```python
# Flask-WTF CSRF protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# All POST/PUT/DELETE forms automatically require CSRF token
# Include in templates: {{ form.csrf_token }}
```

### CWE-434 — Unrestricted Upload of File with Dangerous Type (Rank 10)
The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.
- **Fix:** Validate file type by content (magic bytes), not just extension; store uploads outside web root; use antivirus scanning.

```python
# Python — File type validation
import magic  # python-magic library

def validate_upload(file_data: bytes, allowed_types: list) -> bool:
    detected_type = magic.from_buffer(file_data, mime=True)
    return detected_type in allowed_types

# Usage
if not validate_upload(file.read(), ['image/jpeg', 'image/png']):
    raise ValueError("Invalid file type")
```

### CWE-287 — Improper Authentication (Rank 11)
When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.
- **Fix:** Use strong authentication mechanisms; implement MFA; never rely solely on client-supplied identity claims.

### CWE-476 — NULL Pointer Dereference (Rank 12)
A null pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash.
- **Fix:** Always check return values; validate pointers before use; use optional/nullable types correctly.

### CWE-502 — Deserialization of Untrusted Data (Rank 13)
The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.
- **Fix:** Never deserialize data from untrusted sources; use allowlists for deserializable classes; prefer JSON over binary serialization.

```python
# Python — WRONG
import pickle
data = pickle.loads(user_supplied_bytes)  # Remote code execution risk

# Python — CORRECT (use JSON for data exchange)
import json
data = json.loads(user_supplied_string)  # Safe for data; validate schema separately
```

```java
// Java — Unsafe deserialization
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Dangerous if inputStream from untrusted source

// Java — Use a whitelist filter
ObjectInputStream ois = new SafeObjectInputStream(inputStream, allowedClasses);
```

### CWE-190 — Integer Overflow or Wraparound (Rank 14)
The software performs a calculation that can produce an integer overflow or wraparound when the logic assumes that the resulting value will always be larger than the original value.
- **Fix:** Validate integer ranges before arithmetic; use checked arithmetic functions; be aware of type sizes.

### CWE-798 — Use of Hardcoded Credentials (Rank 15)
The software contains hardcoded credentials, such as a password or cryptographic key, that it uses for its own inbound authentication or for authentication with external components.
- **Fix:** Store credentials in environment variables or secrets managers; never commit credentials to source control.

### CWE-306 — Missing Authentication for Critical Function (Rank 16)
The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.
- **Fix:** Require authentication for all sensitive operations; implement proper access controls; use authorization middleware.

### CWE-862 — Missing Authorization (Rank 17)
The software performs a authorization check, but the check does not cover all critical code paths.
- **Fix:** Apply authorization checks at every sensitive code path; use middleware/decorators to enforce consistently; log authorization failures.

### CWE-94 — Code Injection (Rank 18)
The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.
- **Fix:** Never use eval() with user input; use parameterization; implement allowlists for dynamic code.

```python
# Python — WRONG
result = eval(user_expression)  # Code injection!

# Python — CORRECT
# Use ast.literal_eval for safe expression evaluation (literals only)
import ast
result = ast.literal_eval(user_expression)  # Safe for literals
```

### CWE-269 — Improper Privilege Management (Rank 19)
The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.
- **Fix:** Apply principle of least privilege; drop privileges as soon as elevated access is no longer needed.

### CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor (Rank 20)
The product exposes information to an actor that is not explicitly authorized to have access to that information.
- **Fix:** Log errors server-side; return generic messages to users; protect sensitive data at rest and in transit.

### CWE-400 — Uncontrolled Resource Consumption (Rank 21)
The software does not properly restrict the amount or velocity of input that it accepts, causing resource exhaustion.
- **Fix:** Implement rate limiting; set timeouts; validate input size limits; use circuit breakers.

### CWE-918 — Server-Side Request Forgery (SSRF) (Rank 22)
The web server receives a user-supplied URL and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.
- **Fix:** Validate URLs against allowlists; block internal IP ranges; use network segmentation.

```python
# Python — SSRF prevention
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = {"api.example.com", "cdn.example.com"}

def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.netloc not in ALLOWED_DOMAINS:
        return False
    try:
        # Block private/loopback addresses
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass  # Hostname, not IP — OK if domain is allowlisted
    return True
```

### CWE-611 — XML External Entity (XXE) Injection (Rank 23)
The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.
- **Fix:** Disable external entity processing in XML parsers; use less complex data formats like JSON.

```python
# Python — XXE prevention (defusedxml)
import defusedxml.ElementTree as ET  # Safe XML parsing
tree = ET.parse('file.xml')  # External entities disabled by default
```

```java
// Java — XXE prevention
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

### CWE-362 — Race Condition (Rank 24)
The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.
- **Fix:** Use proper locking mechanisms; use atomic operations; avoid TOCTOU (Time-of-Check-Time-of-Use) patterns.

### CWE-601 — URL Redirection to Untrusted Site (Open Redirect) (Rank 25)
A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.
- **Fix:** Use allowlists for redirect destinations; validate redirect URLs; avoid including raw user input in redirect targets.

---

## Summary Severity Table

| CWE | Name | OWASP Category | Severity |
|-----|------|----------------|----------|
| CWE-89 | SQL Injection | A03 Injection | Critical |
| CWE-79 | XSS | A03 Injection | High |
| CWE-78 | OS Command Injection | A03 Injection | Critical |
| CWE-798 | Hardcoded Credentials | A07 Auth Failures | High |
| CWE-502 | Unsafe Deserialization | A08 Data Integrity | Critical |
| CWE-22 | Path Traversal | A01 Access Control | High |
| CWE-352 — CSRF | Cross-Site Request Forgery | A01 Access Control | High |
| CWE-287 | Improper Authentication | A07 Auth Failures | High |
| CWE-918 | SSRF | A10 SSRF | High |
| CWE-200 | Sensitive Data Exposure | A02 Crypto Failures | Medium |

## References
- MITRE CWE Top 25 — https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html
- OWASP Top 10 — https://owasp.org/Top10/
- NIST NVD — https://nvd.nist.gov/
