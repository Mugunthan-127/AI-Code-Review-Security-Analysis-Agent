# Python Secure Coding Guidelines (CWE-20, CWE-22, CWE-502, CWE-676)

## Overview
Python-specific security best practices covering common vulnerabilities found
in Python applications: path traversal, insecure deserialization, dangerous built-ins,
improper input validation, and unsafe file operations.

---

## Path Traversal / Directory Traversal (CWE-22)

Path traversal vulnerabilities allow attackers to access files outside the intended directory
by using `../` sequences or absolute paths in user-supplied filenames.

### Vulnerable Example
```python
# DANGEROUS: User input used directly as file path
import os
filename = request.GET['filename']
filepath = os.path.join('/var/app/uploads/', filename)
with open(filepath, 'r') as f:  # attacker can pass: ../../etc/passwd
    return f.read()
```

### Secure Example
```python
# SAFE: Validate and canonicalize the path before use
import os

BASE_DIR = '/var/app/uploads/'

def safe_open(filename):
    # Remove any path separators from filename
    safe_name = os.path.basename(filename)
    # Build the full path and resolve to canonical form
    full_path = os.path.realpath(os.path.join(BASE_DIR, safe_name))
    # Ensure the resolved path is still within BASE_DIR
    if not full_path.startswith(os.path.realpath(BASE_DIR)):
        raise PermissionError("Path traversal detected")
    return open(full_path, 'r')
```

---

## Insecure Deserialization (CWE-502)

Python's `pickle` module can execute arbitrary code when deserializing untrusted data.

### Vulnerable Example
```python
# DANGEROUS: Deserializing user-controlled pickle data
import pickle
data = request.body  # attacker can craft malicious pickle bytes
obj = pickle.loads(data)  # Can execute arbitrary Python code!
```

### Secure Example
```python
# SAFE: Use JSON for data exchange, never pickle for untrusted data
import json
data = request.body
obj = json.loads(data)  # JSON cannot execute code

# If you must serialize complex objects, use a safe alternative
import marshmallow  # schema-based serialization with validation
```

---

## Dangerous Built-in Functions

### eval() and exec() — Never Use on Untrusted Input
```python
# DANGEROUS
user_input = request.GET['expr']
result = eval(user_input)    # Executes arbitrary Python
exec(user_input)             # Same danger
compile(user_input, '', 'exec')  # Also dangerous

# SAFE alternatives
import ast
value = ast.literal_eval(user_input)  # Only parses literals (strings, numbers, lists, etc.)
```

### __import__() and importlib
```python
# DANGEROUS: Dynamic import of user-controlled module name
module_name = request.GET['plugin']
module = __import__(module_name)  # Attacker can import os, subprocess, etc.

# SAFE: Allowlist approach
ALLOWED_PLUGINS = {'plugin_a', 'plugin_b', 'plugin_c'}
if module_name not in ALLOWED_PLUGINS:
    raise ValueError(f"Plugin {module_name} not allowed")
import importlib
module = importlib.import_module(f'plugins.{module_name}')
```

---

## Improper Input Validation (CWE-20)

### Integer Overflow / Type Confusion
```python
# DANGEROUS: No type checking
def divide(a, b):
    return a / b  # No validation — what if b is 0? or a string?

# SAFE: Explicit validation
def divide(a: float, b: float) -> float:
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        raise TypeError("Arguments must be numeric")
    if b == 0:
        raise ZeroDivisionError("Division by zero is not allowed")
    return a / b
```

### Open Redirect (CWE-601)
```python
# DANGEROUS: Redirect to user-supplied URL
redirect_url = request.GET['next']
return redirect(redirect_url)  # Attacker can redirect to phishing site

# SAFE: Validate that redirect stays on the same domain
from urllib.parse import urlparse, urljoin

def safe_redirect(url, host):
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc != host:
        return '/'  # Fall back to home page
    return url
```

---

## Insecure File Operations

### Temporary Files (CWE-377)
```python
# DANGEROUS: Predictable temp file names
import os
tmpfile = '/tmp/myapp_' + str(os.getpid())  # Predictable, race condition risk

# SAFE: Use tempfile module
import tempfile
with tempfile.NamedTemporaryFile(delete=True) as f:
    f.write(data)
    # File is automatically deleted when closed
```

### File Permission Issues
```python
# DANGEROUS: Created files are world-readable by default
open('sensitive_data.txt', 'w').write(data)

# SAFE: Set restrictive permissions
import os
fd = os.open('sensitive_data.txt', os.O_WRONLY | os.O_CREAT, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(data)
```

---

## XML External Entity (XXE) Injection (CWE-611)

```python
# DANGEROUS: Default XML parsers may resolve external entities
from xml.etree import ElementTree as ET
tree = ET.parse(user_uploaded_xml)  # May be vulnerable to XXE

# SAFE: Use defusedxml which disables dangerous XML features
import defusedxml.ElementTree as ET
tree = ET.parse(user_uploaded_xml)  # Safe — external entities disabled
```

---

## Server-Side Template Injection (SSTI) (CWE-94)

```python
# DANGEROUS: Rendering user input as a Jinja2 template
from jinja2 import Template
template_str = request.GET['template']
template = Template(template_str)  # Attacker can execute: {{ ''.__class__.__mro__[1].__subclasses__() }}
result = template.render()

# SAFE: Never render user input as a template
# Sanitize input or use template variables instead
template = Template("Hello {{ name }}!")
result = template.render(name=user_input)  # Safe — user input is a variable, not code
```

## References
- CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- CWE-502 Insecure Deserialization: https://cwe.mitre.org/data/definitions/502.html
- Python Security: https://docs.python.org/3/library/security_warnings.html
- OWASP Python Security Cheat Sheet
