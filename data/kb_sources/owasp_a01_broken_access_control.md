# OWASP A01:2021 – Broken Access Control & Path Traversal (CWE-22, CWE-284, CWE-285, CWE-639)

## Overview
Broken access control is the most commonly found vulnerability in web applications.
It occurs when restrictions on what authenticated users are allowed to do are
not properly enforced. Attackers can exploit these flaws to access unauthorized
functionality or data, such as other users' accounts, sensitive files, or admin functions.

---

## Path Traversal / Directory Traversal (CWE-22)

Path traversal allows attackers to read files outside the intended directory
by using `../` sequences, absolute paths, or URL-encoded variants like `%2e%2e%2f`.

### Common Attack Payloads
- `../../../../etc/passwd` — Read Unix password file
- `..\..\Windows\System32\config\SAM` — Windows SAM database
- `/proc/self/environ` — Environment variables (may contain secrets)
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd` — URL-encoded traversal

### Vulnerable Python Example
```python
# DANGEROUS
def serve_file(filename):
    path = f"/var/www/uploads/{filename}"
    return open(path).read()
# Attacker passes: ../../../../etc/passwd
```

### Secure Python Example
```python
# SAFE: Sanitize and canonicalize
import os
BASE = os.path.realpath("/var/www/uploads")

def serve_file(filename):
    # Strip path components from filename
    safe_name = os.path.basename(filename)
    full = os.path.realpath(os.path.join(BASE, safe_name))
    if not full.startswith(BASE + os.sep):
        raise PermissionError("Access denied")
    with open(full) as f:
        return f.read()
```

### Secure Java Example
```java
File base = new File("/var/www/uploads").getCanonicalFile();
File requested = new File(base, filename).getCanonicalFile();
if (!requested.getPath().startsWith(base.getPath())) {
    throw new SecurityException("Path traversal attempt blocked");
}
```

---

## Insecure Direct Object Reference (IDOR) (CWE-639)

IDOR occurs when internal implementation objects (database IDs, filenames, etc.)
are exposed to users without access control checks.

### Vulnerable Example
```python
# DANGEROUS: No authorization check — any user can view any order
@app.route('/order/<int:order_id>')
def get_order(order_id):
    order = db.query(Order).filter_by(id=order_id).first()
    return jsonify(order)
# Attacker increments order_id to access other users' orders
```

### Secure Example
```python
# SAFE: Always verify the resource belongs to the current user
@app.route('/order/<int:order_id>')
@login_required
def get_order(order_id):
    order = db.query(Order).filter_by(
        id=order_id,
        user_id=current_user.id  # Enforce ownership
    ).first()
    if not order:
        abort(403)  # Forbidden
    return jsonify(order)
```

---

## Missing Function Level Access Control (CWE-285)

### Vulnerable Example
```python
# DANGEROUS: Admin endpoint only hidden in UI, not protected server-side
@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    user_id = request.json['user_id']
    db.query(User).filter_by(id=user_id).delete()
    # No role check! Any authenticated user can call this
```

### Secure Example
```python
# SAFE: Enforce role-based access control
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.has_role('admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/delete-user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    user_id = request.json['user_id']
    db.query(User).filter_by(id=user_id).delete()
```

---

## Mass Assignment Vulnerability (CWE-915)

Occurs when user-controlled input is passed directly to model constructors
without filtering which fields are allowed to be set.

### Vulnerable Python Example
```python
# DANGEROUS: User can set any field including 'is_admin'
@app.route('/profile', methods=['PUT'])
def update_profile():
    data = request.json  # User sends: {"name": "John", "is_admin": true}
    current_user.update(**data)  # Sets is_admin=True!
```

### Secure Example
```python
# SAFE: Explicitly allowlist updatable fields
ALLOWED_FIELDS = {'name', 'email', 'bio', 'avatar_url'}

@app.route('/profile', methods=['PUT'])
def update_profile():
    data = request.json
    safe_data = {k: v for k, v in data.items() if k in ALLOWED_FIELDS}
    current_user.update(**safe_data)
```

---

## Privilege Escalation Prevention

### Principle of Least Privilege
- Grant users only the minimum access required for their role
- Use role-based access control (RBAC) or attribute-based access control (ABAC)
- Never trust client-side data for authorization decisions
- Log all access control failures for monitoring and alerting

### Secure Default Access
```python
# SAFE: Deny by default, allow explicitly
class Resource:
    def can_access(self, user):
        # Default: deny
        if not user.is_authenticated:
            return False
        # Explicit allow conditions
        if user.id == self.owner_id:
            return True
        if user.has_permission('resource.read'):
            return True
        return False  # Deny everything else
```

---

## File Upload Security

### Vulnerable Example
```python
# DANGEROUS: Accepting any file type and saving to web-accessible directory
file = request.files['upload']
file.save('/var/www/uploads/' + file.filename)
```

### Secure Example
```python
import os
import uuid
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
UPLOAD_DIR = '/var/private/uploads'  # NOT web-accessible

def save_upload(file):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File type {ext} not allowed")
    # Generate random filename to prevent path traversal
    safe_name = str(uuid.uuid4()) + ext
    file.save(os.path.join(UPLOAD_DIR, safe_name))
    return safe_name
```

## References
- OWASP Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
- OWASP Authorization Cheat Sheet
