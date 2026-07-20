# XSS — Cross-Site Scripting Prevention Cheat Sheet

**Category:** Cross-Site Scripting (XSS)  
**OWASP ID:** A03 (Injection)  
**CWE:** CWE-79 – Improper Neutralization of Input During Web Page Generation  

## Overview

Cross-Site Scripting (XSS) attacks are a type of injection in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser-side script, to a different end user.

## XSS Types

### Reflected XSS
Malicious script comes from the current HTTP request. The application receives user data in an HTTP request and includes it in the immediate response in an unsafe way.

### Stored XSS (Persistent XSS)
Malicious script comes from the website's database. The script is permanently stored on the target servers — in a database, message forum, visitor log, comment field, etc.

### DOM-Based XSS
The vulnerability exists in client-side code rather than server-side code. The malicious script modifies the DOM environment in the victim's browser.

## Prevention Rules

### Rule 1 — Never Insert Untrusted Data Except in Allowed Locations
Do not put untrusted data in script blocks, HTML attribute event handlers, CSS values, URLs, or HTML comments:

```html
<!-- WRONG — Do not inject data into these locations -->
<script>var x = "UNTRUSTED_DATA";</script>         <!-- script context -->
<div onclick="handler('UNTRUSTED_DATA')">           <!-- event handler attribute -->
<style>color: UNTRUSTED_DATA</style>               <!-- CSS value -->
<a href="UNTRUSTED_DATA">click</a>                 <!-- URL context -->
```

### Rule 2 — HTML-Encode Before Inserting into HTML Element Content

```python
# Python — Use html.escape()
import html
safe_output = html.escape(user_input)
# html.escape converts: & " < > ' to their HTML entities
```

```java
// Java — Use Apache Commons Text StringEscapeUtils or OWASP Java Encoder
import org.apache.commons.text.StringEscapeUtils;
String safe = StringEscapeUtils.escapeHtml4(userInput);

// Or OWASP Java Encoder (preferred)
import org.owasp.encoder.Encode;
String safe = Encode.forHtml(userInput);
```

### Rule 3 — Attribute-Encode Before Inserting into HTML Attributes
For untrusted data placed in HTML attributes (not event handlers or CSS):

```python
# Python
import html
safe_attr = html.escape(user_input, quote=True)
```

```java
// OWASP Java Encoder
String safeAttr = Encode.forHtmlAttribute(userInput);
```

### Rule 4 — JavaScript-Encode Before Inserting into JavaScript Data Values
Only put untrusted data into a quoted "data value" — never into executable code like function names or property names:

```python
# Python — JSON encode for JavaScript context
import json
# Outputs: "user_value"
safe_js_value = json.dumps(user_input)
```

```java
// OWASP Java Encoder
String safeJs = Encode.forJavaScript(userInput);
```

### Rule 5 — URL-Encode Before Inserting into HTML URL Parameter Values

```python
from urllib.parse import quote
safe_url_param = quote(user_input)
```

```java
import java.net.URLEncoder;
String safeParam = URLEncoder.encode(userInput, "UTF-8");
```

## Content Security Policy (CSP)

CSP is a defense-in-depth control that significantly reduces XSS impact. It restricts which scripts can execute:

```
# HTTP Response Header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none';
```

Key CSP directives:
- `default-src 'self'` — only allow resources from same origin by default
- `script-src 'self'` — no inline scripts, no eval()
- `object-src 'none'` — no Flash/plugins
- `base-uri 'self'` — prevent base tag injection

## Flask-Specific XSS Prevention

```python
from flask import Flask, render_template, request, escape, Markup

app = Flask(__name__)

# BAD — Using Markup() without sanitization allows XSS
@app.route('/bad')
def bad_route():
    user_input = request.args.get('name')
    return f"<p>Hello {user_input}</p>"  # XSS vulnerability

# GOOD — Jinja2 auto-escaping (default in render_template)
@app.route('/good')
def good_route():
    user_input = request.args.get('name')
    return render_template('hello.html', name=user_input)  # Auto-escaped

# Also good — manual escape
@app.route('/also-good')
def also_good():
    user_input = request.args.get('name')
    safe = escape(user_input)  # Flask's escape function
    return f"<p>Hello {safe}</p>"
```

## Spring/Java XSS Prevention

```java
// Use Thymeleaf (auto-escaping by default)
// th:text automatically escapes HTML
// <p th:text="${userInput}">Default text</p>

// HttpServletRequest — encode response output
response.setContentType("text/html; charset=UTF-8");
PrintWriter out = response.getWriter();
out.println("<p>" + Encode.forHtml(userInput) + "</p>");

// Never concatenate user input into HTML
// BAD:
out.println("<p>" + request.getParameter("name") + "</p>");

// GOOD:
out.println("<p>" + Encode.forHtml(request.getParameter("name")) + "</p>");
```

## DOM XSS Prevention

```javascript
// WRONG — DOM XSS sinks
document.innerHTML = userInput;        // Interprets HTML
element.outerHTML = userInput;         // Interprets HTML
document.write(userInput);             // Interprets HTML
eval(userInput);                       // Executes as code

// CORRECT — Safe DOM manipulation
element.textContent = userInput;       // Treats as text, not HTML
element.setAttribute('value', userInput);  // Safe attribute setting
```

## References
- OWASP XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP DOM XSS Prevention Cheat Sheet
- OWASP Java Encoder — https://owasp.org/www-project-java-encoder/
- CWE-79: Cross-Site Scripting
