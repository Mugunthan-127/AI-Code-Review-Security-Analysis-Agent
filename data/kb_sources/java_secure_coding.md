# Java Secure Coding Guidelines (CWE-89, CWE-22, CWE-502, CWE-79)

## Overview
Java-specific security best practices addressing SQL injection, XSS, insecure deserialization,
path traversal, XML vulnerabilities, and improper exception handling in Java applications.

---

## SQL Injection in Java (CWE-89)

### Vulnerable JDBC Usage
```java
// DANGEROUS: String concatenation creates SQL injection vulnerability
public User findUser(String username) throws SQLException {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);  // Attacker input: ' OR '1'='1
    // ...
}
```

### Secure PreparedStatement Usage
```java
// SAFE: Always use PreparedStatement with bind parameters
public User findUser(String username) throws SQLException {
    String sql = "SELECT * FROM users WHERE username = ?";
    PreparedStatement stmt = connection.prepareStatement(sql);
    stmt.setString(1, username);  // Input is safely escaped
    ResultSet rs = stmt.executeQuery();
    // ...
}
```

### JPA / Hibernate Named Parameters (Preferred)
```java
// SAFE: Named parameters in HQL
String hql = "FROM User WHERE username = :username";
Query query = session.createQuery(hql);
query.setParameter("username", username);
List<User> users = query.list();
```

---

## Cross-Site Scripting (XSS) in Java Web Apps (CWE-79)

### Vulnerable JSP/Servlet
```java
// DANGEROUS: Directly outputting user input to HTML
String userInput = request.getParameter("name");
out.println("<h1>Hello " + userInput + "</h1>");  // Attacker: <script>alert('xss')</script>
```

### Secure Output Encoding
```java
// SAFE: Always HTML-encode output
import org.apache.commons.text.StringEscapeUtils;
String userInput = request.getParameter("name");
String safe = StringEscapeUtils.escapeHtml4(userInput);
out.println("<h1>Hello " + safe + "</h1>");
// Or use OWASP Java Encoder library:
// out.println("<h1>Hello " + Encode.forHtml(userInput) + "</h1>");
```

---

## Insecure Deserialization (CWE-502)

Java's native deserialization mechanism is highly dangerous with untrusted data.

### Vulnerable Code
```java
// DANGEROUS: Deserializing untrusted bytes
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Can trigger gadget chains for RCE!
```

### Secure Alternatives
```java
// OPTION 1: Use JSON with Jackson (with type restrictions)
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NONE);  // Disable polymorphic typing
MyClass obj = mapper.readValue(jsonString, MyClass.class);

// OPTION 2: Implement a look-ahead ObjectInputStream to allowlist classes
// OPTION 3: Use serialization frameworks that are not vulnerable (Protocol Buffers, Avro)
```

---

## Path Traversal in Java (CWE-22)

### Vulnerable Code
```java
// DANGEROUS: Using user input directly in file paths
String filename = request.getParameter("file");
File file = new File("/var/uploads/" + filename);
FileInputStream fis = new FileInputStream(file);  // ../../etc/passwd
```

### Secure Code
```java
// SAFE: Canonicalize and validate the path
String filename = request.getParameter("file");
File baseDir = new File("/var/uploads/").getCanonicalFile();
File targetFile = new File(baseDir, filename).getCanonicalFile();

// Ensure the canonical path starts with the base directory
if (!targetFile.getPath().startsWith(baseDir.getPath() + File.separator)) {
    throw new SecurityException("Path traversal detected");
}
FileInputStream fis = new FileInputStream(targetFile);
```

---

## XML External Entity (XXE) in Java (CWE-611)

### Vulnerable Code
```java
// DANGEROUS: Default DocumentBuilder allows XXE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(untrustedXML);  // XXE attack possible
```

### Secure Code
```java
// SAFE: Disable external entity processing
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

---

## Improper Exception Handling (CWE-209)

### Vulnerable Code
```java
// DANGEROUS: Exposing stack traces and internal details to users
try {
    processRequest(input);
} catch (Exception e) {
    response.getWriter().println("Error: " + e.getMessage());  // May expose internals
    e.printStackTrace();  // Logs sensitive stack trace information
}
```

### Secure Code
```java
// SAFE: Log internally, show generic message to user
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

private static final Logger logger = LoggerFactory.getLogger(MyClass.class);

try {
    processRequest(input);
} catch (Exception e) {
    logger.error("Error processing request for user {}: {}", userId, e.getMessage(), e);
    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred");
}
```

---

## Hardcoded Passwords and Keys in Java (CWE-798)

### Vulnerable
```java
// DANGEROUS: Hardcoded credentials
private static final String DB_PASSWORD = "admin123";
private static final String JWT_SECRET = "my-super-secret-key";
DriverManager.getConnection(url, "root", "hardcoded_password");
```

### Secure
```java
// SAFE: Read from environment variables or a secrets vault
String dbPassword = System.getenv("DB_PASSWORD");
String jwtSecret = System.getenv("JWT_SECRET");
if (dbPassword == null || jwtSecret == null) {
    throw new IllegalStateException("Required environment variables not set");
}
```

---

## Input Validation Best Practices

```java
// Use Bean Validation (JSR-380) for declarative validation
public class UserInput {
    @NotNull
    @Size(min = 1, max = 50)
    @Pattern(regexp = "^[a-zA-Z0-9_]+$")  // Only alphanumeric and underscore
    private String username;

    @Email
    private String email;

    @Min(0) @Max(150)
    private int age;
}
```

## References
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Java Security Cheat Sheet
- Oracle Secure Coding Guidelines for Java SE
