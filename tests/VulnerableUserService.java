/**
 * Sample Java file with DELIBERATE security vulnerabilities and code quality issues.
 * Used for Milestone 2 validation accuracy testing.
 * Ground-truth issues documented in validation_ground_truth.md
 *
 * DO NOT use this code in any real application.
 */
import java.sql.*;
import java.io.*;
import java.util.*;
import java.security.MessageDigest;

public class VulnerableUserService {

    // ─── Ground Truth Finding 1 ─────────────────────────────────────────────
    // FindSecBugs HARD_CODE_PASSWORD / CWE-798: Hardcoded credential
    // Expected: severity=high, owasp_type=Hardcoded Credentials, line ~17
    // ────────────────────────────────────────────────────────────────────────
    private static final String DB_PASSWORD = "admin123";
    private static final String API_SECRET  = "sk-prod-hardcoded-secret-key";

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(
            "jdbc:postgresql://localhost:5432/appdb",
            "admin",
            DB_PASSWORD  // Using hardcoded credential
        );
    }

    // ─── Ground Truth Finding 2 ─────────────────────────────────────────────
    // FindSecBugs SQL_INJECTION_JDBC / CWE-89: SQL Injection via concatenation
    // Expected: severity=high, owasp_type=SQL Injection, line ~33
    // ────────────────────────────────────────────────────────────────────────
    public List<String> getUsersByRole(String role) throws SQLException {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        // VULNERABLE: String concatenation in SQL — SQL injection possible
        String sql = "SELECT username FROM users WHERE role = '" + role + "'";
        ResultSet rs = stmt.executeQuery(sql);
        List<String> users = new ArrayList<>();
        while (rs.next()) {
            users.add(rs.getString("username"));
        }
        return users;
    }

    // ─── Ground Truth Finding 3 ─────────────────────────────────────────────
    // FindSecBugs OBJECT_DESERIALIZATION / CWE-502: Unsafe deserialization
    // Expected: severity=high, owasp_type=Unsafe Deserialization, line ~51
    // ────────────────────────────────────────────────────────────────────────
    public Object loadSessionData(byte[] sessionBytes) throws Exception {
        // VULNERABLE: Java deserialization of untrusted bytes enables RCE
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(sessionBytes));
        return ois.readObject();
    }

    // ─── Ground Truth Finding 4 ─────────────────────────────────────────────
    // FindSecBugs COMMAND_INJECTION / CWE-78: OS Command Injection
    // Expected: severity=high, owasp_type=Command Injection, line ~61
    // ────────────────────────────────────────────────────────────────────────
    public String executeReport(String reportName) throws Exception {
        // VULNERABLE: Runtime.exec with user-controlled input
        Process p = Runtime.getRuntime().exec("generate_report.sh " + reportName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        return sb.toString();
    }

    // ─── Ground Truth Finding 5 ─────────────────────────────────────────────
    // FindSecBugs WEAK_MESSAGE_DIGEST_MD5 / CWE-328: Weak hashing algorithm
    // Expected: severity=high, owasp_type=Insecure Cryptography, line ~77
    // ────────────────────────────────────────────────────────────────────────
    public String hashPassword(String password) throws Exception {
        // VULNERABLE: MD5 is cryptographically broken for password storage
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes("UTF-8"));
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    // ─── Ground Truth Finding 6 (Code Quality) ──────────────────────────────
    // PMD GodClass / HIGH: Class with too many responsibilities
    // This entire class is a God Class — handles DB, auth, crypto, reporting
    // Expected: agent_source=code_analysis, severity=high
    // ────────────────────────────────────────────────────────────────────────

    // ─── Ground Truth Finding 7 (Code Quality) ──────────────────────────────
    // PMD ExcessiveMethodLength / MEDIUM: Overly long method
    // Expected: agent_source=code_analysis, severity=medium, line ~90
    // ────────────────────────────────────────────────────────────────────────
    public Map<String, Object> processUserRegistration(
            String username, String password, String email,
            String firstName, String lastName, String phone,
            String address, String country, String role) throws Exception {

        Map<String, Object> result = new HashMap<>();

        // Validate username
        if (username == null || username.isEmpty()) {
            result.put("error", "username required");
            return result;
        }
        if (username.length() < 3) {
            result.put("error", "username too short");
            return result;
        }
        if (username.length() > 50) {
            result.put("error", "username too long");
            return result;
        }

        // Validate password
        if (password == null || password.isEmpty()) {
            result.put("error", "password required");
            return result;
        }
        if (password.length() < 8) {
            result.put("error", "password too short");
            return result;
        }

        // Validate email
        if (email == null || !email.contains("@")) {
            result.put("error", "invalid email");
            return result;
        }

        // Hash password (still uses vulnerable MD5)
        String hashedPw = hashPassword(password);

        // Insert to database (still vulnerable to SQL injection)
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        String insertSql = "INSERT INTO users (username, password, email, first_name, last_name, phone, address, country, role) " +
                "VALUES ('" + username + "', '" + hashedPw + "', '" + email + "', '" +
                firstName + "', '" + lastName + "', '" + phone + "', '" + address + "', '" + country + "', '" + role + "')";
        stmt.executeUpdate(insertSql);

        result.put("success", true);
        result.put("username", username);
        return result;
    }

    // ─── Ground Truth Finding 8 (Code Quality) ──────────────────────────────
    // PMD AvoidCatchingGenericException / MEDIUM: Catching generic Exception
    // Expected: agent_source=code_analysis, severity=medium, line ~148
    // ────────────────────────────────────────────────────────────────────────
    public boolean validateUser(String username, String password) {
        try {
            List<String> users = getUsersByRole("admin");
            return users.contains(username);
        } catch (Exception e) {  // Too broad — catches everything
            return false;
        }
    }
}
