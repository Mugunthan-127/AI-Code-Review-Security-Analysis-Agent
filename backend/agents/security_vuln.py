"""
Security Vulnerability Agent — Milestone 2
Scans submitted code for OWASP-standard vulnerabilities.
Classifies each finding by OWASP type, CWE ID, severity, and exact location.
Uses RAG-grounded LLM enrichment to validate and explain each finding.
"""
import json
from typing import Dict, Any, List, Optional
from .state import ScanState
from services.python_analyzer import run_bandit, run_semgrep as run_python_semgrep
from services.java_analyzer import run_spotbugs, run_semgrep as run_java_semgrep
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from services.rag import retrieve
from database import SessionLocal


# ---------------------------------------------------------------------------
# OWASP Category Mapping Table
# Maps tool rule IDs → (owasp_type, cwe_id, severity_override)
# ---------------------------------------------------------------------------

# Bandit (Python) rule_id → (owasp_type, cwe_id, severity_override or None)
BANDIT_OWASP_MAP: Dict[str, tuple] = {
    # SQL Injection
    "B608": ("SQL Injection",            "CWE-89",  "high"),
    # Hardcoded Secrets / Credentials
    "B105": ("Hardcoded Credentials",    "CWE-798", "high"),
    "B106": ("Hardcoded Credentials",    "CWE-798", "high"),
    "B107": ("Hardcoded Credentials",    "CWE-798", "medium"),
    # Command Injection
    "B602": ("Command Injection",        "CWE-78",  "high"),
    "B603": ("Command Injection",        "CWE-78",  "medium"),
    "B604": ("Command Injection",        "CWE-78",  "high"),
    "B605": ("Command Injection",        "CWE-78",  "high"),
    "B606": ("Command Injection",        "CWE-78",  "medium"),
    "B607": ("Command Injection",        "CWE-78",  "medium"),
    # Path Traversal
    "B101": ("Insecure Code",            "CWE-703", "low"),   # assert statements
    "B404": ("Command Injection",        "CWE-78",  "low"),   # subprocess import
    # Unsafe Deserialization
    "B301": ("Unsafe Deserialization",   "CWE-502", "high"),  # pickle
    "B302": ("Unsafe Deserialization",   "CWE-502", "high"),  # marshal
    "B303": ("Insecure Cryptography",    "CWE-327", "high"),  # MD5/SHA1
    "B304": ("Insecure Cryptography",    "CWE-327", "high"),  # Ciphers
    "B305": ("Insecure Cryptography",    "CWE-327", "medium"),
    # Weak Cryptography
    "B321": ("Insecure Cryptography",    "CWE-327", "high"),  # FTP
    "B322": ("Insecure Code",            "CWE-78",  "high"),  # input() Python 2
    "B307": ("Code Injection",           "CWE-94",  "high"),  # eval
    "B102": ("Code Injection",           "CWE-94",  "high"),  # exec
    "B324": ("Insecure Cryptography",    "CWE-328", "medium"), # hashlib weak
    # XSS (Flask/Jinja)
    "B703": ("Cross-Site Scripting",     "CWE-79",  "high"),  # jinja2 autoescape off
    "B701": ("Cross-Site Scripting",     "CWE-79",  "high"),  # jinja2 autoescape
    # Insecure HTTP
    "B501": ("Broken Access Control",    "CWE-295", "high"),  # SSL verification disabled
    "B502": ("Broken Access Control",    "CWE-295", "high"),  # SSL allow all
    "B503": ("Broken Access Control",    "CWE-295", "medium"),
    "B504": ("Broken Access Control",    "CWE-295", "medium"),
    "B505": ("Insecure Cryptography",    "CWE-326", "high"),   # weak key
    # XML
    "B405": ("XML External Entities",    "CWE-611", "medium"),
    "B406": ("XML External Entities",    "CWE-611", "medium"),
    "B407": ("XML External Entities",    "CWE-611", "high"),
    "B408": ("XML External Entities",    "CWE-611", "high"),
    "B409": ("XML External Entities",    "CWE-611", "medium"),
    "B410": ("XML External Entities",    "CWE-611", "high"),
    # Logging
    "B112": ("Insecure Configuration",   "CWE-778", "low"),
    # SSRF
    "B310": ("SSRF",                     "CWE-918", "medium"),
    "B311": ("Insecure Randomness",      "CWE-330", "medium"),
    "B312": ("SSRF",                     "CWE-918", "medium"),
    "B313": ("SSRF",                     "CWE-918", "medium"),
    "B314": ("SSRF",                     "CWE-918", "high"),
}

# SpotBugs / FindSecBugs (Java) bug type → (owasp_type, cwe_id)
SPOTBUGS_OWASP_MAP: Dict[str, tuple] = {
    "SQL_INJECTION":                    ("SQL Injection",          "CWE-89",  None),
    "SQL_INJECTION_JDBC":               ("SQL Injection",          "CWE-89",  "high"),
    "SQL_INJECTION_JPA":                ("SQL Injection",          "CWE-89",  "high"),
    "SQL_INJECTION_HIBERNATE":          ("SQL Injection",          "CWE-89",  "high"),
    "COMMAND_INJECTION":                ("Command Injection",       "CWE-78",  "high"),
    "XSS_REQUEST_PARAMETER_TO_SEND":    ("Cross-Site Scripting",   "CWE-79",  "high"),
    "XSS_REQUEST_PARAMETER_TO_JSP":     ("Cross-Site Scripting",   "CWE-79",  "high"),
    "XSS_REQUEST_PARAMETER_TO_SERVLET": ("Cross-Site Scripting",   "CWE-79",  "high"),
    "HARD_CODE_PASSWORD":               ("Hardcoded Credentials",  "CWE-798", "high"),
    "HARD_CODE_KEY":                    ("Hardcoded Credentials",  "CWE-798", "high"),
    "LDAP_INJECTION":                   ("Injection",              "CWE-90",  "high"),
    "XPATH_INJECTION":                  ("Injection",              "CWE-643", "high"),
    "PATH_TRAVERSAL_IN":                ("Path Traversal",         "CWE-22",  "high"),
    "PATH_TRAVERSAL_OUT":               ("Path Traversal",         "CWE-22",  "high"),
    "OBJECT_DESERIALIZATION":           ("Unsafe Deserialization", "CWE-502", "high"),
    "DESERIALIZATION_GADGET":           ("Unsafe Deserialization", "CWE-502", "high"),
    "WEAK_MESSAGE_DIGEST_MD5":          ("Insecure Cryptography",  "CWE-328", "high"),
    "WEAK_MESSAGE_DIGEST_SHA1":         ("Insecure Cryptography",  "CWE-328", "medium"),
    "DEFAULT_HTTP_CLIENT":              ("Insecure Configuration", "CWE-295", "medium"),
    "TRUST_BOUNDARY_VIOLATION":         ("Broken Access Control",  "CWE-501", "medium"),
    "CSRF":                             ("CSRF",                   "CWE-352", "high"),
    "SSRF":                             ("SSRF",                   "CWE-918", "high"),
    "INSECURE_COOKIE":                  ("Insecure Configuration", "CWE-614", "medium"),
    "HTTPONLY_COOKIE":                  ("Insecure Configuration", "CWE-1004","low"),
    "UNVALIDATED_REDIRECT":             ("Broken Access Control",  "CWE-601", "medium"),
}


def _classify_bandit_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Apply OWASP type classification to a Bandit finding."""
    rule_id = finding.get("rule_id", "")
    mapping = BANDIT_OWASP_MAP.get(rule_id)
    if mapping:
        owasp_type, cwe_id, sev_override = mapping
        finding["owasp_type"] = owasp_type
        finding["cwe_id"] = cwe_id
        if sev_override:
            finding["severity"] = sev_override
    else:
        # Fallback: use Bandit's native severity (already High/Medium/Low)
        finding.setdefault("owasp_type", "Security Vulnerability")
    return finding


def _classify_spotbugs_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Apply OWASP type classification to a SpotBugs finding."""
    rule_id = finding.get("rule_id", "")
    mapping = SPOTBUGS_OWASP_MAP.get(rule_id)
    if mapping:
        owasp_type, cwe_id, sev_override = mapping
        finding["owasp_type"] = owasp_type
        finding["cwe_id"] = cwe_id
        if sev_override:
            finding["severity"] = sev_override
    else:
        finding.setdefault("owasp_type", "Security Vulnerability")
    return finding


def _classify_semgrep_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Apply OWASP type classification to a Semgrep finding."""
    # Semgrep rules are varied; we try to map based on rule_id if possible, or fallback.
    rule_id = finding.get("rule_id", "").lower()
    if "sql" in rule_id:
        finding["owasp_type"] = "SQL Injection"
        finding["cwe_id"] = "CWE-89"
    elif "xss" in rule_id or "cross-site" in rule_id:
        finding["owasp_type"] = "Cross-Site Scripting"
        finding["cwe_id"] = "CWE-79"
    elif "command" in rule_id or "exec" in rule_id:
        finding["owasp_type"] = "Command Injection"
        finding["cwe_id"] = "CWE-78"
    elif "crypto" in rule_id or "md5" in rule_id or "sha1" in rule_id or "cipher" in rule_id:
        finding["owasp_type"] = "Insecure Cryptography"
        finding["cwe_id"] = "CWE-327"
    elif "secret" in rule_id or "password" in rule_id or "credential" in rule_id:
        finding["owasp_type"] = "Hardcoded Credentials"
        finding["cwe_id"] = "CWE-798"
    else:
        finding.setdefault("owasp_type", "Security Vulnerability")
    return finding


def security_vuln_node(state: ScanState) -> Dict[str, Any]:
    """
    Security Vulnerability Agent node for LangGraph.
    
    Input state keys used: code, language
    Output state keys produced: security_findings
    
    This node:
    1. Runs the appropriate static security tool (Bandit/SpotBugs)
    2. Classifies each finding with an OWASP type and CWE ID
    3. Retrieves relevant KB context via RAG for grounding
    4. Uses an LLM to validate findings and enrich explanations
    """
    code = state["code"]
    lang = state["language"]

    # Step 1 — Run static security tool
    raw_findings = []
    if lang == "python":
        bandit_findings = run_bandit(code)
        bandit_findings = [_classify_bandit_finding(f) for f in bandit_findings]
        
        semgrep_findings = run_python_semgrep(code, config="p/security-audit")
        semgrep_findings = [_classify_semgrep_finding(f) for f in semgrep_findings if f.get("category") == "security"]
        
        raw_findings = bandit_findings + semgrep_findings
    else:
        spotbugs_findings = run_spotbugs(code)
        spotbugs_findings = [_classify_spotbugs_finding(f) for f in spotbugs_findings]
        
        semgrep_findings = run_java_semgrep(code, config="p/security-audit")
        semgrep_findings = [_classify_semgrep_finding(f) for f in semgrep_findings if f.get("category") == "security"]
        
        raw_findings = spotbugs_findings + semgrep_findings

    if not raw_findings:
        raw_findings = []

    # Group findings by (line, owasp_type) to merge detected_by
    grouped = {}
    for f in raw_findings:
        key = (f.get("line"), f.get("owasp_type"))
        if key not in grouped:
            grouped[key] = f
            tool_name = "SpotBugs" if f.get("tool") == "spotbugs" else f.get("tool").capitalize() if f.get("tool") else "Unknown"
            grouped[key]["detected_by"] = [tool_name]
        else:
            tool_name = "SpotBugs" if f.get("tool") == "spotbugs" else f.get("tool").capitalize() if f.get("tool") else "Unknown"
            if tool_name not in grouped[key]["detected_by"]:
                grouped[key]["detected_by"].append(tool_name)
            # If incoming is higher severity, inherit it
            existing_sev = grouped[key].get("severity", "low").lower()
            incoming_sev = f.get("severity", "low").lower()
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            if sev_rank.get(incoming_sev, 4) < sev_rank.get(existing_sev, 4):
                grouped[key]["severity"] = incoming_sev
                grouped[key]["rule_id"] = f.get("rule_id")
                
    raw_findings = list(grouped.values())

    # Tag agent source on all raw findings
    for f in raw_findings:
        f["agent_source"] = "security_vulnerability"
        f.setdefault("category", "security")

    # Step 2 — RAG retrieval: fetch KB context for each finding
    db = SessionLocal()
    try:
        for finding in raw_findings:
            owasp_type = finding.get("owasp_type", "")
            cwe_id = finding.get("cwe_id", "")
            rule_id = finding.get("rule_id", "")
            category = finding.get("category", "")
            severity = finding.get("severity", "low")
            
            query = f"{lang} security vulnerability {owasp_type} {cwe_id} {rule_id} prevention"
            chunks = retrieve(
                db, 
                query, 
                k=2,
                language=lang,
                category=category if category != "security" else None, # The tool finding category is 'security', not very useful for KB filtering unless mapped, but passing it anyway or using owasp_type
                severity=severity
            )
            context = "\n\n".join(
                [f"[{c.source_name}]: {c.chunk_text}" for c in chunks]
            )
            finding["_retrieved_context"] = context
    finally:
        db.close()

    # Step 3 — LLM enrichment with RAG grounding
    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)

    prompt = f"""You are a senior Security Auditor reviewing {lang} code. 
You have been given raw findings from a static security scanner plus relevant 
Knowledge Base context on each vulnerability.

CODE:
{code}

RAW FINDINGS WITH KNOWLEDGE BASE CONTEXT:
{json.dumps(raw_findings, indent=2)}

Your task for EACH raw finding (if any):
1. Validate if it is a real vulnerability based on actual code context. Set a new field 'validation_status' to exactly one of: "YES", "NO", or "MAYBE". Do NOT drop any findings from the output, even if you think they are false positives. You are a validator, not a filter.
2. Improve 'title': concise, specific (max 12 words).
3. Improve 'explanation': 3-5 sentences — what the vulnerability is, why it's dangerous, cite the Knowledge Base context where applicable.
4. Set 'grounding_source' to the KB source filename most relevant to this finding (from _retrieved_context), or null if no KB context was relevant.
5. Provide a 'confidence_score' as a percentage string (e.g., "96%") reflecting how certain you are in your validation status.
6. Provide a 'cvss_score' (number between 0.0 and 10.0) reflecting a realistic CVSS v3 score for this vulnerability.
7. Append "LLM Validation" to the existing 'detected_by' list.
8. Preserve: 'line', 'column', 'tool', 'rule_id', 'severity', 'category', 'agent_source', 'owasp_type', 'cwe_id', and the updated 'detected_by' list.

9. IMPORTANT: If you spot any glaring security vulnerabilities in the code (e.g. SQL Injection, XSS, Command Injection) that are NOT listed in the RAW FINDINGS, you MUST add them as new findings.
   - For new findings, set 'tool' to 'LLM', 'rule_id' to a descriptive name (e.g. 'llm-sql-injection'), 'severity' (critical/high/medium), 'owasp_type' (e.g. 'SQL Injection'), 'cwe_id', 'validation_status' to 'YES', 'detected_by' to ["LLM Security Review"], 'category' to 'security', and 'agent_source' to 'security_vulnerability'.
   - Provide the line number, a title, explanation, cvss_score, and confidence_score just like the other findings.

Return ONLY a JSON array of ALL original findings with the updated fields PLUS any new findings you identified. No markdown, no preamble."""

    try:
        response = llm.invoke([
            SystemMessage(content="You return ONLY a valid JSON array. No markdown, no extra text."),
            HumanMessage(content=prompt)
        ])
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        content = str(raw_content).strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        enriched = json.loads(content.strip())
        # Clean up the context field (not stored to DB)
        for f in enriched:
            f.pop("_retrieved_context", None)
            f["agent_source"] = "security_vulnerability"  # Always ensure set
        return {"security_findings": enriched}
    except Exception as e:
        print(f"[Security Vulnerability Agent] LLM enrichment error: {e}")
        # Fallback: return raw findings with context stripped
        for f in raw_findings:
            f.pop("_retrieved_context", None)
        return {"security_findings": raw_findings}
