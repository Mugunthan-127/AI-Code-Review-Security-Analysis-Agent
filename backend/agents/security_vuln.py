"""
Security Vulnerability Agent — Milestone 2
Scans submitted code for OWASP-standard vulnerabilities.
Classifies each finding by OWASP type, CWE ID, severity, and exact location.
Uses RAG-grounded LLM enrichment to validate and explain each finding.
"""
import json
from typing import Dict, Any, List, Optional
from .state import ScanState
from services.python_analyzer import run_bandit
from services.java_analyzer import run_spotbugs
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
    if lang == "python":
        raw_findings = run_bandit(code)
        # Apply OWASP classification
        raw_findings = [_classify_bandit_finding(f) for f in raw_findings]
    else:
        raw_findings = run_spotbugs(code)
        raw_findings = [_classify_spotbugs_finding(f) for f in raw_findings]

    if not raw_findings:
        return {"security_findings": []}

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
            query = f"{lang} security vulnerability {owasp_type} {cwe_id} {rule_id} prevention"
            chunks = retrieve(db, query, k=2)
            context = "\n\n".join(
                [f"[{c.source_name}]: {c.chunk_text}" for c in chunks]
            )
            finding["_retrieved_context"] = context
    finally:
        db.close()

    # Step 3 — LLM enrichment with RAG grounding
    llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=0)

    prompt = f"""You are a senior Security Auditor reviewing {lang} code. 
You have been given raw findings from a static security scanner plus relevant 
Knowledge Base context on each vulnerability.

CODE:
{code}

RAW FINDINGS WITH KNOWLEDGE BASE CONTEXT:
{json.dumps(raw_findings, indent=2)}

Your task for EACH finding:
1. Confirm it is a real vulnerability based on actual code context. If it is a clear false positive (e.g. the flagged code path is unreachable or the finding rule does not apply), drop it from the output.
2. Improve 'title': concise, specific (max 12 words).
3. Improve 'explanation': 3-5 sentences — what the vulnerability is, why it's dangerous, cite the Knowledge Base context where applicable.
4. Set 'grounding_source' to the KB source filename most relevant to this finding (from _retrieved_context), or null if no KB context was relevant.
5. Preserve: 'line', 'column', 'tool', 'rule_id', 'severity', 'category', 'agent_source', 'owasp_type', 'cwe_id'.
6. Do NOT add new findings. Do NOT change 'agent_source'.

Return ONLY a JSON array of confirmed findings. No markdown, no preamble."""

    try:
        response = llm.invoke([
            SystemMessage(content="You return ONLY a valid JSON array. No markdown, no extra text."),
            HumanMessage(content=prompt)
        ])
        content = response.content.strip()
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
