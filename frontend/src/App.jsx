import { useState, useEffect, useRef } from 'react'
import Editor from '@monaco-editor/react'
import ChatUI from './ChatUI'
import KBTester from './KBTester'

/* ─── Robust Automatic Language Detector ─── */
export function detectLanguage(sourceCode = '', fileName = '') {
  if (fileName) {
    const ext = fileName.split('.').pop()?.toLowerCase()
    if (ext === 'java') return 'java'
    if (ext === 'py') return 'python'
  }
  if (!sourceCode || typeof sourceCode !== 'string') return 'python'

  const javaIndicators = [
    /\bpublic\s+(?:class|interface|enum)\b/,
    /\bimport\s+java\./,
    /\bimport\s+javax\./,
    /\bSystem\.(?:out|err)\./,
    /\bpublic\s+static\s+void\s+main\b/,
    /\bpackage\s+[\w.]+;/,
    /\b(?:private|protected|public)\s+[\w<>[\]]+\s+\w+\s*\(/,
    /\bthrows\s+\w+Exception\b/,
    /\bPreparedStatement\b/,
    /\bDriverManager\b/,
    /\bSQLException\b/,
    /\btry\s*\(/,
    /\bString\[\]\s*args\b/,
    /@Override/,
    /@SpringBootApplication/,
  ]

  const pythonIndicators = [
    /\bdef\s+\w+\s*\(/,
    /\bimport\s+(?:os|sys|re|json|math|typing|subprocess|pickle|requests|fastapi|pydantic)\b/,
    /\bfrom\s+[\w.]+\s+import\b/,
    /\belif\b/,
    /\bexcept\s*(?:\w+)?(?:\s+as\s+\w+)?:\s*$/,
    /\bif\s+__name__\s*==\s*['"]__main__['"]\s*:/,
    /\bprint\s*\(/,
    /^\s*#.*$/m,
    /\bself\.\w+/,
    /\blambda\b/,
    /\basync\s+def\b/,
    /\b__init__\b/,
  ]

  let javaScore = 0
  let pyScore = 0

  for (const regex of javaIndicators) {
    if (regex.test(sourceCode)) javaScore += 3
  }
  for (const regex of pythonIndicators) {
    if (regex.test(sourceCode)) pyScore += 3
  }

  // Structural syntax cues
  const semicolonLines = (sourceCode.match(/;\s*$/gm) || []).length
  const curlyBraceLines = (sourceCode.match(/[{}]/gm) || []).length
  if (semicolonLines > 0) javaScore += semicolonLines * 0.5
  if (curlyBraceLines > 0) javaScore += curlyBraceLines * 0.5

  const colonDefs = (sourceCode.match(/:\s*$/gm) || []).length
  if (colonDefs > 0) pyScore += colonDefs * 0.3

  if (javaScore >= pyScore && javaScore > 0) return 'java'
  if (pyScore > javaScore) return 'python'
  return (semicolonLines > 0 || curlyBraceLines > 0) ? 'java' : 'python'
}

/* ─── Sample Preset Codes for Instant Testing ─── */
const PRESETS = [
  {
    id: 'java-vuln',
    title: '☕ Java: SQLi & Hardcoded Secrets',
    lang: 'java',
    badge: 'Vulnerable',
    badgeColor: '#ef4444',
    code: `package com.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class VulnerableLogin {

    public static void main(String[] args) throws Exception {

        String username = "admin";
        String password = "Admin123";

        Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test",
                "root",
                password);

        Statement statement = connection.createStatement();

        String query =
                "SELECT * FROM users WHERE username='"
                        + username + "'";

        statement.executeQuery(query);

        Runtime.getRuntime().exec("notepad.exe");

        System.out.println(query);

        connection.close();
    }
}`
  },
  {
    id: 'java-clean',
    title: '☕ Java: Clean Try-with-Resources',
    lang: 'java',
    badge: '100% Clean',
    badgeColor: '#10b981',
    code: `package com.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class CleanLoginService {

    public static void main(String[] args) {
        String username = "admin";
        String dbUrl = System.getenv("DB_URL");
        String dbUser = System.getenv("DB_USER");
        String dbPass = System.getenv("DB_PASSWORD");

        String query = "SELECT id, username, email FROM users WHERE username = ?";

        try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPass);
             PreparedStatement statement = connection.prepareStatement(query)) {
            
            statement.setString(1, username);
            try (ResultSet resultSet = statement.executeQuery()) {
                while (resultSet.next()) {
                    System.out.println("User ID: " + resultSet.getInt("id"));
                }
            }
        } catch (SQLException e) {
            System.err.println("Database query error: " + e.getMessage());
        }
    }
}`
  },
  {
    id: 'py-vuln',
    title: '🐍 Python: Command Injection & Secrets',
    lang: 'python',
    badge: 'Vulnerable',
    badgeColor: '#ef4444',
    code: `import os
import subprocess
import pickle

API_KEY = "sk-live-93849384938493849384"

def run_backup(user_input):
    # Command Injection vulnerability
    cmd = "tar -czf backup.tar.gz " + user_input
    os.system(cmd)
    
    # Insecure Deserialization
    data = pickle.loads(user_input.encode())
    return data

def execute_action(user_cmd):
    # Subprocess shell injection
    subprocess.run(user_cmd, shell=True)
`
  },
  {
    id: 'py-clean',
    title: '🐍 Python: Clean Async Service',
    lang: 'python',
    badge: '100% Clean',
    badgeColor: '#10b981',
    code: `import os
import subprocess
from typing import List

def run_backup_secure(target_directory: str) -> bool:
    """Safely executes backup using parameterized arguments without shell."""
    safe_dir = os.path.abspath(target_directory)
    if not os.path.exists(safe_dir):
        return False
        
    cmd: List[str] = ["tar", "-czf", "backup.tar.gz", safe_dir]
    res = subprocess.run(cmd, shell=False, capture_output=True, check=True)
    return res.returncode == 0
`
  }
]

/* ─── Severity badge helpers ─── */
const SEV_META = {
  critical: { color: '#f43f5e', bg: 'rgba(244, 63, 94, 0.12)', border: 'rgba(244, 63, 94, 0.35)', label: 'CRITICAL', icon: '🔴' },
  high:     { color: '#fb923c', bg: 'rgba(251, 146, 60, 0.12)', border: 'rgba(251, 146, 60, 0.35)', label: 'HIGH', icon: '🟠' },
  medium:   { color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.12)', border: 'rgba(251, 191, 36, 0.35)', label: 'MEDIUM', icon: '🟡' },
  low:      { color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.12)', border: 'rgba(56, 189, 248, 0.35)', label: 'LOW', icon: '🔵' },
  info:     { color: '#a78bfa', bg: 'rgba(167, 139, 250, 0.12)', border: 'rgba(167, 139, 250, 0.35)', label: 'INFO', icon: 'ℹ️' },
}
const getSevMeta = (sev) => SEV_META[String(sev).toLowerCase()] || SEV_META.low

/* ─── Agent source badge ─── */
function AgentBadge({ source }) {
  if (!source) return null
  const isSec = source === 'security_vulnerability'
  const isQual = source === 'code_analysis'
  const isComp = source === 'complexity'
  const isDep = source === 'dependency'
  const isLic = source === 'license'

  let bg = 'rgba(139,92,246,0.12)'; let col = '#c084fc'; let bor = 'rgba(139,92,246,0.35)'; let lbl = '🔍 Code Quality'
  
  if (isSec) { bg = 'rgba(239,68,68,0.12)'; col = '#f87171'; bor = 'rgba(239,68,68,0.35)'; lbl = '🔒 Security Agent' }
  else if (isComp) { bg = 'rgba(59,130,246,0.12)'; col = '#60a5fa'; bor = 'rgba(59,130,246,0.35)'; lbl = '🧠 AST Complexity' }
  else if (isDep) { bg = 'rgba(245,158,11,0.12)'; col = '#fbbf24'; bor = 'rgba(245,158,11,0.35)'; lbl = '📦 Dependency' }
  else if (isLic) { bg = 'rgba(16,185,129,0.12)'; col = '#34d399'; bor = 'rgba(16,185,129,0.35)'; lbl = '⚖️ License' }

  return (
    <span
      className="agent-badge"
      style={{ background: bg, color: col, border: `1px solid ${bor}`, borderRadius: '8px', padding: '3px 10px', fontSize: '11px', fontWeight: '700', letterSpacing: '0.3px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
    >
      {lbl}
    </span>
  )
}

/* ─── Severity pill ─── */
function SevPill({ severity, cvss }) {
  const m = getSevMeta(severity)
  return (
    <span
      className="sev-pill"
      style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}`, borderRadius: '8px', padding: '3px 10px', fontSize: '11px', fontWeight: '700', letterSpacing: '0.4px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
    >
      <span>{m.icon}</span>
      {cvss ? `CVSS ${cvss} ` : ''}{m.label}
    </span>
  )
}

/* ─── Validation pill ─── */
function ValidationPill({ status }) {
  if (!status) return null
  const isYes = status === 'YES'
  const isNo = status === 'NO'
  const color = isYes ? '#10b981' : isNo ? '#ef4444' : '#f59e0b'
  const bg = isYes ? 'rgba(16,185,129,0.12)' : isNo ? 'rgba(239,68,68,0.12)' : 'rgba(245,158,11,0.12)'
  const border = isYes ? 'rgba(16,185,129,0.35)' : isNo ? 'rgba(239,68,68,0.35)' : 'rgba(245,158,11,0.35)'
  const label = isYes ? '✓ Validated Bug' : isNo ? '✗ False Positive' : '⚠ Under Review'
  return (
    <span className="sev-pill" style={{ color, background: bg, border: `1px solid ${border}`, borderRadius: '8px', padding: '3px 8px', fontSize: '11px', fontWeight: '600' }}>
      {label}
    </span>
  )
}

/* ─── Security Advice Card (from RAG KB) ─── */
function SecurityAdviceCard({ advice }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="sa">
      <button className="sa-hd" onClick={() => setOpen(v => !v)}>
        <div className="sa-hd-l">
          <span className="sa-ico">🛡️</span>
          <div className="sa-meta">
            <span className="sa-src">{advice.source.replace(/\.md$/, '').replace(/_/g, ' ')}</span>
            <div className="sa-badges">
              {advice.owasp_id && <span className="sa-badge sa-owasp">{advice.owasp_id}</span>}
              {advice.cwe_id   && <span className="sa-badge sa-cwe">{advice.cwe_id}</span>}
              {advice.category && <span className="sa-badge sa-cat">{advice.category.replace(/_/g, ' ')}</span>}
            </div>
          </div>
        </div>
        <span className="sa-chev" data-open={open}>▾</span>
      </button>
      {open && (
        <div className="sa-body">
          <p className="sa-text">{advice.text}{advice.text.length >= 400 ? '…' : ''}</p>
        </div>
      )}
    </div>
  )
}

/* ─── Finding Card ─── */
function FindingCard({ finding, index, scanId, setCode, setTab, setChatQuery }) {
  const [open, setOpen] = useState(index < 3) // First 3 expanded by default
  const [fixing, setFixing] = useState(false)
  const [copied, setCopied] = useState(false)
  const isSec = finding.agent_source === 'security_vulnerability'
  const sevMeta = getSevMeta(finding.severity)

  const handleApplyFix = async () => {
    if (!finding.id || !scanId) return alert("Missing finding ID or scan ID");
    setFixing(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/${scanId}/fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: finding.id })
      });
      if (!res.ok) throw new Error("Fix generation failed");
      const data = await res.json();
      setCode(data.patched_code);
      setTab('paste');
      alert("✅ Code successfully updated in the editor!");
    } catch (e) {
      alert("Error applying fix: " + e.message);
    } finally {
      setFixing(false);
    }
  };

  return (
    <div className={`fc ${isSec ? 'fc-sec' : 'fc-quality'}`} style={{ '--sev-color': sevMeta.color, '--sev-border': sevMeta.border }}>
      <button className="fc-hd" onClick={() => setOpen(v => !v)}>
        <div className="fc-hd-l">
          {/* Severity strip indicator */}
          <div className="fc-sev-strip" style={{ background: sevMeta.color }} />

          <div className="fc-meta">
            <div className="fc-meta-top">
              <AgentBadge source={finding.agent_source} />
              <SevPill severity={finding.severity} cvss={finding.cvss_score} />
              <ValidationPill status={finding.validation_status} />
              {finding.line != null && (
                <span className="fc-loc">
                  📍 Line {finding.line}{finding.column != null ? ` : ${finding.column}` : ''}
                </span>
              )}
            </div>

            {/* Title */}
            <span className="fc-title">{finding.title || finding.issue}</span>

            {/* OWASP / CWE badges */}
            <div className="fc-badges">
              {finding.owasp_type && (
                <span className="fc-badge fc-owasp">🛡️ {finding.owasp_type}</span>
              )}
              {finding.cwe_id && (
                <span className="fc-badge fc-cwe">🏷️ {finding.cwe_id}</span>
              )}
              {finding.tool && (
                <span className="fc-badge fc-tool">⚙️ {finding.tool.toUpperCase()}</span>
              )}
              {finding.rule_id && (
                <span className="fc-badge fc-rule">📋 {finding.rule_id}</span>
              )}
            </div>
          </div>
        </div>
        <span className="fc-chev" data-open={open}>▾</span>
      </button>

      {open && (
        <div className="fc-body">
          {/* Explanation */}
          {(finding.explanation || finding.fix) && (
            <div className="fc-explanation">
              <span className="fc-section-lbl">💡 AI Analysis & Impact</span>
              <p className="fc-explanation-text">{finding.explanation || finding.fix}</p>
            </div>
          )}

          {/* Ask the Assistant Button */}
          {setChatQuery && (
            <div style={{ marginTop: '8px', marginBottom: '8px' }}>
              <button 
                onClick={(e) => { 
                  e.stopPropagation(); 
                  setChatQuery(`Explain this finding and how to resolve it safely: ${finding.title || finding.issue}`);
                }}
                className="fc-chat-btn"
              >
                <span>💬</span> Ask AI Assistant to Explain & Advise
              </button>
            </div>
          )}

          {/* Technical Explainability Block */}
          <div className="fc-explainability-block">
            <div style={{ flex: '1 1 120px' }}>
              <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.72rem' }}>DETECTED BY</div>
              <ul style={{ listStyleType: 'none', padding: 0, margin: 0 }}>
                {finding.detected_by ? (
                  (typeof finding.detected_by === 'string' ? JSON.parse(finding.detected_by) : finding.detected_by).map((tool, idx) => (
                    <li key={idx} style={{ color: '#38bdf8', fontSize: '0.85rem', marginBottom: '2px', fontWeight: 'bold' }}>
                      ⚡ {tool}
                    </li>
                  ))
                ) : (
                  <li style={{ color: '#38bdf8', fontSize: '0.85rem', fontWeight: 'bold' }}>⚡ {finding.tool || 'Static Rule Analyzer'}</li>
                )}
              </ul>
            </div>

            {finding.confidence_score && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.72rem' }}>CONFIDENCE</div>
                <div style={{ color: '#10b981', fontSize: '0.85rem', fontWeight: 'bold' }}>
                  🎯 {Math.round(Number(finding.confidence_score) * 100)}% Match
                </div>
              </div>
            )}

            {finding.cvss_score && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.72rem' }}>CVSS SCORE</div>
                <div style={{ color: '#f87171', fontSize: '0.85rem', fontWeight: 'bold' }}>
                  🔥 {finding.cvss_score} / 10.0
                </div>
              </div>
            )}
          </div>

          {/* Grounding source (RAG KB) */}
          {finding.grounding_source && (
            <div className="fc-grounding">
              <span className="fc-section-lbl">📚 Grounded in Knowledge Base</span>
              <span className="fc-grounding-src">
                📖 {finding.grounding_source.replace(/\.md$/, '').replace(/_/g, ' ')}
              </span>
            </div>
          )}

          {/* Auto Fix / Diff View */}
          {(finding.suggested_fix || finding.fix) && (
            <div className="fc-fix" style={{ marginTop: '16px' }}>
              
              {/* Original Code */}
              {finding.original_code && (
                <div style={{ marginBottom: '12px' }}>
                  <span className="fc-section-lbl" style={{ color: '#ef4444' }}>❌ Vulnerable Code Snippet</span>
                  <pre className="fc-code fc-code-vuln">
                    <code>{finding.original_code}</code>
                  </pre>
                </div>
              )}

              {/* Secure Remediated Code */}
              <div style={{ position: 'relative' }}>
                <span className="fc-section-lbl" style={{ color: '#10b981' }}>✅ Secure Remediated Code</span>
                <pre className="fc-code fc-code-sec" style={{ paddingBottom: '44px' }}>
                  <code>{finding.suggested_fix || finding.fix}</code>
                </pre>
                
                {/* Action Buttons */}
                <div className="fc-code-actions">
                  <button 
                    onClick={(e) => { 
                      e.stopPropagation(); 
                      const text = finding.suggested_fix || finding.fix;
                      if (navigator.clipboard && window.isSecureContext) {
                          navigator.clipboard.writeText(text);
                      } else {
                          const ta = document.createElement('textarea');
                          ta.value = text;
                          ta.style.position = 'absolute';
                          ta.style.left = '-9999px';
                          document.body.appendChild(ta);
                          ta.select();
                          document.execCommand('copy');
                          document.body.removeChild(ta);
                      }
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="fc-btn-copy"
                  >
                    {copied ? "✅ Copied!" : "📋 Copy Fix"}
                  </button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); handleApplyFix(); }}
                    disabled={fixing}
                    className="fc-btn-apply"
                  >
                    {fixing ? "Applying…" : "🪄 Apply to Editor"}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── Global Fix Section ─── */
function GlobalFixSection({ scanId, setCode, setTab }) {
  const [generating, setGenerating] = useState(false);
  const [patchedCode, setPatchedCode] = useState(null);
  const [copied, setCopied] = useState(false);

  const generateFullCode = async () => {
    if (!scanId) return;
    setGenerating(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/${scanId}/fix-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) throw new Error("Failed to generate full corrected code.");
      const data = await res.json();
      setPatchedCode(data.patched_code);
    } catch (e) {
      alert(e.message);
    } finally {
      setGenerating(false);
    }
  };

  const handleAutoFix = () => {
    if (!patchedCode) return;
    setCode(patchedCode);
    setTab('paste');
    alert("✅ Corrected code successfully loaded into the editor!");
  };

  return (
    <div className="global-fix-section">
      <div className="gfs-header">
        <div className="gfs-icon-wrap">🪄</div>
        <div>
          <h3 className="gfs-title">One-Click Full Project Remediation</h3>
          <p className="gfs-subtitle">Synthesizes all security patches and quality repairs into a unified, secure file.</p>
        </div>
      </div>
      
      {!patchedCode ? (
        <button 
          onClick={generateFullCode}
          disabled={generating}
          className="gfs-generate-btn"
        >
          {generating ? '✨ Generating Unified Secure Code…' : '🚀 Generate Complete Secure File'}
        </button>
      ) : (
        <div style={{ position: 'relative', marginTop: '16px' }}>
          <pre className="fc-code fc-code-sec" style={{ maxHeight: '350px', overflowY: 'auto', paddingBottom: '48px' }}>
            <code>{patchedCode}</code>
          </pre>
          <div className="fc-code-actions">
            <button 
              onClick={() => {
                  if (navigator.clipboard && window.isSecureContext) {
                      navigator.clipboard.writeText(patchedCode);
                  } else {
                      const ta = document.createElement('textarea');
                      ta.value = patchedCode;
                      ta.style.position = 'absolute';
                      ta.style.left = '-9999px';
                      document.body.appendChild(ta);
                      ta.select();
                      document.execCommand('copy');
                      document.body.removeChild(ta);
                  }
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
              }}
              className="fc-btn-copy"
            >
              {copied ? "✅ Copied!" : "📋 Copy Full Code"}
            </button>
            <button 
              onClick={handleAutoFix}
              className="fc-btn-apply"
            >
              🪄 Load into Editor
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Agent Stats Panel (Visual Dashboard) ─── */
function AgentStats({ findings, riskScore, history, scanId }) {
  const secCount = findings.filter(f => f.agent_source === 'security_vulnerability').length
  const qualCount = findings.filter(f => f.agent_source === 'code_analysis').length
  const compCount = findings.filter(f => f.agent_source === 'complexity').length
  const depCount = findings.filter(f => f.agent_source === 'dependency').length
  const licCount = findings.filter(f => f.agent_source === 'license').length

  const computedHealth = riskScore !== undefined && riskScore !== null ? Math.max(0, 100 - riskScore) : 100

  // Trend
  let trendText = null;
  let trendColor = 'var(--txt-muted)';
  let trendIcon = '⚪';
  if (history && history.length > 0 && riskScore !== undefined && riskScore !== null) {
    const currentIsFirst = history[0].scan_id === scanId;
    const previousScan = currentIsFirst ? history[1] : history[0];
    
    if (previousScan && previousScan.risk_score !== undefined && previousScan.risk_score !== null) {
      const prevScore = previousScan.risk_score;
      if (riskScore < prevScore) {
        trendText = `Prev (${prevScore}%) → Current (${riskScore}%) · Risk Lowered ✨`;
        trendColor = '#10b981';
        trendIcon = '🟢';
      } else if (riskScore > prevScore) {
        trendText = `Prev (${prevScore}%) → Current (${riskScore}%) · Risk Increased`;
        trendColor = '#ef4444';
        trendIcon = '🔴';
      } else {
        trendText = `Prev (${prevScore}%) · Risk Steady`;
        trendColor = '#94a3b8';
      }
    }
  }

  // Health Grade
  let healthGrade = 'F';
  let gradeColor = '#ef4444';
  let gradeDesc = 'High Vulnerability Exposure';
  if (computedHealth >= 95) { healthGrade = 'A+'; gradeColor = '#10b981'; gradeDesc = 'Flawless Security & Clean Architecture ✨'; }
  else if (computedHealth >= 85) { healthGrade = 'A'; gradeColor = '#10b981'; gradeDesc = 'Excellent · Low Risk Codebase'; }
  else if (computedHealth >= 75) { healthGrade = 'B'; gradeColor = '#38bdf8'; gradeDesc = 'Good · Minor Quality Improvements'; }
  else if (computedHealth >= 60) { healthGrade = 'C'; gradeColor = '#fbbf24'; gradeDesc = 'Moderate Risk · Needs Security Review'; }
  else if (computedHealth >= 40) { healthGrade = 'D'; gradeColor = '#f97316'; gradeDesc = 'High Risk · Action Required'; }

  // SVG Gauge calculations
  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (computedHealth / 100) * circumference;

  return (
    <div className="scanner-stats-container">
      
      {/* Code Health Score Banner with Circular Gauge */}
      <div className="scanner-health-banner">
        <div className="shb-gauge-wrap">
          <svg className="shb-gauge-svg" width="96" height="96" viewBox="0 0 96 96">
            <circle
              className="shb-gauge-bg"
              cx="48" cy="48" r={radius}
              stroke="rgba(255,255,255,0.08)"
              strokeWidth="7"
              fill="transparent"
            />
            <circle
              className="shb-gauge-val"
              cx="48" cy="48" r={radius}
              stroke={gradeColor}
              strokeWidth="7"
              fill="transparent"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dashoffset 0.8s ease-in-out' }}
            />
          </svg>
          <div className="shb-gauge-center">
            <span className="shb-grade" style={{ color: gradeColor }}>{healthGrade}</span>
            <span className="shb-pct">{computedHealth}%</span>
          </div>
        </div>

        <div className="shb-info">
          <div className="shb-lbl">Overall Code Health Grade</div>
          <div className="shb-desc" style={{ color: gradeColor }}>{gradeDesc}</div>
          <div className="shb-meta-row">
            <span className="shb-findings-pill">🛡️ {findings.length} Finding{findings.length !== 1 ? 's' : ''}</span>
            {trendText && (
              <span className="shb-trend-pill" style={{ color: trendColor }}>
                {trendIcon} {trendText}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Category Metric Tiles */}
      <div className="scanner-tiles-grid">
        <div className="scanner-tile tile-sec">
          <div className="st-top">
            <span className="st-ico">🔒</span>
            <span className="st-count" style={{ color: secCount > 0 ? '#f87171' : '#10b981' }}>{secCount}</span>
          </div>
          <span className="st-lbl">Security Agent</span>
          <span className="st-sub">{secCount === 0 ? '✓ 0 Vulnerabilities' : `${secCount} Risks Detected`}</span>
        </div>

        <div className="scanner-tile tile-quality">
          <div className="st-top">
            <span className="st-ico">🔍</span>
            <span className="st-count" style={{ color: qualCount > 0 ? '#c084fc' : '#10b981' }}>{qualCount}</span>
          </div>
          <span className="st-lbl">Quality & Linter</span>
          <span className="st-sub">{qualCount === 0 ? '✓ Clean Standards' : `${qualCount} Style Issues`}</span>
        </div>

        <div className="scanner-tile tile-comp">
          <div className="st-top">
            <span className="st-ico">🧠</span>
            <span className="st-count" style={{ color: compCount > 0 ? '#60a5fa' : '#10b981' }}>{compCount}</span>
          </div>
          <span className="st-lbl">Complexity AST</span>
          <span className="st-sub">{compCount === 0 ? '✓ Optimal Depth' : `${compCount} High Complexity`}</span>
        </div>

        <div className="scanner-tile tile-dep">
          <div className="st-top">
            <span className="st-ico">📦</span>
            <span className="st-count" style={{ color: depCount > 0 ? '#fbbf24' : '#10b981' }}>{depCount}</span>
          </div>
          <span className="st-lbl">Dependencies</span>
          <span className="st-sub">{depCount === 0 ? '✓ Secure Packages' : `${depCount} Outdated/CVEs`}</span>
        </div>

        <div className="scanner-tile tile-lic">
          <div className="st-top">
            <span className="st-ico">⚖️</span>
            <span className="st-count" style={{ color: licCount > 0 ? '#f43f5e' : '#34d399' }}>{licCount}</span>
          </div>
          <span className="st-lbl">License Compliance</span>
          <span className="st-sub">{licCount === 0 ? '✓ Permissive OK' : `${licCount} Alerts`}</span>
        </div>
      </div>
    </div>
  )
}

/* ─── Helpers ─── */
function getSessionId() {
  let sid = localStorage.getItem('acr_session_id')
  if (!sid) {
    sid = crypto.randomUUID()
    localStorage.setItem('acr_session_id', sid)
  }
  return sid
}

function fmtDate(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/* ─── History Item ─── */
function HistoryItem({ item, onLoadInScanner, onDeleteScan, onExportReport, setChatQuery, setCode, setLang, setTab, setView }) {
  const [open, setOpen] = useState(false)
  const [details, setDetails] = useState(null)
  const [loadingDetails, setLoadingDetails] = useState(false)
  const [activeTab, setActiveTab] = useState('findings')
  const [copiedCode, setCopiedCode] = useState(false)

  const status = item?.status || 'unknown'
  const lang = (item?.language || 'unknown').toLowerCase()
  const source = item?.source_type || 'paste'
  const riskScore = item?.risk_score ?? (details?.risk_score ?? 0)
  const healthScore = Math.max(0, 100 - riskScore)
  const findingsCount = item?.findings_count ?? (details?.findings?.length ?? 0)
  const isClean = (status === 'validated' || status === 'completed') && findingsCount === 0 && riskScore === 0
  const isFailed = status === 'failed' || status === 'rejected'

  const langIcon = lang === 'python' ? '🐍' : (lang === 'java' ? '☕' : '📄')
  const srcIcon = source === 'upload' ? '📂 File' : '📝 Paste'

  const toggleOpen = async () => {
    const nextOpen = !open
    setOpen(nextOpen)
    if (nextOpen && !details) {
      setLoadingDetails(true)
      try {
        const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/scan/${item.scan_id}`)
        if (res.ok) {
          const data = await res.json()
          setDetails(data)
        }
      } catch (e) {
        console.error("Failed to load scan details:", e)
      } finally {
        setLoadingDetails(false)
      }
    }
  }

  const handleCopyCode = (text) => {
    if (!text) return
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text)
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'absolute'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    setCopiedCode(true)
    setTimeout(() => setCopiedCode(false), 2000)
  }

  const rawCode = details?.raw_code || item?.raw_code || item?.snippet || ''
  const findings = details?.findings || []
  const summaryText = details?.summary_text || item?.summary_text

  let parsedSummary = null
  if (summaryText) {
    try {
      parsedSummary = JSON.parse(summaryText)
    } catch {
      parsedSummary = { executive_overview: summaryText }
    }
  }

  return (
    <div className={`hist-card ${open ? 'hist-card-open' : ''} ${isClean ? 'hist-card-clean' : ''}`}>
      {/* Header */}
      <div className="hist-card-header" onClick={toggleOpen}>
        <div className="hist-card-header-left">
          {/* Health Gauge Badge */}
          <div className={`hist-score-badge ${isClean ? 'score-clean' : riskScore > 30 ? 'score-high-risk' : 'score-med-risk'}`}>
            <span className="hist-score-num">{isClean ? 100 : healthScore}</span>
            <span className="hist-score-lbl">HEALTH</span>
          </div>

          <div className="hist-card-meta">
            <div className="hist-card-meta-top">
              <span className={`hist-lang-pill ${lang}`}>
                {langIcon} {lang.toUpperCase()}
              </span>
              <span className="hist-src-pill">{srcIcon}</span>
              <span className={`hist-status-pill ${isClean ? 'pill-clean' : isFailed ? 'pill-err' : 'pill-warn'}`}>
                {isClean ? '✓ 100% Secure & Clean' : isFailed ? '✗ Analysis Failed' : `⚠ ${findingsCount} Issues Found`}
              </span>
            </div>

            <div className="hist-card-title-row">
              <span className="hist-card-title">
                {isClean 
                  ? `Scan #${item.scan_id.slice(0, 8)}: Passed Security & Quality Review`
                  : `Scan #${item.scan_id.slice(0, 8)}: ${findingsCount} Findings (${riskScore}% Risk)`}
              </span>
            </div>

            {/* Quick Severity Chips */}
            <div className="hist-card-sev-row">
              {item.critical_count > 0 && <span className="sev-chip chip-critical">🔴 {item.critical_count} Critical</span>}
              {item.high_count > 0 && <span className="sev-chip chip-high">🟠 {item.high_count} High</span>}
              {item.medium_count > 0 && <span className="sev-chip chip-med">🟡 {item.medium_count} Medium</span>}
              {item.low_count > 0 && <span className="sev-chip chip-low">🔵 {item.low_count} Low</span>}
              {findingsCount === 0 && <span className="sev-chip chip-clean">🛡️ 0 Vulnerabilities · 0 Quality Bugs</span>}
            </div>
          </div>
        </div>

        <div className="hist-card-header-right">
          <span className="hist-card-time">{fmtDate(item?.created_at)}</span>
          <div className="hist-card-actions">
            <button
              className="hist-btn-load"
              title="Load into Scanner Workspace"
              onClick={(e) => {
                e.stopPropagation()
                if (details) {
                  onLoadInScanner(details)
                } else {
                  fetch(`http://127.0.0.1:8000/api/v1/submit/scan/${item.scan_id}`)
                    .then(r => r.json())
                    .then(d => onLoadInScanner(d))
                }
              }}
            >
              ⚡ Open
            </button>
            <button
              className="hist-btn-export"
              title="Export Report"
              onClick={(e) => {
                e.stopPropagation()
                onExportReport(item.scan_id)
              }}
            >
              📥
            </button>
            <button
              className="hist-btn-delete"
              title="Delete Scan Record"
              onClick={(e) => {
                e.stopPropagation()
                if (confirm("Delete this scan record permanently?")) {
                  onDeleteScan(item.scan_id)
                }
              }}
            >
              🗑️
            </button>
            <span className="hist-chev" data-open={open}>▾</span>
          </div>
        </div>
      </div>

      {/* Expanded Accordion Body */}
      {open && (
        <div className="hist-card-body">
          {loadingDetails ? (
            <div className="hist-loading-state">
              <span className="run-spin" />
              <span>Fetching full source code and analysis artifacts…</span>
            </div>
          ) : (
            <>
              {/* Internal Tab Navigation */}
              <div className="hist-inner-tabs">
                <button
                  className={`hist-inner-tab ${activeTab === 'findings' ? 'active' : ''}`}
                  onClick={() => setActiveTab('findings')}
                >
                  🔍 Detected Findings ({findings.length})
                </button>
                <button
                  className={`hist-inner-tab ${activeTab === 'code' ? 'active' : ''}`}
                  onClick={() => setActiveTab('code')}
                >
                  📄 Full Source Code ({rawCode ? rawCode.split('\n').length : 0} lines)
                </button>
                {summaryText && (
                  <button
                    className={`hist-inner-tab ${activeTab === 'summary' ? 'active' : ''}`}
                    onClick={() => setActiveTab('summary')}
                  >
                    📝 Executive Summary
                  </button>
                )}
              </div>

              {/* Tab: Findings List */}
              {activeTab === 'findings' && (
                <div className="hist-tab-content">
                  {findings.length === 0 ? (
                    <div className="hist-clean-message">
                      <span style={{ fontSize: '32px' }}>🌟</span>
                      <div>
                        <strong>No vulnerabilities or quality defects detected in this scan!</strong>
                        <p style={{ color: 'var(--txt-muted)', fontSize: '0.85rem', margin: '4px 0 0' }}>Code is compliant with OWASP Top 10, AST nesting limits, and static analysis guidelines.</p>
                      </div>
                    </div>
                  ) : (
                    <div className="hist-findings-stack">
                      {findings.map((f, fIdx) => (
                        <FindingCard
                          key={fIdx}
                          index={fIdx}
                          scanId={item.scan_id}
                          finding={f}
                          setCode={setCode}
                          setTab={setTab}
                          setChatQuery={setChatQuery}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab: Source Code Viewer */}
              {activeTab === 'code' && (
                <div className="hist-tab-content">
                  <div className="hist-code-container">
                    <div className="hist-code-header">
                      <span className="hist-code-meta">
                        {lang.toUpperCase()} Source File · {rawCode.length} characters
                      </span>
                      <div className="hist-code-btns">
                        <button
                          className="hist-btn-code-action"
                          onClick={() => handleCopyCode(rawCode)}
                        >
                          {copiedCode ? '✅ Copied!' : '📋 Copy Source'}
                        </button>
                        <button
                          className="hist-btn-code-action primary"
                          onClick={() => {
                            setCode(rawCode)
                            setTab('paste')
                            setView('scanner')
                          }}
                        >
                          🪄 Load in Editor
                        </button>
                      </div>
                    </div>
                    <pre className="hist-code-block">
                      <code>{rawCode || '// No code stored for this scan.'}</code>
                    </pre>
                  </div>
                </div>
              )}

              {/* Tab: Executive Summary */}
              {activeTab === 'summary' && summaryText && (
                <div className="hist-tab-content">
                  {parsedSummary?.executive_overview && (
                    <div className="hist-summary-card">
                      <div className="hist-summary-title">Executive Summary</div>
                      <p className="hist-summary-body">{parsedSummary.executive_overview}</p>
                    </div>
                  )}
                  {parsedSummary?.prioritized_findings && parsedSummary.prioritized_findings.length > 0 && (
                    <div className="hist-summary-card" style={{ marginTop: '12px' }}>
                      <div className="hist-summary-title">Prioritized Action Items</div>
                      <ul style={{ paddingLeft: '20px', color: 'var(--txt)' }}>
                        {parsedSummary.prioritized_findings.map((item, pIdx) => (
                          <li key={pIdx} style={{ marginBottom: '6px' }}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Card Footer */}
              <div className="hist-card-footer">
                <button
                  className="hist-footer-launch-btn"
                  onClick={() => {
                    if (details) {
                      onLoadInScanner(details)
                    } else {
                      fetch(`http://127.0.0.1:8000/api/v1/submit/scan/${item.scan_id}`)
                        .then(r => r.json())
                        .then(d => onLoadInScanner(d))
                    }
                  }}
                >
                  ⚡ Open in Full Workspace (AI Assistant & Live Patches)
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── History Section ─── */
function HistorySection({
  history,
  histLoading,
  fetchHistory,
  onLoadInScanner,
  onDeleteScan,
  onExportReport,
  setChatQuery,
  setCode,
  setLang,
  setTab,
  setView
}) {
  const [searchTerm, setSearchTerm] = useState('')
  const [langFilter, setLangFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [sortBy, setSortBy] = useState('newest')

  const totalScans = history.length
  const javaScans = history.filter(h => (h.language || '').toLowerCase() === 'java').length
  const pyScans = history.filter(h => (h.language || '').toLowerCase() === 'python').length
  const avgHealth = totalScans > 0 
    ? Math.round(history.reduce((acc, h) => acc + (100 - (h.risk_score || 0)), 0) / totalScans) 
    : 100
  const totalIssues = history.reduce((acc, h) => acc + (h.findings_count || 0), 0)
  const cleanScans = history.filter(h => (h.findings_count || 0) === 0 && (h.risk_score || 0) === 0).length

  const filteredScans = history.filter(item => {
    const lang = (item.language || '').toLowerCase()
    const isClean = (item.findings_count || 0) === 0 && (item.risk_score || 0) === 0
    
    if (langFilter !== 'all' && lang !== langFilter) return false
    if (statusFilter === 'clean' && !isClean) return false
    if (statusFilter === 'issues' && isClean) return false
    
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase()
      const matchId = (item.scan_id || '').toLowerCase().includes(q)
      const matchSnippet = (item.snippet || item.raw_code || '').toLowerCase().includes(q)
      const matchLang = lang.includes(q)
      if (!matchId && !matchSnippet && !matchLang) return false
    }
    return true
  }).sort((a, b) => {
    if (sortBy === 'risk') return (b.risk_score || 0) - (a.risk_score || 0)
    if (sortBy === 'issues') return (b.findings_count || 0) - (a.findings_count || 0)
    return new Date(b.created_at || 0) - new Date(a.created_at || 0)
  })

  return (
    <section className="hist-dashboard">
      {/* 1. Header Banner */}
      <div className="hist-dash-header">
        <div className="hist-dash-header-left">
          <div className="hist-dash-icon-glow">🕑</div>
          <div>
            <h2 className="hist-dash-title">Scan History & Audit Logs</h2>
            <p className="hist-dash-subtitle">Review previous vulnerability audits, inspect complete source code, and restore scan sessions.</p>
          </div>
        </div>
        <div className="hist-dash-header-right">
          <button
            id="refresh-history-btn"
            className="hist-refresh-btn-premium"
            onClick={fetchHistory}
            disabled={histLoading}
            title="Refresh history"
          >
            <span style={{ display: 'inline-block', animation: histLoading ? 'spin 1s linear infinite' : 'none' }}>↻</span>
            <span>{histLoading ? 'Refreshing…' : 'Refresh Scans'}</span>
          </button>
        </div>
      </div>

      {/* 2. Analytics Metric Cards */}
      <div className="hist-metrics-grid">
        <div className="hist-metric-card">
          <div className="hist-metric-icon">📊</div>
          <div className="hist-metric-data">
            <span className="hist-metric-val">{totalScans}</span>
            <span className="hist-metric-lbl">Total Scans Executed</span>
          </div>
        </div>
        <div className="hist-metric-card">
          <div className="hist-metric-icon">🛡️</div>
          <div className="hist-metric-data">
            <span className="hist-metric-val" style={{ color: avgHealth >= 80 ? '#10b981' : avgHealth >= 50 ? '#f59e0b' : '#ef4444' }}>
              {avgHealth}/100
            </span>
            <span className="hist-metric-lbl">Average Health Score</span>
          </div>
        </div>
        <div className="hist-metric-card">
          <div className="hist-metric-icon">⚠️</div>
          <div className="hist-metric-data">
            <span className="hist-metric-val" style={{ color: totalIssues > 0 ? '#f87171' : '#10b981' }}>
              {totalIssues}
            </span>
            <span className="hist-metric-lbl">Vulnerabilities Detected</span>
          </div>
        </div>
        <div className="hist-metric-card">
          <div className="hist-metric-icon">✨</div>
          <div className="hist-metric-data">
            <span className="hist-metric-val" style={{ color: '#38bdf8' }}>{cleanScans}</span>
            <span className="hist-metric-lbl">Clean Passes (100%)</span>
          </div>
        </div>
      </div>

      {/* 3. Search & Filter Bar */}
      <div className="hist-controls-bar">
        <div className="hist-search-wrap">
          <span className="hist-search-icon">🔍</span>
          <input
            type="text"
            className="hist-search-input"
            placeholder="Search code snippets, scan IDs, or languages…"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button className="hist-search-clear" onClick={() => setSearchTerm('')}>✕</button>
          )}
        </div>

        <div className="hist-filters-wrap">
          <div className="hist-filter-group">
            <button
              className={`hist-filter-pill ${langFilter === 'all' ? 'active' : ''}`}
              onClick={() => setLangFilter('all')}
            >
              All ({totalScans})
            </button>
            <button
              className={`hist-filter-pill ${langFilter === 'java' ? 'active' : ''}`}
              onClick={() => setLangFilter('java')}
            >
              ☕ Java ({javaScans})
            </button>
            <button
              className={`hist-filter-pill ${langFilter === 'python' ? 'active' : ''}`}
              onClick={() => setLangFilter('python')}
            >
              🐍 Python ({pyScans})
            </button>
          </div>

          <div className="hist-filter-group">
            <button
              className={`hist-filter-pill ${statusFilter === 'all' ? 'active' : ''}`}
              onClick={() => setStatusFilter('all')}
            >
              All Status
            </button>
            <button
              className={`hist-filter-pill ${statusFilter === 'clean' ? 'active' : ''}`}
              onClick={() => setStatusFilter('clean')}
            >
              ✅ Clean
            </button>
            <button
              className={`hist-filter-pill ${statusFilter === 'issues' ? 'active' : ''}`}
              onClick={() => setStatusFilter('issues')}
            >
              ⚠️ Issues
            </button>
          </div>

          <select
            className="hist-sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="newest">🕒 Newest First</option>
            <option value="risk">🔥 Highest Risk</option>
            <option value="issues">⚡ Most Issues</option>
          </select>
        </div>
      </div>

      {/* 4. List of Scans */}
      <div className="hist-cards-list">
        {histLoading && history.length === 0 ? (
          <div className="hist-empty-state">
            <span className="run-spin" style={{ width: '36px', height: '36px' }} />
            <p>Loading scan history…</p>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="hist-empty-state">
            <span style={{ fontSize: '48px' }}>📭</span>
            <h3>No Scans Found</h3>
            <p>{searchTerm || langFilter !== 'all' || statusFilter !== 'all' ? 'No scans match your search or filter criteria.' : 'No scans run yet in this browser session. Switch to the Scanner to run your first code review!'}</p>
            {(searchTerm || langFilter !== 'all' || statusFilter !== 'all') ? (
              <button
                className="hist-btn-reset-filters"
                onClick={() => { setSearchTerm(''); setLangFilter('all'); setStatusFilter('all'); }}
              >
                Reset Filters
              </button>
            ) : (
              <button
                className="hist-btn-reset-filters"
                onClick={() => setView('scanner')}
              >
                🛡️ Open Scanner Workspace
              </button>
            )}
          </div>
        ) : (
          filteredScans.map((item) => (
            <HistoryItem
              key={item.scan_id}
              item={item}
              onLoadInScanner={onLoadInScanner}
              onDeleteScan={onDeleteScan}
              onExportReport={onExportReport}
              setChatQuery={setChatQuery}
              setCode={setCode}
              setLang={setLang}
              setTab={setTab}
              setView={setView}
            />
          ))
        )}
      </div>
    </section>
  )
}

/* ─── Main App ─── */
export default function App() {
  const [view,        setView]        = useState('scanner')
  const [tab,         setTab]         = useState('paste')
  const [code,        setCode]        = useState('')
  const [file,        setFile]        = useState(null)
  const [loading,     setLoading]     = useState(false)
  const [result,      setResult]      = useState(null)
  const [history,     setHistory]     = useState([])
  const [histLoading, setHistLoading] = useState(false)
  const [secAdvice,   setSecAdvice]   = useState([])
  const [filterAgent, setFilterAgent] = useState('all')
  const [filterSev,   setFilterSev]   = useState('all')
  const [searchFilter, setSearchFilter] = useState('')
  const [chatQuery,   setChatQuery]   = useState('')
  const [dragOver,    setDragOver]    = useState(false)
  const [scanStage,   setScanStage]   = useState('')
  const [copiedCode,  setCopiedCode]  = useState(false)

  // Real-time automatic language detection
  const detectedLang = tab === 'upload' && file ? detectLanguage('', file.name) : detectLanguage(code)

  const sessionId = getSessionId()
  const allFindings = result?.findings ?? result?.syntax_errors ?? []
  const rawFindings = allFindings.filter(f => f.validation_status !== 'NO')
  const falsePositives = allFindings.filter(f => f.validation_status === 'NO')
  
  let parsedSummary = null;
  if (result?.summary_text) {
    try {
      parsedSummary = JSON.parse(result.summary_text);
    } catch (e) {
      parsedSummary = { executive_overview: result.summary_text, severity_breakdown: {}, prioritized_findings: [] };
    }
  }
  
  const scanId      = result?.scan_id
  const riskScore   = result?.risk_score
  const isValid     = (result?.status === 'validated' || result?.status === 'completed') && rawFindings.length === 0

  // Apply filters & search query
  const visibleFindings = rawFindings.filter(f => {
    const agentOk = filterAgent === 'all' || f.agent_source === filterAgent
    const sevOk   = filterSev === 'all' || String(f.severity).toLowerCase() === filterSev
    let textOk = true
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase()
      const titleMatch = (f.title || f.issue || '').toLowerCase().includes(q)
      const cweMatch   = (f.cwe_id || '').toLowerCase().includes(q)
      const ruleMatch  = (f.rule_id || '').toLowerCase().includes(q)
      const toolMatch  = (f.tool || '').toLowerCase().includes(q)
      textOk = titleMatch || cweMatch || ruleMatch || toolMatch
    }
    return agentOk && sevOk && textOk
  })

  const fetchHistory = async () => {
    setHistLoading(true)
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/history?session_id=${sessionId}&limit=50`)
      if (res.ok) setHistory(await res.json())
    } catch { /* backend not available */ }
    setHistLoading(false)
  }

  useEffect(() => { fetchHistory() }, [])

  const handleLoadInScanner = (scanData) => {
    setCode(scanData.raw_code || scanData.code || '')
    setTab('paste')
    setResult(scanData)
    setSecAdvice(scanData.security_advice || [])
    setView('scanner')
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const handleDeleteScan = async (scanId) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/${scanId}`, { method: 'DELETE' })
      if (res.ok) {
        setHistory(prev => prev.filter(h => h.scan_id !== scanId))
      } else {
        alert("Failed to delete scan.")
      }
    } catch (e) {
      alert("Error deleting scan: " + e.message)
    }
  }

  const handleExportReport = async (scanId) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/reports/${scanId}/export/markdown`)
      if (!res.ok) throw new Error("Failed to export markdown report")
      const text = await res.text()
      const blob = new Blob([text], { type: 'text/markdown' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scan_report_${scanId.slice(0, 8)}.md`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    } catch (e) {
      alert("Error exporting report: " + e.message)
    }
  }

  const handleCopyEditorCode = () => {
    if (!code) return
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(code)
    } else {
      const ta = document.createElement('textarea')
      ta.value = code
      ta.style.position = 'absolute'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    }
    setCopiedCode(true)
    setTimeout(() => setCopiedCode(false), 2000)
  }

  const run = async () => {
    if (tab === 'paste' && !code.trim()) {
      alert("Please enter code or choose a sample preset.");
      return;
    }
    setLoading(true); setResult(null); setFilterAgent('all'); setFilterSev('all'); setSearchFilter(''); setScanStage('Validating syntax…')
    try {
      let res
      const stages = [
        { text: 'Validating AST syntax & parsing…', delay: 0 },
        { text: 'Running Parallel Security Agents…', delay: 2000 },
        { text: 'Executing Code Quality & Style Linters…', delay: 4000 },
        { text: 'Analyzing Cyclomatic Complexity & AST nesting…', delay: 6000 },
        { text: 'Cross-referencing RAG Security Knowledge Base…', delay: 9000 },
        { text: 'Synthesizing automated remediation patches…', delay: 12000 },
        { text: 'Computing comprehensive Risk & Health Score…', delay: 15000 },
        { text: 'Composing Executive Pull Request Summary…', delay: 18000 },
      ]
      const timers = stages.map(s => setTimeout(() => setScanStage(s.text), s.delay))
      if (tab === 'paste') {
        res = await fetch('http://127.0.0.1:8000/api/v1/submit/paste', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language: detectedLang, session_id: sessionId }),
        })
      } else {
        if (!file) { alert('Select a file first.'); setLoading(false); return }
        const fd = new FormData()
        fd.append('file', file)
        res = await fetch('http://127.0.0.1:8000/api/v1/submit/upload', {
          method: 'POST',
          headers: { 'x-session-id': sessionId },
          body: fd,
        })
      }
      const data = await res.json()
      setResult(data)
      setSecAdvice(data.security_advice ?? [])
      setScanStage('')
      fetchHistory()
    } catch {
      setResult({ status: 'error', message: 'Cannot reach backend server. Please verify the FastAPI service is running.', findings: [] })
      setScanStage('')
    }
    setLoading(false)
  }

  const secCount     = rawFindings.filter(f => f.agent_source === 'security_vulnerability').length
  const qualityCount = rawFindings.filter(f => f.agent_source === 'code_analysis').length
  const compCount    = rawFindings.filter(f => f.agent_source === 'complexity').length
  const depCount     = rawFindings.filter(f => f.agent_source === 'dependency').length

  const lineCount = code ? code.split('\n').length : 0
  const charCount = code ? code.length : 0

  return (
    <>
      {/* ══ HEADER ══ */}
      <header className="hdr">
        <div className="hdr-brand">
          <div className="hdr-logo">
            <div className="hlg-ring hlg-r1" />
            <div className="hlg-ring hlg-r2" />
            <div className="hlg-core">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
              </svg>
            </div>
          </div>
          <div>
            <h1 className="hdr-h1">Smart Code Inspection Platform with <span>Vulnerability Detection System</span></h1>
            <p className="hdr-tag">Multi-Agent Static Analysis · RAG Knowledge Base · Instant Fixes</p>
          </div>
        </div>
        <nav className="hdr-pills">
          <button id="nav-scanner" className={`hdr-pill ${view === 'scanner' ? 'hdr-pill-active' : ''}`} onClick={() => setView('scanner')}>
            <span>🛡️</span> Scanner Studio
          </button>
          <button id="nav-kb" className={`hdr-pill ${view === 'kb' ? 'hdr-pill-active' : ''}`} onClick={() => setView('kb')}>
            <span>📚</span> Knowledge Base
          </button>
          <button id="nav-history" className={`hdr-pill ${view === 'history' ? 'hdr-pill-active' : ''}`} onClick={() => setView('history')}>
            <span>🕑</span> Audit History {history.length > 0 && <span className="hdr-badge-count">{history.length}</span>}
          </button>
        </nav>
      </header>

      {/* ══ MAIN VIEW ══ */}
      {view === 'kb' ? (
        <KBTester />
      ) : view === 'scanner' ? (
      <main className="app-grid">

        {/* LEFT PANEL: Monaco Studio */}
        <section className="panel left-panel">
          <div className="p-inner">
            
            {/* Studio Header Bar */}
            <div className="studio-topbar">
              {/* Tab Mode Switcher */}
              <div className="tabs-row">
                <button id="tab-paste" className={`ptab ${tab === 'paste' ? 'ptab-on' : ''}`} onClick={() => setTab('paste')}>
                  <span>📝</span> Editor
                </button>
                <button id="tab-upload" className={`ptab ${tab === 'upload' ? 'ptab-on' : ''}`} onClick={() => setTab('upload')}>
                  <span>📂</span> Upload File
                </button>
              </div>

              {/* Dynamic Auto-Detected Language Pill Badge */}
              <div className="studio-auto-badge" title="Language is automatically detected from your code syntax in real-time">
                <span className="sab-pulse-dot" />
                <span className="sab-label">Language:</span>
                <span className={`sab-pill ${detectedLang}`}>
                  {detectedLang === 'java' ? '☕ Java (Auto)' : '🐍 Python (Auto)'}
                </span>
              </div>
            </div>

            {/* Quick Sample Preset Pills */}
            <div className="preset-pill-bar">
              <span className="preset-bar-lbl">✨ Quick Samples:</span>
              <div className="preset-pills-list">
                {PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    className="preset-chip"
                    onClick={() => {
                      setCode(preset.code)
                      setTab('paste')
                    }}
                    title="Load sample snippet into Monaco Editor"
                  >
                    <span>{preset.title}</span>
                    <span className="preset-badge" style={{ background: preset.badgeColor }}>
                      {preset.badge}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Editor Workspace */}
            {tab === 'paste' ? (
              <div className="editor-wrapper">
                <div className="editor-top-meta">
                  <span className="editor-meta-pill">
                    📏 {lineCount} lines · {charCount} chars · UTF-8
                  </span>
                  <div className="editor-meta-actions">
                    <button
                      className="editor-tool-btn"
                      onClick={handleCopyEditorCode}
                      title="Copy code to clipboard"
                    >
                      {copiedCode ? '✅ Copied!' : '📋 Copy'}
                    </button>
                    <button
                      className="editor-tool-btn"
                      onClick={() => setCode('')}
                      title="Clear editor contents"
                    >
                      🧹 Clear
                    </button>
                  </div>
                </div>
                <div className="editor-box">
                  <Editor
                    height="100%"
                    language={detectedLang}
                    theme="vs-dark"
                    value={code}
                    onChange={v => setCode(v ?? '')}
                    options={{
                      minimap: { enabled: false },
                      fontSize: 13.5,
                      fontFamily: 'JetBrains Mono, monospace',
                      padding: { top: 16, bottom: 16 },
                      lineNumbers: 'on',
                      scrollBeyondLastLine: false,
                      roundedSelection: true,
                      automaticLayout: true,
                      cursorBlinking: 'smooth',
                      cursorSmoothCaretAnimation: 'on',
                      smoothScrolling: true,
                    }}
                  />
                </div>
              </div>
            ) : (
              <label
                className={`drop-zone ${dragOver ? 'drop-zone-over' : ''}`}
                onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={e => {
                  e.preventDefault()
                  setDragOver(false)
                  const droppedFile = e.dataTransfer.files?.[0]
                  if (droppedFile) {
                    const ext = droppedFile.name.split('.').pop()?.toLowerCase()
                    if (ext === 'py' || ext === 'java') {
                      setFile(droppedFile)
                    } else {
                      alert('Unsupported file type. Please upload .py or .java files.')
                    }
                  }
                }}
              >
                <input id="file-upload" type="file" accept=".py,.java" style={{ display: 'none' }}
                  onChange={e => {
                    const f = e.target.files?.[0]
                    if (f) {
                      setFile(f)
                    }
                  }} />
                <div className="dz-icon-circle">
                  <span className="dz-ico">{dragOver ? '⬇️' : '📂'}</span>
                </div>
                <strong className="dz-title">{dragOver ? 'Drop it right here!' : 'Drag & drop source file here'}</strong>
                <span className="dz-hint">Supports Java (.java) and Python (.py) · Click to browse</span>
                {file && (
                  <div className="dz-file-badge">
                    <span>📄 {file.name}</span>
                    <span className="dz-file-size">({Math.round(file.size / 1024)} KB)</span>
                    <button className="dz-remove" onClick={(e) => { e.preventDefault(); setFile(null); }}>✕</button>
                  </div>
                )}
              </label>
            )}

            {/* Run & Action Row */}
            <div className="run-row-cute">
              <div className="run-row-left">
                <button
                  id="run-analysis-btn"
                  className={`run-btn-radiant ${loading ? 'run-loading' : ''}`}
                  onClick={run}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <span className="run-spin" />
                      <span>Analyzing AST & Security Rules…</span>
                    </>
                  ) : (
                    <>
                      <span className="run-bolt">⚡</span>
                      <span>Run Multi-Agent Scan</span>
                    </>
                  )}
                </button>
                {result && (
                  <button
                    id="new-analysis-btn"
                    className="run-btn-secondary"
                    onClick={() => { setResult(null); setCode(''); setFile(null); }}
                  >
                    🔄 Clear Scan
                  </button>
                )}
              </div>

              <div className="run-agent-status-pill">
                <span className="status-dot-pulse" />
                <span>4 AI Agents Active</span>
              </div>
            </div>

            {/* Animated Progress Bar with Live Multi-Agent Stages */}
            {loading && (
              <div className="scan-progress-cute">
                <div className="progress-bar-track">
                  <div className="progress-bar-fill" />
                </div>
                <div className="progress-agents-row">
                  <div className="par-agent-badge"><span className="par-agent-dot active" />🛡️ Syntax AST</div>
                  <div className="par-agent-badge"><span className="par-agent-dot active" />🤖 Security Scanner</div>
                  <div className="par-agent-badge"><span className="par-agent-dot active" />🔍 Quality Linter</div>
                  <div className="par-agent-badge"><span className="par-agent-dot active" />🧠 Complexity Engine</div>
                  <div className="par-agent-badge"><span className="par-agent-dot active" />🪄 Auto-Remediation</div>
                </div>
                {scanStage && (
                  <div className="progress-stage-text">
                    {scanStage}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* RIGHT PANEL: Intelligence & Remediation */}
        <section className="panel right-panel">
          <div className="p-inner">
            
            <div className="rp-top">
              <div className="rp-title-wrap">
                <h2 className="rp-h2">Scan Results & Remediation</h2>
                {result && (
                  <span className="rp-sub-stats">
                    Session ID: {scanId ? scanId.slice(0, 8) : 'Local'}
                  </span>
                )}
              </div>
              {result && (
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span className={`rp-pill ${isValid ? 'rpill-ok' : 'rpill-err'}`}>
                    {isValid ? '● Clean Pass' : `● ${rawFindings.length} Issue${rawFindings.length !== 1 ? 's' : ''}`}
                  </span>
                  {scanId && (
                    <button
                      className="rp-export-btn"
                      onClick={() => handleExportReport(scanId)}
                      title="Download Markdown Report"
                    >
                      📥 Export
                    </button>
                  )}
                </div>
              )}
            </div>

            <div className="rp-body">
              {!result ? (
                /* EMPTY STATE */
                <div className="empty-st-cute">
                  <div className="mascot-orb-wrap">
                    <div className="mascot-orb-core">🛡️</div>
                    <div className="mascot-orb-ring r1" />
                    <div className="mascot-orb-ring r2" />
                  </div>
                  <h3 className="empty-title">Ready for Deep Code Review</h3>
                  <p className="empty-subtitle">
                    Select a sample preset or paste your Java / Python code to start our multi-agent static security scan.
                  </p>
                  <div className="empty-feature-cards">
                    <div className="ef-card">
                      <span className="ef-icon">🔒</span>
                      <strong>Security Agent</strong>
                      <span>SpotBugs & Bandit OWASP injection analysis</span>
                    </div>
                    <div className="ef-card">
                      <span className="ef-icon">🔍</span>
                      <strong>Quality Linter</strong>
                      <span>PMD & Pylint clean code standards</span>
                    </div>
                    <div className="ef-card">
                      <span className="ef-icon">🪄</span>
                      <strong>Auto Fix Engine</strong>
                      <span>Instant side-by-side patch generation</span>
                    </div>
                  </div>
                </div>

              ) : isValid ? (
                /* INLINE CELEBRATORY SUCCESS */
                <div className="inline-ok-cute">
                  <div className="iok-trophy-wrap">
                    <span className="iok-trophy">🌟</span>
                  </div>
                  <h3 className="iok-title">100% Clean Security Pass!</h3>
                  <p className="iok-sub">
                    Zero vulnerabilities, zero high-complexity nesting issues, and zero quality defects detected.
                  </p>
                  <div className="iok-cert-badge">
                    <span>🛡️ Verified Clean Code · Grade A+ (100/100)</span>
                  </div>
                </div>

              ) : rawFindings.length > 0 ? (
                /* FINDINGS STATE */
                <div className="err-state">
                  
                  {/* Dashboard Metrics */}
                  <AgentStats findings={rawFindings} riskScore={riskScore} history={history} scanId={scanId} />

                  {/* Executive PR Summary */}
                  {parsedSummary && (
                    <div className="pr-summary-card-cute">
                      <div className="prs-header">
                        <span className="prs-icon">📝</span>
                        <div>
                          <strong className="prs-title">Executive Pull Request Summary</strong>
                          <div className="prs-sub">Automated developer remediation insights</div>
                        </div>
                        {parsedSummary.total_estimated_fix_time && (
                          <div className="prs-time-pill">
                            ⏱️ Est. Fix Time: {parsedSummary.total_estimated_fix_time}
                          </div>
                        )}
                      </div>
                      
                      <div className="prs-overview">
                        {parsedSummary.executive_overview}
                      </div>

                      {parsedSummary.prioritized_findings && parsedSummary.prioritized_findings.length > 0 && (
                        <div className="prs-priorities">
                          <span className="prs-priorities-lbl">Top Priority Remediation Items:</span>
                          <div className="prs-priorities-list">
                            {parsedSummary.prioritized_findings.map((pf, idx) => (
                              <div key={idx} className="prs-priority-item">
                                <div className="prs-p-top">
                                  <span className={`sev-chip ${pf.severity === 'critical' ? 'chip-critical' : pf.severity === 'high' ? 'chip-high' : 'chip-med'}`}>
                                    {pf.severity.toUpperCase()}
                                  </span>
                                  <strong className="prs-p-title">{pf.title}</strong>
                                  {pf.fix_time_estimate && (
                                    <span className="prs-p-time">⏱ {pf.fix_time_estimate}</span>
                                  )}
                                </div>
                                <div className="prs-p-rec">{pf.recommendation}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Global One-Click Fix Section */}
                  <GlobalFixSection scanId={scanId} setCode={setCode} setTab={setTab} />

                  {/* Search and Filters Toolbar */}
                  <div className="findings-filter-toolbar">
                    <div className="ff-search-box">
                      <span className="ff-search-icon">🔍</span>
                      <input
                        type="text"
                        className="ff-search-input"
                        placeholder="Filter findings by keyword, CWE, rule ID…"
                        value={searchFilter}
                        onChange={(e) => setSearchFilter(e.target.value)}
                      />
                      {searchFilter && (
                        <button className="ff-clear-btn" onClick={() => setSearchFilter('')}>✕</button>
                      )}
                    </div>

                    <div className="ff-pills-row">
                      <div className="ff-group">
                        <span className="ff-lbl">Agent:</span>
                        <div className="ff-chips">
                          {[
                            { v: 'all',                    label: `All (${rawFindings.length})` },
                            { v: 'security_vulnerability', label: `🔒 Security (${secCount})` },
                            { v: 'code_analysis',          label: `🔍 Quality (${qualityCount})` },
                            { v: 'complexity',             label: `🧠 Complexity (${compCount})` },
                            { v: 'dependency',             label: `📦 Dependencies (${depCount})` },
                          ].map(({ v, label }) => (
                            <button
                              key={v}
                              id={`filter-agent-${v}`}
                              className={`ff-pill ${filterAgent === v ? 'active' : ''}`}
                              onClick={() => setFilterAgent(v)}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="ff-group">
                        <span className="ff-lbl">Severity:</span>
                        <div className="ff-chips">
                          {['all', 'critical', 'high', 'medium', 'low'].map(sv => (
                            <button
                              key={sv}
                              id={`filter-sev-${sv}`}
                              className={`ff-pill ${filterSev === sv ? 'active' : ''}`}
                              onClick={() => setFilterSev(sv)}
                            >
                              {sv.charAt(0).toUpperCase() + sv.slice(1)}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Findings list */}
                  <div className="fc-stack">
                    {visibleFindings.length > 0
                      ? visibleFindings.map((f, i) => (
                          <FindingCard
                            key={i}
                            index={i}
                            scanId={scanId}
                            finding={{
                              ...f,
                              title: f.title || f.issue,
                              suggested_fix: f.suggested_fix || f.fix,
                            }}
                            setCode={setCode}
                            setTab={setTab}
                            setChatQuery={setChatQuery}
                          />
                        ))
                      : (
                        <div className="no-match-cute">
                          <span>🔍</span>
                          <p>No findings match the current search or severity filter.</p>
                          <button
                            className="no-match-reset-btn"
                            onClick={() => { setFilterAgent('all'); setFilterSev('all'); setSearchFilter(''); }}
                          >
                            Reset Filters
                          </button>
                        </div>
                      )
                    }
                  </div>

                  {/* False Positives Section */}
                  {falsePositives.length > 0 && (
                    <div style={{ marginTop: '24px' }}>
                      <h3 style={{ color: 'var(--txt-muted)', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '8px', marginBottom: '16px', fontSize: '1rem' }}>
                        Dismissed False Positives ({falsePositives.length})
                      </h3>
                      <div className="fc-stack" style={{ opacity: 0.75 }}>
                        {falsePositives.map((f, i) => (
                          <FindingCard
                            key={`fp-${i}`}
                            index={3}
                            scanId={scanId}
                            finding={{
                              ...f,
                              title: f.title || f.issue,
                              suggested_fix: f.suggested_fix || f.fix,
                            }}
                            setCode={setCode}
                            setTab={setTab}
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Chat UI */}
                  {scanId && <ChatUI scanId={scanId} sessionId={sessionId} externalQuery={chatQuery} setExternalQuery={setChatQuery} />}
                </div>

              ) : (
                /* Backend Error Message */
                <div className="result-box"><pre>{result.message}</pre></div>
              )}

              {/* ── Security Advice from RAG KB ── */}
              {secAdvice.length > 0 && (
                <div className="sa-section">
                  <div className="sa-section-hd">
                    <span>🧠</span>
                    <span className="sa-section-title">Knowledge Base Grounding</span>
                    <span className="sa-section-sub">{secAdvice.length} standard reference articles</span>
                  </div>
                  {secAdvice.map((a, i) => <SecurityAdviceCard key={i} advice={a} />)}
                </div>
              )}
            </div>
          </div>
        </section>

      </main>
      ) : (
        <HistorySection
          history={history}
          histLoading={histLoading}
          fetchHistory={fetchHistory}
          onLoadInScanner={handleLoadInScanner}
          onDeleteScan={handleDeleteScan}
          onExportReport={handleExportReport}
          setChatQuery={setChatQuery}
          setCode={setCode}
          setLang={setLang}
          setTab={setTab}
          setView={setView}
        />
      )}
    </>
  )
}
