import { useState, useEffect, useRef } from 'react'
import Editor from '@monaco-editor/react'
import ChatUI from './ChatUI'
import KBTester from './KBTester'


/* ─── Severity badge helpers ─── */
const SEV_META = {
  critical: { color: 'var(--red)',    bg: 'var(--red-bg)',   border: 'var(--red-border)',   label: 'CRITICAL' },
  high:     { color: 'var(--red)',    bg: 'var(--red-bg)',   border: 'var(--red-border)',   label: 'HIGH'     },
  medium:   { color: 'var(--gold)',   bg: 'var(--gold-bg)',  border: 'var(--gold-border)',  label: 'MEDIUM'   },
  low:      { color: '#64748b',       bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.3)', label: 'LOW' },
  info:     { color: 'var(--primary)', bg: 'rgba(14,165,233,0.1)', border: 'rgba(14,165,233,0.3)', label: 'INFO' },
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
  
  if (isSec) { bg = 'rgba(239,68,68,0.1)'; col = '#f87171'; bor = 'rgba(239,68,68,0.3)'; lbl = '🔒 Security' }
  else if (isComp) { bg = 'rgba(59,130,246,0.1)'; col = '#60a5fa'; bor = 'rgba(59,130,246,0.3)'; lbl = '🧠 Complexity' }
  else if (isDep) { bg = 'rgba(245,158,11,0.1)'; col = '#fbbf24'; bor = 'rgba(245,158,11,0.3)'; lbl = '📦 Dependency' }
  else if (isLic) { bg = 'rgba(16,185,129,0.1)'; col = '#34d399'; bor = 'rgba(16,185,129,0.3)'; lbl = '⚖️ License' }

  return (
    <span
      className="agent-badge"
      style={{ background: bg, color: col, border: `1px solid ${bor}` }}
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
      style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
    >
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
  const bg = isYes ? 'rgba(16,185,129,0.1)' : isNo ? 'rgba(239,68,68,0.1)' : 'rgba(245,158,11,0.1)'
  const border = isYes ? 'rgba(16,185,129,0.3)' : isNo ? 'rgba(239,68,68,0.3)' : 'rgba(245,158,11,0.3)'
  const label = isYes ? '✓ Validated' : isNo ? '✗ False Positive' : '⚠ Needs Review'
  return (
    <span className="sev-pill" style={{ color, background: bg, border: `1px solid ${border}`, marginLeft: '8px' }}>
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
          <span className="sa-ico">🛡</span>
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
      // Update the editor code and switch tab
      setCode(data.patched_code);
      setTab('paste');
      alert("✅ Code updated in the compiler!");
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
          {/* Left strip: severity color */}
          <div className="fc-sev-strip" style={{ background: sevMeta.color }} />

          <div className="fc-meta">
            <div className="fc-meta-top">
              {/* Agent badge */}
              <AgentBadge source={finding.agent_source} />
              {/* Severity pill */}
              <SevPill severity={finding.severity} cvss={finding.cvss_score} />
              {/* Validation Status pill */}
              <ValidationPill status={finding.validation_status} />
              {/* Location */}
              {finding.line != null && (
                <span className="fc-loc">
                  Line {finding.line}{finding.column != null ? ` · Col ${finding.column}` : ''}
                </span>
              )}
            </div>

            {/* Title */}
            <span className="fc-title">{finding.title || finding.issue}</span>

            {/* OWASP / CWE badges for security findings */}
            {isSec && (
              <div className="fc-badges">
                {finding.owasp_type && (
                  <span className="fc-badge fc-owasp">{finding.owasp_type}</span>
                )}
                {finding.cwe_id && (
                  <span className="fc-badge fc-cwe">{finding.cwe_id}</span>
                )}
                {finding.tool && (
                  <span className="fc-badge fc-tool">{finding.tool.toUpperCase()}</span>
                )}
              </div>
            )}
            {!isSec && finding.tool && (
              <div className="fc-badges">
                <span className="fc-badge fc-tool">{finding.tool.toUpperCase()}</span>
                {finding.rule_id && <span className="fc-badge fc-rule">{finding.rule_id}</span>}
              </div>
            )}
          </div>
        </div>
        <span className="fc-chev" data-open={open}>▾</span>
      </button>

      {open && (
        <div className="fc-body">
          {/* Explanation */}
          {(finding.explanation || finding.fix) && (
            <div className="fc-explanation">
              <span className="fc-section-lbl">📋 Explanation</span>
              <p className="fc-explanation-text">{finding.explanation || finding.fix}</p>
            </div>
          )}

          {/* Ask the Assistant */}
          {setChatQuery && (
            <div style={{ marginTop: '12px', marginBottom: '12px' }}>
              <button 
                onClick={(e) => { 
                  e.stopPropagation(); 
                  setChatQuery(`Explain this finding: ${finding.title || finding.issue}`);
                }}
                style={{ background: 'rgba(14, 165, 233, 0.15)', border: '1px solid rgba(14, 165, 233, 0.3)', padding: '6px 12px', borderRadius: '6px', color: '#38bdf8', cursor: 'pointer', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 'bold' }}
              >
                <span>💬</span> Ask the Assistant about this
              </button>
            </div>
          )}

          {/* Explainability Block (Phase 11) */}
          <div className="fc-explainability-block" style={{ marginTop: '12px', padding: '12px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
            
            <div style={{ flex: '1 1 120px' }}>
              <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.75rem' }}>DETECTED BY</div>
              <ul style={{ listStyleType: 'none', padding: 0, margin: 0 }}>
                {finding.detected_by ? (
                  (typeof finding.detected_by === 'string' ? JSON.parse(finding.detected_by) : finding.detected_by).map((tool, idx) => (
                    <li key={idx} style={{ color: 'var(--primary)', fontSize: '0.9rem', marginBottom: '2px', fontWeight: 'bold' }}>
                      ↓ {tool}
                    </li>
                  ))
                ) : (
                  <li style={{ color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold' }}>↓ {finding.tool || 'Unknown'}</li>
                )}
              </ul>
            </div>

            {finding.rule_id && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.75rem' }}>RULE</div>
                <div style={{ color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold' }}>↓ {finding.rule_id}</div>
              </div>
            )}

            {finding.owasp_type && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.75rem' }}>OWASP</div>
                <div style={{ color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold' }}>↓ {finding.owasp_type}</div>
              </div>
            )}

            {finding.cwe_id && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.75rem' }}>CWE</div>
                <div style={{ color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold' }}>↓ {finding.cwe_id}</div>
              </div>
            )}

            {finding.confidence_score && (
              <div style={{ flex: '1 1 120px' }}>
                <div className="fc-section-lbl" style={{ marginBottom: '4px', color: 'var(--txt-muted)', fontSize: '0.75rem' }}>CONFIDENCE</div>
                <div style={{ color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold' }}>↓ {finding.confidence_score}</div>
              </div>
            )}

          </div>

          {/* Grounding source (RAG KB) */}
          {finding.grounding_source && (
            <div className="fc-grounding">
              <span className="fc-section-lbl">📚 Knowledge Base Reference</span>
              <span className="fc-grounding-src">
                {finding.grounding_source.replace(/\.md$/, '').replace(/_/g, ' ')}
              </span>
            </div>
          )}

          {/* Auto Fix / Diff View */}
          {(finding.suggested_fix || finding.fix) && (
            <div className="fc-fix" style={{ marginTop: '16px' }}>
              
              {/* Original Code */}
              {finding.original_code && (
                <div style={{ marginBottom: '12px' }}>
                  <span className="fc-section-lbl" style={{ color: '#ef4444' }}>❌ Original Code</span>
                  <pre className="fc-code" style={{ borderLeft: '3px solid #ef4444' }}>
                    <code>{finding.original_code}</code>
                  </pre>
                </div>
              )}

              {/* Secure Code */}
              <div style={{ position: 'relative' }}>
                <span className="fc-section-lbl" style={{ color: '#10b981' }}>✅ Secure Code</span>
                <pre className="fc-code" style={{ borderLeft: '3px solid #10b981', paddingBottom: '40px' }}>
                  <code>{finding.suggested_fix || finding.fix}</code>
                </pre>
                
                {/* Action Buttons */}
                <div style={{ position: 'absolute', bottom: '8px', right: '8px', display: 'flex', gap: '8px' }}>
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
                    style={{ background: 'rgba(255,255,255,0.1)', border: 'none', padding: '4px 8px', borderRadius: '4px', color: 'var(--txt-muted)', cursor: 'pointer', fontSize: '0.8rem' }}
                  >
                    {copied ? "✅ Copied!" : "📋 Copy"}
                  </button>
                  <button 
                    onClick={(e) => { e.stopPropagation(); handleApplyFix(); }}
                    disabled={fixing}
                    style={{ background: 'var(--primary)', border: 'none', padding: '4px 12px', borderRadius: '4px', color: '#000', fontWeight: 'bold', cursor: 'pointer', fontSize: '0.8rem' }}
                  >
                    {fixing ? "Fixing..." : "🪄 Apply Fix"}
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
    alert("✅ Code automatically pasted to compiler view!");
  };

  return (
    <div className="global-fix-section" style={{ marginTop: '24px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)', borderRadius: '12px', padding: '20px' }}>
      <h3 style={{ margin: '0 0 12px 0', color: '#10b981', display: 'flex', alignItems: 'center', gap: '8px' }}>
        ✨ After Analysis: Full Corrected Code
      </h3>
      <p style={{ color: 'var(--txt-muted)', fontSize: '0.9rem', marginBottom: '16px', lineHeight: '1.4' }}>
        Generate a single unified file containing all the fixes for the issues found during analysis.
      </p>
      
      {!patchedCode ? (
        <button 
          onClick={generateFullCode}
          disabled={generating}
          style={{ background: '#10b981', color: 'black', padding: '10px 16px', border: 'none', borderRadius: '6px', fontWeight: 'bold', cursor: 'pointer', opacity: generating ? 0.7 : 1 }}
        >
          {generating ? 'Generating Code...' : '🚀 Generate Full Corrected Code'}
        </button>
      ) : (
        <div style={{ position: 'relative' }}>
          <pre className="fc-code" style={{ borderLeft: '3px solid #10b981', paddingBottom: '40px', maxHeight: '400px', overflowY: 'auto' }}>
            <code>{patchedCode}</code>
          </pre>
          <div style={{ position: 'absolute', bottom: '8px', right: '8px', display: 'flex', gap: '8px' }}>
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
                  alert("Copied to clipboard!");
              }}
              style={{ background: 'rgba(255,255,255,0.1)', border: 'none', padding: '6px 12px', borderRadius: '4px', color: 'var(--txt-muted)', cursor: 'pointer', fontSize: '0.85rem' }}
            >
              📋 Copy
            </button>
            <button 
              onClick={handleAutoFix}
              style={{ background: '#10b981', border: 'none', padding: '6px 16px', borderRadius: '4px', color: '#000', fontWeight: 'bold', cursor: 'pointer', fontSize: '0.9rem' }}
            >
              🪄 Auto Fix (Paste to Compiler)
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

  // Calculate Trend
  let trendText = null;
  let trendColor = 'var(--txt-muted)';
  if (history && history.length > 0 && riskScore !== undefined && riskScore !== null) {
    // History is ordered newest first. Find the previous scan.
    // If the first scan in history is the current one, look at the second one.
    const currentIsFirst = history[0].scan_id === scanId;
    const previousScan = currentIsFirst ? history[1] : history[0];
    
    if (previousScan && previousScan.risk_score !== undefined && previousScan.risk_score !== null) {
      const prevScore = previousScan.risk_score;
      if (riskScore < prevScore) {
        trendText = `Previous Scan (${prevScore}) ↓ Current Scan (${riskScore}) [Trending Down 🟢]`;
        trendColor = '#10b981';
      } else if (riskScore > prevScore) {
        trendText = `Previous Scan (${prevScore}) ↑ Current Scan (${riskScore}) [Trending Up 🔴]`;
        trendColor = '#ef4444';
      } else {
        trendText = `Previous Scan (${prevScore}) → Current Scan (${riskScore}) [Unchanged ⚪]`;
        trendColor = '#94a3b8';
      }
    }
  }

  // Calculate Health Grade
  let healthGrade = 'F';
  let gradeColor = '#ef4444';
  if (riskScore >= 90) { healthGrade = 'A'; gradeColor = '#10b981'; }
  else if (riskScore >= 80) { healthGrade = 'B'; gradeColor = '#34d399'; }
  else if (riskScore >= 70) { healthGrade = 'C'; gradeColor = '#fbbf24'; }
  else if (riskScore >= 60) { healthGrade = 'D'; gradeColor = '#f59e0b'; }

  // Visual Bars Helper
  const renderBlocks = (count) => {
    if (count === 0) return <span style={{color: 'var(--txt-muted)'}}>0</span>;
    return '■'.repeat(Math.min(count, 15)) + (count > 15 ? '+' : '');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Code Health Score Banner */}
      {riskScore !== undefined && riskScore !== null && (
        <div style={{ background: 'rgba(255,255,255,0.03)', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: '0.9rem', color: 'var(--txt-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>Overall Code Health</div>
            <div style={{ fontSize: '2.5rem', fontWeight: 'bold', color: gradeColor, lineHeight: '1' }}>{healthGrade} <span style={{ fontSize: '1rem', color: 'var(--txt-muted)' }}>({riskScore}/100)</span></div>
          </div>
          {trendText && (
            <div style={{ fontSize: '0.85rem', color: trendColor, background: 'rgba(0,0,0,0.2)', padding: '6px 12px', borderRadius: '20px' }}>
              {trendText}
            </div>
          )}
        </div>
      )}

      <div className="agent-stats">

      {/* Category Charts */}
      <div className="agent-stat-card agent-stat-sec">
        <span className="ast-ico">🔒</span>
        <div className="ast-info">
          <span className="ast-count" style={{ letterSpacing: '2px', color: '#f87171' }}>{renderBlocks(secCount)}</span>
          <span className="ast-label">Security ({secCount})</span>
        </div>
      </div>
      <div className="agent-stat-card agent-stat-quality">
        <span className="ast-ico">🔍</span>
        <div className="ast-info">
          <span className="ast-count" style={{ letterSpacing: '2px', color: '#c084fc' }}>{renderBlocks(qualCount)}</span>
          <span className="ast-label">Quality ({qualCount})</span>
        </div>
      </div>
      <div className="agent-stat-card" style={{ background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.2)' }}>
        <span className="ast-ico">🧠</span>
        <div className="ast-info">
          <span className="ast-count" style={{ color: '#60a5fa' }}>{compCount}</span>
          <span className="ast-label">Complexity</span>
        </div>
      </div>
      <div className="agent-stat-card" style={{ background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.2)' }}>
        <span className="ast-ico">📦</span>
        <div className="ast-info">
          <span className="ast-count" style={{ color: '#fbbf24' }}>{depCount}</span>
          <span className="ast-label">Dependency</span>
        </div>
      </div>
      <div className="agent-stat-card" style={{ background: 'rgba(16,185,129,0.05)', border: '1px solid rgba(16,185,129,0.2)' }}>
        <span className="ast-ico">⚖️</span>
        <div className="ast-info">
          <span className="ast-count" style={{ color: '#34d399' }}>{licCount}</span>
          <span className="ast-label">License</span>
        </div>
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
function HistoryItem({ item }) {
  const [open, setOpen] = useState(false)
  const status = item?.status || 'unknown'
  const lang = item?.language || 'unknown'
  const source = item?.source_type || 'unknown'
  const ok = status === 'validated' || status === 'completed'
  const isFailed = status === 'failed' || status === 'rejected'
  const langIcon = lang.toLowerCase() === 'python' ? '🐍' : (lang.toLowerCase() === 'java' ? '☕' : '📄')
  const srcIcon = source === 'upload' ? '📂' : '📝'

  return (
    <div className={`hi ${open ? 'hi-open' : ''}`}>
      <button className="hi-hd" onClick={() => setOpen(v => !v)}>
        <div className="hi-left">
          <div className="hi-icon-wrap">
            <span className={`hi-dot ${ok ? 'hi-dot-ok' : isFailed ? 'hi-dot-err' : 'hi-dot-warn'}`} />
          </div>
          <div className="hi-meta">
            <span className={`hi-lang ${lang.toLowerCase()}`}>
              {langIcon} {lang.charAt(0).toUpperCase() + lang.slice(1)}
            </span>
            <span className="hi-src" title={`Source: ${source}`}>{srcIcon}</span>
          </div>
          <span className={`hi-status ${ok ? 'hi-ok' : isFailed ? 'hi-fail' : 'hi-warn'}`}>
            {ok ? '✓ Passed' : status === 'rejected' ? '⚠ Rejected' : isFailed ? '✗ Failed' : '⚠ Unknown'}
          </span>
        </div>
        <div className="hi-right">
          <span className="hi-time">{fmtDate(item?.created_at)}</span>
          <div className={`hi-chev ${open ? 'open' : ''}`}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
        </div>
      </button>
      {open && item?.snippet && (
        <div className="hi-body">
          <span className="hi-snip-lbl">Code Snippet</span>
          <code className="hi-snip">{item.snippet}{item.snippet.length >= 120 ? '…' : ''}</code>
        </div>
      )}
    </div>
  )
}

/* ─── Main App ─── */
export default function App() {
  const [view,        setView]        = useState('scanner')
  const [tab,         setTab]         = useState('paste')
  const [code,        setCode]        = useState('')
  const [lang,        setLang]        = useState('python')
  const [file,        setFile]        = useState(null)
  const [loading,     setLoading]     = useState(false)
  const [result,      setResult]      = useState(null)
  const [history,     setHistory]     = useState([])
  const [histLoading, setHistLoading] = useState(false)
  const [secAdvice,   setSecAdvice]   = useState([])
  const [filterAgent, setFilterAgent] = useState('all')   // 'all' | 'security_vulnerability' | 'code_analysis'
  const [filterSev,   setFilterSev]   = useState('all')   // 'all' | 'critical' | 'high' | 'medium' | 'low'
  const [chatQuery,   setChatQuery]   = useState('')
  const [dragOver,    setDragOver]    = useState(false)
  const [scanStage,   setScanStage]   = useState('')

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

  // Apply filters
  const visibleFindings = rawFindings.filter(f => {
    const agentOk = filterAgent === 'all' || f.agent_source === filterAgent
    const sevOk   = filterSev === 'all' || String(f.severity).toLowerCase() === filterSev
    return agentOk && sevOk
  })

  const fetchHistory = async () => {
    setHistLoading(true)
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/submit/history?session_id=${sessionId}&limit=20`)
      if (res.ok) setHistory(await res.json())
    } catch { /* backend not available */ }
    setHistLoading(false)
  }

  useEffect(() => { fetchHistory() }, [])

  const run = async () => {
    if (tab === 'paste' && !code.trim()) {
      alert("Please enter code.");
      return;
    }
    setLoading(true); setResult(null); setFilterAgent('all'); setFilterSev('all'); setScanStage('Validating syntax…')
    try {
      let res
      // Start stage progression
      const stages = [
        { text: 'Validating syntax…', delay: 0 },
        { text: 'Running Security Agent…', delay: 2000 },
        { text: 'Running Code Quality Agent…', delay: 4000 },
        { text: 'Analysing Complexity…', delay: 6000 },
        { text: 'Merging findings…', delay: 9000 },
        { text: 'Generating fixes…', delay: 12000 },
        { text: 'Computing risk score…', delay: 15000 },
        { text: 'Writing PR summary…', delay: 18000 },
      ]
      const timers = stages.map(s => setTimeout(() => setScanStage(s.text), s.delay))
      if (tab === 'paste') {
        res = await fetch('http://127.0.0.1:8000/api/v1/submit/paste', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language: lang, session_id: sessionId }),
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
      setResult({ status: 'error', message: 'Cannot reach backend server.', findings: [] })
      setScanStage('')
    }
    setLoading(false)
  }

  const secCount     = rawFindings.filter(f => f.agent_source === 'security_vulnerability').length
  const qualityCount = rawFindings.filter(f => f.agent_source === 'code_analysis').length
  const compCount    = rawFindings.filter(f => f.agent_source === 'complexity').length
  const depCount     = rawFindings.filter(f => f.agent_source === 'dependency').length

  return (
    <>
      {/* ══ HEADER ══ */}
      <header className="hdr">
        <div className="hdr-brand">
          <div className="hdr-logo">
            <div className="hlg-ring hlg-r1" />
            <div className="hlg-ring hlg-r2" />
            <div className="hlg-core">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
              </svg>
            </div>
          </div>
          <div>
            <h1 className="hdr-h1">AI Code Review <span>Agent</span></h1>
            <p className="hdr-tag">Parallel analysis · Security + Quality · Smart fixes</p>
          </div>
        </div>
        <nav className="hdr-pills">
          <button id="nav-scanner" className={`hdr-pill ${view === 'scanner' ? 'hdr-pill-active' : ''}`} onClick={() => setView('scanner')} style={{cursor: 'pointer', border: 'none', background: view === 'scanner' ? 'rgba(14, 165, 233, 0.2)' : 'rgba(255, 255, 255, 0.05)', color: view === 'scanner' ? 'var(--primary)' : 'var(--txt-muted)'}}>🛡 Scanner</button>
          <button id="nav-kb" className={`hdr-pill ${view === 'kb' ? 'hdr-pill-active' : ''}`} onClick={() => setView('kb')} style={{cursor: 'pointer', border: 'none', background: view === 'kb' ? 'rgba(14, 165, 233, 0.2)' : 'rgba(255, 255, 255, 0.05)', color: view === 'kb' ? 'var(--primary)' : 'var(--txt-muted)'}}>📚 KB Tester</button>
          <button id="nav-history" className={`hdr-pill ${view === 'history' ? 'hdr-pill-active' : ''}`} onClick={() => setView('history')} style={{cursor: 'pointer', border: 'none', background: view === 'history' ? 'rgba(14, 165, 233, 0.2)' : 'rgba(255, 255, 255, 0.05)', color: view === 'history' ? 'var(--primary)' : 'var(--txt-muted)'}}>🕑 History</button>
        </nav>
      </header>

      {/* ══ MAIN VIEW ══ */}
      {view === 'kb' ? (
        <KBTester />
      ) : view === 'scanner' ? (
      <main className="app-grid">

        {/* LEFT: Editor panel */}
        <section className="panel left-panel">
          <div className="p-inner">
            <div className="tabs-row">
              <button id="tab-paste" className={`ptab ${tab === 'paste' ? 'ptab-on' : ''}`} onClick={() => setTab('paste')}>
                <span>📝</span> Paste Code
              </button>
              <button id="tab-upload" className={`ptab ${tab === 'upload' ? 'ptab-on' : ''}`} onClick={() => setTab('upload')}>
                <span>📂</span> Upload File
              </button>

            </div>

            {tab === 'paste' ? (
              <div className="editor-box">
                <Editor
                  height="100%"
                  language={lang}
                  theme="vs-dark"
                  value={code}
                  onChange={v => setCode(v ?? '')}
                  options={{
                    minimap: { enabled: false }, fontSize: 14,
                    fontFamily: 'JetBrains Mono', padding: { top: 20 },
                    lineNumbers: 'on', scrollBeyondLastLine: false,
                  }}
                />
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
                  onChange={e => e.target.files?.[0] && setFile(e.target.files[0])} />
                <span className="dz-ico">{dragOver ? '⬇️' : '📁'}</span>
                <strong className="dz-title">{dragOver ? 'Drop it here!' : 'Drag & drop your code file here'}</strong>
                <span className="dz-hint">Supports .py and .java files · Click to browse</span>
                {file && <span className="dz-sel">✓ {file.name}</span>}
              </label>
            )}

            <div className="run-row">
              {result && (
                <span className={`r-badge ${isValid ? 'r-ok' : 'r-err'}`}>
                  {isValid ? '✓ Passed' : `✗ ${rawFindings.length} Issue${rawFindings.length !== 1 ? 's' : ''}`}
                </span>
              )}
              {result && (
                <button id="new-analysis-btn" className="run-btn" style={{background: 'rgba(255,255,255,0.05)', color: 'var(--txt-muted)', border: '1px solid rgba(255,255,255,0.1)'}} onClick={() => {setResult(null); setCode(''); setFile(null)}}>
                  🔄 New Analysis
                </button>
              )}
              <button id="run-analysis-btn" className={`run-btn ${loading ? 'run-loading' : ''}`} onClick={run} disabled={loading}>
                {loading
                  ? <><span className="run-spin" />  <span>Analysing...</span></>
                  : <span>⚡ Run Analysis</span>}
              </button>
            </div>

            {/* Animated Progress Bar with Stage Labels */}
            {loading && (
              <div className="scan-progress" style={{ padding: '16px' }}>
                <div className="progress-bar-track">
                  <div className="progress-bar-fill" />
                </div>
                <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginTop: '12px', flexWrap: 'wrap' }}>
                  <div className="par-lane"><div className="par-dot par-dot-active" /><span>Code Quality</span></div>
                  <div className="par-lane"><div className="par-dot par-dot-active" /><span>Security</span></div>
                  <div className="par-lane"><div className="par-dot par-dot-active" /><span>Complexity</span></div>
                  <div className="par-lane"><div className="par-dot par-dot-active" /><span>Dependency</span></div>
                </div>
                {scanStage && (
                  <div style={{ textAlign: 'center', marginTop: '8px', color: 'var(--primary)', fontSize: '0.9rem', fontWeight: 'bold', animation: 'pulse 1.5s ease-in-out infinite' }}>
                    {scanStage}
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* RIGHT: Results panel */}
        <section className="panel right-panel">
          <div className="p-inner">
            <div className="rp-top">
              <h2 className="rp-h2">Scan Results</h2>
              {result && (
                <span className={`rp-pill ${isValid ? 'rpill-ok' : 'rpill-err'}`}>
                  {isValid ? '● All Clear' : `● ${rawFindings.length} Issue${rawFindings.length !== 1 ? 's' : ''}`}
                </span>
              )}
            </div>

            <div className="rp-body">
              {!result ? (
                /* EMPTY STATE */
                <div className="empty-st">
                  <div className="mag-wrap">
                    <span className="mag-ico">🔍</span>
                  </div>
                  <p className="empty-txt">
                    Paste or upload your code,<br />then click <em>Run Analysis</em>
                  </p>
                  <div className="empty-caps">
                    <span>Security Agent</span><span>·</span><span>Code Quality Agent</span><span>·</span><span>Parallel</span>
                  </div>
                </div>

              ) : isValid ? (
                /* INLINE SUCCESS */
                <div className="inline-ok">
                  <div className="iok-check-circle">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                      <polyline points="22 4 12 14.01 9 11.01"></polyline>
                    </svg>
                  </div>
                  <h3>Analysis Complete</h3>
                  <p>Zero issues detected. Your code passed all checks from both agents.</p>
                </div>

              ) : rawFindings.length > 0 ? (
                /* FINDINGS STATE */
                <div className="err-state">
                  <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px'}}>
                    <div className="err-hdr">
                      <span className="err-bug-ico">🔬</span>
                      <div>
                        <p className="err-hdr-t">Issues Detected</p>
                        <p className="err-hdr-s">
                          {rawFindings.length} finding{rawFindings.length !== 1 ? 's' : ''} — expand cards for fixes
                        </p>
                      </div>
                    </div>
                    {scanId && (
                      <a href={`http://127.0.0.1:8000/api/scans/${scanId}/export/markdown`} download
                        style={{padding: '8px 16px', background: 'var(--primary)', color: 'black', borderRadius: '8px', textDecoration: 'none', fontWeight: 'bold', fontSize: '13px', whiteSpace: 'nowrap'}}>
                        ⬇ Export
                      </a>
                    )}
                  </div>

                  {/* Agent Statistics */}
                  <AgentStats findings={rawFindings} riskScore={riskScore} history={history} scanId={scanId} />

                  {/* PR Summary */}
                  {parsedSummary && (
                    <div className="pr-summary-box" style={{ background: 'rgba(255,255,255,0.03)', padding: '20px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.1)' }}>
                      <div className="pr-summary-hd" style={{ borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '12px', marginBottom: '16px' }}>
                        <span style={{ fontSize: '1.2rem', marginRight: '8px' }}>📝</span>
                        <span style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>Executive PR Summary</span>
                      </div>
                      
                      <div style={{ marginBottom: '16px', lineHeight: '1.5', color: 'var(--txt-main)' }}>
                        <strong>Overview:</strong> {parsedSummary.executive_overview}
                      </div>

                      {parsedSummary.prioritized_findings && parsedSummary.prioritized_findings.length > 0 && (
                        <div>
                          <strong style={{ color: 'var(--txt-muted)' }}>Top Priorities:</strong>
                          <ul style={{ listStyleType: 'none', paddingLeft: 0, marginTop: '8px' }}>
                            {parsedSummary.prioritized_findings.map((pf, idx) => (
                              <li key={idx} style={{ marginBottom: '12px', background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '8px' }}>
                                <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '4px' }}>
                                  <span className={`fc-badge`} style={{ padding: '2px 6px', fontSize: '0.7rem', background: 'rgba(255,255,255,0.1)' }}>{pf.severity.toUpperCase()}</span>
                                  <strong>{pf.title}</strong>
                                  {pf.fix_time_estimate && (
                                    <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: '#60a5fa', background: 'rgba(59,130,246,0.1)', padding: '2px 8px', borderRadius: '12px', border: '1px solid rgba(59,130,246,0.2)' }}>⏱ {pf.fix_time_estimate}</span>
                                  )}
                                </div>
                                <div style={{ fontSize: '0.9rem', color: 'var(--txt-muted)' }}>{pf.recommendation}</div>
                              </li>
                            ))}
                          </ul>
                          {parsedSummary.total_estimated_fix_time && (
                            <div style={{ textAlign: 'right', fontSize: '0.9rem', color: '#60a5fa', fontWeight: 'bold', marginTop: '8px', padding: '8px 12px', background: 'rgba(59,130,246,0.08)', borderRadius: '8px', border: '1px solid rgba(59,130,246,0.15)' }}>
                              ⏱ Total Estimated Fix Time: {parsedSummary.total_estimated_fix_time}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Global Auto Fix Section */}
                  <GlobalFixSection scanId={scanId} setCode={setCode} setTab={setTab} />

                  {/* Filter Bar */}
                  <div className="filter-bar">
                    <div className="filter-group">
                      <span className="filter-label">Agent</span>
                      <div className="filter-pills" style={{ flexWrap: 'wrap', gap: '4px' }}>
                        {[
                          { v: 'all',                    label: 'All' },
                          { v: 'security_vulnerability', label: `🔒 (${secCount})` },
                          { v: 'code_analysis',          label: `🔍 (${qualityCount})` },
                          { v: 'complexity',             label: `🧠 (${compCount})` },
                          { v: 'dependency',             label: `📦 (${depCount})` },
                        ].map(({ v, label }) => (
                          <button
                            key={v}
                            id={`filter-agent-${v}`}
                            className={`filter-pill ${filterAgent === v ? 'filter-pill-on' : ''}`}
                            onClick={() => setFilterAgent(v)}
                          >{label}</button>
                        ))}
                      </div>
                    </div>
                    <div className="filter-group">
                      <span className="filter-label">Severity</span>
                      <div className="filter-pills">
                        {['all', 'high', 'medium', 'low'].map(sv => (
                          <button
                            key={sv}
                            id={`filter-sev-${sv}`}
                            className={`filter-pill ${filterSev === sv ? 'filter-pill-on' : ''}`}
                            onClick={() => setFilterSev(sv)}
                          >{sv.charAt(0).toUpperCase() + sv.slice(1)}</button>
                        ))}
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
                      : <div className="no-match">No findings match the current filters.</div>
                    }
                  </div>

                  {/* False Positives Section */}
                  {falsePositives.length > 0 && (
                    <div style={{ marginTop: '24px' }}>
                      <h3 style={{ color: 'var(--txt-muted)', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '8px', marginBottom: '16px' }}>False Positives ({falsePositives.length})</h3>
                      <div className="fc-stack" style={{ opacity: 0.7 }}>
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
                /* Error / no findings */
                <div className="result-box"><pre>{result.message}</pre></div>
              )}

              {/* ── Security Advice from KB ── */}
              {secAdvice.length > 0 && (
                <div className="sa-section">
                  <div className="sa-section-hd">
                    <span>🧠</span>
                    <span className="sa-section-title">Knowledge Base Insights</span>
                    <span className="sa-section-sub">{secAdvice.length} relevant references</span>
                  </div>
                  {secAdvice.map((a, i) => <SecurityAdviceCard key={i} advice={a} />)}
                </div>
              )}
            </div>
          </div>
        </section>

      </main>
      ) : (
      <section className="hist-section" style={{maxWidth: '800px', margin: '0 auto', marginTop: '32px'}}>
        <div className="hist-hd">
          <div className="hist-hd-l">
            <span className="hist-icon">🕑</span>
            <h2 className="hist-title">Scan History</h2>
            <span className="hist-count">{history.length} scans</span>
          </div>
          <button id="refresh-history-btn" className="hist-refresh" onClick={fetchHistory} disabled={histLoading} title="Refresh history">
            <span style={{ display: 'inline-block', animation: histLoading ? 'spin 1s linear infinite' : 'none' }}>↻</span>
          </button>
        </div>

        <div className="hist-body">
          {histLoading ? (
            <div className="hist-empty"><span className="run-spin" />Loading…</div>
          ) : history.length === 0 ? (
            <div className="hist-empty">
              <span style={{ fontSize: 32 }}>📭</span>
              <p>No scans yet for this browser.<br />Run your first analysis above!</p>
            </div>
          ) : (
            history.map((item) => <HistoryItem key={item.scan_id} item={item} />)
          )}
        </div>
      </section>
      )}
    </>
  )
}
