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
  const isSecAgent = source === 'security_vulnerability'
  return (
    <span
      className="agent-badge"
      style={{
        background: isSecAgent ? 'rgba(239,68,68,0.1)' : 'rgba(139,92,246,0.12)',
        color:      isSecAgent ? '#f87171' : '#c084fc',
        border:     isSecAgent ? '1px solid rgba(239,68,68,0.3)' : '1px solid rgba(139,92,246,0.35)',
      }}
    >
      {isSecAgent ? '🔒 Security' : '🔍 Code Quality'}
    </span>
  )
}

/* ─── Severity pill ─── */
function SevPill({ severity }) {
  const m = getSevMeta(severity)
  return (
    <span
      className="sev-pill"
      style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}
    >
      {m.label}
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

/* ─── Finding Card (Milestone 2: shows agent_source, owasp_type, cwe_id, severity) ─── */
function FindingCard({ finding, index }) {
  const [open, setOpen] = useState(index < 3) // First 3 expanded by default
  const isSec = finding.agent_source === 'security_vulnerability'
  const sevMeta = getSevMeta(finding.severity)

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
              <SevPill severity={finding.severity} />
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

          {/* Grounding source (RAG KB) */}
          {finding.grounding_source && (
            <div className="fc-grounding">
              <span className="fc-section-lbl">📚 Knowledge Base Reference</span>
              <span className="fc-grounding-src">
                {finding.grounding_source.replace(/\.md$/, '').replace(/_/g, ' ')}
              </span>
            </div>
          )}

          {/* Suggested fix */}
          {(finding.suggested_fix || finding.fix) && (
            <div className="fc-fix-block">
              <span className="fc-section-lbl">💡 How to Fix</span>
              <pre className="fc-fix-code">{finding.suggested_fix || finding.fix}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── Agent Stats Panel ─── */
function AgentStats({ findings }) {
  const secFindings     = findings.filter(f => f.agent_source === 'security_vulnerability')
  const qualityFindings = findings.filter(f => f.agent_source === 'code_analysis')
  const criticalCount   = findings.filter(f => ['critical','high'].includes(String(f.severity).toLowerCase())).length
  const mediumCount     = findings.filter(f => String(f.severity).toLowerCase() === 'medium').length

  return (
    <div className="agent-stats">
      <div className="agent-stat-card agent-stat-sec">
        <span className="ast-ico">🔒</span>
        <div className="ast-info">
          <span className="ast-count">{secFindings.length}</span>
          <span className="ast-label">Security Issues</span>
        </div>
      </div>
      <div className="agent-stat-card agent-stat-quality">
        <span className="ast-ico">🔍</span>
        <div className="ast-info">
          <span className="ast-count">{qualityFindings.length}</span>
          <span className="ast-label">Code Quality</span>
        </div>
      </div>
      <div className="agent-stat-card agent-stat-critical">
        <span className="ast-ico">🚨</span>
        <div className="ast-info">
          <span className="ast-count">{criticalCount}</span>
          <span className="ast-label">High+ Severity</span>
        </div>
      </div>
      <div className="agent-stat-card agent-stat-medium">
        <span className="ast-ico">⚠️</span>
        <div className="ast-info">
          <span className="ast-count">{mediumCount}</span>
          <span className="ast-label">Medium</span>
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
  const ok = status === 'validated'
  const isFailed = status === 'failed'
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
            {ok ? '✓ Passed' : isFailed ? '✗ Failed' : '⚠ Unknown'}
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

  const sessionId = getSessionId()
  const rawFindings = result?.findings ?? result?.syntax_errors ?? []
  const summary     = result?.summary_text
  const scanId      = result?.scan_id
  const isValid     = result?.status === 'validated' && rawFindings.length === 0

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
    setLoading(true); setResult(null); setFilterAgent('all'); setFilterSev('all')
    try {
      let res
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
      fetchHistory()
    } catch {
      setResult({ status: 'error', message: 'Cannot reach backend server.', findings: [] })
    }
    setLoading(false)
  }

  const secCount     = rawFindings.filter(f => f.agent_source === 'security_vulnerability').length
  const qualityCount = rawFindings.filter(f => f.agent_source === 'code_analysis').length

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
              {tab === 'paste' && (
                <select id="lang-selector" className="lang-sel" value={lang} onChange={e => setLang(e.target.value)}>
                  <option value="python">🐍 Python</option>
                  <option value="java">☕ Java</option>
                </select>
              )}
            </div>

            {tab === 'paste' ? (
              <div className="editor-box">
                <Editor
                  height="500px"
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
              <label className="drop-zone">
                <input id="file-upload" type="file" accept=".py,.java" style={{ display: 'none' }}
                  onChange={e => e.target.files?.[0] && setFile(e.target.files[0])} />
                <span className="dz-ico">📁</span>
                <strong className="dz-title">Drop your code file here</strong>
                <span className="dz-hint">Supports .py and .java files</span>
                {file && <span className="dz-sel">✓ {file.name}</span>}
              </label>
            )}

            <div className="run-row">
              {result && (
                <span className={`r-badge ${isValid ? 'r-ok' : 'r-err'}`}>
                  {isValid ? '✓ Passed' : `✗ ${rawFindings.length} Issue${rawFindings.length !== 1 ? 's' : ''}`}
                </span>
              )}
              <button id="run-analysis-btn" className={`run-btn ${loading ? 'run-loading' : ''}`} onClick={run} disabled={loading}>
                {loading
                  ? <><span className="run-spin" />  <span>Analysing...</span></>
                  : <span>⚡ Run Analysis</span>}
              </button>
            </div>

            {/* Parallel execution indicator */}
            {loading && (
              <div className="parallel-indicator">
                <div className="par-lane">
                  <div className="par-dot par-dot-active" />
                  <span>Code Analysis Agent</span>
                  <div className="par-pulse" />
                </div>
                <div className="par-merge">⇢ Merge ⇢</div>
                <div className="par-lane">
                  <div className="par-dot par-dot-active" />
                  <span>Security Vulnerability Agent</span>
                  <div className="par-pulse" />
                </div>
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
                  <AgentStats findings={rawFindings} />

                  {/* PR Summary */}
                  {summary && (
                    <div className="pr-summary-box">
                      <div className="pr-summary-hd">
                        <span>📝</span>
                        <span>PR Summary</span>
                        <span className="pr-summary-sub">AI-generated review narrative</span>
                      </div>
                      <div className="pr-summary-body">{summary}</div>
                    </div>
                  )}

                  {/* Filter Bar */}
                  <div className="filter-bar">
                    <div className="filter-group">
                      <span className="filter-label">Agent</span>
                      <div className="filter-pills">
                        {[
                          { v: 'all',                    label: 'All' },
                          { v: 'security_vulnerability', label: `🔒 Security (${secCount})` },
                          { v: 'code_analysis',          label: `🔍 Quality (${qualityCount})` },
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
                            finding={{
                              ...f,
                              title: f.title || f.issue,
                              suggested_fix: f.suggested_fix || f.fix,
                            }}
                          />
                        ))
                      : <div className="no-match">No findings match the current filters.</div>
                    }
                  </div>

                  {/* Chat UI */}
                  {scanId && <ChatUI scanId={scanId} sessionId={sessionId} />}
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
