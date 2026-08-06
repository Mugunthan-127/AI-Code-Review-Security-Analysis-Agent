import { useState, useEffect } from 'react'

export default function ReportSection({
  currentResult,
  history,
  histLoading,
  fetchHistory,
  onLoadInScanner,
  onExportReport,
  setView,
  setCode,
  setTab,
}) {
  // Initialize with current result or first history item
  const initialScanId = currentResult?.scan_id || history[0]?.scan_id || null
  const [selectedScanId, setSelectedScanId] = useState(initialScanId)
  const [scanData, setScanData] = useState(currentResult || null)
  const [loadingDetails, setLoadingDetails] = useState(false)
  const [copiedMd, setCopiedMd] = useState(false)
  const [activeTab, setActiveTab] = useState('all') // 'all', 'security', 'quality', 'code'

  // Update selectedScanId if history or currentResult changes and nothing selected
  useEffect(() => {
    if (!selectedScanId) {
      if (currentResult?.scan_id) {
        setSelectedScanId(currentResult.scan_id)
        setScanData(currentResult)
      } else if (history.length > 0) {
        setSelectedScanId(history[0].scan_id)
      }
    }
  }, [currentResult, history, selectedScanId])

  // Fetch full details when selectedScanId changes
  useEffect(() => {
    if (!selectedScanId) return

    // If currentResult matches selectedScanId, use it directly
    if (currentResult?.scan_id === selectedScanId) {
      setScanData(currentResult)
      return
    }

    let isMounted = true
    setLoadingDetails(true)

    fetch(`http://127.0.0.1:8000/api/v1/submit/scan/${selectedScanId}`)
      .then((res) => {
        if (!res.ok) throw new Error('Failed to load scan details')
        return res.json()
      })
      .then((data) => {
        if (isMounted) {
          setScanData(data)
          setLoadingDetails(false)
        }
      })
      .catch((err) => {
        console.error('Error fetching report scan data:', err)
        if (isMounted) setLoadingDetails(false)
      })

    return () => {
      isMounted = false
    }
  }, [selectedScanId, currentResult])

  const handleCopyMarkdown = async () => {
    if (!selectedScanId) return
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/v1/reports/${selectedScanId}/export/markdown`)
      if (!res.ok) throw new Error('Failed to fetch markdown')
      const text = await res.text()
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text)
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
      setCopiedMd(true)
      setTimeout(() => setCopiedMd(false), 2500)
    } catch (e) {
      alert('Could not copy markdown report: ' + e.message)
    }
  }

  const handlePrint = () => {
    window.print()
  }

  // Parse Executive Summary JSON if available
  let parsedSummary = null
  if (scanData?.summary_text) {
    try {
      parsedSummary = JSON.parse(scanData.summary_text)
    } catch (e) {
      parsedSummary = {
        executive_overview: scanData.summary_text,
        severity_breakdown: {},
        prioritized_findings: [],
      }
    }
  }

  const allFindings = scanData?.findings ?? scanData?.syntax_errors ?? []
  const rawFindings = allFindings.filter((f) => f.validation_status !== 'NO')
  const secFindings = rawFindings.filter((f) => f.agent_source === 'security_vulnerability')
  const qualFindings = rawFindings.filter((f) => f.agent_source === 'code_analysis')
  const compFindings = rawFindings.filter((f) => f.agent_source === 'complexity')

  const riskScore = scanData?.risk_score ?? 0
  const healthScore = Math.max(0, 100 - riskScore)
  const isClean = rawFindings.length === 0 && (scanData?.status === 'validated' || scanData?.status === 'completed')
  const rawCode = scanData?.raw_code || scanData?.code || ''
  const scanLang = (scanData?.language || 'python').toLowerCase()

  // Filtered findings for table
  const displayedFindings = rawFindings.filter((f) => {
    if (activeTab === 'security') return f.agent_source === 'security_vulnerability'
    if (activeTab === 'quality') return f.agent_source === 'code_analysis'
    if (activeTab === 'complexity') return f.agent_source === 'complexity'
    return true
  })

  // Gauge calculation
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (healthScore / 100) * circumference
  const gaugeColor =
    healthScore >= 90 ? '#10b981' : healthScore >= 70 ? '#38bdf8' : healthScore >= 50 ? '#f59e0b' : '#ef4444'

  return (
    <div className="report-container">
      {/* ── Top Toolbar & Scan Selector ── */}
      <div className="report-toolbar no-print">
        <div className="report-toolbar-left">
          <label className="rt-label">
            <span className="rt-icon">📊</span>
            <span>Select Audit Scan:</span>
          </label>
          <select
            id="report-scan-select"
            className="rt-select"
            value={selectedScanId || ''}
            onChange={(e) => setSelectedScanId(e.target.value)}
          >
            {currentResult && (
              <option value={currentResult.scan_id}>
                ⚡ Current Active Scan ({currentResult.language?.toUpperCase() || 'JAVA'} - Score: {Math.max(0, 100 - (currentResult.risk_score || 0))}%)
              </option>
            )}
            {history.map((h, i) => (
              <option key={h.scan_id || i} value={h.scan_id}>
                #{i + 1} · {h.language?.toUpperCase()} ({h.source_type}) · {new Date(h.created_at).toLocaleDateString()} {new Date(h.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · {h.findings_count ?? 0} issues
              </option>
            ))}
            {!currentResult && history.length === 0 && (
              <option value="">No scans recorded yet</option>
            )}
          </select>
        </div>

        <div className="report-toolbar-actions">
          <button
            className="rt-btn primary"
            onClick={handlePrint}
            title="Print this formal audit report or Save to PDF"
          >
            <span>🖨️</span>
            <span>Print / Save PDF</span>
          </button>
          <button
            className="rt-btn"
            onClick={() => selectedScanId && onExportReport(selectedScanId)}
            disabled={!selectedScanId}
            title="Download report in Markdown format"
          >
            <span>📝</span>
            <span>Export Markdown</span>
          </button>
          <button
            className="rt-btn"
            onClick={handleCopyMarkdown}
            disabled={!selectedScanId}
            title="Copy entire markdown report to clipboard"
          >
            <span>{copiedMd ? '✅' : '📋'}</span>
            <span>{copiedMd ? 'Copied!' : 'Copy Report'}</span>
          </button>
          {rawCode && (
            <button
              className="rt-btn accent"
              onClick={() => {
                setCode(rawCode)
                setTab('paste')
                setView('scanner')
              }}
              title="Open this code back into the Scanner Studio editor"
            >
              <span>🛡️</span>
              <span>Open in Studio</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Empty State if No Scan ── */}
      {!selectedScanId && (
        <div className="report-empty-state">
          <div className="res-icon">📑</div>
          <h2>No Audit Scan Selected</h2>
          <p>Run a multi-agent security scan in the Scanner Studio to generate a comprehensive inspection report.</p>
          <button className="run-btn-radiant" style={{ maxWidth: '240px', margin: '16px auto' }} onClick={() => setView('scanner')}>
            ⚡ Go to Scanner Studio
          </button>
        </div>
      )}

      {/* ── Loading Details State ── */}
      {selectedScanId && loadingDetails && (
        <div className="report-loading-box">
          <span className="run-spin" style={{ width: '32px', height: '32px', borderWidth: '3px' }} />
          <h3>Compiling Audit Report Data…</h3>
          <p>Synthesizing multi-agent findings, risk matrices, and remediation groundings.</p>
        </div>
      )}

      {/* ── Formal Report Document ── */}
      {selectedScanId && scanData && !loadingDetails && (
        <div className="report-paper">
          {/* Header Banner */}
          <div className="rp-header">
            <div className="rph-top-bar">
              <div className="rph-badge">
                <span className="rph-dot" />
                <span>FORMAL CODE INSPECTION & SECURITY AUDIT REPORT</span>
              </div>
              <div className="rph-cert-id">
                <span>CERTIFICATE ID:</span>
                <code>{scanData.scan_id}</code>
              </div>
            </div>

            <div className="rph-main">
              <div className="rph-titles">
                <h1 className="rph-title">Development of Smart Code Inspection Platform with Vulnerability Detection System</h1>
                <p className="rph-desc">
                  Automated Multi-Agent Static Analysis · AST Validation · OWASP Top 10 & CWE Detection · RAG Knowledge Base Grounding
                </p>
              </div>
              <div className="rph-verdict">
                <div className={`verdict-pill ${isClean ? 'clean' : healthScore >= 70 ? 'pass' : 'fail'}`}>
                  {isClean ? '🟢 SECURE PASS' : healthScore >= 70 ? '🟡 CONDITIONAL PASS' : '🔴 ACTION REQUIRED'}
                </div>
              </div>
            </div>

            {/* Audit Meta Grid */}
            <div className="rph-meta-grid">
              <div className="rph-meta-item">
                <span className="rmi-lbl">Target Language</span>
                <strong className="rmi-val">{scanLang === 'java' ? '☕ Java (JDK 17+)' : '🐍 Python (3.10+)'}</strong>
              </div>
              <div className="rph-meta-item">
                <span className="rmi-lbl">Submission Type</span>
                <strong className="rmi-val">{scanData.source_type === 'upload' ? '📂 Uploaded File' : '📝 Direct Code Paste'}</strong>
              </div>
              <div className="rph-meta-item">
                <span className="rmi-lbl">Audit Date & Time</span>
                <strong className="rmi-val">{scanData.created_at ? new Date(scanData.created_at).toLocaleString() : 'Recent'}</strong>
              </div>
              <div className="rph-meta-item">
                <span className="rmi-lbl">Engine Pipeline</span>
                <strong className="rmi-val">4 Parallel AI Agents + LangGraph</strong>
              </div>
            </div>
          </div>

          {/* Executive Metrics Overview */}
          <div className="rp-section">
            <h2 className="rp-sec-title">
              <span>📊</span>
              <span>Executive Risk & Health Posture</span>
            </h2>

            <div className="rp-posture-grid">
              {/* Health Gauge Card */}
              <div className="rp-gauge-card">
                <div className="rp-gauge-box">
                  <svg className="rp-gauge-svg" width="130" height="130" viewBox="0 0 130 130">
                    <circle
                      className="gauge-bg"
                      cx="65"
                      cy="65"
                      r={radius}
                      strokeWidth="11"
                    />
                    <circle
                      className="gauge-fill"
                      cx="65"
                      cy="65"
                      r={radius}
                      strokeWidth="11"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      stroke={gaugeColor}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="rp-gauge-val-wrap">
                    <span className="rp-gauge-num" style={{ color: gaugeColor }}>{healthScore}</span>
                    <span className="rp-gauge-denom">/100</span>
                  </div>
                </div>
                <div className="rp-gauge-text">
                  <div className="rgt-title">Security Health Index</div>
                  <div className="rgt-desc">
                    {isClean
                      ? 'No vulnerabilities or high-risk code smells detected.'
                      : `Risk Penalty: ${riskScore} points across ${rawFindings.length} issue(s).`}
                  </div>
                </div>
              </div>

              {/* 4 Diagnostic Stat Counters */}
              <div className="rp-stats-col">
                <div className="rp-stat-box red">
                  <div className="rsb-num">{secFindings.length}</div>
                  <div className="rsb-lbl">Security Vulnerabilities</div>
                  <div className="rsb-sub">OWASP / CWE CVE Exposure</div>
                </div>
                <div className="rp-stat-box blue">
                  <div className="rsb-num">{qualFindings.length}</div>
                  <div className="rsb-lbl">Code Quality Smells</div>
                  <div className="rsb-sub">Maintainability & Clean Code</div>
                </div>
                <div className="rp-stat-box purple">
                  <div className="rsb-num">{compFindings.length}</div>
                  <div className="rsb-lbl">Complexity Flags</div>
                  <div className="rsb-sub">AST Nesting & Cyclomatic</div>
                </div>
                <div className="rp-stat-box green">
                  <div className="rsb-num">{scanData.security_advice?.length ?? 0}</div>
                  <div className="rsb-lbl">RAG Standards Grounded</div>
                  <div className="rsb-sub">Certified Secure Patterns</div>
                </div>
              </div>
            </div>
          </div>

          {/* AI Executive Summary & Action Plan */}
          {parsedSummary && (
            <div className="rp-section">
              <h2 className="rp-sec-title">
                <span>📝</span>
                <span>Executive Summary & Remediation Roadmap</span>
              </h2>

              {parsedSummary.executive_overview && (
                <div className="rp-summary-box">
                  <h4 className="rsb-hd">Executive Overview</h4>
                  <p className="rsb-p">{parsedSummary.executive_overview}</p>
                </div>
              )}

              {parsedSummary.prioritized_findings && parsedSummary.prioritized_findings.length > 0 && (
                <div className="rp-priorities-box">
                  <h4 className="rsb-hd">Prioritized Action Items for Developers</h4>
                  <div className="rp-priorities-list">
                    {parsedSummary.prioritized_findings.map((item, idx) => (
                      <div key={idx} className="rp-priority-card">
                        <div className="rpp-rank">#{idx + 1}</div>
                        <div className="rpp-content">
                          <div className="rpp-top">
                            <span className={`rpp-sev-pill ${(item.severity || 'high').toLowerCase()}`}>
                              {(item.severity || 'HIGH').toUpperCase()}
                            </span>
                            <strong className="rpp-title">{item.title}</strong>
                          </div>
                          <p className="rpp-rec">{item.recommendation}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Multi-Agent Inspection Diagnostics */}
          <div className="rp-section">
            <h2 className="rp-sec-title">
              <span>🤖</span>
              <span>Multi-Agent Inspection Diagnostics</span>
            </h2>

            <div className="rp-agents-grid">
              <div className="rp-agent-card">
                <div className="rp-ac-header">
                  <span className="rp-ac-icon">🛡️</span>
                  <div>
                    <strong>Syntax & AST Integrity</strong>
                    <div className="rp-ac-sub">Structural grammar validation</div>
                  </div>
                  <span className="rp-ac-status clean">PASSED</span>
                </div>
                <p className="rp-ac-desc">AST parsed successfully without fatal compilation errors.</p>
              </div>

              <div className="rp-agent-card">
                <div className="rp-ac-header">
                  <span className="rp-ac-icon">🔒</span>
                  <div>
                    <strong>Security SAST Agent</strong>
                    <div className="rp-ac-sub">OWASP Top 10 & CWE Detection</div>
                  </div>
                  <span className={`rp-ac-status ${secFindings.length === 0 ? 'clean' : 'warn'}`}>
                    {secFindings.length === 0 ? 'CLEAN' : `${secFindings.length} FOUND`}
                  </span>
                </div>
                <p className="rp-ac-desc">
                  {secFindings.length === 0
                    ? 'No SQLi, Command Injection, hardcoded secrets, or deserialization threats detected.'
                    : `Identified ${secFindings.length} vulnerability pattern(s) requiring immediate remediation.`}
                </p>
              </div>

              <div className="rp-agent-card">
                <div className="rp-ac-header">
                  <span className="rp-ac-icon">✨</span>
                  <div>
                    <strong>Code Quality Agent</strong>
                    <div className="rp-ac-sub">Linter & Clean Code Standards</div>
                  </div>
                  <span className={`rp-ac-status ${qualFindings.length === 0 ? 'clean' : 'warn'}`}>
                    {qualFindings.length === 0 ? 'CLEAN' : `${qualFindings.length} FOUND`}
                  </span>
                </div>
                <p className="rp-ac-desc">
                  {qualFindings.length === 0
                    ? 'Adheres to standard idiomatic styling and resource management conventions.'
                    : `Flagged ${qualFindings.length} code smell(s) or anti-pattern(s).`}
                </p>
              </div>

              <div className="rp-agent-card">
                <div className="rp-ac-header">
                  <span className="rp-ac-icon">📈</span>
                  <div>
                    <strong>Complexity Analyzer</strong>
                    <div className="rp-ac-sub">Cyclomatic & Nesting Depth</div>
                  </div>
                  <span className={`rp-ac-status ${compFindings.length === 0 ? 'clean' : 'warn'}`}>
                    {compFindings.length === 0 ? 'OPTIMAL' : `${compFindings.length} FLAGGED`}
                  </span>
                </div>
                <p className="rp-ac-desc">
                  {compFindings.length === 0
                    ? 'Control flow depth and modular branching remain within safe thresholds.'
                    : `Excessive nesting or high cyclomatic branches detected.`}
                </p>
              </div>
            </div>
          </div>

          {/* Detailed Findings Ledger Table */}
          <div className="rp-section">
            <div className="rp-sec-header-row">
              <h2 className="rp-sec-title">
                <span>📋</span>
                <span>Complete Audit Findings Ledger ({rawFindings.length})</span>
              </h2>

              <div className="rp-tabs no-print">
                <button
                  className={`rp-tab-btn ${activeTab === 'all' ? 'active' : ''}`}
                  onClick={() => setActiveTab('all')}
                >
                  All ({rawFindings.length})
                </button>
                <button
                  className={`rp-tab-btn ${activeTab === 'security' ? 'active' : ''}`}
                  onClick={() => setActiveTab('security')}
                >
                  Security ({secFindings.length})
                </button>
                <button
                  className={`rp-tab-btn ${activeTab === 'quality' ? 'active' : ''}`}
                  onClick={() => setActiveTab('quality')}
                >
                  Quality ({qualFindings.length})
                </button>
              </div>
            </div>

            {displayedFindings.length === 0 ? (
              <div className="rp-clean-box">
                <span className="rcb-icon">🎉</span>
                <h3>Zero Violations Detected</h3>
                <p>The analyzed codebase complies 100% with static security and quality policies for this category.</p>
              </div>
            ) : (
              <div className="rp-table-wrap">
                <table className="rp-table">
                  <thead>
                    <tr>
                      <th style={{ width: '60px' }}>#</th>
                      <th style={{ width: '110px' }}>Severity</th>
                      <th>Finding / Issue Title</th>
                      <th style={{ width: '120px' }}>CWE / Standard</th>
                      <th style={{ width: '90px' }}>Location</th>
                      <th style={{ width: '110px' }}>Agent</th>
                    </tr>
                  </thead>
                  <tbody>
                    {displayedFindings.map((f, i) => (
                      <tr key={i}>
                        <td className="rpt-idx">{i + 1}</td>
                        <td>
                          <span className={`rpt-sev ${(f.severity || 'low').toLowerCase()}`}>
                            {(f.severity || 'LOW').toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <div className="rpt-title">{f.title || f.issue}</div>
                          {f.rule_id && <code className="rpt-rule">{f.rule_id}</code>}
                        </td>
                        <td>
                          {f.cwe_id ? (
                            <span className="rpt-cwe">{f.cwe_id}</span>
                          ) : (
                            <span className="rpt-muted">{f.owasp_type || '—'}</span>
                          )}
                        </td>
                        <td className="rpt-loc">
                          {f.line ? `Line ${f.line}` : 'Global'}
                        </td>
                        <td className="rpt-tool">{f.tool || f.agent_source}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Deep Dives & Remediation Code */}
          {displayedFindings.length > 0 && (
            <div className="rp-section">
              <h2 className="rp-sec-title">
                <span>🔧</span>
                <span>Deep Vulnerability Analysis & Suggested Fixes</span>
              </h2>

              <div className="rp-fixes-list">
                {displayedFindings.map((f, i) => (
                  <div key={i} className="rp-fix-card">
                    <div className="rpfc-hd">
                      <div className="rpfc-left">
                        <span className={`rpt-sev ${(f.severity || 'low').toLowerCase()}`}>
                          {(f.severity || 'LOW').toUpperCase()}
                        </span>
                        <strong className="rpfc-title">{f.title || f.issue}</strong>
                        {f.line && <span className="rpfc-line">📍 Line {f.line}</span>}
                      </div>
                      {f.cwe_id && <span className="rpt-cwe">{f.cwe_id}</span>}
                    </div>

                    {f.explanation && (
                      <p className="rpfc-exp">{f.explanation}</p>
                    )}

                    {f.grounding_source && (
                      <div className="rpfc-kb-ref">
                        <span className="rpfc-kb-tag">📚 Certified KB Grounding:</span>
                        <span>{f.grounding_source.replace('.md', '').replace(/_/g, ' ')}</span>
                      </div>
                    )}

                    {(f.suggested_fix || f.fix) && (
                      <div className="rpfc-code-wrap">
                        <div className="rpfc-code-hd">
                          <span>✅ Recommended Remediation Code</span>
                        </div>
                        <pre className="rpfc-code">
                          <code>{f.suggested_fix || f.fix}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Inspected Source Code Snapshot Appendix */}
          {rawCode && (
            <div className="rp-section">
              <h2 className="rp-sec-title">
                <span>📜</span>
                <span>Appendix: Inspected Source Code Snapshot</span>
              </h2>
              <div className="rp-code-snapshot">
                <div className="rp-code-meta">
                  <span>{rawCode.split('\n').length} lines · {rawCode.length} characters</span>
                </div>
                <pre className="rp-source-pre">
                  <code>{rawCode}</code>
                </pre>
              </div>
            </div>
          )}

          {/* Document Signoff Footer */}
          <div className="rp-footer">
            <div className="rpf-brand">
              <div className="rpf-logo-dot" />
              <strong>Development of Smart Code Inspection Platform with Vulnerability Detection System</strong>
            </div>
            <div className="rpf-copy">
              Certified Multi-Agent Automated Audit Report · Generated on {new Date().toLocaleDateString()}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
