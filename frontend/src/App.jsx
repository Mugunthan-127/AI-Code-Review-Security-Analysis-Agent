import { useState, useEffect, useRef } from 'react'
import Editor from '@monaco-editor/react'

/* ─── Precomputed background code-symbol particles ─── */
const SYM_SET = ['{ }', '</>', '//', '[ ]', '( )', '&&', '++', '!==', '===', 'fn', '0x', '=>', '**', '#!']
const BG_PTS = Array.from({ length: 20 }, (_, i) => ({
  id:  i,
  sym: SYM_SET[i % SYM_SET.length],
  lft: Math.round(((i * 5.13 + 2.9) % 95) + 2),
  dur: Math.round(10 + (i * 1.71) % 14),
  del: -Math.round((i * 2.43) % 22),
  sz:  Math.round(10 + (i * 0.89) % 13),
  op:  parseFloat((0.035 + (i * 0.005) % 0.065).toFixed(3)),
}))

function BgParticles() {
  return (
    <div className="bg-pts" aria-hidden="true">
      {BG_PTS.map(p => (
        <span key={p.id} className="bg-sym" style={{
          left: `${p.lft}%`, fontSize: `${p.sz}px`, opacity: p.op,
          animationDuration: `${p.dur}s`, animationDelay: `${p.del}s`,
        }}>{p.sym}</span>
      ))}
    </div>
  )
}

/* ─── Cursor trail: code symbols float from the mouse ─── */
function CursorTrail() {
  const ref = useRef(null)
  useEffect(() => {
    const SYMS = ['{}', '//', '=>', '[ ]', '( )', '&&', '++', '0x', 'fn', '!=', '===', '**', '</', '#!']
    const COLS = ['#06d6f0', '#b06bff', '#2eef7b', '#ffc53d', '#ff67c3', '#ff8c42']
    let lx = -9999, ly = -9999
    const onMove = e => {
      if (Math.hypot(e.clientX - lx, e.clientY - ly) < 28) return
      lx = e.clientX; ly = e.clientY
      const el = document.createElement('span')
      el.className = 'cur-sym'
      el.textContent = SYMS[Math.floor(Math.random() * SYMS.length)]
      el.style.cssText = [
        `left:${lx + (Math.random() - 0.5) * 34}px`,
        `top:${ly + (Math.random() - 0.5) * 34}px`,
        `color:${COLS[Math.floor(Math.random() * COLS.length)]}`,
        `font-size:${8 + Math.floor(Math.random() * 10)}px`,
      ].join(';')
      ref.current?.appendChild(el)
      setTimeout(() => el.remove(), 950)
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    return () => window.removeEventListener('mousemove', onMove)
  }, [])
  return <div ref={ref} className="cur-trail" aria-hidden="true" />
}

/* ─── Scan-beam laser that sweeps editor during analysis ─── */
function ScanBeam({ active }) {
  if (!active) return null
  return (
    <div className="sbeam-wrap" aria-hidden="true">
      <div className="sbeam-line" />
      <div className="sbeam-glow" />
    </div>
  )
}

/* ─── Canvas-based fireworks bursts ─── */
function FireworksCanvas() {
  const cvs = useRef(null)
  useEffect(() => {
    const canvas = cvs.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const W = canvas.width  = window.innerWidth
    const H = canvas.height = window.innerHeight
    const COLS = ['#22d3ee', '#a78bfa', '#4ade80', '#fbbf24', '#f472b6', '#ffffff', '#fb923c']

    class Spark {
      constructor(x, y, col) {
        this.x = x; this.y = y; this.col = col
        const a = Math.random() * Math.PI * 2
        const s = 2.5 + Math.random() * 5.5
        this.vx = Math.cos(a) * s; this.vy = Math.sin(a) * s - 1
        this.al = 1; this.r = 1.5 + Math.random() * 2.5
        this.dec = 0.011 + Math.random() * 0.009
      }
      tick() {
        this.x += this.vx; this.y += this.vy
        this.vy += 0.065; this.vx *= 0.99; this.al -= this.dec
      }
      draw() {
        ctx.beginPath()
        ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2)
        ctx.fillStyle = this.col
        ctx.globalAlpha = Math.max(0, this.al)
        ctx.shadowBlur = 10; ctx.shadowColor = this.col
        ctx.fill(); ctx.shadowBlur = 0
      }
    }

    let sparks = []
    const burst = () => {
      const x = 80 + Math.random() * (W - 160)
      const y = 60 + Math.random() * (H * 0.52)
      const c = COLS[Math.floor(Math.random() * COLS.length)]
      for (let i = 0; i < 80 + Math.floor(Math.random() * 40); i++)
        sparks.push(new Spark(x, y, c))
    }

    burst(); burst(); burst()
    const ts = [350, 750, 1100, 1550, 1950, 2400, 2900].map((d, i) =>
      setTimeout(() => { burst(); if (i % 2 === 0) burst() }, d)
    )

    let raf
    const draw = () => {
      ctx.fillStyle = 'rgba(0,0,0,0.13)'; ctx.fillRect(0, 0, W, H)
      sparks = sparks.filter(s => s.al > 0)
      sparks.forEach(s => { s.tick(); s.draw() })
      ctx.globalAlpha = 1
      raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); ts.forEach(clearTimeout) }
  }, [])
  return <canvas ref={cvs} className="fw-canvas" />
}

/* ─── Full-screen success celebration ─── */
function SuccessOverlay({ onDismiss }) {
  return (
    <div className="sov" onClick={onDismiss}>
      <FireworksCanvas />
      <div className="sov-card" onClick={e => e.stopPropagation()}>
        <div className="trophy-box">
          <div className="trophy-ring-bg" />
          <div className="trophy-emoji">🏆</div>
          <div className="sparkle-ring">
            {Array.from({ length: 8 }, (_, i) => (
              <div key={i} className="sdot" style={{ '--si': i }} />
            ))}
          </div>
        </div>
        <h2 className="sov-title">Code Looks <span>Perfect!</span></h2>
        <p className="sov-sub">Zero issues detected · All validation checks passed ✓</p>
        <div className="sov-checks">
          {['Syntax', 'Symbols', 'Structure', 'Types'].map(label => (
            <div key={label} className="sov-chk">
              <span className="schk-ico">✓</span>
              <span className="schk-lbl">{label}</span>
            </div>
          ))}
        </div>
        <button className="btn-dismiss" onClick={onDismiss}>
          Continue Coding <span>→</span>
        </button>
      </div>
    </div>
  )
}

/* ─── Security Advice Card (from RAG KB) ─── */
function SecurityAdviceCard({ advice, index }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="sa" style={{ animationDelay: `${index * 70}ms` }}>
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

/* ─── Collapsible error card ─── */
function ErrorCard({ error, index }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="ec" style={{ animationDelay: `${index * 90}ms` }}>
      <button className="ec-hd" onClick={() => setOpen(v => !v)}>
        <div className="ec-hd-l">
          <span className="ec-bug">🐛</span>
          <div className="ec-meta">
            {error.line != null && (
              <span className="ec-ltag">
                Line {error.line}{error.column != null ? ` · Col ${error.column}` : ''}
              </span>
            )}
            <span className="ec-issue">{error.issue}</span>
          </div>
        </div>
        <span className="ec-chev" data-open={open}>▾</span>
      </button>
      {open && (
        <div className="ec-body">
          {error.snippet && (
            <div className="ec-snip">
              <span className="ec-snip-lbl">Code at this line</span>
              <code className="ec-code">{error.snippet}</code>
            </div>
          )}
          <div className="ec-fix">
            <span className="ec-fix-ico">💡</span>
            <div>
              <span className="ec-fix-lbl">How to fix</span>
              <p className="ec-fix-p">{error.fix}</p>
            </div>
          </div>
        </div>
      )}
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
function HistoryItem({ item, index }) {
  const [open, setOpen] = useState(false)
  const ok = item.status === 'validated'
  return (
    <div className="hi" style={{ animationDelay: `${index * 60}ms` }}>
      <button className="hi-hd" onClick={() => setOpen(v => !v)}>
        <div className="hi-left">
          <span className={`hi-dot ${ok ? 'hi-dot-ok' : 'hi-dot-err'}`} />
          <span className={`hi-lang ${item.language}`}>
            {item.language === 'python' ? '🐍' : '☕'} {item.language}
          </span>
          <span className="hi-src">{item.source_type === 'upload' ? '📂' : '📝'}</span>
          <span className={`hi-status ${ok ? 'hi-ok' : 'hi-fail'}`}>
            {ok ? '✓ Passed' : '✗ Failed'}
          </span>
        </div>
        <div className="hi-right">
          <span className="hi-time">{fmtDate(item.created_at)}</span>
          <span className="hi-chev" data-open={open}>▾</span>
        </div>
      </button>
      {open && item.snippet && (
        <div className="hi-body">
          <span className="hi-snip-lbl">Code preview</span>
          <code className="hi-snip">{item.snippet}{item.snippet.length >= 120 ? '…' : ''}</code>
        </div>
      )}
    </div>
  )
}

/* ─── Main App ─── */
export default function App() {
  const [tab,     setTab]     = useState('paste')
  const [code,    setCode]    = useState('')
  const [lang,    setLang]    = useState('python')
  const [file,    setFile]    = useState(null)
  const [loading, setLoading] = useState(false)
  const [result,  setResult]  = useState(null)
  const [showOv,  setShowOv]  = useState(false)
  const [history, setHistory] = useState([])
  const [histLoading, setHistLoading] = useState(false)
  const [secAdvice, setSecAdvice] = useState([])

  const sessionId = getSessionId()
  const errors  = result?.errors ?? []
  const isValid = result?.status === 'validated'

  const fetchHistory = async () => {
    setHistLoading(true)
    try {
      const res = await fetch(`http://localhost:8000/api/v1/submit/history?session_id=${sessionId}&limit=20`)
      if (res.ok) setHistory(await res.json())
    } catch { /* backend not available */ }
    setHistLoading(false)
  }

  useEffect(() => { fetchHistory() }, [])

  const run = async () => {
    setLoading(true); setResult(null); setShowOv(false)
    try {
      let res
      if (tab === 'paste') {
        res = await fetch('http://localhost:8000/api/v1/submit/paste', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language: lang, session_id: sessionId }),
        })
      } else {
        if (!file) { alert('Select a file first.'); setLoading(false); return }
        const fd = new FormData()
        fd.append('file', file)
        res = await fetch('http://localhost:8000/api/v1/submit/upload', {
          method: 'POST',
          headers: { 'x-session-id': sessionId },
          body: fd,
        })
      }
      const data = await res.json()
      setResult(data)
      setSecAdvice(data.security_advice ?? [])
      if (data.status === 'validated') setShowOv(true)
      fetchHistory()   // refresh history after new scan
    } catch {
      setResult({ status: 'error', message: 'Cannot reach backend server.', errors: [] })
    }
    setLoading(false)
  }

  return (
    <>
      <BgParticles />
      <CursorTrail />
      {showOv && <SuccessOverlay onDismiss={() => setShowOv(false)} />}

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
            <p className="hdr-tag">Deep analysis · Real-time feedback · Smart fixes</p>
          </div>
        </div>
        <nav className="hdr-pills">
          <span className="hdr-pill">🛡 Security</span>
          <span className="hdr-pill">⚡ Instant</span>
          <span className="hdr-pill">🔬 Precise</span>
        </nav>
      </header>

      {/* ══ MAIN GRID ══ */}
      <main className="app-grid">

        {/* LEFT: Editor panel */}
        <section className="panel left-panel">
          <div className="p-inner">
            <div className="tabs-row">
              <button className={`ptab ${tab === 'paste' ? 'ptab-on' : ''}`} onClick={() => setTab('paste')}>
                <span>📝</span> Paste Code
              </button>
              <button className={`ptab ${tab === 'upload' ? 'ptab-on' : ''}`} onClick={() => setTab('upload')}>
                <span>📂</span> Upload File
              </button>
              {tab === 'paste' && (
                <select className="lang-sel" value={lang} onChange={e => setLang(e.target.value)}>
                  <option value="python">🐍 Python</option>
                  <option value="java">☕ Java</option>
                </select>
              )}
            </div>

            {tab === 'paste' ? (
              <div className="editor-box">
                <ScanBeam active={loading} />
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
                <input type="file" accept=".py,.java" style={{ display: 'none' }}
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
                  {isValid ? '✓ Passed' : `✗ ${errors.length} Issue${errors.length !== 1 ? 's' : ''}`}
                </span>
              )}
              <button className={`run-btn ${loading ? 'run-loading' : ''}`} onClick={run} disabled={loading}>
                {loading
                  ? <><span className="run-spin" /><span>Analysing...</span></>
                  : <><span className="run-hex">⬡</span><span>Run Analysis</span></>
                }
              </button>
            </div>
          </div>
        </section>

        {/* RIGHT: Results panel */}
        <section className="panel right-panel">
          <div className="p-inner">
            <div className="rp-top">
              <h2 className="rp-h2">Scan Results</h2>
              {result && (
                <span className={`rp-pill ${isValid ? 'rpill-ok' : 'rpill-err'}`}>
                  {isValid ? '● All Clear' : `● ${errors.length} Bug${errors.length !== 1 ? 's' : ''}`}
                </span>
              )}
            </div>

            <div className="rp-body">
              {!result ? (
                /* EMPTY STATE — bouncing magnifier + pulse rings */
                <div className="empty-st">
                  <div className="mag-wrap">
                    <span className="mag-ico">🔍</span>
                    <div className="pulse-rings"><div /><div /><div /></div>
                  </div>
                  <p className="empty-txt">
                    Paste or upload your code,<br />then click <em>Run Analysis</em>
                  </p>
                  <div className="empty-caps">
                    <span>Syntax</span><span>·</span><span>Semantics</span><span>·</span><span>Fixes</span>
                  </div>
                </div>

              ) : isValid && !showOv ? (
                /* INLINE SUCCESS */
                <div className="inline-ok">
                  <span className="iok-trophy">🏆</span>
                  <h3>All Clear!</h3>
                  <p>No issues found in your code.</p>
                  <button className="btn-replay" onClick={() => setShowOv(true)}>
                    Replay Celebration 🎆
                  </button>
                </div>

              ) : !isValid ? (
                /* ERROR STATE */
                <div className="err-state">
                  <div className="err-hdr">
                    <span className="err-bug-ico">🐛</span>
                    <div>
                      <p className="err-hdr-t">Issues Detected</p>
                      <p className="err-hdr-s">
                        {errors.length} problem{errors.length !== 1 ? 's' : ''} — expand each card for the fix
                      </p>
                    </div>
                  </div>
                  <div className="ec-stack">
                    {errors.length > 0
                      ? errors.map((e, i) => <ErrorCard key={i} error={e} index={i} />)
                      : <div className="result-box"><pre>{result.message}</pre></div>
                    }
                  </div>
                </div>

              ) : null}

              {/* ── Security Advice from KB ── */}
              {secAdvice.length > 0 && (
                <div className="sa-section">
                  <div className="sa-section-hd">
                    <span>🧠</span>
                    <span className="sa-section-title">Knowledge Base Insights</span>
                    <span className="sa-section-sub">{secAdvice.length} relevant references</span>
                  </div>
                  {secAdvice.map((a, i) => <SecurityAdviceCard key={i} advice={a} index={i} />)}
                </div>
              )}
            </div>
          </div>
        </section>

      </main>

      {/* ══ HISTORY PANEL ══ */}
      <section className="hist-section">
        <div className="hist-hd">
          <div className="hist-hd-l">
            <span className="hist-icon">🕑</span>
            <h2 className="hist-title">Scan History</h2>
            <span className="hist-count">{history.length} scans</span>
          </div>
          <button className="hist-refresh" onClick={fetchHistory} disabled={histLoading} title="Refresh history">
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
            history.map((item, i) => <HistoryItem key={item.scan_id} item={item} index={i} />)
          )}
        </div>
      </section>
    </>
  )
}
