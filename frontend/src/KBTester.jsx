import { useState, useEffect } from 'react';

const API = 'http://127.0.0.1:8000';

function StatCard({ label, value, icon, color }) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.04)',
      border: `1px solid ${color || 'var(--surf-border)'}`,
      borderRadius: '12px',
      padding: '16px 20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '6px',
      minWidth: '140px',
    }}>
      <span style={{ fontSize: '1.4em' }}>{icon}</span>
      <span style={{ fontSize: '1.6em', fontWeight: 700, color: color || 'var(--primary)' }}>{value}</span>
      <span style={{ fontSize: '0.78em', color: 'var(--txt-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
    </div>
  );
}

function ScoreBadge({ score }) {
  // Use sigmoid function to convert logits into a probability percentage (0 to 1)
  const pct = 1 / (1 + Math.exp(-score));
  const color = pct > 0.7 ? '#22c55e' : pct > 0.4 ? '#f59e0b' : '#94a3b8';
  return (
    <span style={{
      background: `${color}22`,
      border: `1px solid ${color}55`,
      color,
      borderRadius: '999px',
      padding: '2px 10px',
      fontSize: '0.78em',
      fontWeight: 700,
      whiteSpace: 'nowrap',
    }}>
      {(pct * 100).toFixed(0)}% match
    </span>
  );
}

export default function KBTester() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [resetLoading, setResetLoading] = useState(false);
  const [resetMsg, setResetMsg] = useState('');
  const [activeTab, setActiveTab] = useState('search'); // 'search' | 'stats'

  // Filters
  const [filterLanguage, setFilterLanguage] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterOwasp, setFilterOwasp] = useState('');
  const [kCount, setKCount] = useState(5);

  const loadStats = async () => {
    setStatsLoading(true);
    try {
      const res = await fetch(`${API}/api/kb/stats`);
      const data = await res.json();
      setStats(data);
    } catch { setStats(null); }
    setStatsLoading(false);
  };

  useEffect(() => { loadStats(); }, []);

  const search = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setResults([]);
    try {
      const body = {
        query: query.trim(),
        k: kCount,
        ...(filterLanguage && { language: filterLanguage }),
        ...(filterCategory && { category: filterCategory }),
        ...(filterSeverity && { severity: filterSeverity }),
        ...(filterOwasp && { owasp_id: filterOwasp }),
      };
      const res = await fetch(`${API}/api/kb/retrieve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setResults(data.results || []);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  const handleReset = async () => {
    if (!window.confirm('This will clear all ChromaDB chunks and re-ingest from kb_sources. Continue?')) return;
    setResetLoading(true);
    setResetMsg('');
    try {
      const res = await fetch(`${API}/api/kb/reset`, { method: 'POST' });
      const data = await res.json();
      setResetMsg(data.message || 'Reset started.');
      setTimeout(loadStats, 3000);
    } catch {
      setResetMsg('Reset request failed.');
    }
    setResetLoading(false);
  };

  const tabStyle = (tab) => ({
    padding: '8px 20px',
    borderRadius: '8px',
    border: 'none',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: '0.9em',
    background: activeTab === tab ? 'var(--primary)' : 'rgba(255,255,255,0.06)',
    color: activeTab === tab ? '#000' : 'var(--txt-muted)',
    transition: 'all 0.2s',
  });

  const inputStyle = {
    padding: '10px 14px',
    borderRadius: '8px',
    border: '1px solid var(--surf-border)',
    background: 'rgba(0,0,0,0.25)',
    color: 'white',
    fontSize: '0.9em',
    outline: 'none',
  };

  const selectStyle = { ...inputStyle, cursor: 'pointer' };

  return (
    <section className="hist-section" style={{ maxWidth: '900px', margin: '0 auto', marginTop: '32px' }}>
      {/* Header */}
      <div className="hist-hd">
        <div className="hist-hd-l">
          <span className="hist-icon">🗄️</span>
          <h2 className="hist-title">VectorDB Explorer</h2>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button style={tabStyle('search')} onClick={() => setActiveTab('search')}>🔍 Search</button>
          <button style={tabStyle('stats')} onClick={() => { setActiveTab('stats'); loadStats(); }}>📊 Stats</button>
        </div>
      </div>

      <div className="hist-body" style={{ padding: '24px' }}>

        {/* ─── SEARCH TAB ─── */}
        {activeTab === 'search' && (
          <>
            {/* Quick stat pill */}
            {stats && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px' }}>
                <span style={{ fontSize: '0.82em', color: 'var(--txt-muted)' }}>
                  🗄️ ChromaDB · <strong style={{ color: 'var(--primary)' }}>{stats.total_chunks?.toLocaleString() || 0}</strong> chunks indexed
                </span>
                <span style={{ fontSize: '0.82em', color: 'var(--txt-muted)', background: 'rgba(255,255,255,0.06)', padding: '2px 10px', borderRadius: '999px' }}>
                  {stats.collection_name || 'kb_chunks'}
                </span>
              </div>
            )}

            {/* Main search bar */}
            <form onSubmit={search} style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
              <input
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="e.g. SQL injection prevention, hardcoded secrets, XSS..."
                style={{ ...inputStyle, flex: 1, fontSize: '1em' }}
              />
              <button
                type="submit"
                disabled={loading}
                style={{
                  padding: '0 24px',
                  borderRadius: '8px',
                  background: loading ? 'rgba(255,255,255,0.1)' : 'var(--primary)',
                  color: loading ? 'var(--txt-muted)' : '#000',
                  fontWeight: 700,
                  border: 'none',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  transition: 'all 0.2s',
                  whiteSpace: 'nowrap',
                }}
              >
                {loading ? '⏳ Searching...' : '🔍 Search'}
              </button>
            </form>

            {/* Filters row */}
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '24px' }}>
              <select value={filterLanguage} onChange={e => setFilterLanguage(e.target.value)} style={selectStyle}>
                <option value="">All Languages</option>
                <option value="python">Python</option>
                <option value="java">Java</option>
              </select>
              <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} style={selectStyle}>
                <option value="">Any Severity</option>
                <option value="critical">Critical+</option>
                <option value="high">High+</option>
                <option value="medium">Medium+</option>
                <option value="low">Low+</option>
              </select>
              <select value={filterOwasp} onChange={e => setFilterOwasp(e.target.value)} style={selectStyle}>
                <option value="">Any OWASP</option>
                {['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10'].map(id => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <input
                type="text"
                value={filterCategory}
                onChange={e => setFilterCategory(e.target.value)}
                placeholder="Category (e.g. injection)"
                style={{ ...inputStyle, width: '180px' }}
              />
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <label style={{ fontSize: '0.82em', color: 'var(--txt-muted)', whiteSpace: 'nowrap' }}>Top-K</label>
                <input
                  type="number"
                  min={1} max={20}
                  value={kCount}
                  onChange={e => setKCount(Number(e.target.value))}
                  style={{ ...inputStyle, width: '64px', textAlign: 'center' }}
                />
              </div>
            </div>

            {/* Results */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {results.length === 0 && !loading && query && (
                <p style={{ color: 'var(--txt-muted)', textAlign: 'center', padding: '24px' }}>
                  No results found. Try a different query or remove filters.
                </p>
              )}
              {results.map((r, i) => (
                <div
                  key={i}
                  className="sa"
                  style={{
                    background: 'rgba(255,255,255,0.025)',
                    padding: '16px',
                    borderRadius: '10px',
                    border: '1px solid var(--surf-border)',
                    transition: 'border-color 0.2s',
                  }}
                >
                  {/* Meta row */}
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '10px', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.88em', color: 'var(--primary)' }}>#{i + 1}</span>
                    <span className="sa-src" style={{ fontSize: '0.82em' }}>{r.source}</span>
                    {r.owasp_id && <span className="sa-badge sa-owasp">{r.owasp_id}</span>}
                    {r.cwe_id && <span className="sa-badge sa-cwe">{r.cwe_id}</span>}
                    {r.category && <span className="sa-badge sa-cat">{r.category}</span>}
                    {r.language && (
                      <span className="sa-badge" style={{ background: 'rgba(99,102,241,0.15)', color: '#a5b4fc', border: '1px solid rgba(99,102,241,0.3)' }}>
                        {r.language}
                      </span>
                    )}
                    {r.severity && (
                      <span className="sa-badge" style={{
                        background: r.severity === 'high' ? 'rgba(239,68,68,0.15)' : r.severity === 'medium' ? 'rgba(245,158,11,0.15)' : 'rgba(148,163,184,0.1)',
                        color: r.severity === 'high' ? '#fca5a5' : r.severity === 'medium' ? '#fcd34d' : '#94a3b8',
                        border: '1px solid transparent',
                      }}>
                        {r.severity}
                      </span>
                    )}
                    <div style={{ marginLeft: 'auto' }}>
                      <ScoreBadge score={r.score || 0} />
                    </div>
                  </div>
                  {/* Chunk text */}
                  <p style={{
                    color: 'var(--txt-muted)',
                    fontSize: '0.88em',
                    lineHeight: 1.65,
                    margin: 0,
                    display: '-webkit-box',
                    WebkitLineClamp: 5,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                  }}>
                    {r.text}
                  </p>
                  {/* Token count */}
                  <div style={{ marginTop: '8px', fontSize: '0.75em', color: 'rgba(148,163,184,0.5)' }}>
                    {r.token_count} tokens
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {/* ─── STATS TAB ─── */}
        {activeTab === 'stats' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
              <h3 style={{ margin: 0, fontSize: '1em', color: 'var(--txt-muted)' }}>ChromaDB Collection Stats</h3>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button onClick={loadStats} disabled={statsLoading} style={{
                  padding: '8px 16px', borderRadius: '8px', border: '1px solid var(--surf-border)',
                  background: 'rgba(255,255,255,0.06)', color: 'white', cursor: 'pointer', fontSize: '0.85em',
                }}>
                  {statsLoading ? '...' : '🔄 Refresh'}
                </button>
                <button onClick={handleReset} disabled={resetLoading} style={{
                  padding: '8px 16px', borderRadius: '8px', border: '1px solid rgba(239,68,68,0.4)',
                  background: 'rgba(239,68,68,0.1)', color: '#fca5a5', cursor: 'pointer', fontSize: '0.85em',
                }}>
                  {resetLoading ? '...' : '🗑️ Reset & Re-ingest'}
                </button>
              </div>
            </div>

            {resetMsg && (
              <div style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: '8px', padding: '12px 16px', marginBottom: '20px', color: '#86efac', fontSize: '0.88em' }}>
                ✅ {resetMsg}
              </div>
            )}

            {stats && !stats.error ? (
              <>
                {/* Top stat cards */}
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '28px' }}>
                  <StatCard icon="🧩" label="Total Chunks" value={stats.total_chunks?.toLocaleString() || '0'} color="var(--primary)" />
                  <StatCard icon="📂" label="Categories" value={Object.keys(stats.categories || {}).length} color="#818cf8" />
                  <StatCard icon="🌐" label="Languages" value={Object.keys(stats.languages || {}).length || '—'} color="#34d399" />
                </div>

                {/* Category breakdown */}
                {Object.keys(stats.categories || {}).length > 0 && (
                  <div style={{ marginBottom: '24px' }}>
                    <h4 style={{ fontSize: '0.85em', color: 'var(--txt-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
                      Category Breakdown
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {Object.entries(stats.categories)
                        .sort(([,a], [,b]) => b - a)
                        .map(([cat, count]) => {
                          const pct = stats.total_chunks ? (count / stats.total_chunks * 100).toFixed(1) : 0;
                          return (
                            <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                              <span style={{ width: '200px', fontSize: '0.85em', color: 'white', flexShrink: 0 }}>{cat}</span>
                              <div style={{ flex: 1, background: 'rgba(255,255,255,0.06)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
                                <div style={{ width: `${pct}%`, background: 'var(--primary)', height: '100%', borderRadius: '4px', transition: 'width 0.5s' }} />
                              </div>
                              <span style={{ fontSize: '0.8em', color: 'var(--txt-muted)', width: '60px', textAlign: 'right' }}>{count} ({pct}%)</span>
                            </div>
                          );
                        })}
                    </div>
                  </div>
                )}

                {/* Storage info */}
                <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: '10px', padding: '16px', border: '1px solid var(--surf-border)', fontSize: '0.84em', color: 'var(--txt-muted)' }}>
                  <div style={{ marginBottom: '6px' }}>📁 <strong style={{ color: 'white' }}>Collection:</strong> {stats.collection_name}</div>
                  <div>💾 <strong style={{ color: 'white' }}>Path:</strong> {stats.chroma_db_path}</div>
                </div>
              </>
            ) : statsLoading ? (
              <p style={{ color: 'var(--txt-muted)', textAlign: 'center', padding: '32px' }}>Loading stats...</p>
            ) : (
              <p style={{ color: '#fca5a5', textAlign: 'center', padding: '32px' }}>
                {stats?.error || 'Could not load ChromaDB stats.'}
              </p>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
