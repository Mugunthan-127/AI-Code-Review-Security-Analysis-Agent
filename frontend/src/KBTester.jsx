import { useState } from 'react';

export default function KBTester() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const search = async (e) => {
    e.preventDefault();
    if (!query) return;
    setLoading(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/kb/retrieve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, k: 5 }),
      });
      const data = await res.json();
      setResults(data.results || []);
    } catch {}
    setLoading(false);
  };

  return (
    <section className="hist-section" style={{maxWidth: '800px', margin: '0 auto', marginTop: '32px'}}>
      <div className="hist-hd">
        <div className="hist-hd-l">
          <span className="hist-icon">📚</span>
          <h2 className="hist-title">KB Retrieval Tester</h2>
        </div>
      </div>
      <div className="hist-body" style={{padding: '24px'}}>
        <form onSubmit={search} style={{display: 'flex', gap: '12px', marginBottom: '24px'}}>
          <input type="text" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search security patterns..." style={{flex: 1, padding: '12px', borderRadius: '8px', border: '1px solid var(--surf-border)', background: 'rgba(0,0,0,0.2)', color: 'white', fontSize: '16px'}} />
          <button type="submit" disabled={loading} style={{padding: '0 24px', borderRadius: '8px', background: 'var(--primary)', color: 'black', fontWeight: 'bold', border: 'none', cursor: 'pointer'}}>
            {loading ? 'Searching...' : 'Search'}
          </button>
        </form>
        
        <div style={{display: 'flex', flexDirection: 'column', gap: '12px'}}>
          {results.map((r, i) => (
            <div key={i} className="sa" style={{background: 'rgba(255,255,255,0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--surf-border)'}}>
              <div style={{display: 'flex', gap: '8px', marginBottom: '8px'}}>
                <span className="sa-src">{r.source}</span>
                {r.owasp_id && <span className="sa-badge sa-owasp">{r.owasp_id}</span>}
                {r.cwe_id && <span className="sa-badge sa-cwe">{r.cwe_id}</span>}
                <span className="sa-badge sa-cat">{r.category}</span>
              </div>
              <p style={{color: 'var(--txt-muted)', fontSize: '0.9em', lineHeight: 1.5}}>{r.text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
