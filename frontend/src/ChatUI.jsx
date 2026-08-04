import { useState, useEffect, useRef } from 'react';

/* ── Simple inline markdown renderer ── */
function renderMarkdown(text) {
  if (!text) return null;
  // Split by code blocks first
  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('```')) {
      const lines = part.slice(3).split('\n');
      const lang = lines[0].trim();
      const code = lines.slice(1, -1).join('\n');
      return (
        <pre key={idx} style={{ background: 'rgba(0,0,0,0.4)', padding: '12px', borderRadius: '6px', overflowX: 'auto', margin: '8px 0', fontSize: '0.85em', border: '1px solid rgba(255,255,255,0.1)' }}>
          {lang && <span style={{ color: '#60a5fa', fontSize: '0.75em', display: 'block', marginBottom: '4px' }}>{lang}</span>}
          <code style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{code}</code>
        </pre>
      );
    }
    // Inline rendering: split by lines
    return part.split('\n').map((line, li) => {
      // Heading
      if (line.startsWith('### ')) return <h4 key={li} style={{ margin: '8px 0 4px', color: '#e2e8f0', fontSize: '1em' }}>{line.slice(4)}</h4>;
      if (line.startsWith('## '))  return <h3 key={li} style={{ margin: '10px 0 4px', color: '#e2e8f0', fontSize: '1.05em' }}>{line.slice(3)}</h3>;
      if (line.startsWith('# '))   return <h2 key={li} style={{ margin: '12px 0 4px', color: '#f1f5f9', fontSize: '1.1em' }}>{line.slice(2)}</h2>;
      // Bullet
      if (line.startsWith('- ') || line.startsWith('* ')) {
        return <div key={li} style={{ margin: '2px 0', paddingLeft: '12px', display: 'flex', gap: '6px' }}><span style={{ color: 'var(--primary)' }}>•</span><span>{inlineFormat(line.slice(2))}</span></div>;
      }
      // Numbered list
      const numMatch = line.match(/^(\d+)\. (.+)/);
      if (numMatch) {
        return <div key={li} style={{ margin: '2px 0', paddingLeft: '12px', display: 'flex', gap: '6px' }}><span style={{ color: 'var(--primary)', minWidth: '16px' }}>{numMatch[1]}.</span><span>{inlineFormat(numMatch[2])}</span></div>;
      }
      if (line.trim() === '') return <div key={li} style={{ height: '6px' }} />;
      return <p key={li} style={{ margin: '3px 0', lineHeight: '1.55' }}>{inlineFormat(line)}</p>;
    });
  });
}

function inlineFormat(text) {
  // Bold **text** and inline `code`
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((p, i) => {
    if (p.startsWith('**') && p.endsWith('**')) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.startsWith('`') && p.endsWith('`'))   return <code key={i} style={{ background: 'rgba(255,255,255,0.1)', padding: '1px 5px', borderRadius: '3px', fontSize: '0.9em', fontFamily: 'monospace' }}>{p.slice(1, -1)}</code>;
    return p;
  });
}

export default function ChatUI({ scanId, sessionId, externalQuery, setExternalQuery }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput]       = useState('');
  const [chatSession, setChatSession] = useState(null);
  const [loading, setLoading]   = useState(false);
  const inputRef  = useRef(null);
  const bottomRef = useRef(null);

  // Auto-scroll when messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  // External query injection (from "Ask Assistant" button on FindingCard)
  useEffect(() => {
    if (externalQuery) {
      setExternalQuery('');
      sendDirectMessage(externalQuery);
    }
  }, [externalQuery]); // eslint-disable-line react-hooks/exhaustive-deps

  const sendDirectMessage = async (text) => {
    if (!text.trim()) return;
    const userMsg = { role: 'user', content: text };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);
    await callApi(text, userMsg);
    setLoading(false);
  };

  const callApi = async (text, userMsg) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/scans/${scanId}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, session_id: chatSession }),
      });
      const data = await res.json();
      setChatSession(data.session_id);
      setMessages(prev => [...prev, { role: 'assistant', content: data.reply, citations: data.citations }]);
    } catch {
      setMessages(prev => [...prev, { role: 'assistant', content: '❌ Network error. Is the backend running?' }]);
    }
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;
    const text = input.trim();
    setInput('');
    await sendDirectMessage(text);
  };

  const handleQuickAction = (action) => {
    if (loading) return;
    if (action === 'Fix specific line...') {
      setInput('Fix line ');
      inputRef.current?.focus();
    } else {
      sendDirectMessage(action);
    }
  };

  const QUICK_ACTIONS = [
    'Explain Like Beginner',
    'Generate Secure Version',
    'Compare Old vs New',
    'Which OWASP?',
    'Why was this found?',
    'Show Example',
    'Fix specific line...',
  ];

  return (
    <div className="chat-ui" style={{ marginTop: '24px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', padding: '16px', border: '1px solid var(--surf-border)' }}>
      {/* Header */}
      <div className="sa-section-hd" style={{ marginBottom: '16px' }}>
        <span>💬</span>
        <span className="sa-section-title">AI Code Assistant</span>
        <span className="sa-section-sub">RAG-powered • grounded in OWASP knowledge base</span>
      </div>

      {/* Message thread */}
      <div style={{ maxHeight: '380px', overflowY: 'auto', marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '10px', padding: '4px 0' }}>
        {messages.length === 0 && (
          <div style={{ textAlign: 'center', color: 'var(--txt-muted)', fontSize: '0.9em', padding: '20px 0' }}>
            <div style={{ fontSize: '2rem', marginBottom: '8px' }}>🤖</div>
            Ask me anything about your findings. Use the quick actions below or type your own question.
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} style={{
            alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
            background: m.role === 'user'
              ? 'linear-gradient(135deg, rgba(14,165,233,0.25), rgba(14,165,233,0.15))'
              : 'rgba(255,255,255,0.04)',
            padding: '10px 14px',
            borderRadius: m.role === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
            maxWidth: '88%',
            border: m.role === 'user' ? '1px solid rgba(14,165,233,0.3)' : '1px solid rgba(255,255,255,0.08)',
          }}>
            <div style={{ fontSize: '0.72em', opacity: 0.6, marginBottom: '4px', fontWeight: 'bold', letterSpacing: '0.5px' }}>
              {m.role === 'user' ? '👤 YOU' : '🤖 AI ASSISTANT'}
            </div>
            <div style={{ fontSize: '0.9em', lineHeight: '1.55', color: 'var(--txt-main)' }}>
              {m.role === 'assistant' ? renderMarkdown(m.content) : m.content}
            </div>
            {m.citations && m.citations.length > 0 && (
              <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.1)', fontSize: '0.75em', color: 'var(--txt-muted)' }}>
                📚 <strong>Sources:</strong> {m.citations.map(c => c.replace('.md', '').replace(/_/g, ' ')).join(' · ')}
              </div>
            )}
          </div>
        ))}
        {loading && (
          <div style={{
            alignSelf: 'flex-start',
            background: 'rgba(255,255,255,0.04)',
            padding: '10px 14px',
            borderRadius: '12px 12px 12px 2px',
            border: '1px solid rgba(255,255,255,0.08)',
            color: 'var(--txt-muted)',
            fontSize: '0.9em',
          }}>
            🤖 <span style={{ display: 'inline-block', animation: 'pulse 1.2s ease-in-out infinite' }}>Thinking…</span>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick Actions */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '12px' }}>
        {QUICK_ACTIONS.map(action => (
          <button
            key={action}
            onClick={() => handleQuickAction(action)}
            disabled={loading}
            style={{
              padding: '5px 11px',
              background: 'rgba(14,165,233,0.08)',
              border: '1px solid rgba(14,165,233,0.2)',
              borderRadius: '16px',
              color: loading ? 'var(--txt-muted)' : '#38bdf8',
              fontSize: '0.82em',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s',
              opacity: loading ? 0.5 : 1,
            }}
            onMouseOver={e => { if (!loading) e.currentTarget.style.background = 'rgba(14,165,233,0.18)'; }}
            onMouseOut={e => { e.currentTarget.style.background = 'rgba(14,165,233,0.08)'; }}
          >
            {action}
          </button>
        ))}
      </div>

      {/* Input bar */}
      <form onSubmit={sendMessage} style={{ display: 'flex', gap: '8px' }}>
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Ask your AI Tutor about the findings..."
          disabled={loading}
          style={{
            flex: 1,
            padding: '10px 14px',
            borderRadius: '8px',
            border: '1px solid var(--surf-border)',
            background: 'rgba(0,0,0,0.25)',
            color: 'white',
            fontSize: '0.9em',
            outline: 'none',
            opacity: loading ? 0.6 : 1,
          }}
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          style={{
            padding: '10px 18px',
            borderRadius: '8px',
            background: 'var(--primary)',
            color: '#000',
            fontWeight: 'bold',
            border: 'none',
            cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
            opacity: loading || !input.trim() ? 0.6 : 1,
            fontSize: '0.9em',
            transition: 'opacity 0.15s',
          }}
        >
          {loading ? '⏳' : 'Send ↵'}
        </button>
      </form>
    </div>
  );
}
