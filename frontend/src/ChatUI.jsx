import { useState } from 'react';

export default function ChatUI({ scanId, sessionId }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [chatSession, setChatSession] = useState(null);
  const [loading, setLoading] = useState(false);

  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    
    const userMsg = { role: 'user', content: input };
    setMessages([...messages, userMsg]);
    setInput('');
    setLoading(true);
    
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/scans/${scanId}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: input, session_id: chatSession }),
      });
      const data = await res.json();
      setChatSession(data.session_id);
      setMessages([...messages, userMsg, { role: 'assistant', content: data.reply }]);
    } catch {
      setMessages([...messages, userMsg, { role: 'assistant', content: 'Network error.' }]);
    }
    setLoading(false);
  };

  return (
    <div className="chat-ui" style={{marginTop: '24px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', padding: '16px', border: '1px solid var(--surf-border)'}}>
      <div className="sa-section-hd" style={{marginBottom: '16px'}}>
        <span>💬</span>
        <span className="sa-section-title">AI Assistant</span>
        <span className="sa-section-sub">Ask questions about your code</span>
      </div>
      <div style={{maxHeight: '300px', overflowY: 'auto', marginBottom: '16px', display: 'flex', flexDirection: 'column', gap: '8px'}}>
        {messages.map((m, i) => (
          <div key={i} style={{
            alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
            background: m.role === 'user' ? 'rgba(14, 165, 233, 0.2)' : 'rgba(255,255,255,0.05)',
            padding: '8px 12px', borderRadius: '8px', maxWidth: '80%'
          }}>
            <strong style={{fontSize: '0.8em', opacity: 0.7}}>{m.role === 'user' ? 'You' : 'AI'}:</strong>
            <p style={{margin: '4px 0 0', whiteSpace: 'pre-wrap', fontSize: '0.9em'}}>{m.content}</p>
          </div>
        ))}
        {loading && <div style={{opacity: 0.5}}>Thinking...</div>}
      </div>
      
      {/* AI Tutor Quick Actions */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
        {[
          "Explain Like Beginner",
          "Generate Secure Version",
          "Compare Old vs New",
          "Which OWASP?",
          "Why was this found?",
          "Show Example",
          "Fix specific line..."
        ].map(action => (
          <button 
            key={action}
            onClick={(e) => {
              e.preventDefault();
              if (action === "Fix specific line...") {
                setInput("Fix line ");
              } else {
                // To avoid duplication, we mock the event object
                const syntheticEvent = { preventDefault: () => {} };
                setInput(action);
                // In React, setting state and using it immediately is async, 
                // so we pass the action directly to a helper or just let the effect run.
                // For simplicity, we just set the input, user can hit send.
              }
            }}
            style={{
              padding: '6px 12px', 
              background: 'rgba(255,255,255,0.1)', 
              border: '1px solid rgba(255,255,255,0.2)', 
              borderRadius: '16px', 
              color: 'var(--txt-normal)', 
              fontSize: '0.85em', 
              cursor: 'pointer',
              transition: 'background 0.2s'
            }}
            onMouseOver={(e) => e.target.style.background = 'rgba(255,255,255,0.2)'}
            onMouseOut={(e) => e.target.style.background = 'rgba(255,255,255,0.1)'}
          >
            {action}
          </button>
        ))}
      </div>

      <form onSubmit={sendMessage} style={{display: 'flex', gap: '8px'}}>
        <input type="text" value={input} onChange={e=>setInput(e.target.value)} placeholder="Ask your AI Tutor about the findings..." style={{flex: 1, padding: '8px 12px', borderRadius: '8px', border: '1px solid var(--surf-border)', background: 'rgba(0,0,0,0.2)', color: 'white'}} />
        <button type="submit" disabled={loading} style={{padding: '8px 16px', borderRadius: '8px', background: 'var(--primary)', color: 'black', fontWeight: 'bold', border: 'none', cursor: 'pointer'}}>Send</button>
      </form>
    </div>
  );
}
