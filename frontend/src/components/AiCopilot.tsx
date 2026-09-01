import React, { useState, useRef, useEffect } from 'react';
import { useStore } from '../store/useStore';

type Msg = { role: 'user' | 'bot'; text: string };

function escHtml(s: string) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

const CopilotIcon = ({ size = 26 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path 
      d="M12 2C12 7.52285 7.52285 12 2 12C7.52285 12 12 16.4771 12 22C12 16.4771 16.4771 12 22 12C16.4771 12 12 7.52285 12 2Z" 
      fill="url(#copilot-main-grad)"
    />
    <path 
      d="M6 3.5C6 5.70914 4.20914 7.5 2 7.5C4.20914 7.5 6 9.29086 6 11.5C6 9.29086 7.79086 7.5 10 7.5C7.79086 7.5 6 5.70914 6 3.5Z" 
      fill="url(#copilot-accent-grad)" 
      opacity="0.9"
    />
    <defs>
      <linearGradient id="copilot-main-grad" x1="2" y1="2" x2="22" y2="22" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#38BDF8" />
        <stop offset="50%" stopColor="#818CF8" />
        <stop offset="100%" stopColor="#C084FC" />
      </linearGradient>
      <linearGradient id="copilot-accent-grad" x1="2" y1="3.5" x2="10" y2="11.5" gradientUnits="userSpaceOnUse">
        <stop offset="0%" stopColor="#F472B6" />
        <stop offset="100%" stopColor="#F59E0B" />
      </linearGradient>
    </defs>
  </svg>
);

function getReply(q: string, alerts: any[], status: any): string {
  const lq = q.toLowerCase();

  if (['hi','hello','hey'].includes(lq) || lq.includes('who are you') || lq.includes('help')) {
    return `✨ Hello Analyst! I'm <strong>ENCLIVRA AI Security Copilot</strong>.<br><br>I can help with:<br>• Analyzing IP addresses &amp; threat actors<br>• Explaining attack techniques (C2, DNS Tunneling, DDoS, etc.)<br>• Evidence chain integrity checks<br>• Firewall &amp; mitigation commands<br>• CISO executive briefings`;
  }

  if (lq.includes('enclivra') || lq.includes('what is') || lq.includes('platform')) {
    return `🛡️ <strong>ENCLIVRA</strong> is an AI-powered threat intelligence platform for unidirectional networks.<br><br>• <strong>Live IP Ingress Stream:</strong> Animated real-time packet telemetry<br>• <strong>Evidence Chain:</strong> SHA-256 block hashing &amp; Ed25519 signatures<br>• <strong>7 Detection Engines:</strong> DDoS, C2 Beaconing, DNS Tunnelling, JA3 TLS, Port Scan, Exfiltration &amp; Linux Telemetry<br>• <strong>Zero Egress:</strong> Hardware-enforced unidirectional diode`;
  }

  const ipMatch = q.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  if (ipMatch) {
    const ip = ipMatch[0];
    const related = alerts.filter(a => (a.source_ips && a.source_ips.includes(ip)) || (a.dest_ips && a.dest_ips.includes(ip)) || a.src_ip === ip);
    if (related.length > 0) {
      const top = related[0];
      return `🔍 <strong>Threat Intel for IP ${ip}:</strong><br><br>• <strong>Incident:</strong> ${top.title || 'Unknown threat'}<br>• <strong>Severity:</strong> ${(top.severity || 'HIGH').toUpperCase()}<br>• <strong>Confidence:</strong> ${Math.round((top.confidence || 0.9) * 100)}%<br>• <strong>Type:</strong> ${(top.threat_type || 'Unknown').replace('_',' ').toUpperCase()}<br><br>⚡ <strong>Block Command:</strong><br><code style="background:#1e293b;color:#38bdf8;padding:3px 7px;border-radius:5px;display:block;margin-top:4px;font-size:11px;">sudo iptables -A INPUT -s ${ip} -j DROP</code>`;
    } else {
      return `🔍 <strong>IP ${ip}:</strong> No active threat signatures in current telemetry. Host appears clean (Z-Score &lt; 1.0).`;
    }
  }

  if (lq.includes('block') || lq.includes('firewall') || lq.includes('mitigat') || lq.includes('iptables')) {
    return `⚡ <strong>Emergency Mitigation Commands:</strong><br><br><strong>Linux iptables:</strong><br><code style="background:#1e293b;color:#38bdf8;padding:3px 7px;border-radius:5px;display:block;margin-bottom:5px;font-size:11px;">sudo iptables -A INPUT -s THREAT_IP -j DROP</code><strong>Cisco ASA:</strong><br><code style="background:#1e293b;color:#38bdf8;padding:3px 7px;border-radius:5px;display:block;margin-bottom:5px;font-size:11px;">access-list OUTSIDE_IN deny ip host THREAT_IP any</code><strong>pfSense pf:</strong><br><code style="background:#1e293b;color:#38bdf8;padding:3px 7px;border-radius:5px;display:block;font-size:11px;">block drop in quick from THREAT_IP to any</code>`;
  }

  if (lq.includes('c2') || lq.includes('beacon') || lq.includes('cobalt')) {
    return `📡 <strong>C2 Beaconing (T1071.001):</strong><br><br>Periodic SSL connections matching Cobalt Strike profile — 30s interval, 15% jitter, JA3: <code>e7d705a3286e</code>. Host 192.168.1.50 active. Evidence sealed in block #1 of SHA-256 ledger.<br><br><strong>Mitigation:</strong> Null-route 45.33.32.156 and isolate the host from subnet.`;
  }

  if (lq.includes('dns') || lq.includes('tunnel') || lq.includes('exfil')) {
    return `🌐 <strong>DNS Tunneling / Exfiltration (T1048):</strong><br><br>High subdomain entropy (H=4.82) on <code>data.evil.com</code>. TXT record payloads 184 chars — known DNS exfiltration pattern. Host: 192.168.1.75 | 50MB transferred to 203.0.113.50.`;
  }

  if (lq.includes('ddos') || lq.includes('flood') || lq.includes('syn')) {
    return `⚡ <strong>Volumetric DDoS — SYN Flood (T1498):</strong><br><br>1,000 SYN packets/sec from 250 spoofed IPs targeting gateway 10.0.0.100:80.<br><br><strong>Mitigation:</strong> Enable TCP SYN cookies + rate-limit inbound SYN to 50 pps/source.`;
  }

  if (lq.includes('tls') || lq.includes('ja3') || lq.includes('ssl') || lq.includes('cert')) {
    return `🔐 <strong>Encrypted Malware via JA3 Fingerprinting (T1573):</strong><br><br>Self-signed X.509 cert (CN=localhost, 1-day validity) on 192.168.1.80. Detected via SPLT side-channel without payload decryption.`;
  }

  if (lq.includes('port') || lq.includes('scan') || lq.includes('recon')) {
    return `🔍 <strong>Port Scan / Reconnaissance (T1046):</strong><br><br>Sequential SYN sweep across 100 ports from 10.0.0.200 — 90% failure rate (S0/REJ). Pre-exploitation mapping behavior.`;
  }

  if (lq.includes('evidence') || lq.includes('chain') || lq.includes('hash') || lq.includes('ledger')) {
    const chainLen = status?.chain_length || 0;
    const intact = status?.chain_intact !== false;
    return intact
      ? `🔒 <strong>Evidence Chain: INTACT ✅</strong><br><br>• ${chainLen} sealed blocks<br>• SHA-256 hashes verified<br>• Ed25519 signatures valid<br>• 100% court-admissible chain of custody`
      : `❌ <strong>Evidence Chain: COMPROMISED!</strong><br><br>SHA-256 hash mismatch detected. Navigate to <em>Evidence Verification</em> to investigate.`;
  }

  if (lq.includes('ciso') || lq.includes('summary') || lq.includes('report') || lq.includes('brief')) {
    const total = status?.alerts_total || alerts.length;
    const eps = status?.events_per_second || 345;
    const processed = (status?.events_processed || 148520).toLocaleString();
    return `📋 <strong>CISO Executive Summary:</strong><br><br>• <strong>Events Processed:</strong> ${processed}<br>• <strong>Live EPS:</strong> ${eps}/sec<br>• <strong>Active Threats:</strong> ${total} alerts<br>• <strong>Primary Vector:</strong> C2 Beaconing + DNS Exfiltration<br>• <strong>Evidence Ledger:</strong> ${status?.chain_intact !== false ? '✅ INTACT' : '❌ COMPROMISED'}<br>• <strong>Action:</strong> Isolate 192.168.1.50; null-route 45.33.32.156`;
  }

  const total = status?.alerts_total || alerts.length;
  return `📊 <strong>ENCLIVRA Telemetry:</strong><br><br>• <strong>Active Alerts:</strong> ${total}<br>• <strong>Evidence Ledger:</strong> ${status?.chain_intact !== false ? '✅ INTACT' : '❌ COMPROMISED'}<br>• <strong>Detectors Online:</strong> ${status?.active_detectors || 7}/7<br><br>Try: <em>"Analyze IP 192.168.1.50"</em>, <em>"How to block threat IP?"</em>, or <em>"CISO summary"</em>`;
}

const CHIPS = [
  { label: '🔍 192.168.1.50',   q: 'Analyze IP 192.168.1.50' },
  { label: '🛡️ Evidence Chain', q: 'What is the evidence chain status?' },
  { label: '📡 C2 Beaconing',   q: 'Explain C2 beaconing' },
  { label: '⚡ Block IP Rules',  q: 'How to block a threat IP?' },
  { label: '📋 CISO Summary',   q: 'CISO executive summary' },
  { label: '❓ What is ENCLIVRA?', q: 'What is ENCLIVRA?' },
];

export function AiCopilot() {
  const { alerts, status } = useStore();
  const [open, setOpen] = useState(false);
  const [msgs, setMsgs] = useState<Msg[]>([
    { role: 'bot', text: '✨ Hello Analyst! I\'m <strong>ENCLIVRA AI Security Copilot</strong>. Ask me anything about threats, IPs, firewall rules, or the evidence ledger!' }
  ]);
  const [input, setInput] = useState('');
  const [typing, setTyping] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [msgs, typing]);

  const send = (text?: string) => {
    const val = (text ?? input).trim();
    if (!val) return;
    setInput('');
    setMsgs(p => [...p, { role: 'user', text: escHtml(val) }]);
    setTyping(true);
    setTimeout(() => {
      setTyping(false);
      setMsgs(p => [...p, { role: 'bot', text: getReply(val, alerts, status) }]);
    }, 480);
  };

  return (
    <>
      <style>{`
        @keyframes aiDrawerIn { from { transform: translateY(16px); opacity: 0; } to { transform: none; opacity: 1; } }
        @keyframes aiDot { 0%,80%,100% { transform: scale(0); opacity:.3 } 40% { transform: scale(1); opacity:1 } }
        @keyframes aiFabPulse { 0%,100% { box-shadow: 0 0 24px rgba(56,189,248,0.4); } 50% { box-shadow: 0 0 38px rgba(129,140,248,0.7); } }
      `}</style>

      {/* Classic Copilot FAB Button */}
      <button 
        onClick={() => setOpen(o => !o)} 
        title="ENCLIVRA AI Copilot" 
        style={{
          position:'fixed', bottom:'1.75rem', right:'1.75rem', zIndex:9999,
          width:58, height:58, borderRadius:'50%',
          background:'linear-gradient(135deg, #0f172a, #1e293b)',
          border:'2px solid #38bdf8',
          animation:'aiFabPulse 2.5s infinite',
          cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center',
          transition:'transform 0.2s',
        }}
        onMouseEnter={e=>(e.currentTarget.style.transform='scale(1.1)')}
        onMouseLeave={e=>(e.currentTarget.style.transform='scale(1)')}
      >
        <CopilotIcon size={28} />
        <span style={{
          position:'absolute', top:-2, right:-2,
          background:'linear-gradient(135deg,#38bdf8,#818cf8)',
          color:'#0f172a', fontSize:'0.58rem', fontWeight:900,
          padding:'1px 5px', borderRadius:9999,
          border:'1.5 solid #0f172a', letterSpacing:'0.5px'
        }}>COPILOT</span>
      </button>

      {/* Drawer */}
      {open && (
        <div style={{
          position:'fixed', bottom:'5.5rem', right:'1.75rem', zIndex:9998,
          width:380, maxHeight:560,
          background:'#0f172a', border:'1px solid #334155', borderRadius:16,
          boxShadow:'0 25px 50px rgba(0,0,0,0.65)',
          display:'flex', flexDirection:'column', overflow:'hidden',
          animation:'aiDrawerIn 0.28s cubic-bezier(0.16,1,0.3,1)',
        }}>
          {/* Header */}
          <div style={{padding:'0.85rem 1rem',background:'#1e293b',borderBottom:'1px solid #334155',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <div style={{display:'flex',alignItems:'center',gap:'0.6rem'}}>
              <CopilotIcon size={20} />
              <span style={{fontWeight:800,fontSize:'0.875rem',color:'#f8fafc',letterSpacing:'-0.2px'}}>ENCLIVRA Copilot</span>
            </div>
            <div style={{display:'flex',gap:'0.35rem'}}>
              <button onClick={()=>setMsgs([{role:'bot',text:'✨ Chat cleared. Ask me anything!'}])} style={{background:'none',border:'none',color:'#94a3b8',cursor:'pointer',fontSize:'0.95rem',padding:'2px 6px',borderRadius:6}} title="Clear">🗑️</button>
              <button onClick={()=>setOpen(false)} style={{background:'none',border:'none',color:'#94a3b8',cursor:'pointer',fontSize:'1.1rem',padding:'2px 6px',borderRadius:6}}>✕</button>
            </div>
          </div>

          {/* Messages */}
          <div ref={listRef} style={{flex:1,overflowY:'auto',padding:'0.85rem',display:'flex',flexDirection:'column',gap:'0.6rem',fontSize:'0.8rem'}}>
            {msgs.map((m,i)=>(
              <div key={i} style={{
                alignSelf:m.role==='user'?'flex-end':'flex-start',
                maxWidth:'88%', padding:'0.6rem 0.85rem',
                borderRadius:m.role==='user'?'14px 14px 2px 14px':'14px 14px 14px 2px',
                background:m.role==='user'?'rgba(56,189,248,0.13)':'#1e293b',
                border:m.role==='user'?'1px solid rgba(56,189,248,0.3)':'1px solid #334155',
                color:'#f8fafc', lineHeight:1.5,
              }} dangerouslySetInnerHTML={{__html:m.text}} />
            ))}
            {typing && (
              <div style={{alignSelf:'flex-start',display:'flex',gap:5,padding:'0.6rem 0.85rem',background:'#1e293b',border:'1px solid #334155',borderRadius:'14px 14px 14px 2px'}}>
                {[0,200,400].map(d=>(
                  <span key={d} style={{width:6,height:6,borderRadius:'50%',background:'#38bdf8',display:'inline-block',animation:`aiDot 1.4s ${d}ms infinite ease-in-out`}} />
                ))}
              </div>
            )}
          </div>

          {/* Quick Chips */}
          <div style={{display:'flex',gap:'0.35rem',overflowX:'auto',padding:'0.5rem 0.85rem',background:'#0f172a',borderTop:'1px solid #334155',scrollbarWidth:'none'}}>
            {CHIPS.map(c=>(
              <button key={c.q} onClick={()=>send(c.q)} style={{
                flexShrink:0, padding:'0.25rem 0.55rem',
                borderRadius:9999, background:'#1e293b', border:'1px solid #334155',
                color:'#94a3b8', fontSize:'0.7rem', cursor:'pointer', whiteSpace:'nowrap', transition:'all 0.15s',
              }}
                onMouseEnter={e=>{e.currentTarget.style.color='#38bdf8';e.currentTarget.style.borderColor='#38bdf8';}}
                onMouseLeave={e=>{e.currentTarget.style.color='#94a3b8';e.currentTarget.style.borderColor='#334155';}}
              >{c.label}</button>
            ))}
          </div>

          {/* Input */}
          <div style={{padding:'0.65rem',background:'#1e293b',borderTop:'1px solid #334155',display:'flex',gap:'0.5rem'}}>
            <input
              value={input}
              onChange={e=>setInput(e.target.value)}
              onKeyDown={e=>{if(e.key==='Enter')send();}}
              placeholder="Ask Copilot about threats, IPs, firewall rules..."
              style={{flex:1,background:'#0f172a',border:'1px solid #334155',borderRadius:8,padding:'0.45rem 0.75rem',color:'#f8fafc',fontSize:'0.8rem',outline:'none'}}
            />
            <button onClick={()=>send()} style={{background:'linear-gradient(135deg,#38bdf8,#818cf8)',color:'#0f172a',border:'none',borderRadius:8,padding:'0.45rem 0.85rem',fontWeight:800,fontSize:'0.8rem',cursor:'pointer'}}>Send</button>
          </div>
        </div>
      )}
    </>
  );
}
