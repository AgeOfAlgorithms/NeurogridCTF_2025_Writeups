function $(id) { return document.getElementById(id); }

function nearBottom(el) {
  const eps = 40;
  return el.scrollHeight - el.scrollTop - el.clientHeight < eps;
}
function autoscroll(el) { el.scrollTop = el.scrollHeight; }

function setStatus(dot, textEl, state) {
  if (state === 'ok') {
    dot.style.background = '#46d3c6';
    textEl.textContent = 'Connected';
  } else if (state === 'retry') {
    dot.style.background = '#f59e0b';
    textEl.textContent = 'Reconnecting…';
  } else {
    dot.style.background = '#9aa6b2';
    textEl.textContent = 'Connecting…';
  }
}

function fmtTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch { return ''; }
}

function renderMsg(m) {
  const wrap = document.createElement('div');
  wrap.style.display = 'flex';
  wrap.style.gap = '10px';
  wrap.style.alignItems = 'flex-start';

  const avatar = document.createElement('div');
  avatar.textContent = (m.user?.name || 'U').slice(0,1).toUpperCase();
  avatar.style.width = '28px';
  avatar.style.height = '28px';
  avatar.style.borderRadius = '50%';
  avatar.style.background = 'rgba(255,255,255,.10)';
  avatar.style.display = 'flex';
  avatar.style.alignItems = 'center';
  avatar.style.justifyContent = 'center';
  avatar.style.fontSize = '.85rem';
  avatar.style.color = 'var(--ow-text)';

  const bubble = document.createElement('div');
  bubble.style.flex = '1';
  bubble.style.background = 'rgba(2, 8, 23, .55)';
  bubble.style.border = '1px solid var(--ow-border)';
  bubble.style.borderRadius = '12px';
  bubble.style.padding = '8px 10px';

  const head = document.createElement('div');
  head.style.display = 'flex';
  head.style.justifyContent = 'space-between';
  head.style.gap = '8px';
  head.style.marginBottom = '2px';

  const name = document.createElement('span');
  name.className = 'ow-title';
  name.style.fontSize = '.92rem';
  name.textContent = m.user?.name || 'Unknown';

  const time = document.createElement('span');
  time.className = 'ow-subtle';
  time.style.fontSize = '.8rem';
  time.textContent = fmtTime(m.created_at);

  const body = document.createElement('div');
  body.style.whiteSpace = 'pre-wrap';
  body.style.wordBreak = 'break-word';
  body.style.color = 'var(--ow-text)';
  body.textContent = m.body; // safe (server returns text only)

  head.appendChild(name);
  head.appendChild(time);
  bubble.appendChild(head);
  bubble.appendChild(body);

  wrap.appendChild(avatar);
  wrap.appendChild(bubble);
  return wrap;
}

export function initChat() {
  const root   = $('ow-chat-root');
  if (!root) return;

  const list   = $('ow-messages');
  const form   = $('ow-form');
  const input  = $('ow-input');
  const send   = $('ow-send');
  const dot    = $('ow-status-dot');
  const stext  = $('ow-status-text');
  const csrf   = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

  let lastId   = 0;
  let polling  = null;
  let backoff  = 2500; // ms

  const appendMessages = (msgs) => {
    if (!msgs || !msgs.length) return;
    const doScroll = nearBottom(list);
    for (const m of msgs) {
      list.appendChild(renderMsg(m));
      lastId = Math.max(lastId, m.id || 0);
    }
    if (doScroll) autoscroll(list);
  };

  const fetchMessages = async () => {
    try {
      const url = lastId > 0
        ? `/challenge/api/messages?after_id=${encodeURIComponent(lastId)}&limit=100`
        : `/challenge/api/messages?limit=50`;
      const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
      if (!res.ok) throw new Error('net');
      const data = await res.json();
      appendMessages(data.messages || []);
      setStatus(dot, stext, 'ok');
      backoff = 2500;
    } catch {
      setStatus(dot, stext, 'retry');
      backoff = Math.min(15000, Math.floor(backoff * 1.7));
    } finally {
      clearTimeout(polling);
      polling = setTimeout(fetchMessages, backoff);
    }
  };

  const sendMessage = async (text) => {
    send.disabled = true;
    try {
      const res = await fetch('/challenge/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-TOKEN': csrf,
        },
        body: JSON.stringify({ body: text }),
      });
      if (res.status === 201) {
        input.value = '';
        const m = await res.json();
        appendMessages([m]);
      } else {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Failed to send message.');
      }
    } catch {
      alert('Network error. Please try again.');
    } finally {
      send.disabled = false;
      input.focus();
    }
  };

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const text = (input.value || '').trim();
    if (!text) return;
    if (text.length > 400) {
      alert('Message too long (max 400 characters).');
      return;
    }
    sendMessage(text);
  });

  // Kick off
  setStatus(dot, stext, 'connecting');
  fetchMessages();
  input?.focus();
}
