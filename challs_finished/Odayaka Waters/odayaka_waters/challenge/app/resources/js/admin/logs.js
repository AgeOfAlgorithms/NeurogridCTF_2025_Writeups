function $(id){ return document.getElementById(id); }

export function initLogs() {
  const root = $('ow-logs-root');
  if (!root) return;

  const view = $('ow-logs-view');
  const olderBtn = $('ow-logs-older');
  const refreshBtn = $('ow-logs-refresh');
  const meta = $('ow-logs-meta');

  const CHUNK = 64 * 1024; // must match server cap
  let fileSize = 0;
  let head = 0; // byte offset of first byte currently loaded
  let tailLoaded = false;

  const render = (text, appendToEnd = true) => {
    if (appendToEnd) {
      const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 20;
      view.textContent += text;
      if (atBottom) view.scrollTop = view.scrollHeight;
    } else {
      const prevTop = view.scrollTop;
      const prevHeight = view.scrollHeight;
      view.textContent = text + view.textContent;
      // keep viewport anchored after prepending
      view.scrollTop = view.scrollHeight - prevHeight + prevTop;
    }
  };

  const updateMeta = () => {
    meta.textContent = `Size: ${fileSize} bytes • Showing from ${head}`;
  };

  async function fetchChunk(params) {
    const qs = new URLSearchParams(params).toString();
    const res = await fetch(`/challenge/admin/logs/chunk?${qs}`, { headers: { 'Accept':'application/json' }});
    if (!res.ok) throw new Error('net');
    return await res.json();
  }

  async function loadLatest() {
    try {
      const data = await fetchChunk({ start: -CHUNK, length: CHUNK });
      fileSize = data.size;
      head = data.start;
      view.textContent = ''; // reset
      render(data.data, true);
      tailLoaded = true;
      updateMeta();
    } catch {
      view.textContent = 'Failed to load log.';
    }
  }

  async function loadOlder() {
    if (head <= 0) return; // already at file start
    const nextStart = Math.max(0, head - CHUNK);
    const length = head - nextStart;
    try {
      const data = await fetchChunk({ start: nextStart, length });
      head = data.start;
      render(data.data, false); // prepend
      updateMeta();
    } catch {
      // ignore
    }
  }

  refreshBtn?.addEventListener('click', loadLatest);
  olderBtn?.addEventListener('click', loadOlder);

  // initial load
  loadLatest();
}
