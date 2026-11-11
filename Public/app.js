(() => {
  const $ = (id) => document.getElementById(id);
  const gate = $('gate'), gateForm = $('gateForm'), keyInput = $('key'), gateErr = $('gateErr'), gateBtn = $('gateBtn');
  const chat = $('chat'), list = $('list'), empty = $('empty'), composer = $('composer');
  const box = $('box'), sendBtn = $('send'), lockBtn = $('lock'), clearBtn = $('clear');
  const keyDlg = $('keyDlg'), keyForm = $('keyForm'), curKey = $('curKey'), newKey = $('newKey'), newKey2 = $('newKey2');
  const keyErr = $('keyErr'), keySave = $('keySave');

  const POLL_MS = 2500;
  const IDLE_MS = 10 * 60 * 1000;

  // Everything lives in memory only. Refresh = everything gone = key asked again.
  let token = null, role = null, pollTimer = null, idleTimer = null;
  let signature = '', rendered = false, polling = false, stick = false;

  async function api(path, body) {
    const res = await fetch(path, {
      method: body === undefined && path === '/api/messages' ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
    });
    let data = {};
    try { data = await res.json(); } catch { /* ignore */ }
    if (res.status === 401 && token) lock('Session ended. Enter your key again.');
    return { ok: res.ok, status: res.status, data };
  }

  function fmt(t) {
    return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function render(messages) {
    const sig = messages.map((m) => m.id).join(',');
    if (sig === signature && rendered) return;
    const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80;
    signature = sig;
    list.textContent = '';
    const frag = document.createDocumentFragment();
    for (const m of messages) {
      const row = document.createElement('div');
      row.className = 'row' + (m.r === role ? ' mine' : '');
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.textContent = m.text; // textContent only, never innerHTML
      const time = document.createElement('span');
      time.className = 'time';
      time.textContent = fmt(m.t);
      row.append(bubble, time);
      frag.append(row);
    }
    list.append(frag);
    empty.hidden = messages.length > 0;
    if (nearBottom || stick || !rendered) list.scrollTop = list.scrollHeight;
    rendered = true;
    stick = false;
  }

  async function poll() {
    if (!token || polling) return;
    polling = true;
    try {
      const r = await api('/api/messages');
      if (r.ok && token) render(r.data.messages || []);
    } catch { /* network hiccup, try again next tick */ }
    polling = false;
  }

  function resetIdle() {
    clearTimeout(idleTimer);
    if (token) idleTimer = setTimeout(() => lock('Locked after inactivity.'), IDLE_MS);
  }

  function lock(msg) {
    token = null; role = null;
    clearInterval(pollTimer); clearTimeout(idleTimer);
    list.textContent = ''; signature = ''; rendered = false;
    box.value = ''; box.style.height = 'auto';
    keyForm.reset(); if (keyDlg.open) keyDlg.close();
    chat.hidden = true; gate.hidden = false;
    document.body.classList.remove('away');
    keyInput.value = '';
    gateErr.textContent = msg || '';
    gateBtn.disabled = false;
    keyInput.focus();
  }

  gateForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = keyInput.value;
    if (!code) return;
    gateBtn.disabled = true;
    gateErr.textContent = '';
    try {
      const r = await api('/api/login', { code });
      keyInput.value = '';
      if (!r.ok) {
        gateErr.textContent = r.data.error || 'Something went wrong.';
        gateBtn.disabled = false;
        keyInput.focus();
        return;
      }
      token = r.data.token; role = r.data.role;
      gate.hidden = true; chat.hidden = false;
      gateBtn.disabled = false;
      await poll();
      pollTimer = setInterval(poll, POLL_MS);
      resetIdle();
      box.focus();
    } catch {
      gateErr.textContent = 'Connection problem. Try again.';
      gateBtn.disabled = false;
    }
  });

  function resize() {
    box.style.height = 'auto';
    box.style.height = Math.min(box.scrollHeight, 140) + 'px';
  }
  box.addEventListener('input', resize);
  box.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      composer.requestSubmit();
    }
  });

  composer.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = box.value.trim();
    if (!text || !token) return;
    sendBtn.disabled = true;
    box.value = ''; resize();
    try {
      const r = await api('/api/send', { text });
      if (r.ok) { stick = true; await poll(); }
      else if (token) { box.value = text; resize(); }
    } catch {
      box.value = text; resize();
    }
    sendBtn.disabled = false;
    box.focus();
  });

  lockBtn.addEventListener('click', () => lock(''));

  $('keyBtn').addEventListener('click', () => {
    keyForm.reset(); keyErr.textContent = '';
    keyDlg.showModal(); curKey.focus();
  });
  $('keyCancel').addEventListener('click', () => { keyForm.reset(); keyDlg.close(); });
  keyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!curKey.value || !newKey.value) { keyErr.textContent = 'Fill in all fields.'; return; }
    if (newKey.value !== newKey2.value) { keyErr.textContent = "New keys don't match."; return; }
    keySave.disabled = true; keyErr.textContent = '';
    try {
      const r = await api('/api/change-key', { current: curKey.value, next: newKey.value });
      if (r.ok) { token = r.data.token; keyForm.reset(); keyDlg.close(); resetIdle(); }
      else if (token) keyErr.textContent = r.data.error || 'Could not change key.';
    } catch { keyErr.textContent = 'Connection problem. Try again.'; }
    keySave.disabled = false;
  });
  clearBtn.addEventListener('click', async () => {
    if (!confirm('Delete all messages for both of you?')) return;
    const r = await api('/api/clear', {});
    if (r.ok) { rendered = false; await poll(); }
  });

  ['pointerdown', 'keydown', 'touchstart'].forEach((ev) => document.addEventListener(ev, resetIdle, { passive: true }));

  // Blur the chat whenever the window loses focus (shoulder-surfing / screen switching).
  const away = () => { if (token) document.body.classList.add('away'); };
  const back = () => document.body.classList.remove('away');
  window.addEventListener('blur', away);
  window.addEventListener('focus', back);
  document.addEventListener('visibilitychange', () => (document.hidden ? away() : back()));
})();
