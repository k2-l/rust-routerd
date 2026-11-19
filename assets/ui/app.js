'use strict';

/* ============================== helpers ============================== */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SVG_ATTR = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';

const ICON = {
  overview: `<svg ${SVG_ATTR}><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>`,
  network: `<svg ${SVG_ATTR}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.5 4 5.6 4 9s-1.4 6.5-4 9c-2.6-2.5-4-5.6-4-9s1.4-6.5 4-9z"/></svg>`,
  wireless: `<svg ${SVG_ATTR}><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1"/><path d="M2 9a15 15 0 0 1 20 0"/></svg>`,
  clients: `<svg ${SVG_ATTR}><circle cx="9" cy="8" r="3.2"/><path d="M3.5 20c0-3.2 2.5-5.5 5.5-5.5s5.5 2.3 5.5 5.5"/><circle cx="17.5" cy="9" r="2.5"/><path d="M16 14.6c2.6.3 4.5 2.4 4.5 5.4"/></svg>`,
  firewall: `<svg ${SVG_ATTR}><path d="M12 3l7 3v5c0 4.6-2.9 8.3-7 10-4.1-1.7-7-5.4-7-10V6l7-3z"/><path d="M9.5 12l1.8 1.8 3.4-3.6"/></svg>`,
  access: `<svg ${SVG_ATTR}><path d="M12 3l7 3v5c0 4.6-2.9 8.3-7 10-4.1-1.7-7-5.4-7-10V6l7-3z"/><circle cx="12" cy="10.5" r="2.2"/><path d="M12 12.7v3.3"/></svg>`,
  system: `<svg ${SVG_ATTR}><rect x="6" y="6" width="12" height="12" rx="2.5"/><path d="M9.5 9.5h5v5h-5z"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>`,
  logs: `<svg ${SVG_ATTR}><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M7 9l2.5 3L7 15M12 15h5"/></svg>`,
  refresh: `<svg ${SVG_ATTR}><path d="M20 11a8 8 0 1 0-2.3 6.6"/><path d="M20 5v6h-6"/></svg>`,
  logout: `<svg ${SVG_ATTR}><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 17l5-5-5-5M15 12H3"/></svg>`,
  power: `<svg ${SVG_ATTR}><path d="M12 3v9"/><path d="M7 6.5a8 8 0 1 0 10 0"/></svg>`,
  plus: `<svg ${SVG_ATTR}><path d="M12 5v14M5 12h14"/></svg>`,
  trash: `<svg ${SVG_ATTR}><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13h10l1-13"/></svg>`,
  upload: `<svg ${SVG_ATTR}><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/></svg>`,
  check: `<svg ${SVG_ATTR}><path d="M5 12.5l4.5 4.5L19 7"/></svg>`,
  alert: `<svg ${SVG_ATTR}><path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4M12 17h.01"/></svg>`,
  memory: `<svg ${SVG_ATTR}><rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 7v10M12 7v10M17 7v10M5 17v3M12 17v3M19 17v3"/></svg>`,
  temp: `<svg ${SVG_ATTR}><path d="M10 13.5V5a2 2 0 1 1 4 0v8.5a4 4 0 1 1-4 0z"/><path d="M12 8v6"/></svg>`,
  clock: `<svg ${SVG_ATTR}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`,
  link: `<svg ${SVG_ATTR}><path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/></svg>`,
  lock: `<svg ${SVG_ATTR}><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  save: `<svg ${SVG_ATTR}><path d="M5 4h11l3 3v13H5z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/></svg>`,
  play: `<svg ${SVG_ATTR}><path d="M7 5l12 7-12 7V5z"/></svg>`,
  stop: `<svg ${SVG_ATTR}><rect x="6" y="6" width="12" height="12" rx="2"/></svg>`,
  reset: `<svg ${SVG_ATTR}><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>`,
};

const state = {
  csrf: null,
  meta: {},
  view: 'overview',
  timer: null,
};

const VIEWS = {
  overview: { label: '概览', title: '概览', sub: '设备运行状态与实时流量', icon: 'overview', render: renderOverview },
  network: { label: '网络', title: '网络', sub: 'WAN / LAN 与路由', icon: 'network', render: renderNetwork },
  wireless: { label: '无线', title: '无线', sub: '射频与 SSID 配置', icon: 'wireless', render: renderWireless },
  clients: { label: '客户端', title: '客户端', sub: '在线设备与 DHCP 租约', icon: 'clients', render: renderClients },
  access: { label: '访问控制', title: '访问控制', sub: '新设备上网授权与 AI 接入', icon: 'access', render: renderAccess },
  firewall: { label: '防火墙', title: '防火墙', sub: '端口转发与区域策略', icon: 'firewall', render: renderFirewall },
  system: { label: '系统', title: '系统', sub: '设备信息、升级与服务', icon: 'system', render: renderSystem },
  logs: { label: '日志', title: '日志', sub: '系统日志实时查看', icon: 'logs', render: renderLogs },
};

class ApiErr extends Error {
  constructor(message, code, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function icon(name) {
  return ICON[name] || '';
}

function fmtBytes(n) {
  if (n == null || isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtRate(kbps) {
  if (kbps == null || isNaN(kbps)) return '—';
  if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`;
  return `${Math.round(kbps)} Kbps`;
}

function fmtUptime(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}天 ${h}小时`;
  if (h > 0) return `${h}小时 ${m}分`;
  return `${m}分 ${sec % 60}秒`;
}

function fmtTime(unix) {
  if (!unix) return '—';
  try {
    return new Date(unix * 1000).toLocaleString('zh-CN', { hour12: false });
  } catch (e) { return '—'; }
}

function pct(v, max) {
  if (!max) return 0;
  return Math.max(0, Math.min(100, (Number(v) / Number(max)) * 100));
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/* ============================== api ============================== */

async function api(path, opts = {}) {
  const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
  const isForm = opts.body instanceof FormData;
  if (opts.body && !isForm && typeof opts.body !== 'string') {
    opts.body = JSON.stringify(opts.body);
  }
  if (opts.body && !isForm) headers['Content-Type'] = 'application/json';
  const method = (opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  const res = await fetch(path, { ...opts, method, headers, credentials: 'same-origin' });
  let payload = null;
  try { payload = await res.json(); } catch (e) { /* non-json */ }
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/login') showLogin();
    const msg = (payload && payload.error) || `请求失败 (${res.status})`;
    throw new ApiErr(msg, payload && payload.code, res.status);
  }
  return payload ? payload.data : null;
}

function toast(message, type = 'good') {
  const box = $('#toast');
  const el = document.createElement('div');
  el.className = `toast-item ${type}`;
  el.innerHTML = `<span class="ic">${type === 'bad' ? icon('alert') : icon('check')}</span><span>${esc(message)}</span>`;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(6px)'; }, 3200);
  setTimeout(() => el.remove(), 3600);
}

function handleErr(err) {
  if (!(err instanceof ApiErr)) console.error(err);
  if (err && err.code === 'password_change_required') {
    forcePasswordChange();
    return;
  }
  if (err && err.status === 401) return;
  toast((err && err.message) || '操作失败', 'bad');
}

/* ============================== modal ============================== */

function openModal(html, opts = {}) {
  const root = $('#modal-root');
  const back = document.createElement('div');
  back.className = 'modal-backdrop';
  back.innerHTML = `<div class="modal">${html}</div>`;
  root.appendChild(back);
  const close = () => back.remove();
  if (opts.closable !== false) {
    back.addEventListener('click', (e) => { if (e.target === back) close(); });
  }
  const onKey = (e) => {
    if (e.key === 'Escape' && opts.closable !== false) { close(); document.removeEventListener('keydown', onKey); }
  };
  document.addEventListener('keydown', onKey);
  if (opts.onMount) opts.onMount(back, close);
  return { el: back, close };
}

function confirmDialog(title, message, okText = '确认', danger = false) {
  return new Promise((resolve) => {
    const { close } = openModal(
      `<h3>${esc(title)}</h3><p class="sub">${esc(message)}</p>
       <div class="btn-row">
         <button class="btn" data-cancel>取消</button>
         <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-ok>${esc(okText)}</button>
       </div>`,
      {
        closable: false,
        onMount(el, closeFn) {
          el.querySelector('[data-cancel]').onclick = () => { closeFn(); resolve(false); };
          el.querySelector('[data-ok]').onclick = () => { closeFn(); resolve(true); };
        },
      }
    );
    void close;
  });
}

/* ============================== auth / boot ============================== */

async function init() {
  bindTopButtons();
  bindLogin();
  try {
    const s = await api('/api/session');
    state.meta = (s && s.meta) || {};
    if (s && s.authenticated) {
      state.csrf = s.csrf;
      enterApp();
    } else {
      showLogin();
    }
  } catch (e) {
    showLogin();
  }
}

function showLogin() {
  clearTimer();
  const app = $('#app');
  const login = $('#login-view');
  $('#boot').classList.add('hidden');
  app.classList.add('hidden');
  login.classList.remove('hidden');
  $('#login-device').textContent = state.meta.model
    ? `${state.meta.model} · ${state.meta.hostname || ''}`
    : 'Cudy TR3000';
  $('#login-version').textContent = `routerd ${state.meta.version || ''}`.trim();
  $('#login-tls').textContent = state.meta.tls ? 'HTTPS 安全连接' : 'HTTP 连接';
  setTimeout(() => { const p = $('#login-form input[name=password]'); if (p) p.focus(); }, 80);
}

function bindLogin() {
  const form = $('#login-form');
  if (!form || form.dataset.bound) return;
  form.dataset.bound = '1';
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const btn = $('#login-btn');
    const errBox = $('#login-error');
    errBox.classList.add('hidden');
    btn.disabled = true;
    btn.textContent = '正在验证…';
    try {
      const d = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username: fd.get('username'), password: fd.get('password') }),
      });
      state.csrf = d.csrf;
      state.meta = d.meta || {};
      $('#login-view').classList.add('hidden');
      enterApp();
    } catch (err) {
      errBox.textContent = err.message || '登录失败';
      errBox.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = '进入控制台';
    }
  });
}

function forcePasswordChange() {
  if ($('#force-pw')) return;
  openModal(
    `<h3 id="force-pw">设置新的管理员密码</h3>
     <p class="sub">当前使用的是默认密码，为避免设备被他人控制，请先设置新密码。</p>
     <form id="force-form">
       <label class="field"><span>当前密码</span><input name="current" type="password" autocomplete="current-password" required></label>
       <label class="field"><span>新密码（至少 8 位）</span><input name="next" type="password" autocomplete="new-password" minlength="8" required></label>
       <label class="field"><span>确认新密码</span><input name="confirm" type="password" autocomplete="new-password" minlength="8" required></label>
       <div class="form-error hidden" data-err></div>
       <div class="btn-row"><button class="btn btn-primary" type="submit">保存并继续</button></div>
     </form>`,
    {
      closable: false,
      onMount(el, close) {
        el.querySelector('#force-form').addEventListener('submit', async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          const err = el.querySelector('[data-err]');
          err.classList.add('hidden');
          if (f.get('next') !== f.get('confirm')) {
            err.textContent = '两次输入的新密码不一致';
            err.classList.remove('hidden');
            return;
          }
          try {
            await api('/api/system/password', {
              method: 'POST',
              body: { current: f.get('current'), new: f.get('next') },
            });
            state.meta.must_change = false;
            close();
            toast('密码已更新');
            go(state.view);
          } catch (ex) {
            err.textContent = ex.message || '修改失败';
            err.classList.remove('hidden');
          }
        });
      },
    }
  );
}

function enterApp() {
  $('#boot').classList.add('hidden');
  $('#login-view').classList.add('hidden');
  $('#app').classList.remove('hidden');
  const host = state.meta.hostname || 'router';
  $('#side-host').textContent = host;
  $('#top-host').textContent = host;
  $('#side-ver').textContent = `routerd ${state.meta.version || ''}`.trim();

  $$('#nav .nav-item').forEach((btn) => {
    const v = btn.dataset.view;
    btn.innerHTML = `${icon(VIEWS[v].icon)}<span>${VIEWS[v].label}</span>`;
  });

  const mobile = $('#mobile-nav');
  mobile.innerHTML = Object.entries(VIEWS)
    .map(([k, v]) => `<button data-view="${k}">${icon(v.icon)}<span>${v.label}</span></button>`)
    .join('');
  $$('#mobile-nav button').forEach((b) => b.addEventListener('click', () => go(b.dataset.view)));
  $$('#nav .nav-item').forEach((b) => b.addEventListener('click', () => go(b.dataset.view)));

  if (state.meta.must_change) {
    $('#view').innerHTML = '<div class="card"><div class="empty">首次使用请先设置管理员密码</div></div>';
    setTimeout(forcePasswordChange, 250);
  } else {
    go(state.view);
  }
}

function bindTopButtons() {
  $('#btn-refresh').innerHTML = icon('refresh');
  $('#btn-logout').innerHTML = icon('logout');
  $('#btn-refresh').addEventListener('click', () => {
    const b = $('#btn-refresh');
    b.classList.add('spin');
    go(state.view).finally(() => setTimeout(() => b.classList.remove('spin'), 500));
  });
  $('#btn-logout').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
    state.csrf = null;
    showLogin();
  });
}

/* ============================== router ============================== */

function clearTimer() {
  if (state.timer) { clearInterval(state.timer); state.timer = null; }
}

function setTimer(fn, ms) {
  clearTimer();
  state.timer = setInterval(() => { if (document.hidden) return; fn().catch((e) => { /* ignore poll errors */ }); }, ms);
}

async function go(view) {
  if (!VIEWS[view]) view = 'overview';
  state.view = view;
  clearTimer();
  $$('#nav .nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('#mobile-nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $('#view-title').textContent = VIEWS[view].title;
  $('#view-sub').textContent = VIEWS[view].sub;
  $('#view').innerHTML = '<div class="empty">正在加载…</div>';
  try {
    await VIEWS[view].render();
  } catch (e) {
    $('#view').innerHTML = `<div class="card"><div class="empty">加载失败：${esc(e.message || e)}</div></div>`;
    handleErr(e);
  }
}

/* ============================== charts ============================== */

function fitCanvas(canvas) {
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.floor(rect.width));
  const h = Math.max(1, Math.floor(rect.height));
  canvas.width = Math.floor(w * dpr);
  canvas.height = Math.floor(h * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

function drawSeries(ctx, data, color, w, h, max, fill) {
  if (!data || !data.length) return;
  const pad = 4;
  const step = data.length > 1 ? (w - pad * 2) / (data.length - 1) : 0;
  const xy = (i, v) => [pad + step * i, h - pad - (h - pad * 2) * (Math.max(0, v) / max)];
  if (fill) {
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, fill);
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath();
    ctx.moveTo(pad, h - pad);
    data.forEach((v, i) => { const [x, y] = xy(i, v); ctx.lineTo(x, y); });
    ctx.lineTo(pad + step * (data.length - 1), h - pad);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
  }
  ctx.beginPath();
  data.forEach((v, i) => { const [x, y] = xy(i, v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.7;
  ctx.lineJoin = 'round';
  ctx.stroke();
}

function drawTraffic(canvas, rx, tx) {
  if (!canvas) return;
  const { ctx, w, h } = fitCanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(122,162,255,0.08)';
  ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i++) {
    const y = (h / 4) * i;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  const all = [...(rx || []), ...(tx || [])];
  const max = Math.max(1, ...all) * 1.15;
  drawSeries(ctx, tx || [], '#a78bfa', w, h, max, 'rgba(124,92,255,0.22)');
  drawSeries(ctx, rx || [], '#22d3ee', w, h, max, 'rgba(34,211,238,0.18)');
}

function drawSpark(canvas, data, color) {
  if (!canvas) return;
  const { ctx, w, h } = fitCanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(1, ...(data || []));
  drawSeries(ctx, data || [], color, w, h, max * 1.05, null);
}

/* ============================== overview ============================== */

function memBarClass(p) { return p >= 90 ? 'bad' : p >= 75 ? 'warn' : ''; }

function statusPill(up, text) {
  return `<span class="status-pill ${up ? 'good' : 'bad'}">${esc(text || (up ? '已连接' : '未连接'))}</span>`;
}

async function renderOverview() {
  const [sys, hist, wifi, clients, net] = await Promise.all([
    api('/api/system'),
    api('/api/system/history'),
    api('/api/wireless').catch(() => null),
    api('/api/clients').catch(() => null),
    api('/api/network').catch(() => null),
  ]);
  const wanStatus = (net && net.wan_status) || {};
  state.wanIp = (wanStatus.ipv4 && wanStatus.ipv4[0] && wanStatus.ipv4[0].address) || '';
  const wifiClients = clients ? clients.wireless_clients : 0;
  const wired = clients ? clients.wired_clients : 0;
  const radios = (wifi && wifi.radios) || [];
  const ssidRows = radios.flatMap((r) =>
    (r.ifaces || []).map((i) => `
      <div class="list-row">
        <div>
          <div class="list-title">${esc(i.ssid || '(未命名)')}</div>
          <div class="list-sub">${esc(r.name)} · ${esc(i.encryption)} · ${i.assoc_count || 0} 台设备</div>
        </div>
        <span class="badge ${i.disabled ? 'muted' : 'good'}">${i.disabled ? '已关闭' : '广播中'}</span>
      </div>`)
  ).join('');

  $('#view').innerHTML = `
  <div class="card hero">
    <div class="hero-main">
      <div>
        <h2 class="hero-title">${esc(sys.model)}</h2>
        <p class="hero-sub">${esc(sys.firmware.description || sys.firmware.version || 'routerd')}</p>
        <div class="hero-meta">
          <div class="item"><div class="k">运行时间</div><div class="v" id="ov-uptime">${esc(sys.uptime_human)}</div></div>
          <div class="item"><div class="k">WAN 地址</div><div class="v mono" id="ov-wan">${esc(wanAddress())}</div></div>
          <div class="item"><div class="k">MAC</div><div class="v mono">${esc(sys.mac || '—')}</div></div>
          <div class="item"><div class="k">内核</div><div class="v mono">${esc(sys.kernel)}</div></div>
        </div>
      </div>
      <div class="card-actions">
        ${statusPill(!!state.wanIp, state.wanIp ? '外网已连接' : '外网未连接')}
        <button class="btn btn-sm" id="ov-reboot">${icon('power')}重启</button>
      </div>
    </div>
  </div>

  <div class="grid grid-4 mt-20">
    ${statCard('CPU 负载', 'system', `${Number(sys.cpu.usage).toFixed(1)}<small>%</small>`, `${sys.cpu.cores} 核 · ${sys.cpu.freq_mhz ? sys.cpu.freq_mhz + ' MHz' : 'ARM64'}`, 'spark-cpu', 'cyan')}
    ${statCard('内存占用', 'memory', `${Number(sys.memory.percent).toFixed(0)}<small>%</small>`, `${fmtBytes(sys.memory.used)} / ${fmtBytes(sys.memory.total)}`, 'spark-mem', 'violet')}
    ${statCard('在线客户端', 'clients', `${wifiClients + wired}<small>台</small>`, `无线 ${wifiClients} · 有线 ${wired}`, '', 'green')}
    ${statCard('温度', 'temp', `${sys.temperature != null ? Number(sys.temperature).toFixed(0) + '<small>°C</small>' : '—'}`, `存储 ${fmtBytes(sys.storage.used)} / ${fmtBytes(sys.storage.total)}`, '', 'amber')}
  </div>

  <div class="grid grid-main mt-20">
    <div class="grid">
      <div class="card">
        <div class="card-title">
          <h2>实时流量</h2>
          <span class="sub" id="ov-rates">↓ ${fmtRate(sys.traffic.rx_kbps)} · ↑ ${fmtRate(sys.traffic.tx_kbps)}</span>
        </div>
        <div class="chart-wrap"><canvas id="traffic-chart"></canvas></div>
        <div class="chart-legend">
          <span><i class="legend-dot" style="background:#22d3ee"></i>下载</span>
          <span><i class="legend-dot" style="background:#a78bfa"></i>上传</span>
        </div>
      </div>
      <div class="card">
        <div class="card-title"><h2>系统资源</h2><span class="sub">${esc(sys.board)}</span></div>
        <div class="kv">
          <div class="k">平均负载</div><div class="v mono">${(sys.load || []).map((x) => Number(x).toFixed(2)).join(' / ')}</div>
          <div class="k">内存</div><div class="v mono">${fmtBytes(sys.memory.used)} / ${fmtBytes(sys.memory.total)}</div>
          <div class="k">存储</div><div class="v mono">${fmtBytes(sys.storage.used)} / ${fmtBytes(sys.storage.total)}</div>
          <div class="k">架构</div><div class="v mono">${esc(sys.arch)}</div>
        </div>
        <div class="mt-14">
          <div class="row-between tiny muted"><span>内存</span><span>${Number(sys.memory.percent).toFixed(0)}%</span></div>
          <div class="bar ${memBarClass(sys.memory.percent)} mt-14"><i style="width:${pct(sys.memory.used, sys.memory.total)}%"></i></div>
        </div>
        <div class="mt-14">
          <div class="row-between tiny muted"><span>存储</span><span>${Number(sys.storage.percent).toFixed(0)}%</span></div>
          <div class="bar ${memBarClass(sys.storage.percent)} mt-14"><i style="width:${pct(sys.storage.used, sys.storage.total)}%"></i></div>
        </div>
      </div>
    </div>
    <div class="grid">
      <div class="card">
        <div class="card-title"><h2>无线网络</h2><span class="sub">${radios.length} 个射频</span></div>
        <div class="list">${ssidRows || '<div class="empty">未检测到无线配置</div>'}</div>
      </div>
      <div class="card">
        <div class="card-title"><h2>设备</h2><span class="sub">routerd</span></div>
        <div class="kv">
          <div class="k">型号</div><div class="v">${esc(sys.model)}</div>
          <div class="k">固件</div><div class="v mono">${esc(sys.firmware.version || '—')}</div>
          <div class="k">版本号</div><div class="v mono">${esc(sys.firmware.revision || '—')}</div>
          <div class="k">目标</div><div class="v mono">${esc(sys.firmware.target || '—')}</div>
          <div class="k">守护进程</div><div class="v mono">routerd ${esc(state.meta.version || '')}</div>
        </div>
      </div>
    </div>
  </div>`;

  drawTraffic($('#traffic-chart'), hist.rx, hist.tx);
  drawSpark($('#spark-cpu'), hist.cpu, '#22d3ee');
  drawSpark($('#spark-mem'), hist.mem, '#a78bfa');
  const rb = $('#ov-reboot');
  if (rb) rb.addEventListener('click', () => doReboot());

  setTimer(refreshOverview, 2500);
}

function wanAddress() {
  return state.wanIp || '—';
}

function statCard(label, ic, value, sub, sparkId, tone) {
  return `<div class="card stat">
    <div class="stat-top"><span>${esc(label)}</span><span class="stat-icon ${tone}">${icon(ic)}</span></div>
    <div class="stat-value">${value}</div>
    <div class="stat-sub">${esc(sub)}</div>
    ${sparkId ? `<div class="spark"><canvas id="${sparkId}"></canvas></div>` : ''}
  </div>`;
}

async function refreshOverview() {
  const [sys, hist] = await Promise.all([api('/api/system'), api('/api/system/history')]);
  if (state.view !== 'overview') return;
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  set('ov-uptime', esc(sys.uptime_human));
  set('ov-rates', `↓ ${fmtRate(sys.traffic.rx_kbps)} · ↑ ${fmtRate(sys.traffic.tx_kbps)}`);
  drawTraffic($('#traffic-chart'), hist.rx, hist.tx);
  drawSpark($('#spark-cpu'), hist.cpu, '#22d3ee');
  drawSpark($('#spark-mem'), hist.mem, '#a78bfa');
}

async function doReboot() {
  const ok = await confirmDialog('重启设备', '设备将断开所有连接并在约 1 分钟后重新上线。确定继续？', '立即重启', true);
  if (!ok) return;
  try {
    await api('/api/system/reboot', { method: 'POST' });
    toast('设备正在重启…');
  } catch (e) { handleErr(e); }
}

/* ============================== network ============================== */

async function renderNetwork() {
  const d = await api('/api/network');
  const wan = d.wan;
  state.wanIp = ((d.wan_status && d.wan_status.ipv4 && d.wan_status.ipv4[0] && d.wan_status.ipv4[0].address) || '');
  const w = d.wan_status || {};
  const ipv4 = (w.ipv4 && w.ipv4[0]) || null;
  const dns = (w.dns || []).join(', ') || '自动';
  const ifaceRows = (d.interfaces || []).map((i) => {
    const ip = (i.ipv4 || []).map((a) => `${a.address}/${a.mask}`).join('<br>') || '—';
    const rx = (i.statistics && i.statistics.rx_bytes) || 0;
    const tx = (i.statistics && i.statistics.tx_bytes) || 0;
    return `<tr>
      <td class="primary">${esc(i.name)}</td>
      <td><span class="badge ${i.up ? 'good' : 'bad'}">${i.up ? 'UP' : 'DOWN'}</span></td>
      <td class="mono">${esc(i.proto)}</td>
      <td class="mono">${esc(i.device)}</td>
      <td class="mono">${ip}</td>
      <td class="mono">${fmtBytes(rx)} / ${fmtBytes(tx)}</td>
    </tr>`;
  }).join('');
  const routeRows = (d.routes || []).map((r) => `<tr>
      <td class="mono">${esc(r.target)}</td>
      <td class="mono">${esc(r.gateway || '—')}</td>
      <td class="mono">${esc(r.device || '—')}</td>
      <td class="mono">${esc(r.proto || '—')}</td>
      <td class="mono">${esc(r.metric)}</td>
    </tr>`).join('');

  $('#view').innerHTML = `
  <div class="grid grid-2">
    <div class="card">
      <div class="card-title"><h2>WAN 状态</h2>${statusPill(!!w.up, w.proto ? String(w.proto).toUpperCase() : '未配置')}</div>
      <div class="kv">
        <div class="k">IP 地址</div><div class="v mono">${ipv4 ? esc(ipv4.address) + '/' + esc(ipv4.mask) : '—'}</div>
        <div class="k">网关</div><div class="v mono">${esc(w.gateway || '—')}</div>
        <div class="k">DNS</div><div class="v mono">${esc(dns)}</div>
        <div class="k">连接时长</div><div class="v">${w.uptime ? esc(fmtUptime(w.uptime)) : '—'}</div>
        <div class="k">流量</div><div class="v mono">↓ ${fmtBytes(w.statistics && w.statistics.rx_bytes)} · ↑ ${fmtBytes(w.statistics && w.statistics.tx_bytes)}</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><h2>WAN 配置</h2><span class="sub">${esc(wan.section)}</span></div>
      <form id="wan-form">
        <label class="field"><span>连接类型</span>
          <select name="proto">
            <option value="dhcp" ${wan.proto === 'dhcp' ? 'selected' : ''}>DHCP（自动获取）</option>
            <option value="static" ${wan.proto === 'static' ? 'selected' : ''}>静态 IP</option>
            <option value="pppoe" ${wan.proto === 'pppoe' ? 'selected' : ''}>PPPoE 拨号</option>
            <option value="none" ${wan.proto === 'none' ? 'selected' : ''}>禁用</option>
          </select>
        </label>
        <div class="proto-static ${wan.proto === 'static' ? '' : 'hidden'}">
          <div class="field-row">
            <label class="field"><span>IP 地址</span><input name="ipaddr" value="${esc(wan.ipaddr)}" placeholder="192.168.0.2"></label>
            <label class="field"><span>子网掩码</span><input name="netmask" value="${esc(wan.netmask)}" placeholder="255.255.255.0"></label>
          </div>
          <label class="field"><span>网关</span><input name="gateway" value="${esc(wan.gateway)}" placeholder="192.168.0.1"></label>
        </div>
        <div class="proto-pppoe ${wan.proto === 'pppoe' ? '' : 'hidden'}">
          <label class="field"><span>宽带账号</span><input name="username" value="${esc(wan.username)}" autocomplete="off"></label>
          <label class="field"><span>宽带密码</span><input name="password" type="password" value="${esc(wan.password)}" autocomplete="off"></label>
        </div>
        <div class="field-row">
          <label class="field"><span>DNS（空格分隔，留空自动）</span><input name="dns" value="${esc(wan.dns)}" placeholder="223.5.5.5 119.29.29.29"></label>
          <label class="field"><span>MTU（可选）</span><input name="mtu" value="${esc(wan.mtu)}" placeholder="1500"></label>
        </div>
        <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存并应用</button></div>
      </form>
    </div>
  </div>

  <div class="card mt-20">
    <div class="card-title"><h2>LAN 与 DHCP</h2><span class="sub">${esc(d.lan.device)}</span></div>
    <form id="lan-form">
      <div class="grid grid-2">
        <div>
          <div class="field-row">
            <label class="field"><span>LAN IP</span><input name="ipaddr" value="${esc(d.lan.ipaddr)}"></label>
            <label class="field"><span>子网掩码</span><input name="netmask" value="${esc(d.lan.netmask)}"></label>
          </div>
          <div class="field-row">
            <label class="field"><span>DHCP 起始地址</span><input name="dhcp_start" type="number" min="2" max="254" value="${esc(d.lan.dhcp.start)}"></label>
            <label class="field"><span>地址池大小</span><input name="dhcp_limit" type="number" min="1" max="253" value="${esc(d.lan.dhcp.limit)}"></label>
          </div>
        </div>
        <div>
          <label class="field"><span>租期</span><input name="leasetime" value="${esc(d.lan.dhcp.leasetime)}" placeholder="12h"></label>
          <label class="switch" style="margin-top:6px"><input type="checkbox" name="ignore" ${d.lan.dhcp.ignore ? 'checked' : ''}><span class="track"></span>禁用 DHCP 服务</label>
          <p class="form-hint" style="margin-top:14px">修改 LAN IP 后当前连接会断开，请使用新地址重新访问。</p>
        </div>
      </div>
      <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存并应用</button></div>
    </form>
  </div>

  <div class="card mt-20">
    <div class="card-title"><h2>接口</h2><span class="sub">${(d.interfaces || []).length} 个逻辑接口</span></div>
    <div class="table-wrap"><table><thead><tr><th>名称</th><th>状态</th><th>协议</th><th>设备</th><th>地址</th><th>RX / TX</th></tr></thead><tbody>${ifaceRows || '<tr><td colspan="6" class="empty">暂无接口</td></tr>'}</tbody></table></div>
  </div>

  <div class="card mt-20">
    <div class="card-title"><h2>路由表</h2><span class="sub">IPv4</span></div>
    <div class="table-wrap"><table><thead><tr><th>目标</th><th>网关</th><th>设备</th><th>协议</th><th>Metric</th></tr></thead><tbody>${routeRows || '<tr><td colspan="5" class="empty">暂无路由</td></tr>'}</tbody></table></div>
  </div>`;

  const wanForm = $('#wan-form');
  wanForm.proto.addEventListener('change', () => {
    $('.proto-static', wanForm).classList.toggle('hidden', wanForm.proto.value !== 'static');
    $('.proto-pppoe', wanForm).classList.toggle('hidden', wanForm.proto.value !== 'pppoe');
  });
  wanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(wanForm);
    const body = {
      proto: f.get('proto'),
      ipaddr: f.get('ipaddr') || '',
      netmask: f.get('netmask') || '',
      gateway: f.get('gateway') || '',
      username: f.get('username') || '',
      password: f.get('password') || '',
      dns: f.get('dns') || '',
      mtu: f.get('mtu') || '',
    };
    try {
      await api('/api/network/wan', { method: 'PUT', body });
      toast('WAN 配置已保存，网络正在重载');
      setTimeout(() => go('network'), 2600);
    } catch (ex) { handleErr(ex); }
  });

  $('#lan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const ok = await confirmDialog('应用 LAN 配置', '修改 LAN 参数会短暂断开当前连接，确定继续？', '应用', false);
    if (!ok) return;
    try {
      await api('/api/network/lan', {
        method: 'PUT',
        body: {
          ipaddr: f.get('ipaddr'),
          netmask: f.get('netmask'),
          dhcp_start: Number(f.get('dhcp_start')),
          dhcp_limit: Number(f.get('dhcp_limit')),
          leasetime: f.get('leasetime'),
          ignore: f.get('ignore') === 'on',
        },
      });
      toast('LAN 配置已保存，请使用新地址访问');
    } catch (ex) { handleErr(ex); }
  });
}

/* ============================== wireless ============================== */

function encOptions(current) {
  const opts = [
    ['none', '开放（无密码）'],
    ['psk2', 'WPA2-PSK'],
    ['sae', 'WPA3-SAE'],
    ['sae-mixed', 'WPA2/WPA3 混合'],
    ['psk', 'WPA-PSK'],
    ['psk-mixed', 'WPA/WPA2 混合'],
  ];
  return opts.map(([v, l]) => `<option value="${v}" ${current === v ? 'selected' : ''}>${l}</option>`).join('');
}

async function renderWireless() {
  const d = await api('/api/wireless');
  const radios = d.radios || [];
  const live = d.live || [];
  const cards = radios.map((r) => {
    const liveRadio = live.find((l) => (r.ifaces || []).some((i) => i.device && i.device === l.device)) || {};
    const ifaceRows = (r.ifaces || []).map((i) => `
      <div class="card" style="background:rgba(6,10,20,.45);margin-top:12px" data-iface="${esc(i.section)}">
        <div class="row-between">
          <div class="row"><span class="dot ${i.disabled ? 'off' : 'on'}"></span><b>${esc(i.ssid || '(未命名)')}</b>
            <span class="badge muted">${esc(i.network)}</span></div>
          <span class="badge ${i.assoc_count ? 'good' : 'muted'}">${i.assoc_count || 0} 台在线</span>
        </div>
        <div class="field-row mt-14">
          <label class="field"><span>SSID</span><input class="iface-ssid" value="${esc(i.ssid)}" maxlength="32"></label>
          <label class="field"><span>加密方式</span><select class="iface-enc">${encOptions(i.encryption)}</select></label>
        </div>
        <label class="field"><span>Wi-Fi 密码（留空表示不修改）</span><input class="iface-key" type="text" value="" placeholder="${i.encryption === 'none' ? '开放网络' : '至少 8 位'}" autocomplete="off"></label>
        <div class="row wrap gap-14">
          <label class="switch"><input type="checkbox" class="iface-hidden" ${i.hidden ? 'checked' : ''}><span class="track"></span>隐藏 SSID</label>
          <label class="switch"><input type="checkbox" class="iface-disabled" ${i.disabled ? 'checked' : ''}><span class="track"></span>禁用此网络</label>
          <span class="tiny muted">信道 ${esc(i.channel != null ? i.channel : '—')} · 发射功率 ${esc(i.txpower != null ? i.txpower + ' dBm' : '—')}</span>
        </div>
      </div>`).join('');
    return `<div class="card mt-20" data-radio="${esc(r.name)}">
      <div class="card-title">
        <h2>${esc(r.name)} <span class="badge muted">${esc(r.band || r.hwmode || 'radio')}</span></h2>
        <label class="switch"><input type="checkbox" class="radio-disabled" ${r.disabled ? 'checked' : ''}><span class="track"></span>禁用射频</label>
      </div>
      <div class="field-row">
        <label class="field"><span>信道（auto 或 1-196）</span><input class="radio-channel" value="${esc(r.channel)}"></label>
        <label class="field"><span>频宽模式</span>
          <select class="radio-htmode">
            ${['', 'HT20', 'HT40', 'VHT20', 'VHT40', 'VHT80', 'VHT160', 'HE20', 'HE40', 'HE80', 'HE160'].map((h) => `<option value="${h}" ${r.htmode === h ? 'selected' : ''}>${h || '自动'}</option>`).join('')}
          </select>
        </label>
      </div>
      <div class="field-row">
        <label class="field"><span>发射功率 dBm</span><input class="radio-txpower" value="${esc(r.txpower)}" placeholder="auto"></label>
        <div class="field"><span>实时状态</span><div class="row" style="padding-top:8px"><span class="badge ${liveRadio.device ? 'good' : 'muted'}">${liveRadio.device ? esc(liveRadio.device) : '未启动'}</span><span class="tiny muted">${(liveRadio.assoc_count || 0)} 台设备 · 信号 ${liveRadio.signal != null ? esc(liveRadio.signal) + ' dBm' : '—'}</span></div></div>
      </div>
      ${ifaceRows || '<div class="empty">该射频没有配置 SSID</div>'}
    </div>`;
  }).join('');

  $('#view').innerHTML = `
  <div class="card">
    <div class="row-between">
      <div><h2 style="margin:0;font-size:16px">无线网络</h2><p class="muted tiny" style="margin:4px 0 0">修改后点击保存，wifi 会自动重载</p></div>
      <button class="btn btn-primary" id="wifi-save">${icon('save')}保存无线配置</button>
    </div>
  </div>
  ${cards || '<div class="card mt-20"><div class="empty">未检测到无线硬件</div></div>'}`;

  $('#wifi-save').addEventListener('click', async () => {
    const payload = { radios: [] };
    $$('[data-radio]').forEach((card) => {
      const radio = {
        name: card.dataset.radio,
        channel: $('.radio-channel', card).value.trim(),
        htmode: $('.radio-htmode', card).value,
        txpower: $('.radio-txpower', card).value.trim(),
        disabled: $('.radio-disabled', card).checked,
        ifaces: [],
      };
      $$('[data-iface]', card).forEach((row) => {
        const enc = $('.iface-enc', row).value;
        const key = $('.iface-key', row).value;
        const iface = {
          section: row.dataset.iface,
          ssid: $('.iface-ssid', row).value.trim(),
          encryption: enc,
          hidden: $('.iface-hidden', row).checked,
          disabled: $('.iface-disabled', row).checked,
        };
        if (enc !== 'none' && key) iface.key = key;
        radio.ifaces.push(iface);
      });
      payload.radios.push(radio);
    });
    try {
      await api('/api/wireless', { method: 'PUT', body: payload });
      toast('无线配置已保存');
      setTimeout(() => go('wireless'), 1800);
    } catch (ex) { handleErr(ex); }
  });
}

/* ============================== clients ============================== */

function signalBars(dbm) {
  const level = dbm == null ? 0 : dbm >= -50 ? 4 : dbm >= -62 ? 3 : dbm >= -72 ? 2 : 1;
  return `<span class="signal">${[0, 1, 2, 3].map((i) => `<i class="${i < level ? 'on' : ''}"></i>`).join('')}</span>`;
}

function clientsTable(clients, leases) {
  const rows = (clients || []).map((c) => {
    const lease = (leases || []).find((l) => l.mac === c.mac);
    const name = c.hostname || (lease && lease.hostname) || c.mac;
    const ip = c.ip || (lease && lease.ip) || '—';
    return `<tr>
      <td><div class="primary">${esc(name)}</div><div class="tiny muted mono">${esc(c.mac)}</div></td>
      <td class="mono">${esc(ip)}</td>
      <td><span class="badge ${c.wireless ? 'muted' : 'good'}">${c.wireless ? '无线' : '有线'}</span></td>
      <td class="mono">${esc(c.iface || '—')}</td>
      <td>${c.wireless ? `${signalBars(c.signal)} <span class="tiny muted">${c.signal != null ? esc(c.signal) + ' dBm' : ''}</span>` : '—'}</td>
      <td class="mono">${c.rx && c.rx.bytes ? fmtBytes(c.rx.bytes) : '—'}</td>
      <td class="mono">${c.tx && c.tx.bytes ? fmtBytes(c.tx.bytes) : '—'}</td>
    </tr>`;
  }).join('');
  return rows || '<tr><td colspan="7" class="empty">暂无在线客户端</td></tr>';
}

async function renderClients() {
  const d = await api('/api/clients');
  $('#view').innerHTML = `
  <div class="grid grid-3">
    ${statCard('在线客户端', 'clients', `${(d.clients || []).length}<small>台</small>`, '无线 + 有线', '', 'green')}
    ${statCard('无线设备', 'wireless', `${d.wireless_clients || 0}<small>台</small>`, 'Wi-Fi 关联', '', 'cyan')}
    ${statCard('DHCP 租约', 'network', `${(d.leases || []).length}<small>条</small>`, '当前地址池', '', 'violet')}
  </div>
  <div class="card mt-20">
    <div class="card-title"><h2>客户端列表</h2><span class="sub" id="cl-updated">刚刚更新</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>设备</th><th>IP</th><th>接入</th><th>接口</th><th>信号</th><th>RX</th><th>TX</th></tr></thead>
      <tbody id="cl-body">${clientsTable(d.clients, d.leases)}</tbody>
    </table></div>
  </div>
  <div class="card mt-20">
    <div class="card-title"><h2>DHCP 租约</h2><span class="sub">/tmp/dhcp.leases</span></div>
    <div class="table-wrap"><table><thead><tr><th>主机名</th><th>IP</th><th>MAC</th><th>到期</th></tr></thead>
      <tbody>${(d.leases || []).map((l) => `<tr><td>${esc(l.hostname || '—')}</td><td class="mono">${esc(l.ip)}</td><td class="mono">${esc(l.mac)}</td><td class="tiny muted">${esc(fmtTime(l.expires))}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">暂无租约</td></tr>'}</tbody>
    </table></div>
  </div>`;

  const refresh = async () => {
    const nd = await api('/api/clients');
    if (state.view !== 'clients') return;
    const body = $('#cl-body');
    if (body) body.innerHTML = clientsTable(nd.clients, nd.leases);
    const up = $('#cl-updated');
    if (up) up.textContent = '刚刚更新 · ' + (nd.clients || []).length + ' 台';
  };
  setTimer(refresh, 5000);
}


/* ============================== access / AI ============================== */

function accessDeviceName(d) {
  return d.name || d.hostname || d.mac;
}

function accessRows(list, kind) {
  return (list || []).map((d) => {
    let actions = '';
    if (kind === 'pending') {
      actions = `<button class="btn btn-sm btn-primary" data-approve="${esc(d.mac)}">允许上网</button>
        <button class="btn btn-sm btn-danger" data-block="${esc(d.mac)}">拉黑</button>`;
    } else if (kind === 'authorized') {
      actions = `<button class="btn btn-sm" data-revoke="${esc(d.mac)}">撤销</button>
        <button class="btn btn-sm btn-danger" data-block="${esc(d.mac)}">拉黑</button>`;
    } else {
      actions = `<button class="btn btn-sm" data-unblock="${esc(d.mac)}">解除</button>`;
    }
    const expiry = kind === 'authorized'
      ? (d.expires_at ? fmtTime(d.expires_at) : '永久')
      : '—';
    return `<tr>
      <td><div class="primary">${esc(accessDeviceName(d))}</div><div class="tiny muted mono">${esc(d.mac)}</div></td>
      <td class="mono">${esc(d.ip || '—')}</td>
      <td>${d.online ? '<span class="badge good">在线</span>' : '<span class="badge muted">离线</span>'}</td>
      <td class="tiny muted">${d.first_seen ? fmtTime(d.first_seen) : '—'}</td>
      <td class="tiny muted">${expiry}</td>
      <td class="right nowrap">${actions}</td>
    </tr>`;
  }).join('');
}

async function renderAccess() {
  const [d, a] = await Promise.all([api('/api/access'), api('/api/agents')]);
  const counts = d.counts || {};
  const enabled = !!d.enforcement;
  const sim = !!(state.meta && state.meta.sim);
  const nftOk = d.nft_available !== false;

  $('#view').innerHTML = `
  ${sim ? '<div class="card" style="border-color:rgba(251,191,36,.35);margin-bottom:16px"><div class="row-between"><span class="badge warn">演示模式</span><span class="tiny muted">授权、拉黑、启用默认禁止、创建 Token 等写操作已禁用</span></div></div>' : ''}
  <div class="card">
    <div class="row-between wrap gap-14">
      <div>
        <h2 style="margin:0;font-size:16px">新设备默认禁止上网</h2>
        <p class="muted tiny" style="margin:5px 0 0">
          启用后，未授权设备仍能连 Wi-Fi、获取 IP，但无法访问外网。当前在线设备会自动加入白名单。
        </p>
      </div>
      <div class="card-actions">
        <span class="badge ${enabled ? 'good' : 'muted'}">${enabled ? '已启用' : '未启用'}</span>
        <button class="btn ${enabled ? 'btn-danger' : 'btn-primary'}" id="access-toggle" ${nftOk ? '' : 'disabled'}>${enabled ? '关闭默认禁止' : '启用默认禁止'}</button>
      </div>
    </div>
    ${nftOk ? '' : '<div class="form-error mt-14">系统缺少 nft 命令，无法启用数据面拦截。</div>'}
    <div class="grid grid-4 mt-20">
      <div class="card stat"><div class="stat-top"><span>待授权</span><span class="stat-icon amber">${icon('clients')}</span></div><div class="stat-value" id="acc-pending">${counts.pending || 0}</div><div class="stat-sub">等待允许上网</div></div>
      <div class="card stat"><div class="stat-top"><span>已授权</span><span class="stat-icon green">${icon('access')}</span></div><div class="stat-value" id="acc-authorized">${counts.authorized || 0}</div><div class="stat-sub">允许访问外网</div></div>
      <div class="card stat"><div class="stat-top"><span>已拉黑</span><span class="stat-icon violet">${icon('firewall')}</span></div><div class="stat-value" id="acc-blocked">${counts.blocked || 0}</div><div class="stat-sub">禁止上网</div></div>
      <div class="card stat"><div class="stat-top"><span>在线设备</span><span class="stat-icon">${icon('network')}</span></div><div class="stat-value" id="acc-online">${counts.online || 0}</div><div class="stat-sub">ARP + DHCP 租约</div></div>
    </div>
  </div>

  <div class="card mt-20">
    <div class="card-title"><h2>待授权设备</h2><span class="sub">新连接的路由器用户</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>设备</th><th>IP</th><th>状态</th><th>首次发现</th><th>有效期</th><th class="right">操作</th></tr></thead>
      <tbody id="acc-pending-body">${accessRows(d.pending, 'pending') || '<tr><td colspan="6" class="empty">没有待授权设备</td></tr>'}</tbody>
    </table></div>
  </div>

  <div class="grid grid-2 mt-20">
    <div class="card">
      <div class="card-title"><h2>已授权</h2><span class="sub">白名单</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>设备</th><th>IP</th><th>状态</th><th>首次发现</th><th>有效期</th><th class="right">操作</th></tr></thead>
        <tbody id="acc-auth-body">${accessRows(d.authorized, 'authorized') || '<tr><td colspan="6" class="empty">暂无授权设备</td></tr>'}</tbody>
      </table></div>
    </div>
    <div class="card">
      <div class="card-title"><h2>黑名单</h2><span class="sub">禁止访问外网</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>设备</th><th>IP</th><th>状态</th><th>首次发现</th><th>有效期</th><th class="right">操作</th></tr></thead>
        <tbody id="acc-blocked-body">${accessRows(d.blocked, 'blocked') || '<tr><td colspan="6" class="empty">黑名单为空</td></tr>'}</tbody>
      </table></div>
    </div>
  </div>

  <div class="card mt-20">
    <div class="row-between wrap gap-14">
      <div>
        <h2 style="margin:0;font-size:16px">AI 接入</h2>
        <p class="muted tiny" style="margin:5px 0 0">给外部 AI agent 的 Bearer Token。API 文档：<span class="mono">/api/agent/v1/openapi.json</span></p>
      </div>
      <button class="btn btn-primary" id="agent-create" ${sim ? 'disabled' : ''}>${icon('plus')}新建 Token</button>
    </div>
    <div class="table-wrap mt-14"><table>
      <thead><tr><th>名称</th><th>ID</th><th>权限</th><th>最近使用</th><th class="right">操作</th></tr></thead>
      <tbody id="agent-body">${(a.tokens || []).map((t) => `<tr>
        <td class="primary">${esc(t.name)}</td>
        <td class="mono tiny">${esc(t.id)}</td>
        <td class="tiny">${(t.scopes || []).map(esc).join(', ')}</td>
        <td class="tiny muted">${t.last_used ? fmtTime(t.last_used) : '未使用'}</td>
        <td class="right"><button class="btn btn-sm btn-danger" data-agent-del="${esc(t.id)}" ${sim ? 'disabled' : ''}>撤销</button></td>
      </tr>`).join('') || '<tr><td colspan="5" class="empty">还没有 AI Token</td></tr>'}</tbody>
    </table></div>
    <p class="form-hint mt-14">推荐权限：只给 <span class="mono">devices:read</span> + <span class="mono">devices:write</span>；Token 只显示一次。</p>
  </div>`;

  $('#access-toggle').addEventListener('click', async () => {
    const target = !enabled;
    const ok = await confirmDialog(
      target ? '启用默认禁止' : '关闭默认禁止',
      target
        ? '启用后，未授权设备将无法访问外网；当前在线设备会自动授权。确定启用？'
        : '关闭后，所有设备都可以访问外网，授权列表仍保留。确定关闭？',
      target ? '启用' : '关闭',
      !target
    );
    if (!ok) return;
    try {
      await api('/api/access/enforcement', { method: 'POST', body: { enabled: target, authorize_current: true } });
      toast(target ? '已启用默认禁止' : '已关闭默认禁止');
      setTimeout(() => go('access'), 900);
    } catch (e) { handleErr(e); }
  });

  bindAccessButtons();
  $('#agent-create').addEventListener('click', openAgentModal);
  setTimer(refreshAccess, 6000);
}

function bindAccessButtons() {
  $$('[data-approve]').forEach((b) => b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      await api(`/api/access/devices/${encodeURIComponent(b.dataset.approve)}/authorize`, { method: 'POST', body: { name: '', note: 'web approval', expires_in: 0 } });
      toast('设备已授权上网');
      await refreshAccess();
    } catch (e) { handleErr(e); b.disabled = false; }
  }));
  $$('[data-revoke]').forEach((b) => b.addEventListener('click', async () => {
    try {
      await api(`/api/access/devices/${encodeURIComponent(b.dataset.revoke)}/revoke`, { method: 'POST', body: {} });
      toast('已撤销授权');
      await refreshAccess();
    } catch (e) { handleErr(e); }
  }));
  $$('[data-block]').forEach((b) => b.addEventListener('click', async () => {
    const ok = await confirmDialog('拉黑设备', '该设备将无法访问外网，确定继续？', '拉黑', true);
    if (!ok) return;
    try {
      await api(`/api/access/devices/${encodeURIComponent(b.dataset.block)}/block`, { method: 'POST', body: {} });
      toast('设备已拉黑');
      await refreshAccess();
    } catch (e) { handleErr(e); }
  }));
  $$('[data-unblock]').forEach((b) => b.addEventListener('click', async () => {
    try {
      await api(`/api/access/devices/${encodeURIComponent(b.dataset.unblock)}/unblock`, { method: 'POST', body: {} });
      toast('已解除拉黑');
      await refreshAccess();
    } catch (e) { handleErr(e); }
  }));
  $$('[data-agent-del]').forEach((b) => b.addEventListener('click', async () => {
    const ok = await confirmDialog('撤销 Token', '撤销后使用该 Token 的 AI 将立即失去访问权限。确定？', '撤销', true);
    if (!ok) return;
    try {
      await api(`/api/agents/${encodeURIComponent(b.dataset.agentDel)}`, { method: 'DELETE' });
      toast('Token 已撤销');
      setTimeout(() => go('access'), 700);
    } catch (e) { handleErr(e); }
  }));
}

async function refreshAccess() {
  const d = await api('/api/access');
  if (state.view !== 'access') return;
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  set('acc-pending', String((d.counts || {}).pending || 0));
  set('acc-authorized', String((d.counts || {}).authorized || 0));
  set('acc-blocked', String((d.counts || {}).blocked || 0));
  set('acc-online', String((d.counts || {}).online || 0));
  const bodies = [
    ['acc-pending-body', accessRows(d.pending, 'pending') || '<tr><td colspan="6" class="empty">没有待授权设备</td></tr>'],
    ['acc-auth-body', accessRows(d.authorized, 'authorized') || '<tr><td colspan="6" class="empty">暂无授权设备</td></tr>'],
    ['acc-blocked-body', accessRows(d.blocked, 'blocked') || '<tr><td colspan="6" class="empty">黑名单为空</td></tr>'],
  ];
  bodies.forEach(([id, html]) => set(id, html));
  bindAccessButtons();
}

function openAgentModal() {
  openModal(
    `<h3>新建 AI Token</h3>
     <p class="sub">给外部 AI agent 使用。Token 只会显示一次。</p>
     <form id="agent-form">
       <label class="field"><span>名称</span><input name="name" placeholder="例如：Claude 家庭助手" maxlength="40"></label>
       <div class="field"><span>权限</span>
         <label class="switch" style="margin-bottom:6px"><input type="checkbox" name="read" checked><span class="track"></span>devices:read（查看设备）</label>
         <label class="switch"><input type="checkbox" name="write" checked><span class="track"></span>devices:write（授权/拉黑/开关禁止）</label>
       </div>
       <div class="form-error hidden" data-err></div>
       <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">创建</button></div>
     </form>`,
    {
      onMount(el, close) {
        el.querySelector('[data-cancel]').onclick = close;
        el.querySelector('#agent-form').addEventListener('submit', async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          const scopes = [];
          if (f.get('read') === 'on') scopes.push('devices:read');
          if (f.get('write') === 'on') scopes.push('devices:write');
          const err = el.querySelector('[data-err]');
          err.classList.add('hidden');
          if (!scopes.length) {
            err.textContent = '至少选择一个权限';
            err.classList.remove('hidden');
            return;
          }
          try {
            const d = await api('/api/agents', { method: 'POST', body: { name: f.get('name'), scopes } });
            el.querySelector('.modal').innerHTML = `
              <h3>Token 已创建</h3>
              <p class="sub">只显示这一次，请复制保存。</p>
              <pre class="log" id="new-agent-token">${esc(d.token)}</pre>
              <div class="btn-row">
                <button class="btn" data-copy>复制</button>
                <button class="btn btn-primary" data-done>完成</button>
              </div>`;
            el.querySelector('[data-copy]').onclick = async () => {
              try { await navigator.clipboard.writeText(d.token); toast('Token 已复制'); }
              catch (_) { window.prompt('复制 Token', d.token); }
            };
            el.querySelector('[data-done]').onclick = () => { close(); go('access'); };
          } catch (ex) {
            err.textContent = ex.message || '创建失败';
            err.classList.remove('hidden');
          }
        });
      },
    }
  );
}

/* ============================== firewall ============================== */

async function renderFirewall() {
  const d = await api('/api/firewall');
  const zones = (d.zones || []).map((z) => `<span class="chip"><b>${esc(z.name)}</b> · in ${esc(z.input)} · fwd ${esc(z.forward)}${z.masq ? ' · NAT' : ''}</span>`).join('');
  const rows = (d.redirects || []).map((r) => `<tr>
      <td><div class="primary">${esc(r.name)}</div><div class="tiny muted mono">${esc(r.section)}</div></td>
      <td class="mono">${esc(r.proto)}</td>
      <td class="mono">${esc(r.src_dport)} → ${esc(r.dest_ip)}:${esc(r.dest_port)}</td>
      <td><span class="badge ${r.enabled ? 'good' : 'muted'}">${r.enabled ? '启用' : '停用'}</span></td>
      <td class="right"><label class="switch"><input type="checkbox" data-toggle="${esc(r.section)}" ${r.enabled ? 'checked' : ''}><span class="track"></span></label>
        <button class="btn btn-sm btn-danger" data-del="${esc(r.section)}" style="margin-left:8px">${icon('trash')}</button></td>
    </tr>`).join('');

  $('#view').innerHTML = `
  <div class="card">
    <div class="row-between">
      <div><h2 style="margin:0;font-size:16px">区域策略</h2><p class="muted tiny" style="margin:4px 0 0">防火墙区域与转发策略</p></div>
      <button class="btn btn-primary" id="fw-add">${icon('plus')}新增端口转发</button>
    </div>
    <div class="zone-chips mt-14">${zones || '<span class="muted tiny">暂无区域配置</span>'}</div>
  </div>
  <div class="card mt-20">
    <div class="card-title"><h2>端口转发</h2><span class="sub">${(d.redirects || []).length} 条规则</span></div>
    <div class="table-wrap"><table><thead><tr><th>规则</th><th>协议</th><th>映射</th><th>状态</th><th class="right">操作</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="empty">还没有端口转发规则</td></tr>'}</tbody></table></div>
  </div>`;

  $('#fw-add').addEventListener('click', () => openRedirectModal());
  $$('[data-toggle]').forEach((el) => el.addEventListener('change', async () => {
    try {
      await api(`/api/firewall/redirects/${encodeURIComponent(el.dataset.toggle)}`, { method: 'PATCH', body: { enabled: el.checked } });
      toast(el.checked ? '规则已启用' : '规则已停用');
    } catch (e) { handleErr(e); el.checked = !el.checked; }
  }));
  $$('[data-del]').forEach((el) => el.addEventListener('click', async () => {
    const ok = await confirmDialog('删除规则', '确定删除这条端口转发规则？', '删除', true);
    if (!ok) return;
    try {
      await api(`/api/firewall/redirects/${encodeURIComponent(el.dataset.del)}`, { method: 'DELETE' });
      toast('规则已删除');
      setTimeout(() => go('firewall'), 900);
    } catch (e) { handleErr(e); }
  }));
}

function openRedirectModal() {
  openModal(
    `<h3>新增端口转发</h3><p class="sub">把 WAN 侧端口映射到内网设备</p>
     <form id="fw-form">
       <label class="field"><span>规则名称</span><input name="name" placeholder="例如：NAS 管理" required maxlength="32"></label>
       <div class="field-row">
         <label class="field"><span>协议</span><select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp udp">TCP + UDP</option></select></label>
         <label class="field"><span>外部端口</span><input name="src_dport" type="number" min="1" max="65535" required></label>
       </div>
       <div class="field-row">
         <label class="field"><span>内部 IP</span><input name="dest_ip" placeholder="192.168.1.100" required></label>
         <label class="field"><span>内部端口</span><input name="dest_port" type="number" min="1" max="65535" required></label>
       </div>
       <div class="form-error hidden" data-err></div>
       <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">创建规则</button></div>
     </form>`,
    {
      onMount(el, close) {
        el.querySelector('[data-cancel]').onclick = close;
        const form = el.querySelector('#fw-form');
        form.addEventListener('submit', async (e) => {
          e.preventDefault();
          const f = new FormData(form);
          const err = el.querySelector('[data-err]');
          err.classList.add('hidden');
          try {
            await api('/api/firewall/redirects', {
              method: 'POST',
              body: {
                name: f.get('name'), proto: f.get('proto'),
                src_dport: f.get('src_dport'), dest_ip: f.get('dest_ip'), dest_port: f.get('dest_port'),
              },
            });
            close();
            toast('端口转发已创建');
            setTimeout(() => go('firewall'), 900);
          } catch (ex) {
            err.textContent = ex.message || '创建失败';
            err.classList.remove('hidden');
          }
        });
      },
    }
  );
}

/* ============================== system ============================== */

async function renderSystem() {
  const [sys, fw] = await Promise.all([
    api('/api/system'),
    api('/api/firmware').catch(() => null),
  ]);

  $('#view').innerHTML = `
  <div class="grid grid-2">
    <div class="card">
      <div class="card-title"><h2>设备信息</h2><span class="sub">${esc(sys.board)}</span></div>
      <div class="kv">
        <div class="k">型号</div><div class="v">${esc(sys.model)}</div>
        <div class="k">主机名</div><div class="v mono">${esc(sys.hostname)}</div>
        <div class="k">固件</div><div class="v mono">${esc(sys.firmware.version || '—')} (${esc(sys.firmware.revision || '—')})</div>
        <div class="k">内核</div><div class="v mono">${esc(sys.kernel)}</div>
        <div class="k">架构</div><div class="v mono">${esc(sys.arch)}</div>
        <div class="k">MAC</div><div class="v mono">${esc(sys.mac || '—')}</div>
        <div class="k">温度</div><div class="v">${sys.temperature != null ? Number(sys.temperature).toFixed(1) + ' °C' : '—'}</div>
        <div class="k">运行时间</div><div class="v">${esc(sys.uptime_human)}</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><h2>主机名</h2></div>
      <form id="host-form">
        <label class="field"><span>设备名称</span><input name="hostname" value="${esc(sys.hostname)}" maxlength="63" required></label>
        <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存</button></div>
      </form>
      <div class="card-title mt-20"><h2>管理员密码</h2></div>
      <form id="pw-form">
        <label class="field"><span>当前密码</span><input name="current" type="password" autocomplete="current-password" required></label>
        <div class="field-row">
          <label class="field"><span>新密码</span><input name="next" type="password" minlength="8" autocomplete="new-password" required></label>
          <label class="field"><span>确认</span><input name="confirm" type="password" minlength="8" autocomplete="new-password" required></label>
        </div>
        <div class="form-error hidden" data-err></div>
        <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('lock')}修改密码</button></div>
      </form>
    </div>
  </div>

  <div class="card mt-20">
    <div class="card-title"><h2>固件升级</h2><span class="sub">${esc(fw ? fw.board : sys.board)}</span></div>
    <input type="file" id="fw-file" accept=".bin,.img,.tar,.gz" class="hidden">
    <div class="file-drop" id="fw-drop">
      ${icon('upload')}
      <div>点击选择或拖入 sysupgrade 固件</div>
      <div class="tiny muted">仅接受 OpenWrt sysupgrade 格式，最大 64MB</div>
      <div class="file-name hidden" id="fw-name"></div>
    </div>
    <div class="progress hidden mt-14" id="fw-progress"><i></i></div>
    <div class="row-between mt-14 wrap gap-14">
      <label class="switch"><input type="checkbox" id="fw-keep" checked><span class="track"></span>保留当前配置</label>
      <button class="btn btn-danger" id="fw-apply" disabled>${icon('alert')}安装并重启</button>
    </div>
    <div class="tiny muted mt-14" id="fw-note">升级过程中请勿断电，设备会自动重启。</div>
  </div>

  <div class="card mt-20" style="border-color:rgba(251,113,133,.22)">
    <div class="row-between">
      <div><h2 style="margin:0;font-size:15px">重启设备</h2><p class="muted tiny" style="margin:4px 0 0">重启会中断所有网络连接</p></div>
      <button class="btn btn-danger" id="sys-reboot">${icon('power')}重启</button>
    </div>
  </div>`;

  $('#host-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = new FormData(e.target).get('hostname');
    try {
      await api('/api/system/hostname', { method: 'PUT', body: { hostname: name } });
      state.meta.hostname = name;
      $('#side-host').textContent = name;
      $('#top-host').textContent = name;
      toast('主机名已更新');
    } catch (ex) { handleErr(ex); }
  });

  $('#pw-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const err = $('[data-err]', e.target);
    err.classList.add('hidden');
    if (f.get('next') !== f.get('confirm')) {
      err.textContent = '两次输入的新密码不一致';
      err.classList.remove('hidden');
      return;
    }
    try {
      await api('/api/system/password', { method: 'POST', body: { current: f.get('current'), new: f.get('next') } });
      e.target.reset();
      toast('密码已更新');
    } catch (ex) {
      err.textContent = ex.message || '修改失败';
      err.classList.remove('hidden');
    }
  });

  bindFirmwareUpload();
  $('#sys-reboot').addEventListener('click', doReboot);
}

function bindFirmwareUpload() {
  const input = $('#fw-file');
  const drop = $('#fw-drop');
  if (!input || !drop) return;
  let selected = null;

  const choose = () => input.click();
  drop.addEventListener('click', choose);
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('drag'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('drag');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      input.files = e.dataTransfer.files;
      onPick();
    }
  });
  input.addEventListener('change', onPick);

  function onPick() {
    selected = input.files && input.files[0];
    if (!selected) return;
    const name = $('#fw-name');
    name.textContent = `${selected.name} · ${fmtBytes(selected.size)}`;
    name.classList.remove('hidden');
    upload(selected);
  }

  async function upload(file) {
    const prog = $('#fw-progress');
    const bar = $('#fw-progress > i');
    const note = $('#fw-note');
    prog.classList.remove('hidden');
    bar.style.width = '0%';
    note.textContent = '正在上传固件…';
    $('#fw-apply').disabled = true;
    const fd = new FormData();
    fd.append('firmware', file, file.name);
    try {
      const data = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/firmware/upload');
        xhr.setRequestHeader('X-CSRF-Token', state.csrf || '');
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) bar.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
        };
        xhr.onload = () => {
          let j = null;
          try { j = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
          if (xhr.status >= 200 && xhr.status < 300 && j && j.ok) resolve(j.data);
          else reject(new ApiErr((j && j.error) || `上传失败 (${xhr.status})`, j && j.code, xhr.status));
        };
        xhr.onerror = () => reject(new Error('网络错误，上传失败'));
        xhr.send(fd);
      });
      bar.style.width = '100%';
      note.innerHTML = `上传完成 · ${fmtBytes(data.size)} · <span class="mono">${esc(data.sha256).slice(0, 16)}…</span>`;
      $('#fw-apply').disabled = false;
      $('#fw-apply').onclick = () => applyFirmware();
      toast('固件上传完成，可以安装');
    } catch (e) {
      prog.classList.add('hidden');
      note.textContent = '上传失败：' + (e.message || e);
      handleErr(e);
    }
  }

  async function applyFirmware() {
    const keep = $('#fw-keep').checked;
    const ok = await confirmDialog(
      '安装固件',
      keep ? '将保留当前配置并重启设备。确认开始刷写？' : '将清除所有配置并重启设备。确认开始刷写？',
      '开始刷写',
      true
    );
    if (!ok) return;
    try {
      await api('/api/firmware/apply', { method: 'POST', body: { keep_config: keep } });
      toast('正在写入固件，设备即将重启…');
      $('#fw-apply').disabled = true;
    } catch (e) { handleErr(e); }
  }
}

/* ============================== logs ============================== */

async function renderLogs() {
  $('#view').innerHTML = `
  <div class="card">
    <div class="row-between wrap gap-14">
      <div class="row wrap gap-14">
        <label class="field" style="margin:0"><span>过滤关键字</span><input id="log-filter" placeholder="例如 wifi / dhcp / error"></label>
        <label class="field" style="margin:0"><span>行数</span>
          <select id="log-lines"><option>100</option><option selected>300</option><option>600</option><option>1200</option></select>
        </label>
      </div>
      <div class="card-actions">
        <label class="switch"><input type="checkbox" id="log-auto" checked><span class="track"></span>自动刷新</label>
        <button class="btn btn-primary" id="log-refresh">${icon('refresh')}刷新</button>
      </div>
    </div>
    <pre class="log mt-14" id="log-box">正在读取日志…</pre>
  </div>`;

  const load = async () => {
    const filter = $('#log-filter').value.trim();
    const lines = $('#log-lines').value;
    const box = $('#log-box');
    if (!box) return;
    try {
      const d = await api(`/api/logs?lines=${encodeURIComponent(lines)}&filter=${encodeURIComponent(filter)}`);
      box.textContent = d.log || '(无日志)';
      box.scrollTop = box.scrollHeight;
    } catch (e) {
      box.textContent = '读取日志失败：' + (e.message || e);
    }
  };

  $('#log-refresh').addEventListener('click', load);
  $('#log-filter').addEventListener('input', () => { clearTimer(); load(); });
  $('#log-lines').addEventListener('change', load);
  $('#log-auto').addEventListener('change', () => {
    if ($('#log-auto').checked) setTimer(load, 5000); else clearTimer();
  });
  await load();
  setTimer(load, 5000);
}

/* ============================== start ============================== */

window.addEventListener('unhandledrejection', (e) => {
  if (e.reason && e.reason.status === 401) return;
  console.error('unhandled:', e.reason);
});

document.addEventListener('DOMContentLoaded', init);
