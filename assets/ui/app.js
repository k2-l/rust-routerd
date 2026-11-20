'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SVG_ATTR = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';

const ICON = {
  overview: `<svg ${SVG_ATTR}><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>`,
  network: `<svg ${SVG_ATTR}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.5 4 5.6 4 9s-1.4 6.5-4 9c-2.6-2.5-4-5.6-4-9s1.4-6.5 4-9z"/></svg>`,
  wireless: `<svg ${SVG_ATTR}><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5.5 5.5 0 0 1 7 0"/><circle cx="12" cy="19.5" r="1"/><path d="M2 9a15 15 0 0 1 20 0"/></svg>`,
  clients: `<svg ${SVG_ATTR}><circle cx="9" cy="8" r="3.2"/><path d="M3.5 20c0-3.2 2.5-5.5 5.5-5.5s5.5 2.3 5.5 5.5"/><circle cx="17.5" cy="9" r="2.5"/><path d="M16 14.6c2.6.3 4.5 2.4 4.5 5.4"/></svg>`,
  firewall: `<svg ${SVG_ATTR}><path d="M12 3l7 3v5c0 4.6-2.9 8.3-7 10-4.1-1.7-7-5.4-7-10V6l7-3z"/><path d="M9.5 12l1.8 1.8 3.4-3.6"/></svg>`,
  singbox: `<svg ${SVG_ATTR}><path d="M12 2l8 4.5v11L12 22l-8-4.5v-11L12 2z"/><path d="M12 22V12M20 6.5L12 12 4 6.5"/></svg>`,
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
  lock: `<svg ${SVG_ATTR}><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>`,
  save: `<svg ${SVG_ATTR}><path d="M5 4h11l3 3v13H5z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/></svg>`,
  router: `<svg ${SVG_ATTR}><rect x="2" y="13" width="20" height="7" rx="2"/><path d="M6 16.5h.01M10 16.5h.01M14 16.5h4M7 13V7M17 13V7M5 5a4 4 0 0 1 4 0M15 5a4 4 0 0 1 4 0"/></svg>`,
};

const state = { csrf: null, meta: {}, view: 'overview', timer: null, sse: null, wanIp: '' };

const VIEWS = {
  overview: { label: '系统总览', title: '系统总览', sub: '全息网络拓扑、物理网口与硬件卸载遥测', icon: 'overview', render: renderOverview },
  network:  { label: '上网设置', title: '上网设置', sub: 'WAN 拨号诊断、LAN 与路由表管理', icon: 'network', render: renderNetwork },
  wireless: { label: '无线配置', title: '无线配置', sub: '2.4G / 5G 射频参数与 Wi-Fi 6 广播', icon: 'wireless', render: renderWireless },
  clients:  { label: '终端管理', title: '终端管理', sub: '全网在线设备、信号质量与 DHCP 租约', icon: 'clients', render: renderClients },
  access:   { label: '安全管控', title: '安全管控', sub: '零信任设备准入与 AI Agent 令牌', icon: 'access', render: renderAccess },
  firewall: { label: '端口转发', title: '端口转发', sub: 'NAT 端口映射与防火墙区域策略', icon: 'firewall', render: renderFirewall },
  singbox:  { label: '代理核心', title: 'Sing-box 代理核心', sub: '内置透明代理、多协议出站与智能分流引擎', icon: 'singbox', render: renderSingbox },
  system:   { label: '系统固件', title: '系统固件', sub: '硬件详情、密码安全与 sysupgrade 刷机', icon: 'system', render: renderSystem },
  logs:     { label: '内核日志', title: '内核日志', sub: '系统与网络守护进程实时输出', icon: 'logs', render: renderLogs },
};

class ApiErr extends Error {
  constructor(message, code, status) { super(message); this.code = code; this.status = status; }
}

const esc = (v) => String(v == null ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const icon = (name) => ICON[name] || '';

function fmtBytes(n) {
  if (n == null || isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function fmtRate(kbps) {
  if (kbps == null || isNaN(kbps)) return '—';
  return kbps >= 1000 ? `${(kbps / 1000).toFixed(1)} Mbps` : `${Math.round(kbps)} Kbps`;
}

function fmtUptime(sec) {
  sec = Number(sec) || 0;
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}天 ${h}小时`;
  if (h > 0) return `${h}小时 ${m}分`;
  return `${m}分 ${sec % 60}秒`;
}

async function api(path, opts = {}) {
  const headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
  const isForm = opts.body instanceof FormData;
  if (opts.body && !isForm && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
  if (opts.body && !isForm) headers['Content-Type'] = 'application/json';
  const method = (opts.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && state.csrf) headers['X-CSRF-Token'] = state.csrf;

  const res = await fetch(path, { ...opts, method, headers, credentials: 'same-origin' });
  let payload = null;
  try { payload = await res.json(); } catch (e) {}
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/login') showLogin();
    throw new ApiErr((payload && payload.error) || `请求失败 (${res.status})`, payload && payload.code, res.status);
  }
  return payload ? payload.data : null;
}

function toast(message, type = 'good') {
  const box = $('#toast');
  const el = document.createElement('div');
  el.className = `toast-item ${type}`;
  el.innerHTML = `<span class="ic">${type === 'bad' ? icon('alert') : icon('check')}</span><span>${esc(message)}</span>`;
  box.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(6px)'; }, 3000);
  setTimeout(() => el.remove(), 3400);
}

function handleErr(err) {
  if (err && err.code === 'password_change_required') { forcePasswordChange(); return; }
  if (err && err.status === 401) return;
  toast((err && err.message) || '操作失败', 'bad');
}

function openModal(html, opts = {}) {
  const root = $('#modal-root');
  const back = document.createElement('div');
  back.className = 'modal-backdrop';
  back.innerHTML = `<div class="modal">${html}</div>`;
  root.appendChild(back);
  const close = () => back.remove();
  if (opts.closable !== false) back.addEventListener('click', (e) => { if (e.target === back) close(); });
  if (opts.onMount) opts.onMount(back, close);
  return { el: back, close };
}

function confirmDialog(title, message, okText = '确认', danger = false) {
  return new Promise((resolve) => {
    openModal(
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
  });
}

async function init() {
  bindTopButtons();
  bindLogin();
  try {
    const s = await api('/api/session');
    state.meta = (s && s.meta) || {};
    if (s && s.authenticated) { state.csrf = s.csrf; enterApp(); }
    else showLogin();
  } catch (e) { showLogin(); }
}

function showLogin() {
  clearTimer();
  $('#boot').classList.add('hidden');
  $('#app').classList.add('hidden');
  $('#login-view').classList.remove('hidden');
  $('#login-device').textContent = state.meta.model ? `${state.meta.model} · ${state.meta.hostname || ''}` : 'Cudy TR3000 // MT7981';
  $('#login-version').textContent = `routerd ${state.meta.version || ''}`.trim();
  $('#login-tls').textContent = state.meta.tls ? 'TLS 1.3 加密通道' : 'HTTP 明文通道';
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
    btn.disabled = true; btn.textContent = '正在建立安全会话…';
    try {
      const d = await api('/api/login', { method: 'POST', body: { username: fd.get('username'), password: fd.get('password') } });
      state.csrf = d.csrf; state.meta = d.meta || {};
      $('#login-view').classList.add('hidden'); enterApp();
    } catch (err) {
      errBox.textContent = err.message || '认证失败'; errBox.classList.remove('hidden');
    } finally { btn.disabled = false; btn.textContent = '接入控制台'; }
  });
}

function forcePasswordChange() {
  if ($('#force-pw')) return;
  openModal(
    `<h3 id="force-pw">首次登录安全向导</h3>
     <p class="sub">检测到默认初始密码，请设置新的管理员密码以保护路由器。</p>
     <form id="force-form">
       <label class="field"><span>当前默认密码</span><input name="current" type="password" required></label>
       <label class="field"><span>新密码（至少 8 位）</span><input name="next" type="password" minlength="8" required></label>
       <label class="field"><span>确认新密码</span><input name="confirm" type="password" minlength="8" required></label>
       <div class="form-error hidden" data-err></div>
       <div class="btn-row"><button class="btn btn-primary" type="submit">更新密码并进入</button></div>
     </form>`,
    {
      closable: false,
      onMount(el, close) {
        el.querySelector('#force-form').addEventListener('submit', async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          const err = el.querySelector('[data-err]');
          err.classList.add('hidden');
          if (f.get('next') !== f.get('confirm')) { err.textContent = '两次输入的新密码不一致'; err.classList.remove('hidden'); return; }
          try {
            await api('/api/system/password', { method: 'POST', body: { current: f.get('current'), new: f.get('next') } });
            state.meta.must_change = false; close(); toast('密码已更新'); go(state.view);
          } catch (ex) { err.textContent = ex.message || '修改失败'; err.classList.remove('hidden'); }
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
  $('#side-host').textContent = host; $('#top-host').textContent = host;
  $('#side-ver').textContent = `routerd ${state.meta.version || ''}`.trim();

  $$('#nav .nav-item').forEach((btn) => {
    const v = btn.dataset.view;
    btn.innerHTML = `${icon(VIEWS[v].icon)}<span>${VIEWS[v].label}</span>`;
    btn.onclick = () => go(v);
  });

  const mobile = $('#mobile-nav');
  mobile.innerHTML = Object.entries(VIEWS).map(([k, v]) => `<button data-view="${k}">${icon(v.icon)}<span>${v.label}</span></button>`).join('');
  $$('#mobile-nav button').forEach((b) => { b.onclick = () => go(b.dataset.view); });

  if (state.meta.must_change) {
    $('#view').innerHTML = '<div class="card"><div class="empty">请先完成首次登录密码修改</div></div>';
    setTimeout(forcePasswordChange, 200);
  } else go(state.view);
}

function bindTopButtons() {
  $('#btn-refresh').innerHTML = icon('refresh');
  $('#btn-logout').innerHTML = icon('logout');
  $('#btn-refresh').onclick = () => {
    const b = $('#btn-refresh'); b.classList.add('spin');
    go(state.view).finally(() => setTimeout(() => b.classList.remove('spin'), 500));
  };
  $('#btn-logout').onclick = async () => {
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
    state.csrf = null; showLogin();
  };
}

function clearTimer() { if (state.timer) { clearInterval(state.timer); state.timer = null; } if (state.sse) { state.sse.close(); state.sse = null; } }
function setTimer(fn, ms) { clearTimer(); state.timer = setInterval(() => { if (!document.hidden) fn().catch(() => {}); }, ms); }

async function go(view) {
  if (!VIEWS[view]) view = 'overview';
  state.view = view; clearTimer();
  $$('#nav .nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $$('#mobile-nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  $('#view-title').textContent = VIEWS[view].title;
  $('#view-sub').textContent = VIEWS[view].sub;
  $('#view').innerHTML = '<div class="empty">正在同步内核遥测数据…</div>';
  try { await VIEWS[view].render(); }
  catch (e) { $('#view').innerHTML = `<div class="card"><div class="empty">加载失败：${esc(e.message || e)}</div></div>`; handleErr(e); }
}

function fitCanvas(canvas) {
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.floor(rect.width)), h = Math.max(1, Math.floor(rect.height));
  canvas.width = Math.floor(w * dpr); canvas.height = Math.floor(h * dpr);
  const ctx = canvas.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

function drawSeries(ctx, data, color, w, h, max, fill) {
  if (!data || !data.length) return;
  const pad = 4, step = data.length > 1 ? (w - pad * 2) / (data.length - 1) : 0;
  const xy = (i, v) => [pad + step * i, h - pad - (h - pad * 2) * (Math.max(0, v) / max)];
  if (fill) {
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, fill); grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.moveTo(pad, h - pad);
    data.forEach((v, i) => { const [x, y] = xy(i, v); ctx.lineTo(x, y); });
    ctx.lineTo(pad + step * (data.length - 1), h - pad); ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();
  }
  ctx.beginPath();
  data.forEach((v, i) => { const [x, y] = xy(i, v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();
}

function drawTraffic(canvas, rx, tx) {
  if (!canvas) return;
  const { ctx, w, h } = fitCanvas(canvas);
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(56,189,248,0.08)';
  for (let i = 1; i <= 3; i++) { const y = (h / 4) * i; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
  const max = Math.max(1, ...(rx || []), ...(tx || [])) * 1.15;
  drawSeries(ctx, tx || [], '#a78bfa', w, h, max, 'rgba(139,92,246,0.24)');
  drawSeries(ctx, rx || [], '#22d3ee', w, h, max, 'rgba(34,211,238,0.22)');
}

function ringGauge(percent, color, title, sub) {
  const p = Math.max(0, Math.min(100, Number(percent) || 0));
  const r = 42, c = 2 * Math.PI * r, offset = c - (p / 100) * c;
  return `<div class="gauge-box">
    <svg class="gauge-svg" viewBox="0 0 100 100">
      <circle class="gauge-bg" cx="50" cy="50" r="${r}"/>
      <circle class="gauge-fg" cx="50" cy="50" r="${r}" stroke="${color}" stroke-dasharray="${c}" stroke-dashoffset="${offset}"/>
    </svg>
    <div class="gauge-label"><div class="gauge-num">${Math.round(p)}%</div></div>
    <div class="gauge-title">${esc(title)}</div>
    <div class="gauge-sub">${esc(sub)}</div>
  </div>`;
}

function renderPortRack(ports) {
  if (!ports || !ports.length) return '<div class="empty">未检测到物理网口</div>';
  return `<div class="port-rack">${ports.map((p) => {
    const isWan = p.role === 'WAN';
    const speedTxt = p.link_up ? (p.speed_mbps >= 1000 ? `${(p.speed_mbps / 1000).toFixed(p.speed_mbps % 1000 ? 1 : 0)} Gbps` : `${p.speed_mbps} Mbps`) : '未连接';
    return `<div class="rj45-card ${p.link_up ? 'up' : ''} ${isWan ? 'wan' : ''}">
      <span class="rj45-role ${isWan ? 'wan' : 'lan'}">${esc(p.role)}</span>
      <div class="rj45-socket"><span class="rj45-led"></span><i class="rj45-pin"></i><i class="rj45-pin"></i><i class="rj45-pin"></i><i class="rj45-pin"></i></div>
      <div class="rj45-name">${esc(p.label)}</div>
      <div class="rj45-speed">${esc(speedTxt)}</div>
    </div>`;
  }).join('')}</div>`;
}

async function renderOverview() {
  const [sys, hist, wifi, clients, net, hw] = await Promise.all([
    api('/api/system'), api('/api/system/history'),
    api('/api/wireless').catch(() => null), api('/api/clients').catch(() => null),
    api('/api/network').catch(() => null), api('/api/network/hardware').catch(() => null),
  ]);
  if (sys.arch) $('#top-arch').textContent = `${String(sys.arch).toUpperCase()} // MUSL`;
  const wanStatus = (net && net.wan_status) || {};
  state.wanIp = (wanStatus.ipv4 && wanStatus.ipv4[0] && wanStatus.ipv4[0].address) || '';
  const totalClients = ((clients && clients.wireless_clients) || 0) + ((clients && clients.wired_clients) || 0);
  const ports = (hw && hw.ports) || [];
  const hwOffload = hw ? hw.hw_offload : false;
  const radios = (wifi && wifi.radios) || [];

  $('#view').innerHTML = `
    <div class="grid grid-topo">
      <div class="card">
        <div class="card-title">
          <h2>全息网络拓扑</h2>
          <span class="status-pill ${state.wanIp ? 'good' : 'bad'}">${state.wanIp ? `外网在线 (${String(wanStatus.proto || 'WAN').toUpperCase()})` : '外网未连接'}</span>
        </div>
        <div class="topo-stage">
          <div class="topo-node ${state.wanIp ? '' : 'offline'}" data-jump="network">
            <div class="topo-icon">${icon('network')}</div>
            <div class="topo-name">光纤宽带 WAN</div>
            <div class="topo-detail">${esc(state.wanIp || '点击配置拨号')}</div>
          </div>
          <div class="topo-beam ${state.wanIp ? '' : 'off'}"></div>
          <div class="topo-node core" data-jump="system">
            <div class="topo-icon">${icon('router')}</div>
            <div class="topo-name">${esc(sys.model || '核心路由网关')}</div>
            <div class="topo-detail">运行 ${esc(sys.uptime_human)}</div>
          </div>
          <div class="topo-beam"></div>
          <div class="topo-node" data-jump="clients">
            <div class="topo-icon">${icon('clients')}</div>
            <div class="topo-name">在线终端 (${totalClients})</div>
            <div class="topo-detail">无线 ${(clients && clients.wireless_clients) || 0} · 有线 ${(clients && clients.wired_clients) || 0}</div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><h2>物理网口状态</h2><span class="sub">${ports.filter(p => p.link_up).length} / ${ports.length} 已连通</span></div>
        <div id="ov-ports">${renderPortRack(ports)}</div>
      </div>
    </div>

    <div class="grid grid-topo mt-20">
      <div class="card">
        <div class="card-title"><h2>实时速率监控</h2><span class="sub" id="ov-rates">↓ ${fmtRate(sys.traffic.rx_kbps)} · ↑ ${fmtRate(sys.traffic.tx_kbps)}</span></div>
        <div class="chart-wrap"><canvas id="traffic-chart"></canvas></div>
        <div class="chart-legend">
          <span><i class="legend-dot" style="background:#22d3ee"></i>下行吞吐</span>
          <span><i class="legend-dot" style="background:#a78bfa"></i>上行吞吐</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><h2>硬件加速引擎</h2><span class="badge ${hwOffload ? 'good' : 'warn'}">${hwOffload ? 'PPE 硬件加速已开启' : '软件转发模式'}</span></div>
        <div class="gauge-pair" id="ov-gauges">
          ${ringGauge(sys.cpu.usage, '#22d3ee', 'CPU 负载', `${sys.cpu.cores} 核 · ${sys.temperature != null ? Math.round(sys.temperature) + '°C' : '正常'}`)}
          ${ringGauge(sys.memory.percent, '#a78bfa', '内存占用', `${fmtBytes(sys.memory.used)} / ${fmtBytes(sys.memory.total)}`)}
        </div>
        <div class="kv mt-14">
          <div class="k">系统平均负载</div><div class="v mono">${(sys.load || []).map((x) => Number(x).toFixed(2)).join(' / ')}</div>
          <div class="k">固件存储空间</div><div class="v mono">${fmtBytes(sys.storage.used)} / ${fmtBytes(sys.storage.total)}</div>
        </div>
      </div>
    </div>

    <div class="grid grid-2 mt-20">
      <div class="card">
        <div class="card-title"><h2>无线射频广播</h2><span class="sub">${radios.length} 个频段</span></div>
        <div class="list">
          ${radios.flatMap((r) => (r.ifaces || []).map((i) => `
            <div class="list-row">
              <div><div class="list-title">${esc(i.ssid || '(未命名)')}</div><div class="list-sub">${esc(r.name)} · ${esc(i.encryption)} · ${i.assoc_count || 0} 台在线</div></div>
              <span class="badge ${i.disabled ? 'muted' : 'good'}">${i.disabled ? '已关闭' : '广播中'}</span>
            </div>`)).join('') || '<div class="empty">暂无无线配置</div>'}
        </div>
      </div>
      <div class="card">
        <div class="card-title"><h2>快捷运维</h2><span class="sub">${esc(sys.kernel)}</span></div>
        <div class="kv">
          <div class="k">本机 MAC</div><div class="v mono">${esc(sys.mac || '—')}</div>
          <div class="k">固件版本</div><div class="v mono">${esc(sys.firmware.version || '—')}</div>
        </div>
        <div class="btn-row mt-20">
          <button class="btn" id="ov-redial">${icon('refresh')}重拨 WAN</button>
          <button class="btn btn-danger" id="ov-reboot">${icon('power')}重启路由</button>
        </div>
      </div>
    </div>`;

  $$('[data-jump]').forEach((el) => { el.onclick = () => go(el.dataset.jump); });
  drawTraffic($('#traffic-chart'), hist.rx, hist.tx);
  $('#ov-reboot').onclick = doReboot;
  $('#ov-redial').onclick = async () => {
    try { await api('/api/network/wan/redial', { method: 'POST' }); toast('已下发 WAN 重拨指令'); }
    catch (e) { handleErr(e); }
  };

  if (window.EventSource) {
    const es = new EventSource('/api/events');
    state.sse = es;
    es.addEventListener('telemetry', (ev) => {
      if (state.view !== 'overview') return;
      try {
        const t = JSON.parse(ev.data);
        const r = $('#ov-rates');
        if (r) r.textContent = `↓ ${fmtRate(t.rx_kbps)} · ↑ ${fmtRate(t.tx_kbps)}`;
        hist.rx = [...(hist.rx || []).slice(-179), t.rx_kbps];
        hist.tx = [...(hist.tx || []).slice(-179), t.tx_kbps];
        drawTraffic($('#traffic-chart'), hist.rx, hist.tx);
        const g = $('#ov-gauges');
        if (g) g.innerHTML = ringGauge(t.cpu, '#22d3ee', 'CPU 负载', `${sys.cpu.cores} 核 · ${sys.temperature != null ? Math.round(sys.temperature) + '°C' : '正常'}`)
          + ringGauge(t.mem, '#a78bfa', '内存占用', `${fmtBytes(sys.memory.used)} / ${fmtBytes(sys.memory.total)}`);
      } catch (_) {}
    });
  }
}

async function doReboot() {
  if (!await confirmDialog('重启设备', '所有网络连接将中断约 60 秒，确定立即重启？', '立即重启', true)) return;
  try { await api('/api/system/reboot', { method: 'POST' }); toast('设备正在重启…'); }
  catch (e) { handleErr(e); }
}

async function renderNetwork() {
  const [d, hw, modeRes] = await Promise.all([
    api('/api/network'),
    api('/api/network/hardware').catch(() => ({ ports: [] })),
    api('/api/network/mode').catch(() => ({ mode: 'router' })),
  ]);
  const wan = d.wan, w = d.wan_status || {}, ipv4 = (w.ipv4 && w.ipv4[0]) || null;
  const curMode = (modeRes && modeRes.mode) || 'router';

  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between wrap gap-14">
        <div>
          <h2 style="margin:0;font-size:15px">设备工作模式</h2>
          <p class="muted tiny" style="margin:4px 0 0">支持路由拨号模式与有线中继 (AP) 模式一键切换</p>
        </div>
        <div class="card-actions">
          <button class="btn btn-sm ${curMode === 'router' ? 'btn-primary' : ''}" id="mode-router">路由模式 (NAT)</button>
          <button class="btn btn-sm ${curMode === 'ap' ? 'btn-primary' : ''}" id="mode-ap">有线中继 (AP)</button>
        </div>
      </div>
    </div>

    <div class="card mt-20">
      <div class="card-title">
        <h2>物理网口连接拓扑</h2>
        <div class="card-actions">
          <span class="sub">DSA 硬件交换机 · 纯 IPv4</span>
          <button class="btn btn-sm" id="swap-ports-btn">${icon('refresh')}互换 WAN / LAN 端口</button>
        </div>
      </div>
      ${renderPortRack(hw.ports)}
    </div>

    <div class="grid grid-2 mt-20">
      <div class="card">
        <div class="card-title">
          <h2>WAN 链路状态</h2>
          <div class="card-actions">
            <span class="status-pill ${w.up ? 'good' : 'bad'}">${w.proto ? String(w.proto).toUpperCase() : '未连接'}</span>
            <button class="btn btn-sm" id="wan-redial">${icon('refresh')}重拨</button>
          </div>
        </div>
        <div class="kv">
          <div class="k">IPv4 地址</div><div class="v mono">${ipv4 ? esc(ipv4.address) + '/' + esc(ipv4.mask) : '—'}</div>
          <div class="k">默认网关</div><div class="v mono">${esc(w.gateway || '—')}</div>
          <div class="k">DNS 服务器</div><div class="v mono">${esc((w.dns || []).join(', ') || '自动获取')}</div>
          <div class="k">在线时长</div><div class="v">${w.uptime ? esc(fmtUptime(w.uptime)) : '—'}</div>
          <div class="k">累计流量</div><div class="v mono">↓ ${fmtBytes(w.statistics && w.statistics.rx_bytes)} · ↑ ${fmtBytes(w.statistics && w.statistics.tx_bytes)}</div>
        </div>
        <div class="mt-14">
          <div class="row-between tiny muted" style="margin-bottom:6px"><span>PPPoE / netifd 拨号诊断日志</span><button class="btn btn-sm" id="pppoe-log-refresh">刷新日志</button></div>
          <pre class="log" id="pppoe-log-box" style="max-height:150px">正在获取拨号状态…</pre>
        </div>
      </div>

      <div class="card">
        <div class="card-title"><h2>WAN 接入配置</h2><span class="sub">${esc(wan.section)}</span></div>
        <form id="wan-form">
          <label class="field"><span>接入协议</span>
            <select name="proto">
              <option value="dhcp" ${wan.proto === 'dhcp' ? 'selected' : ''}>DHCP（动态获取 IP）</option>
              <option value="pppoe" ${wan.proto === 'pppoe' ? 'selected' : ''}>PPPoE 宽带拨号</option>
              <option value="static" ${wan.proto === 'static' ? 'selected' : ''}>静态固定 IP</option>
              <option value="none" ${wan.proto === 'none' ? 'selected' : ''}>禁用 WAN</option>
            </select>
          </label>
          <div class="proto-static ${wan.proto === 'static' ? '' : 'hidden'}">
            <div class="field-row">
              <label class="field"><span>IP 地址</span><input name="ipaddr" value="${esc(wan.ipaddr)}" placeholder="192.168.0.2"></label>
              <label class="field"><span>子网掩码</span><input name="netmask" value="${esc(wan.netmask)}" placeholder="255.255.255.0"></label>
            </div>
            <label class="field"><span>默认网关</span><input name="gateway" value="${esc(wan.gateway)}" placeholder="192.168.0.1"></label>
          </div>
          <div class="proto-pppoe ${wan.proto === 'pppoe' ? '' : 'hidden'}">
            <label class="field"><span>宽带账号</span><input name="username" value="${esc(wan.username)}" autocomplete="off"></label>
            <label class="field"><span>宽带密码</span><input name="password" type="password" value="${esc(wan.password)}" autocomplete="off"></label>
          </div>
          <div class="field-row">
            <label class="field"><span>自定义 DNS（留空自动）</span><input name="dns" value="${esc(wan.dns)}" placeholder="223.5.5.5 119.29.29.29"></label>
            <label class="field"><span>MTU 大小</span><input name="mtu" value="${esc(wan.mtu)}" placeholder="1500"></label>
          </div>
          <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存并应用</button></div>
        </form>
      </div>
    </div>

    <div class="card mt-20">
      <div class="card-title"><h2>局域网 (LAN) 与 DHCP 服务</h2><span class="sub">${esc(d.lan.device)}</span></div>
      <form id="lan-form">
        <div class="grid grid-2">
          <div>
            <div class="field-row">
              <label class="field"><span>管理网关 IP</span><input name="ipaddr" value="${esc(d.lan.ipaddr)}"></label>
              <label class="field"><span>子网掩码</span><input name="netmask" value="${esc(d.lan.netmask)}"></label>
            </div>
            <div class="field-row">
              <label class="field"><span>DHCP 起始地址</span><input name="dhcp_start" type="number" min="2" max="254" value="${esc(d.lan.dhcp.start)}"></label>
              <label class="field"><span>分配地址数量</span><input name="dhcp_limit" type="number" min="1" max="253" value="${esc(d.lan.dhcp.limit)}"></label>
            </div>
          </div>
          <div>
            <label class="field"><span>地址租期</span><input name="leasetime" value="${esc(d.lan.dhcp.leasetime)}" placeholder="12h"></label>
            <label class="switch" style="margin-top:6px"><input type="checkbox" name="ignore" ${d.lan.dhcp.ignore ? 'checked' : ''}><span class="track"></span>关闭内置 DHCP 服务器</label>
            <p class="form-hint" style="margin-top:14px">修改网关 IP 后请使用新地址重新访问控制台。</p>
          </div>
        </div>
        <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存 LAN 设置</button></div>
      </form>
    </div>

    <div class="card mt-20">
      <div class="card-title"><h2>网络连通性诊断</h2><span class="sub">Ping / 路由追踪 / DNS 解析</span></div>
      <form id="diag-form" class="row wrap gap-10">
        <select name="tool" style="width:140px">
          <option value="ping">Ping 测试</option>
          <option value="traceroute">路由追踪</option>
          <option value="nslookup">DNS 解析</option>
        </select>
        <input name="host" value="223.5.5.5" placeholder="输入域名或 IPv4 地址" style="flex:1;min-width:200px" required>
        <button class="btn btn-primary" type="submit" id="diag-btn">开始测试</button>
      </form>
      <pre class="log mt-14 hidden" id="diag-out" style="max-height:220px"></pre>
    </div>`;

  const loadPppoeLog = async () => {
    try {
      const res = await api('/api/network/wan/pppoe-log?lines=30');
      const box = $('#pppoe-log-box');
      if (box) { box.textContent = (res && res.log) || '暂无最近拨号事件'; box.scrollTop = box.scrollHeight; }
    } catch (e) {}
  };
  loadPppoeLog();
  $('#pppoe-log-refresh').onclick = loadPppoeLog;
  const switchMode = async (targetMode) => {
    if (targetMode === curMode) return;
    const msg = targetMode === 'ap'
      ? '切换为有线中继 (AP) 模式后，本机将关闭 DHCP 并从上级主路由获取管理 IP。确定切换？'
      : '切换为路由模式后，LAN 管理地址将恢复为 192.168.1.1 并开启 DHCP 服务。确定切换？';
    if (!await confirmDialog('切换工作模式', msg, '确认切换')) return;
    try {
      await api('/api/network/mode', { method: 'PUT', body: { mode: targetMode } });
      toast('工作模式已切换，网络正在重载…');
    } catch (e) { handleErr(e); }
  };
  $('#mode-router').onclick = () => switchMode('router');
  $('#mode-ap').onclick = () => switchMode('ap');
  $('#swap-ports-btn').onclick = async () => {
    if (!await confirmDialog('互换 WAN / LAN 物理网口', '将把当前 WAN 口与 LAN 口（如 2.5G 口与 1G 口）角色对调，请随后对调网线。确定继续？', '确认互换')) return;
    try {
      const res = await api('/api/network/ports/swap', { method: 'POST' });
      toast(`端口已互换，当前 WAN 口为 ${res.wan_device}`);
      setTimeout(() => go('network'), 1500);
    } catch (e) { handleErr(e); }
  };
  $('#diag-form').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const btn = $('#diag-btn'), out = $('#diag-out');
    btn.disabled = true; btn.textContent = '正在探测…';
    out.classList.remove('hidden'); out.textContent = '正在执行网络诊断，请稍候…';
    try {
      const res = await api('/api/network/diag', { method: 'POST', body: { tool: f.get('tool'), host: f.get('host') } });
      out.textContent = res.output || '(无输出)';
    } catch (ex) { out.textContent = ex.message || '测试失败'; handleErr(ex); }
    finally { btn.disabled = false; btn.textContent = '开始测试'; }
  };

  $('#wan-redial').onclick = async () => {
    try { await api('/api/network/wan/redial', { method: 'POST' }); toast('正在断开并重新拨号…'); setTimeout(loadPppoeLog, 1800); }
    catch (e) { handleErr(e); }
  };

  const wanForm = $('#wan-form');
  wanForm.proto.onchange = () => {
    $('.proto-static', wanForm).classList.toggle('hidden', wanForm.proto.value !== 'static');
    $('.proto-pppoe', wanForm).classList.toggle('hidden', wanForm.proto.value !== 'pppoe');
  };
  wanForm.onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(wanForm);
    try {
      await api('/api/network/wan', {
        method: 'PUT',
        body: {
          proto: f.get('proto'), ipaddr: f.get('ipaddr') || '', netmask: f.get('netmask') || '',
          gateway: f.get('gateway') || '', username: f.get('username') || '', password: f.get('password') || '',
          dns: f.get('dns') || '', mtu: f.get('mtu') || '',
        },
      });
      toast('WAN 配置已生效'); setTimeout(() => go('network'), 2200);
    } catch (ex) { handleErr(ex); }
  };

  $('#lan-form').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    if (!await confirmDialog('应用 LAN 配置', '局域网接口将重载，连接会短暂中断，确定继续？', '立即应用')) return;
    try {
      await api('/api/network/lan', {
        method: 'PUT',
        body: {
          ipaddr: f.get('ipaddr'), netmask: f.get('netmask'),
          dhcp_start: Number(f.get('dhcp_start')), dhcp_limit: Number(f.get('dhcp_limit')),
          leasetime: f.get('leasetime'), ignore: f.get('ignore') === 'on',
        },
      });
      toast('LAN 配置已保存');
    } catch (ex) { handleErr(ex); }
  };
}

function encOptions(current) {
  return [['none', '开放网络（无密码）'], ['psk2', 'WPA2-PSK 强加密'], ['sae', 'WPA3-SAE 新一代加密'], ['sae-mixed', 'WPA2 / WPA3 混合兼容']]
    .map(([v, l]) => `<option value="${v}" ${current === v ? 'selected' : ''}>${l}</option>`).join('');
}

async function renderWireless() {
  const d = await api('/api/wireless');
  const radios = d.radios || [];
  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between">
        <div><h2 style="margin:0;font-size:15px">Wi-Fi 射频与无线网络</h2><p class="muted tiny" style="margin:4px 0 0">保存后自动热重载无线驱动</p></div>
        <button class="btn btn-primary" id="wifi-save">${icon('save')}保存无线配置</button>
      </div>
    </div>
    ${radios.map((r) => `
      <div class="card mt-20" data-radio="${esc(r.name)}">
        <div class="card-title">
          <h2>${esc(r.name)} <span class="badge muted">${esc(r.band || r.hwmode || 'RADIO')}</span></h2>
          <label class="switch"><input type="checkbox" class="radio-disabled" ${r.disabled ? 'checked' : ''}><span class="track"></span>关闭此射频</label>
        </div>
        <div class="field-row">
          <label class="field"><span>工作信道（auto 或信道号）</span><input class="radio-channel" value="${esc(r.channel)}"></label>
          <label class="field"><span>频宽模式</span>
            <select class="radio-htmode">
              ${['', 'HT20', 'HT40', 'VHT40', 'VHT80', 'HE20', 'HE40', 'HE80', 'HE160'].map((h) => `<option value="${h}" ${r.htmode === h ? 'selected' : ''}>${h || '自动协商'}</option>`).join('')}
            </select>
          </label>
        </div>
        <label class="field"><span>发射功率 (dBm)</span><input class="radio-txpower" value="${esc(r.txpower)}" placeholder="auto"></label>
        ${(r.ifaces || []).map((i) => `
          <div class="card" style="background:rgba(4,8,18,0.65);margin-top:12px" data-iface="${esc(i.section)}">
            <div class="row-between">
              <div class="row"><span class="dot ${i.disabled ? 'off' : 'on'}"></span><b>${esc(i.ssid || '(未命名)')}</b></div>
              <span class="badge ${i.assoc_count ? 'good' : 'muted'}">${i.assoc_count || 0} 台已连接</span>
            </div>
            <div class="field-row mt-14">
              <label class="field"><span>Wi-Fi 名称 (SSID)</span><input class="iface-ssid" value="${esc(i.ssid)}" maxlength="32"></label>
              <label class="field"><span>安全加密</span><select class="iface-enc">${encOptions(i.encryption)}</select></label>
            </div>
            <label class="field"><span>Wi-Fi 密码（留空保持原密码不变）</span><input class="iface-key" type="text" placeholder="至少 8 位字符"></label>
            <div class="row wrap gap-14">
              <label class="switch"><input type="checkbox" class="iface-hidden" ${i.hidden ? 'checked' : ''}><span class="track"></span>隐藏网络 (不广播 SSID)</label>
              <label class="switch"><input type="checkbox" class="iface-disabled" ${i.disabled ? 'checked' : ''}><span class="track"></span>停用此网络</label>
            </div>
          </div>`).join('')}
      </div>`).join('') || '<div class="card mt-20"><div class="empty">未检测到无线网卡</div></div>'}`;

  $('#wifi-save').onclick = async () => {
    const payload = { radios: [] };
    $$('[data-radio]').forEach((card) => {
      const radio = { name: card.dataset.radio, channel: $('.radio-channel', card).value.trim(), htmode: $('.radio-htmode', card).value, txpower: $('.radio-txpower', card).value.trim(), disabled: $('.radio-disabled', card).checked, ifaces: [] };
      $$('[data-iface]', card).forEach((row) => {
        const enc = $('.iface-enc', row).value, key = $('.iface-key', row).value;
        const iface = { section: row.dataset.iface, ssid: $('.iface-ssid', row).value.trim(), encryption: enc, hidden: $('.iface-hidden', row).checked, disabled: $('.iface-disabled', row).checked };
        if (enc !== 'none' && key) iface.key = key;
        radio.ifaces.push(iface);
      });
      payload.radios.push(radio);
    });
    try { await api('/api/wireless', { method: 'PUT', body: payload }); toast('无线配置已生效'); setTimeout(() => go('wireless'), 1500); }
    catch (ex) { handleErr(ex); }
  };
}

function signalBars(dbm) {
  const level = dbm == null ? 0 : dbm >= -50 ? 4 : dbm >= -62 ? 3 : dbm >= -72 ? 2 : 1;
  return `<span class="signal">${[0, 1, 2, 3].map((i) => `<i class="${i < level ? 'on' : ''}"></i>`).join('')}</span>`;
}

async function renderClients() {
  const d = await api('/api/clients');
  const rows = (d.clients || []).map((c) => {
    const lease = (d.leases || []).find((l) => l.mac === c.mac);
    const name = c.alias || c.hostname || (lease && lease.hostname) || c.mac;
    const rxLim = Number(c.rx_limit_kbps) || 0;
    const txLim = Number(c.tx_limit_kbps) || 0;
    const qosBadge = (rxLim > 0 || txLim > 0)
      ? `<span class="badge warn">↓${rxLim ? fmtRate(rxLim) : '不限'} / ↑${txLim ? fmtRate(txLim) : '不限'}</span>`
      : `<span class="badge muted">不限速</span>`;
    return `<tr>
      <td><div class="primary">${esc(name)}</div><div class="tiny muted mono">${esc(c.mac)}</div></td>
      <td class="mono">${esc(c.ip || (lease && lease.ip) || '—')}</td>
      <td><span class="badge ${c.wireless ? 'muted' : 'good'}">${c.wireless ? '无线 Wi-Fi' : '有线网口'}</span></td>
      <td>${c.wireless ? `${signalBars(c.signal)} <span class="tiny muted">${c.signal != null ? esc(c.signal) + ' dBm' : ''}</span>` : '—'}</td>
      <td>${qosBadge}</td>
      <td class="right nowrap">
        <button class="btn btn-sm" data-qos-mac="${esc(c.mac)}" data-qos-name="${esc(c.alias || '')}" data-qos-rx="${rxLim}" data-qos-tx="${txLim}">限速 / 备注</button>
      </td>
    </tr>`;
  }).join('');

  $('#view').innerHTML = `
    <div class="card">
      <div class="card-title"><h2>在线终端列表与 QoS 限速</h2><span class="sub">${(d.clients || []).length} 台设备在线</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>设备名称 / MAC</th><th>IP 地址</th><th>接入介质</th><th>信号强度</th><th>带宽策略</th><th class="right">管理</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty">暂无在线设备</td></tr>'}</tbody>
      </table></div>
    </div>`;

  $$('[data-qos-mac]').forEach((b) => {
    b.onclick = () => openModal(
      `<h3>终端备注与带宽限速</h3>
       <p class="sub mono">${esc(b.dataset.qosMac)} · 设为 0 表示不限制速率</p>
       <form id="qos-f">
         <label class="field"><span>设备别名备注</span><input name="name" value="${esc(b.dataset.qosName)}" placeholder="例如：客厅电视 / 书房电脑" maxlength="32"></label>
         <div class="field-row">
           <label class="field"><span>下载限速 (Kbps)</span><input name="rx" type="number" min="0" max="10000000" value="${esc(b.dataset.qosRx)}" placeholder="例如 10000 = 10Mbps"></label>
           <label class="field"><span>上传限速 (Kbps)</span><input name="tx" type="number" min="0" max="10000000" value="${esc(b.dataset.qosTx)}" placeholder="例如 2000 = 2Mbps"></label>
         </div>
         <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">保存策略</button></div>
       </form>`,
      {
        onMount(el, close) {
          el.querySelector('[data-cancel]').onclick = close;
          el.querySelector('#qos-f').onsubmit = async (e) => {
            e.preventDefault();
            const f = new FormData(e.target);
            try {
              await api(`/api/access/devices/${encodeURIComponent(b.dataset.qosMac)}/limit`, {
                method: 'POST',
                body: {
                  name: f.get('name'),
                  rx_limit_kbps: Number(f.get('rx')) || 0,
                  tx_limit_kbps: Number(f.get('tx')) || 0,
                },
              });
              close(); toast('终端策略已生效'); go('clients');
            } catch (ex) { handleErr(ex); }
          };
        },
      }
    );
  });
}

async function renderAccess() {
  const [d, a] = await Promise.all([api('/api/access'), api('/api/agents')]);
  const enabled = !!d.enforcement, sim = !!(state.meta && state.meta.sim);

  const renderRows = (list, kind) => (list || []).map((dev) => {
    let btns = '';
    if (kind === 'pending') btns = `<button class="btn btn-sm btn-primary" data-approve="${esc(dev.mac)}">放行</button> <button class="btn btn-sm btn-danger" data-block="${esc(dev.mac)}">拉黑</button>`;
    else if (kind === 'authorized') btns = `<button class="btn btn-sm" data-revoke="${esc(dev.mac)}">撤销</button> <button class="btn btn-sm btn-danger" data-block="${esc(dev.mac)}">拉黑</button>`;
    else btns = `<button class="btn btn-sm" data-unblock="${esc(dev.mac)}">解除拉黑</button>`;
    return `<tr>
      <td><div class="primary">${esc(dev.name || dev.hostname || dev.mac)}</div><div class="tiny muted mono">${esc(dev.mac)}</div></td>
      <td class="mono">${esc(dev.ip || '—')}</td>
      <td>${dev.online ? '<span class="badge good">在线</span>' : '<span class="badge muted">离线</span>'}</td>
      <td class="right nowrap">${btns}</td>
    </tr>`;
  }).join('');

  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between wrap gap-14">
        <div><h2 style="margin:0;font-size:15px">零信任准入拦截 (nftables 数据面)</h2><p class="muted tiny" style="margin:4px 0 0">开启后未知新设备必须经授权才可访问外网</p></div>
        <div class="card-actions">
          <span class="badge ${enabled ? 'good' : 'muted'}">${enabled ? '拦截已开启' : '自由接入模式'}</span>
          <button class="btn ${enabled ? 'btn-danger' : 'btn-primary'}" id="access-toggle">${enabled ? '关闭默认拦截' : '开启默认拦截'}</button>
        </div>
      </div>
    </div>
    <div class="grid grid-2 mt-20">
      <div class="card">
        <div class="card-title"><h2>已授权白名单</h2><span class="sub">${(d.authorized || []).length} 台</span></div>
        <div class="table-wrap"><table><thead><tr><th>设备</th><th>IP</th><th>状态</th><th class="right">操作</th></tr></thead>
        <tbody>${renderRows(d.authorized, 'authorized') || '<tr><td colspan="4" class="empty">暂无白名单设备</td></tr>'}</tbody></table></div>
      </div>
      <div class="card">
        <div class="card-title"><h2>黑名单设备</h2><span class="sub">${(d.blocked || []).length} 台</span></div>
        <div class="table-wrap"><table><thead><tr><th>设备</th><th>IP</th><th>状态</th><th class="right">操作</th></tr></thead>
        <tbody>${renderRows(d.blocked, 'blocked') || '<tr><td colspan="4" class="empty">黑名单为空</td></tr>'}</tbody></table></div>
      </div>
    </div>
    <div class="card mt-20">
      <div class="row-between wrap gap-14">
        <div><h2 style="margin:0;font-size:15px">AI Agent 接口令牌</h2><p class="muted tiny" style="margin:4px 0 0">OpenAPI 规范：<span class="mono">/api/agent/v1/openapi.json</span></p></div>
        <button class="btn btn-primary" id="agent-create" ${sim ? 'disabled' : ''}>${icon('plus')}生成 Token</button>
      </div>
      <div class="table-wrap mt-14"><table>
        <thead><tr><th>名称</th><th>ID</th><th>权限域</th><th class="right">操作</th></tr></thead>
        <tbody>${(a.tokens || []).map((t) => `<tr>
          <td class="primary">${esc(t.name)}</td><td class="mono tiny">${esc(t.id)}</td><td class="tiny">${(t.scopes || []).map(esc).join(', ')}</td>
          <td class="right"><button class="btn btn-sm btn-danger" data-agent-del="${esc(t.id)}" ${sim ? 'disabled' : ''}>吊销</button></td>
        </tr>`).join('') || '<tr><td colspan="4" class="empty">暂无已签发的 Token</td></tr>'}</tbody>
      </table></div>
    </div>`;

  $('#access-toggle').onclick = async () => {
    try { await api('/api/access/enforcement', { method: 'POST', body: { enabled: !enabled, authorize_current: true } }); toast(!enabled ? '已启用默认拦截' : '已关闭默认拦截'); go('access'); }
    catch (e) { handleErr(e); }
  };
  $$('[data-approve]').forEach((b) => { b.onclick = async () => { try { await api(`/api/access/devices/${encodeURIComponent(b.dataset.approve)}/authorize`, { method: 'POST', body: { expires_in: 0 } }); toast('已放行'); go('access'); } catch (e) { handleErr(e); } }; });
  $$('[data-revoke]').forEach((b) => { b.onclick = async () => { try { await api(`/api/access/devices/${encodeURIComponent(b.dataset.revoke)}/revoke`, { method: 'POST', body: {} }); toast('已撤销'); go('access'); } catch (e) { handleErr(e); } }; });
  $$('[data-block]').forEach((b) => { b.onclick = async () => { try { await api(`/api/access/devices/${encodeURIComponent(b.dataset.block)}/block`, { method: 'POST', body: {} }); toast('已拉黑'); go('access'); } catch (e) { handleErr(e); } }; });
  $$('[data-unblock]').forEach((b) => { b.onclick = async () => { try { await api(`/api/access/devices/${encodeURIComponent(b.dataset.unblock)}/unblock`, { method: 'POST', body: {} }); toast('已解除拉黑'); go('access'); } catch (e) { handleErr(e); } }; });
  $$('[data-agent-del]').forEach((b) => { b.onclick = async () => { try { await api(`/api/agents/${encodeURIComponent(b.dataset.agentDel)}`, { method: 'DELETE' }); toast('Token 已吊销'); go('access'); } catch (e) { handleErr(e); } }; });
  $('#agent-create').onclick = () => openModal(
    `<h3>签发 AI Agent Token</h3><p class="sub">密钥仅在创建时展示一次</p>
     <form id="ag-f"><label class="field"><span>名称</span><input name="name" placeholder="例如：Home Assistant" required></label>
     <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">创建</button></div></form>`,
    {
      onMount(el, close) {
        el.querySelector('[data-cancel]').onclick = close;
        el.querySelector('#ag-f').onsubmit = async (e) => {
          e.preventDefault();
          try {
            const res = await api('/api/agents', { method: 'POST', body: { name: new FormData(e.target).get('name'), scopes: ['devices:read', 'devices:write'] } });
            el.querySelector('.modal').innerHTML = `<h3>Token 创建成功</h3><pre class="log">${esc(res.token)}</pre><div class="btn-row"><button class="btn btn-primary" data-ok>完成</button></div>`;
            el.querySelector('[data-ok]').onclick = () => { close(); go('access'); };
          } catch (ex) { handleErr(ex); }
        };
      },
    }
  );
}

async function renderFirewall() {
  const d = await api('/api/firewall');
  const rows = (d.redirects || []).map((r) => `<tr>
    <td><div class="primary">${esc(r.name)}</div></td>
    <td class="mono">${esc(r.proto)}</td>
    <td class="mono">WAN:${esc(r.src_dport)} → ${esc(r.dest_ip)}:${esc(r.dest_port)}</td>
    <td><span class="badge ${r.enabled ? 'good' : 'muted'}">${r.enabled ? '生效中' : '已停用'}</span></td>
    <td class="right"><button class="btn btn-sm btn-danger" data-del="${esc(r.section)}">${icon('trash')}</button></td>
  </tr>`).join('');

  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between">
        <div><h2 style="margin:0;font-size:15px">端口转发规则 (DNAT)</h2><p class="muted tiny" style="margin:4px 0 0">基于 fw4 / nftables 转发引擎</p></div>
        <button class="btn btn-primary" id="fw-add">${icon('plus')}新建映射</button>
      </div>
      <div class="table-wrap mt-14"><table>
        <thead><tr><th>名称</th><th>协议</th><th>映射路径</th><th>状态</th><th class="right">删除</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="empty">暂无端口转发规则</td></tr>'}</tbody>
      </table></div>
    </div>`;

  $$('[data-del]').forEach((b) => { b.onclick = async () => { try { await api(`/api/firewall/redirects/${encodeURIComponent(b.dataset.del)}`, { method: 'DELETE' }); toast('规则已删除'); go('firewall'); } catch (e) { handleErr(e); } }; });
  $('#fw-add').onclick = () => openModal(
    `<h3>新增端口转发</h3>
     <form id="fw-f">
       <label class="field"><span>规则名称</span><input name="name" placeholder="NAS" required></label>
       <div class="field-row">
         <label class="field"><span>协议</span><select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp udp">TCP + UDP</option></select></label>
         <label class="field"><span>外部端口</span><input name="src_dport" type="number" min="1" max="65535" required></label>
       </div>
       <div class="field-row">
         <label class="field"><span>内网目标 IP</span><input name="dest_ip" placeholder="192.168.1.100" required></label>
         <label class="field"><span>内网目标端口</span><input name="dest_port" type="number" min="1" max="65535" required></label>
       </div>
       <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">创建</button></div>
     </form>`,
    {
      onMount(el, close) {
        el.querySelector('[data-cancel]').onclick = close;
        el.querySelector('#fw-f').onsubmit = async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          try {
            await api('/api/firewall/redirects', { method: 'POST', body: { name: f.get('name'), proto: f.get('proto'), src_dport: f.get('src_dport'), dest_ip: f.get('dest_ip'), dest_port: f.get('dest_port') } });
            close(); toast('端口转发已创建'); go('firewall');
          } catch (ex) { handleErr(ex); }
        };
      },
    }
  );
}

async function renderSingbox() {
  const data = await api('/api/singbox');
  const st = data.status || {};
  const cfg = data.config || {};
  const outbounds = cfg.outbounds || [];
  const rules = (cfg.route && cfg.route.rules) || [];
  const finalOb = (cfg.route && cfg.route.final) || 'direct';

  const saveConfig = async (nextCfg, msg) => {
    await api('/api/singbox', { method: 'PUT', body: nextCfg });
    toast(msg || 'Sing-box 配置已保存并热重载');
    go('singbox');
  };

  const obRows = outbounds.map((ob, idx) => {
    const isBuiltin = ob.type === 'direct' || ob.type === 'block';
    const addr = isBuiltin ? '内置出站' : `${ob.server || ''}:${ob.server_port || ''}`;
    let sec = '—';
    if (ob.tls && ob.tls.enabled) {
      sec = (ob.tls.reality && ob.tls.reality.enabled) ? '<span class="badge ok">Reality</span>' : '<span class="badge">TLS</span>';
    } else if (ob.type === 'shadowsocks') {
      sec = `<span class="badge">${esc(ob.method || '')}</span>`;
    }
    return `<tr>
      <td><b>${esc(ob.tag)}</b></td>
      <td><span class="badge">${esc(ob.type)}</span></td>
      <td class="mono">${esc(addr)}</td>
      <td>${sec}</td>
      <td class="mono" id="sb-lat-${esc(ob.tag)}">—</td>
      <td class="right">
        ${isBuiltin ? '' : `<button class="btn btn-sm" data-sb-test="${esc(ob.tag)}">测速</button>
        <button class="btn btn-sm btn-danger" data-sb-del-ob="${idx}">${icon('trash')}</button>`}
      </td>
    </tr>`;
  }).join('');

  const ruleSummary = (r) => {
    const parts = [];
    if (r.network && r.network.length) parts.push(`net:${r.network.join(',')}`);
    if (r.src_mac && r.src_mac.length) parts.push(`mac:${r.src_mac.join(',')}`);
    if (r.src_ip_cidr && r.src_ip_cidr.length) parts.push(`src:${r.src_ip_cidr.join(',')}`);
    if (r.ip_cidr && r.ip_cidr.length) parts.push(`ip:${r.ip_cidr.join(',')}`);
    if (r.domain_exact && r.domain_exact.length) parts.push(`exact:${r.domain_exact.join(',')}`);
    if (r.domain_suffix && r.domain_suffix.length) parts.push(`suffix:${r.domain_suffix.join(',')}`);
    if (r.domain_keyword && r.domain_keyword.length) parts.push(`kw:${r.domain_keyword.join(',')}`);
    if (r.port && r.port.length) parts.push(`port:${r.port.join(',')}`);
    return parts.join(' | ') || '（空规则）';
  };

  const ruleRows = rules.map((r, idx) => `<tr>
    <td><b>${esc(r.name || `规则 #${idx + 1}`)}</b></td>
    <td class="mono tiny">${esc(ruleSummary(r))}</td>
    <td><span class="badge">${esc(r.outbound)}</span></td>
    <td class="right"><button class="btn btn-sm btn-danger" data-sb-del-rule="${idx}">${icon('trash')}</button></td>
  </tr>`).join('');

  const obOptions = outbounds.map((ob) => `<option value="${esc(ob.tag)}" ${ob.tag === finalOb ? 'selected' : ''}>${esc(ob.tag)} (${esc(ob.type)})</option>`).join('');

  const devRows = (data.devices || []).map((d) => {
    const opts = [`<option value="default" ${!d.policy ? 'selected' : ''}>默认 (跟随全局)</option>`]
      .concat(outbounds.map((ob) => `<option value="${esc(ob.tag)}" ${d.policy === ob.tag ? 'selected' : ''}>${esc(ob.tag)}</option>`))
      .join('');
    return `<tr>
      <td><b>${esc(d.name || '未知设备')}</b> <span class="badge ${d.online ? 'ok' : ''}">${d.online ? '在线' : '离线'}</span></td>
      <td class="mono">${esc(d.ip || '—')}</td>
      <td class="mono">${esc(d.mac)}</td>
      <td class="right"><select class="btn btn-sm" data-sb-dev-mac="${esc(d.mac)}">${opts}</select></td>
    </tr>`;
  }).join('');

  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between">
        <div>
          <div class="row gap-10">
            <h2 style="margin:0;font-size:15px">核心运行状态</h2>
            <span class="badge ${st.running ? 'ok' : ''}" id="sb-badge">${st.running ? '运行中' : '已停止'}</span>
          </div>
          <p class="muted tiny" style="margin:4px 0 0">内置 Rust 代理引擎 · OpenSSL 3.5 硬件加速 · TProxy + Mixed 入站</p>
        </div>
        <div class="row gap-8">
          <button class="btn ${cfg.enabled ? 'btn-danger' : 'btn-primary'}" id="sb-toggle">${icon('power')}${cfg.enabled ? '停用核心' : '启用核心'}</button>
          <button class="btn" id="sb-restart">${icon('refresh')}重启</button>
        </div>
      </div>
      ${st.last_error ? `<div class="form-error mt-14">${esc(st.last_error)}</div>` : ''}
      <div class="grid grid-4 mt-14">
        <div class="stat"><div class="stat-label">活跃 / 累计连接</div><div class="stat-val" id="sb-conns">${esc(st.active_connections ?? 0)} / ${esc(st.total_connections ?? 0)}</div></div>
        <div class="stat"><div class="stat-label">实时速率 (上/下)</div><div class="stat-val tiny" id="sb-rate">0 Kbps / 0 Kbps</div></div>
        <div class="stat"><div class="stat-label">累计流量 (上/下)</div><div class="stat-val tiny" id="sb-traffic">${fmtBytes(st.tx_bytes)} / ${fmtBytes(st.rx_bytes)}</div></div>
        <div class="stat"><div class="stat-label">运行时长</div><div class="stat-val tiny" id="sb-uptime">${st.running ? fmtUptime(st.uptime_secs) : '—'}</div></div>
      </div>
    </div>

    <div class="card mt-14">
      <div class="row-between">
        <div><h2 style="margin:0;font-size:15px">出站节点</h2><p class="muted tiny" style="margin:4px 0 0">支持 Shadowsocks (2022) / Trojan / VLESS (TLS / Reality)</p></div>
        <div class="row gap-8">
          <button class="btn" id="sb-test-all">批量测速</button>
          <button class="btn btn-primary" id="sb-add-ob">${icon('plus')}添加节点</button>
        </div>
      </div>
      <div class="table-wrap mt-14"><table>
        <thead><tr><th>标签</th><th>协议</th><th>服务器</th><th>加密 / 传输</th><th>延迟</th><th class="right">操作</th></tr></thead>
        <tbody>${obRows || '<tr><td colspan="6" class="empty">暂无出站节点</td></tr>'}</tbody>
      </table></div>
    </div>

    <div class="grid grid-2 mt-14">
      <div class="card">
        <div class="row-between">
          <div><h2 style="margin:0;font-size:15px">分流规则</h2></div>
          <div class="row gap-8">
            <button class="btn btn-sm" id="sb-reset-rules">恢复内置规则</button>
            <button class="btn btn-sm btn-primary" id="sb-add-rule">${icon('plus')}添加规则</button>
          </div>
        </div>
        <div class="table-wrap mt-14"><table>
          <thead><tr><th>规则名称</th><th>匹配条件</th><th>目标出站</th><th class="right">删除</th></tr></thead>
          <tbody>${ruleRows || '<tr><td colspan="4" class="empty">暂无自定义规则</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="card">
        <div class="card-title"><h2>全局路由与内核参数</h2></div>
        <form id="sb-global-form">
          <label class="field"><span>默认兜底出站 (final)</span><select name="final">${obOptions}</select></label>
          <div class="field-row">
            <label class="field"><span>日志级别</span><select name="log_level">
              ${['trace', 'debug', 'info', 'warn', 'error'].map((l) => `<option value="${l}" ${cfg.log_level === l ? 'selected' : ''}>${l}</option>`).join('')}
            </select></label>
            <label class="field"><span>SO_MARK (fwmark)</span><input name="fwmark" type="number" min="1" value="${esc(cfg.fwmark ?? 256)}" required></label>
            <label class="field"><span>策略路由表 ID</span><input name="route_table" type="number" min="1" value="${esc(cfg.route_table ?? 100)}" required></label>
          </div>
          <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存全局设置</button></div>
        </form>
      </div>
    </div>

    <div class="grid grid-2 mt-14">
      <div class="card">
        <div class="row-between">
          <div><h2 style="margin:0;font-size:15px">终端 MAC 分流策略</h2><p class="muted tiny" style="margin:4px 0 0">联动 routerd 终端表，为指定设备单独指定直连 / 代理 / 拦截出站</p></div>
        </div>
        <div class="table-wrap mt-14"><table>
          <thead><tr><th>终端名称</th><th>IP</th><th>MAC 地址</th><th class="right">出站策略</th></tr></thead>
          <tbody>${devRows || '<tr><td colspan="4" class="empty">暂无已发现终端</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="card">
        <div class="card-title"><h2>内置 DNS 分流与 FakeIP</h2></div>
        <form id="sb-dns-form">
          <div class="field-row">
            <label class="field"><span>启用内置 DNS</span><select name="dns_enabled">
              <option value="0" ${!(cfg.dns && cfg.dns.enabled) ? 'selected' : ''}>停用</option>
              <option value="1" ${(cfg.dns && cfg.dns.enabled) ? 'selected' : ''}>启用</option>
            </select></label>
            <label class="field"><span>监听地址</span><input name="dns_listen" value="${esc((cfg.dns && cfg.dns.listen) || '127.0.0.1:7853')}" required></label>
          </div>
          <div class="field-row">
            <label class="field"><span>直连 DNS 上游</span><input name="direct_upstream" value="${esc((cfg.dns && cfg.dns.direct_upstream) || '223.5.5.5:53')}" required></label>
            <label class="field"><span>代理 DNS 上游</span><input name="proxy_upstream" value="${esc((cfg.dns && cfg.dns.proxy_upstream) || '8.8.8.8:53')}" required></label>
          </div>
          <div class="field-row">
            <label class="field"><span>FakeIP 模式</span><select name="fakeip_enabled">
              <option value="0" ${!(cfg.dns && cfg.dns.fakeip && cfg.dns.fakeip.enabled) ? 'selected' : ''}>关闭 (代理隧道解析)</option>
              <option value="1" ${(cfg.dns && cfg.dns.fakeip && cfg.dns.fakeip.enabled) ? 'selected' : ''}>开启 (198.18.0.0/15)</option>
            </select></label>
            <label class="field"><span>联动 dnsmasq-full</span><select name="link_dnsmasq">
              <option value="0" ${!(cfg.dns && cfg.dns.link_dnsmasq) ? 'selected' : ''}>否</option>
              <option value="1" ${(cfg.dns && cfg.dns.link_dnsmasq) ? 'selected' : ''}>是 (自动接管上游)</option>
            </select></label>
          </div>
          <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}保存 DNS 设置</button></div>
        </form>
      </div>
    </div>`;

  $('#sb-toggle').onclick = async () => {
    try {
      await api('/api/singbox/toggle', { method: 'POST', body: { enabled: !cfg.enabled } });
      toast(cfg.enabled ? 'Sing-box 已停用' : 'Sing-box 已启用');
      go('singbox');
    } catch (e) { handleErr(e); }
  };

  $('#sb-restart').onclick = async () => {
    try {
      await api('/api/singbox/restart', { method: 'POST' });
      toast('Sing-box 已重启');
      go('singbox');
    } catch (e) { handleErr(e); }
  };

  if (typeof EventSource !== 'undefined') {
    const es = new EventSource('/api/events', { withCredentials: true });
    state.sse = es;
    es.addEventListener('telemetry', (ev) => {
      if (state.view !== 'singbox') return;
      try {
        const p = JSON.parse(ev.data);
        const sb = p.singbox;
        if (!sb) return;
        const badge = $('#sb-badge');
        if (badge) {
          badge.textContent = sb.running ? '运行中' : '已停止';
          badge.classList.toggle('ok', !!sb.running);
        }
        const conns = $('#sb-conns');
        if (conns) conns.textContent = `${sb.active_connections} / ${sb.total_connections}`;
        const rate = $('#sb-rate');
        if (rate) rate.textContent = `${fmtRate(sb.tx_kbps)} / ${fmtRate(sb.rx_kbps)}`;
        const traf = $('#sb-traffic');
        if (traf) traf.textContent = `${fmtBytes(sb.tx_bytes)} / ${fmtBytes(sb.rx_bytes)}`;
        const up = $('#sb-uptime');
        if (up) up.textContent = sb.running ? fmtUptime(sb.uptime_secs) : '—';
      } catch (_) {}
    });
  }

  $$('[data-sb-test]').forEach((b) => {
    b.onclick = async () => {
      const tag = b.dataset.sbTest;
      const cell = $(`#sb-lat-${CSS.escape(tag)}`);
      if (cell) cell.textContent = '测速中…';
      try {
        const res = await api('/api/singbox/test', { method: 'POST', body: { outbound: tag } });
        if (cell) cell.innerHTML = `<span class="badge ok">${esc(res.latency_ms)} ms</span>`;
      } catch (e) {
        if (cell) cell.innerHTML = `<span class="badge bad">失败</span>`;
        handleErr(e);
      }
    };
  });

  $('#sb-test-all').onclick = async () => {
    try {
      const res = await api('/api/singbox/test-all', { method: 'POST', body: {} });
      (res.results || []).forEach((r) => {
        const cell = $(`#sb-lat-${CSS.escape(r.outbound)}`);
        if (!cell) return;
        cell.innerHTML = r.latency_ms != null
          ? `<span class="badge ok">${esc(r.latency_ms)} ms</span>`
          : `<span class="badge bad" title="${esc(r.error || '')}">超时/失败</span>`;
      });
      toast('批量测速完成');
    } catch (e) { handleErr(e); }
  };

  $$('[data-sb-del-ob]').forEach((b) => {
    b.onclick = async () => {
      const idx = Number(b.dataset.sbDelOb);
      const next = structuredClone(cfg);
      next.outbounds.splice(idx, 1);
      try { await saveConfig(next, '节点已删除'); } catch (e) { handleErr(e); }
    };
  });

  $$('[data-sb-del-rule]').forEach((b) => {
    b.onclick = async () => {
      const idx = Number(b.dataset.sbDelRule);
      const next = structuredClone(cfg);
      next.route.rules.splice(idx, 1);
      try { await saveConfig(next, '规则已删除'); } catch (e) { handleErr(e); }
    };
  });

  $('#sb-reset-rules').onclick = async () => {
    const next = structuredClone(cfg);
    next.route.rules = [
      { name: '私网与保留网段直连', ip_cidr: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4', 'fe80::/10', 'fc00::/7', '::1/128'], outbound: 'direct' },
      { name: '本地域名直连', domain_suffix: ['local', 'lan', 'arpa', 'home.arpa', 'localhost'], outbound: 'direct' },
      { name: 'NTP 校时直连', network: ['udp'], port: [123], outbound: 'direct' },
      { name: '国内常用域名直连', domain_suffix: ['cn', 'baidu.com', 'bdstatic.com', 'qq.com', 'wechat.com', 'taobao.com', 'tmall.com', 'alicdn.com', 'aliyun.com', 'alipay.com', 'jd.com', '360buyimg.com', 'bilibili.com', 'hdslb.com', '163.com', '126.com', 'netease.com', 'zhihu.com', 'douyin.com', 'bytedance.com', 'toutiao.com', 'weibo.com', 'xiaomi.com', 'mi.com', 'huawei.com', 'meituan.com', 'ctrip.com', 'apple.com', 'icloud.com', 'msn.cn', 'bing.com'], outbound: 'direct' },
      { name: '常见广告与遥测拦截', domain_suffix: ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'app-measurement.com'], outbound: 'block' },
    ];
    try { await saveConfig(next, '已恢复内置默认分流规则'); } catch (e) { handleErr(e); }
  };

  $$('[data-sb-dev-mac]').forEach((sel) => {
    sel.onchange = async () => {
      try {
        await api('/api/singbox/device-policy', {
          method: 'POST',
          body: { mac: sel.dataset.sbDevMac, outbound: sel.value },
        });
        toast('终端分流策略已更新');
        go('singbox');
      } catch (e) { handleErr(e); }
    };
  });

  $('#sb-global-form').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const next = structuredClone(cfg);
    next.route.final = f.get('final');
    next.log_level = f.get('log_level');
    next.fwmark = Number(f.get('fwmark'));
    next.route_table = Number(f.get('route_table'));
    try { await saveConfig(next, '全局路由设置已保存'); } catch (ex) { handleErr(ex); }
  };

  $('#sb-dns-form').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const next = structuredClone(cfg);
    next.dns = next.dns || {};
    next.dns.enabled = f.get('dns_enabled') === '1';
    next.dns.listen = f.get('dns_listen').trim();
    next.dns.direct_upstream = f.get('direct_upstream').trim();
    next.dns.proxy_upstream = f.get('proxy_upstream').trim();
    next.dns.link_dnsmasq = f.get('link_dnsmasq') === '1';
    next.dns.fakeip = next.dns.fakeip || { inet4_range: '198.18.0.0/15', ttl: 60 };
    next.dns.fakeip.enabled = f.get('fakeip_enabled') === '1';
    try { await saveConfig(next, 'DNS 与 FakeIP 设置已保存'); } catch (ex) { handleErr(ex); }
  };

  $('#sb-add-ob').onclick = () => openModal(
    `<h3>添加出站节点</h3>
     <form id="sb-ob-f">
       <div class="field-row">
         <label class="field"><span>节点标签</span><input name="tag" placeholder="hk-1" required></label>
         <label class="field"><span>协议类型</span><select name="type" id="sb-ob-type">
           <option value="vless">VLESS</option>
           <option value="vmess">VMess</option>
           <option value="trojan">Trojan</option>
           <option value="shadowsocks">Shadowsocks</option>
           <option value="socks">SOCKS5</option>
           <option value="http">HTTP</option>
         </select></label>
       </div>
       <div class="field-row">
         <label class="field"><span>服务器地址</span><input name="server" placeholder="example.com" required></label>
         <label class="field"><span>端口</span><input name="server_port" type="number" min="1" max="65535" value="443" required></label>
       </div>
       <div id="sb-ss-fields" class="hidden">
         <div class="field-row">
           <label class="field"><span>加密方式</span><select name="method">
             <option value="aes-128-gcm">aes-128-gcm</option>
             <option value="aes-256-gcm">aes-256-gcm</option>
             <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
             <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
             <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
             <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
           </select></label>
           <label class="field"><span>密码</span><input name="ss_password"></label>
         </div>
       </div>
       <div id="sb-cred-field">
         <div class="field-row">
           <label class="field"><span id="sb-cred-label">UUID</span><input name="cred" placeholder="UUID 或密码"></label>
           <label class="field" id="sb-flow-field"><span>流控 (VLESS Flow)</span><select name="flow">
             <option value="">无</option>
             <option value="xtls-rprx-vision">xtls-rprx-vision</option>
           </select></label>
         </div>
       </div>
       <div id="sb-tls-fields">
         <div class="field-row">
           <label class="field"><span>启用 TLS</span><select name="tls_enabled"><option value="1">是</option><option value="0">否</option></select></label>
           <label class="field"><span>跳过证书校验 (insecure)</span><select name="insecure"><option value="0">否 (推荐)</option><option value="1">是</option></select></label>
         </div>
         <label class="field"><span>SNI (server_name)</span><input name="sni" placeholder="example.com"></label>
         <div class="field-row" id="sb-ws-fields">
           <label class="field"><span>传输层</span><select name="transport_type"><option value="tcp">TCP</option><option value="ws">WebSocket (ws)</option></select></label>
           <label class="field"><span>WS Path</span><input name="ws_path" placeholder="/ws"></label>
           <label class="field"><span>WS Host</span><input name="ws_host" placeholder="可选"></label>
         </div>
         <div class="field-row" id="sb-reality-fields">
           <label class="field"><span>Reality Public Key (可选)</span><input name="reality_pk" placeholder="留空则使用普通 TLS"></label>
           <label class="field"><span>Reality Short ID</span><input name="reality_sid" placeholder="可选"></label>
         </div>
       </div>
       <div id="sb-userpass-fields" class="hidden">
         <div class="field-row">
           <label class="field"><span>用户名 (可选)</span><input name="proxy_user"></label>
           <label class="field"><span>密码 (可选)</span><input name="proxy_pass"></label>
         </div>
       </div>
       <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">添加</button></div>
     </form>`,
    {
      onMount(el, close) {
        const typeSel = el.querySelector('#sb-ob-type');
        const syncFields = () => {
          const t = typeSel.value;
          const isAuthProxy = t === 'socks' || t === 'http';
          el.querySelector('#sb-ss-fields').classList.toggle('hidden', t !== 'shadowsocks');
          el.querySelector('#sb-cred-field').classList.toggle('hidden', t === 'shadowsocks' || isAuthProxy);
          el.querySelector('#sb-flow-field').classList.toggle('hidden', t !== 'vless');
          el.querySelector('#sb-tls-fields').classList.toggle('hidden', t === 'shadowsocks' || t === 'socks');
          el.querySelector('#sb-ws-fields').classList.toggle('hidden', isAuthProxy || t === 'shadowsocks');
          el.querySelector('#sb-reality-fields').classList.toggle('hidden', t !== 'vless');
          el.querySelector('#sb-userpass-fields').classList.toggle('hidden', !isAuthProxy);
          el.querySelector('#sb-cred-label').textContent = (t === 'vless' || t === 'vmess') ? 'UUID' : 'Trojan 密码';
        };
        typeSel.onchange = syncFields;
        syncFields();
        el.querySelector('[data-cancel]').onclick = close;
        el.querySelector('#sb-ob-f').onsubmit = async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          const t = f.get('type');
          let ob;
          if (t === 'shadowsocks') {
            ob = {
              type: 'shadowsocks',
              tag: f.get('tag').trim(),
              server: f.get('server').trim(),
              server_port: Number(f.get('server_port')),
              method: f.get('method'),
              password: f.get('ss_password'),
            };
          } else if (t === 'socks' || t === 'http') {
            ob = {
              type: t,
              tag: f.get('tag').trim(),
              server: f.get('server').trim(),
              server_port: Number(f.get('server_port')),
              username: f.get('proxy_user').trim() || null,
              password: f.get('proxy_pass') || null,
            };
            if (t === 'http') {
              ob.tls = {
                enabled: f.get('tls_enabled') === '1',
                server_name: f.get('sni').trim() || null,
                insecure: f.get('insecure') === '1',
                alpn: [],
                reality: null,
              };
            }
          } else {
            const pk = f.get('reality_pk').trim();
            const tls = {
              enabled: f.get('tls_enabled') === '1',
              server_name: f.get('sni').trim() || null,
              insecure: f.get('insecure') === '1',
              alpn: [],
              reality: pk ? { enabled: true, public_key: pk, short_id: f.get('reality_sid').trim() } : null,
            };
            const transport = {
              type: f.get('transport_type') || 'tcp',
              path: f.get('ws_path').trim() || null,
              host: f.get('ws_host').trim() || null,
            };
            if (t === 'vless') {
              ob = { type: 'vless', tag: f.get('tag').trim(), server: f.get('server').trim(), server_port: Number(f.get('server_port')), uuid: f.get('cred').trim(), flow: f.get('flow') || '', tls, transport };
            } else if (t === 'vmess') {
              ob = { type: 'vmess', tag: f.get('tag').trim(), server: f.get('server').trim(), server_port: Number(f.get('server_port')), uuid: f.get('cred').trim(), security: 'auto', tls, transport };
            } else {
              ob = { type: 'trojan', tag: f.get('tag').trim(), server: f.get('server').trim(), server_port: Number(f.get('server_port')), password: f.get('cred'), tls, transport };
            }
          }
          const next = structuredClone(cfg);
          next.outbounds.push(ob);
          try { await saveConfig(next, '出站节点已添加'); close(); } catch (ex) { handleErr(ex); }
        };
      },
    }
  );

  $('#sb-add-rule').onclick = () => openModal(
    `<h3>添加分流规则</h3>
     <form id="sb-rule-f">
       <div class="field-row">
         <label class="field"><span>规则名称</span><input name="name" placeholder="例如：国内直连 / AI 代理" required></label>
         <label class="field"><span>目标出站</span><select name="outbound">${outbounds.map((ob) => `<option value="${esc(ob.tag)}">${esc(ob.tag)}</option>`).join('')}</select></label>
       </div>
       <label class="field"><span>域名后缀 (逗号分隔)</span><input name="domain_suffix" placeholder="cn, baidu.com"></label>
       <label class="field"><span>目标 IP CIDR (逗号分隔)</span><input name="ip_cidr" placeholder="192.168.0.0/16, 10.0.0.0/8"></label>
       <div class="field-row">
         <label class="field"><span>源 IP CIDR</span><input name="src_ip_cidr" placeholder="192.168.1.100/32"></label>
         <label class="field"><span>目标端口</span><input name="port" placeholder="53, 443"></label>
       </div>
       <label class="field"><span>传输协议 (tcp / udp)</span><input name="network" placeholder="udp"></label>
       <div class="btn-row"><button class="btn" type="button" data-cancel>取消</button><button class="btn btn-primary" type="submit">添加</button></div>
     </form>`,
    {
      onMount(el, close) {
        const splitCsv = (s) => (s || '').split(',').map((v) => v.trim()).filter(Boolean);
        el.querySelector('[data-cancel]').onclick = close;
        el.querySelector('#sb-rule-f').onsubmit = async (e) => {
          e.preventDefault();
          const f = new FormData(e.target);
          const rule = {
            name: f.get('name').trim(),
            ip_cidr: splitCsv(f.get('ip_cidr')),
            src_ip_cidr: splitCsv(f.get('src_ip_cidr')),
            domain_suffix: splitCsv(f.get('domain_suffix')),
            domain_exact: [],
            domain_keyword: [],
            port: splitCsv(f.get('port')).map((p) => Number(p)).filter((p) => p > 0 && p <= 65535),
            network: splitCsv(f.get('network')),
            outbound: f.get('outbound'),
          };
          const next = structuredClone(cfg);
          next.route.rules.push(rule);
          try { await saveConfig(next, '分流规则已添加'); close(); } catch (ex) { handleErr(ex); }
        };
      },
    }
  );
}

async function renderSystem() {
  const sys = await api('/api/system');
  $('#view').innerHTML = `
    <div class="grid grid-2">
      <div class="card">
        <div class="card-title"><h2>设备与安全</h2></div>
        <form id="host-form">
          <label class="field"><span>路由器主机名</span><input name="hostname" value="${esc(sys.hostname)}" required></label>
          <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('save')}更新主机名</button></div>
        </form>
        <form id="pw-form" class="mt-20">
          <label class="field"><span>当前管理员密码</span><input name="current" type="password" required></label>
          <div class="field-row">
            <label class="field"><span>新密码</span><input name="next" type="password" minlength="8" required></label>
            <label class="field"><span>确认新密码</span><input name="confirm" type="password" minlength="8" required></label>
          </div>
          <div class="btn-row"><button class="btn btn-primary" type="submit">${icon('lock')}修改管理密码</button></div>
        </form>
      </div>

      <div class="card">
        <div class="card-title"><h2>Sysupgrade 固件刷写</h2><span class="sub">${esc(sys.board)}</span></div>
        <input type="file" id="fw-file" accept=".bin,.img,.tar,.gz" class="hidden">
        <div class="file-drop" id="fw-drop">
          ${icon('upload')}
          <div>点击选择或拖入 sysupgrade 固件包 (.bin)</div>
          <div class="tiny muted">自动校验元数据与 SHA256 · 最大 64MB</div>
          <div class="file-name hidden" id="fw-name"></div>
        </div>
        <div class="progress hidden mt-14" id="fw-progress"><i></i></div>
        <div class="row-between mt-14 wrap gap-14">
          <label class="switch"><input type="checkbox" id="fw-keep" checked><span class="track"></span>保留现有配置与密码</label>
          <button class="btn btn-danger" id="fw-apply" disabled>${icon('alert')}开始刷写并重启</button>
        </div>
        <div class="tiny muted mt-14" id="fw-note">刷机过程中严禁断电。</div>
      </div>
    </div>

    <div class="card mt-20">
      <div class="card-title"><h2>配置备份与系统重置</h2><span class="sub">UCI / ETC 持久化数据</span></div>
      <div class="row-between wrap gap-14">
        <div class="muted tiny">导出当前网络、无线与黑白名单配置归档，或恢复到出厂默认状态。</div>
        <div class="card-actions">
          <input type="file" id="cfg-restore-file" accept=".gz,.tar.gz" class="hidden">
          <a class="btn" href="/api/system/backup" download="routerd-backup.tar.gz">${icon('save')}导出配置备份</a>
          <button class="btn" id="cfg-restore-btn">${icon('upload')}恢复配置</button>
          <button class="btn btn-danger" id="sys-factory-reset">${icon('power')}恢复出厂设置</button>
        </div>
      </div>
    </div>`;

  $('#host-form').onsubmit = async (e) => {
    e.preventDefault();
    const name = new FormData(e.target).get('hostname');
    try { await api('/api/system/hostname', { method: 'PUT', body: { hostname: name } }); $('#side-host').textContent = name; $('#top-host').textContent = name; toast('主机名已更新'); }
    catch (ex) { handleErr(ex); }
  };
  $('#pw-form').onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    if (f.get('next') !== f.get('confirm')) { toast('两次密码不一致', 'bad'); return; }
    try { await api('/api/system/password', { method: 'POST', body: { current: f.get('current'), new: f.get('next') } }); e.target.reset(); toast('管理密码已更新'); }
    catch (ex) { handleErr(ex); }
  };

  const input = $('#fw-file'), drop = $('#fw-drop');
  drop.onclick = () => input.click();
  input.onchange = async () => {
    const file = input.files && input.files[0];
    if (!file) return;
    $('#fw-name').textContent = `${file.name} (${fmtBytes(file.size)})`;
    $('#fw-name').classList.remove('hidden');
    $('#fw-progress').classList.remove('hidden');
    const fd = new FormData(); fd.append('firmware', file, file.name);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/firmware/upload');
    xhr.setRequestHeader('X-CSRF-Token', state.csrf || '');
    xhr.upload.onprogress = (ev) => { if (ev.lengthComputable) $('#fw-progress > i').style.width = `${Math.round((ev.loaded / ev.total) * 100)}%`; };
    xhr.onload = () => {
      const j = JSON.parse(xhr.responseText || '{}');
      if (xhr.status >= 200 && xhr.status < 300 && j.ok) {
        $('#fw-note').textContent = `校验通过 · SHA256: ${String(j.data.sha256).slice(0, 16)}…`;
        $('#fw-apply').disabled = false;
        toast('固件上传完成');
      } else toast(j.error || '上传失败', 'bad');
    };
    xhr.send(fd);
  };
  $('#fw-apply').onclick = async () => {
    if (!await confirmDialog('确认刷写固件', '设备将写入新固件并自动重启，确定继续？', '立即刷写', true)) return;
    try { await api('/api/firmware/apply', { method: 'POST', body: { keep_config: $('#fw-keep').checked } }); toast('正在刷写固件…'); }
    catch (e) { handleErr(e); }
  };

  const restoreInput = $('#cfg-restore-file');
  $('#cfg-restore-btn').onclick = () => restoreInput.click();
  restoreInput.onchange = async () => {
    const file = restoreInput.files && restoreInput.files[0];
    if (!file) return;
    if (!await confirmDialog('恢复配置备份', `确定使用 ${file.name} 覆盖当前配置并重启路由器？`, '恢复并重启', true)) return;
    const fd = new FormData();
    fd.append('backup', file, file.name);
    try {
      await api('/api/system/restore', { method: 'POST', body: fd });
      toast('配置已恢复，设备正在重启…');
    } catch (e) { handleErr(e); }
  };

  $('#sys-factory-reset').onclick = async () => {
    if (!await confirmDialog('恢复出厂设置', '所有自定义网络、Wi-Fi 和安全规则将被彻底清空，密码将重置为默认 admin。确定继续？', '确认重置', true)) return;
    try {
      await api('/api/system/factory-reset', { method: 'POST' });
      toast('正在擦除配置并恢复出厂设置…');
    } catch (e) { handleErr(e); }
  };
}

async function renderLogs() {
  $('#view').innerHTML = `
    <div class="card">
      <div class="row-between wrap gap-14">
        <div class="row wrap gap-14">
          <label class="field" style="margin:0"><span>关键字过滤</span><input id="log-filter" placeholder="pppd / wifi / dhcp"></label>
          <label class="field" style="margin:0"><span>显示行数</span><select id="log-lines"><option>100</option><option selected>300</option><option>800</option></select></label>
        </div>
        <button class="btn btn-primary" id="log-refresh">${icon('refresh')}刷新日志</button>
      </div>
      <pre class="log mt-14" id="log-box">正在读取内核环形缓冲区…</pre>
    </div>`;

  const load = async () => {
    try {
      const d = await api(`/api/logs?lines=${$('#log-lines').value}&filter=${encodeURIComponent($('#log-filter').value.trim())}`);
      const box = $('#log-box');
      if (box) { box.textContent = d.log || '(暂无日志)'; box.scrollTop = box.scrollHeight; }
    } catch (e) {}
  };
  $('#log-refresh').onclick = load;
  $('#log-filter').oninput = load;
  $('#log-lines').onchange = load;
  await load();
  setTimer(load, 5000);
}

document.addEventListener('DOMContentLoaded', init);
