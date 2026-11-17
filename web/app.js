/* AgentMesh 任务面板 — 原生 JS 单页，无构建步骤。
 *
 * 数据面只消费 out/interface-contracts.md（ICON）定义的 HTTP API 与 SSE 流；
 * UI 验收规格为 out/frontend-ui.md（FRU-01）。API 基址为相对路径（同源）。
 *
 * 与实际路由代码（impl/app/api/server.py）对齐的要点：
 * - 静态托管无 SPA fallback（server.py _handle_static 仅返回真实存在的文件）→ 哈希路由。
 * - EventSource 无法带 Authorization 头（server.py check_auth 只读 Bearer 头）→
 *   SSE 用 fetch + ReadableStream 自实现（含 Last-Event-ID 续播 / 心跳假死检测 / 429 处理）。
 * - A4 实际路由为 /api/v1/tasks/{subtask_id}/subtasks/briefs（server.py 路由表 6 段形态，
 *   与 ICON §5.4 的 7 段形态不同——以实际路由代码为准）。
 * - A2 任务列表无 trigger_id 过滤参数（server.py _list_tasks 只支持 status/source/date）。
 * - F4 规则列表 status 只接受单值（server.py _list_rules）→ 不带 status 全量拉取后分组。
 * - D1 executions 缺省 date 由服务端按容器时区取「今天」（server.py _list_executions）→
 *   前端不传 date，避免浏览器时区与服务端时区不一致导致错日。
 */
(() => {
'use strict';

/* ============================================================
 * 0. 常量（词表与枚举：ICON §2 / ARCH §3.1 / FRU-01 §1.4）
 * ============================================================ */

const API = '/api/v1'; // 相对基址（同源静态托管 + 同源 API）

const STATUS_META = {
  pending:             { label: '排队',   cls: 'st-pending' },
  planning:            { label: '规划中', cls: 'st-planning' },
  paused_for_approval: { label: '待审批', cls: 'st-paused_for_approval' },
  running:             { label: '执行中', cls: 'st-running' },
  reviewing:           { label: '验收中', cls: 'st-reviewing' },
  rework:              { label: '返工中', cls: 'st-rework' },
  done:                { label: '✓完成',  cls: 'st-done' },
  failed:              { label: '失败',   cls: 'st-failed' },
  aborted:             { label: '已中止', cls: 'st-aborted' },
  waiting:             { label: '待裁决', cls: 'st-waiting' },
  decided:             { label: '已裁决', cls: 'st-decided' },
  expired:             { label: '已过期', cls: 'st-expired' },
};
const RISK_META = {
  irreversible:       { label: 'R2 不可逆',       cls: 'rk-irreversible' },
  reversible_costly:  { label: 'R1 高成本可逆',   cls: 'rk-reversible_costly' },
  reversible:         { label: 'R0 可逆',         cls: 'rk-reversible' },
};
const SOURCE_META = { user: '👤 user', cron: '⏰ cron', webhook: '🔗 webhook' };
const ICON_EVENT_TYPES = [
  'task_submitted', 'ledger_lookup', 'plan_produced', 'brief_dispatched',
  'subtask_started', 'subtask_stopped', 'llm_call', 'tool_call',
  'state_transition', 'approval_requested', 'approval_decision',
  'approval_timeout_skip', 'rework_instruction', 'review_verdict',
  'error_registered', 'rule_candidate', 'budget_exceeded', 'task_aborted',
  'trigger_fired', 'trigger_missed', 'credential_inject', 'credential_deny',
  'memory_degraded',
];
// FRU-01 §1.3 常驻第 1 条连接的类型集（+task_submitted：V3 TR-08 长跑区块刷新需要）
const GLOBAL_SSE_TYPES =
  'state_transition,approval_requested,approval_decision,approval_timeout_skip,' +
  'budget_exceeded,task_aborted,trigger_fired,trigger_missed,error_registered,' +
  'rule_candidate,memory_degraded,task_submitted';
// ① 区非 paused 归置（FRU-01 §2.1：paused_for_approval 归 ② 区）
const ZONE1_STATUSES = 'pending,planning,running,reviewing,rework';
const ZONE4_STATUSES = 'failed,aborted';
const TIMEOUT_FALLBACK_META = {
  skip_and_continue: '超时兜底：常规类超时跳过该动作并继续推进',
  skip_strict: '超时兜底：付款类直接跳过（不降级不换路径——钱的事宁可不做）',
};
const LS_TOKEN = 'agentmesh.token';
const LS_READ_FAILURES = 'agentmesh.readFailures';

/* ============================================================
 * 1. 基础工具
 * ============================================================ */

const $ = (sel, root) => (root || document).querySelector(sel);

function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = String(v);
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, String(v));
    }
  }
  for (const c of children.flat(9)) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

function uuid() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtClock(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso || '');
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
function fmtDay(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso || '');
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
function fmtCountdown(iso) {
  if (!iso) return '';
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return '';
  if (ms <= 0) return '已过期（兜底即将执行）';
  const h24 = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  if (h24 >= 24) return `剩 ${Math.floor(h24 / 24)}d${h24 % 24}h${m}m`;
  return `剩 ${h24}h${m}m`;
}
function fmtUsd(v) {
  const n = Number(v);
  return Number.isFinite(n) ? `$${n.toFixed(2)}` : '—';
}
function compact(obj, max) {
  try {
    const s = JSON.stringify(obj);
    return s.length > (max || 140) ? s.slice(0, max || 140) + '…' : s;
  } catch { return String(obj); }
}

function toast(msg, kind) {
  const root = $('#toast-root');
  const node = h('div', { class: 'toast' + (kind ? ' ' + kind : ''), text: msg });
  root.append(node);
  setTimeout(() => node.remove(), 6000);
}

let modalCloseFn = null;
function openModal(node) {
  const root = $('#modal-root');
  root.classList.remove('hidden');
  root.replaceChildren(node);
  root.onclick = (e) => { if (e.target === root) closeModal(); };
  modalCloseFn = closeModal;
  return closeModal;
}
function closeModal() {
  const root = $('#modal-root');
  root.classList.add('hidden');
  root.replaceChildren(); // secret_once 等一次性内容随 DOM 移除出内存（TR-05）
  modalCloseFn = null;
}

function openConfirm({ title, message, fields, confirmText, danger, onConfirm }) {
  const errLine = h('div', { class: 'error-text' });
  const inputs = {};
  const form = h('div', { class: 'modal-card' },
    h('h3', { text: title }),
    message ? h('p', { class: 'muted small', text: message }) : null,
    (fields || []).map((f) => {
      const input = h(f.multiline ? 'textarea' : 'input', f.multiline ? { rows: '3' } : { type: f.type || 'text' });
      if (f.placeholder) input.placeholder = f.placeholder;
      inputs[f.key] = input;
      return h('label', null, f.label, input);
    }),
    errLine,
    h('div', { class: 'row' },
      h('button', { class: 'btn', text: '取消', onclick: () => closeModal() }),
      h('button', {
        class: 'btn ' + (danger ? 'danger' : 'primary'),
        text: confirmText || '确认',
        onclick: async () => {
          const values = {};
          for (const f of fields || []) {
            const v = String(inputs[f.key].value || '').trim();
            if (f.required && !v) { errLine.textContent = `${f.label} 必填`; return; }
            values[f.key] = v;
          }
          errLine.textContent = '';
          try { await onConfirm(values); } catch (e) { errLine.textContent = e.message || String(e); }
        },
      }),
    ),
  );
  openModal(form);
}

function copyText(text, hint) {
  const done = () => toast((hint || '已复制') + '：' + text);
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, () => toast('复制失败（请手动复制）：' + text, 'err'));
  } else {
    toast('浏览器不支持剪贴板 API，请手动复制：' + text);
  }
}

/* ============================================================
 * 2. 鉴权与 API（ICON §1.2 / §1.6 错误包络）
 * ============================================================ */

let TOKEN = localStorage.getItem(LS_TOKEN) || '';

function authHeader() {
  return TOKEN ? { Authorization: 'Bearer ' + TOKEN } : {};
}

async function api(path, opts = {}) {
  const headers = { ...authHeader(), 'X-Request-Id': uuid() };
  let body;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  if (opts.headers) Object.assign(headers, opts.headers);
  let res;
  try {
    res = await fetch(path, { method: opts.method || 'GET', headers, body });
  } catch (e) {
    throw { status: 0, code: 'NETWORK', message: '网络请求失败：' + e.message };
  }
  if (res.status === 503) { showKernelDown(); throw { status: 503, code: 'KERNEL_NOT_READY', message: '内核未就绪' }; }
  if (res.status === 401) {
    setToken('');
    showTokenGate('令牌无效或已失效（401 ' + (await errorText(res)) + '）');
    throw { status: 401, code: 'AUTH', message: '鉴权失效' };
  }
  const text = await res.text();
  let data = null;
  if (text) { try { data = JSON.parse(text); } catch { data = null; } }
  if (!res.ok) {
    const err = (data && data.error) || {};
    throw { status: res.status, code: err.code || ('HTTP_' + res.status),
            message: err.message || text || res.statusText, details: err.details || null };
  }
  return data;
}

async function errorText(res) {
  try {
    const j = await res.clone().json();
    return (j && j.error && j.error.code) || res.statusText;
  } catch { return res.statusText; }
}

function showTokenGate(errMsg) {
  $('#app').classList.add('hidden');
  const gate = $('#token-gate');
  gate.classList.remove('hidden');
  $('#token-error').textContent = errMsg || '';
  $('#token-input').focus();
}

function setToken(t) {
  TOKEN = t || '';
  if (TOKEN) localStorage.setItem(LS_TOKEN, TOKEN);
  else localStorage.removeItem(LS_TOKEN);
}

/* ============================================================
 * 3. SSE 客户端（fetch 实现：可带 Bearer 头 + Last-Event-ID 续播）
 *    契约：ICON §4.2（retry:3000、: ping 心跳 15s、>45s 假死重连、
 *    stream_resync 游标过期、429 STREAM_LIMIT_EXCEEDED、3 次失败转 15s 轮询）
 * ============================================================ */

function parseSseFrame(chunk) {
  let id = null; let event = null; const dataLines = [];
  for (const line of chunk.split('\n')) {
    if (!line || line.startsWith(':')) continue; // 心跳注释帧不推进游标
    if (line.startsWith('id:')) id = line.slice(3).trim();
    else if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
    // retry: 行由浏览器语义承担，这里忽略
  }
  if (!event && dataLines.length === 0) return null;
  let data = null;
  const raw = dataLines.join('\n');
  if (raw) { try { data = JSON.parse(raw); } catch { data = raw; } }
  return { id, event: event || 'message', data };
}

async function sseFetch(params, outerSignal, handlers) {
  const qs = new URLSearchParams();
  for (const k of ['task_id', 'correlation_id', 'types', 'since']) {
    if (params[k]) qs.set(k, params[k]);
  }
  const url = `${API}/events/stream?` + qs.toString();
  let lastEventId = params.lastEventId || null;
  let fails = 0;
  while (!outerSignal.aborted) {
    const ctl = new AbortController();
    const onOuterAbort = () => ctl.abort();
    outerSignal.addEventListener('abort', onOuterAbort, { once: true });
    let watchdog = null;
    try {
      const headers = { Accept: 'text/event-stream', ...authHeader() };
      if (lastEventId) headers['Last-Event-ID'] = lastEventId;
      const res = await fetch(url, { headers, signal: ctl.signal });
      if (res.status === 429) {
        handlers.onFrame && handlers.onFrame({ event: '__stream_limit', data: { code: 'STREAM_LIMIT_EXCEEDED' } });
        throw new Error('sse 429');
      }
      if (!res.ok) throw new Error('sse http ' + res.status);
      fails = 0;
      let lastFrameAt = Date.now();
      handlers.onState && handlers.onState('live');
      watchdog = setInterval(() => {
        if (Date.now() - lastFrameAt > 45000) ctl.abort(); // >45s 无帧视为假死（ICON §4.2）
      }, 5000);
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) throw new Error('stream closed');
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const frame = parseSseFrame(buf.slice(0, idx));
          buf = buf.slice(idx + 2);
          if (frame) {
            lastFrameAt = Date.now();
            if (frame.id) lastEventId = frame.id;
            handlers.onFrame && handlers.onFrame(frame);
          }
        }
      }
    } catch (e) {
      if (outerSignal.aborted) { handlers.onState && handlers.onState('closed'); return; }
      fails += 1;
      if (fails >= 3) { handlers.onState && handlers.onState('polling'); return; }
      handlers.onState && handlers.onState('reconnecting');
      await new Promise((r) => setTimeout(r, Math.min(1000 * fails, 5000)));
    } finally {
      if (watchdog) clearInterval(watchdog);
      outerSignal.removeEventListener('abort', onOuterAbort);
    }
  }
}

// ---- 常驻第 1 条连接（全局低频订阅）+ 轮询兜底 ----
const eventBus = { map: new Map(), on(t, fn) { (this.map.get(t) || this.map.set(t, []).get(t)).push(fn); },
                   emit(t, p) { for (const fn of this.map.get(t) || []) { try { fn(p); } catch {} } } };
let globalStreamCtl = null;
let pollTimer = null;
let streamRetryTimer = null;
let sseMode = 'connecting';

function setSseLight(mode) {
  sseMode = mode;
  const el = $('#sse-light');
  el.classList.remove('st-live', 'st-reconnecting', 'st-polling');
  if (mode === 'live') { el.classList.add('st-live'); el.textContent = '● SSE 已连接'; }
  else if (mode === 'reconnecting') { el.classList.add('st-reconnecting'); el.textContent = '● 重连中'; }
  else if (mode === 'polling') { el.classList.add('st-polling'); el.textContent = '● 降级刷新模式'; }
  else el.textContent = '● 事件流';
}

function openGlobalStream() {
  if (globalStreamCtl) globalStreamCtl.abort();
  globalStreamCtl = new AbortController();
  const ctl = globalStreamCtl;
  sseFetch({ types: GLOBAL_SSE_TYPES }, ctl.signal, {
    onFrame: (frame) => {
      if (frame.event === 'stream_resync') { toast('游标已过期，已从最新头部续播（stream_resync，提示非错误）'); return; }
      if (frame.event === '__stream_limit') { toast('SSE 并发流超上限（429 STREAM_LIMIT_EXCEEDED），请关闭多余标签页', 'err'); return; }
      eventBus.emit(frame.event, frame);
      eventBus.emit('*', frame);
    },
    onState: (mode) => {
      setSseLight(mode);
      if (mode === 'polling') {
        if (!pollTimer) pollTimer = setInterval(() => { currentRefresh && currentRefresh(); }, 15000);
        if (!streamRetryTimer) {
          streamRetryTimer = setTimeout(() => { streamRetryTimer = null; if (!ctl.signal.aborted) openGlobalStream(); }, 30000);
        }
      } else {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      }
    },
  });
}

/* ============================================================
 * 4. 健康面（G-03/G-04/G-06）
 * ============================================================ */

let healthDegradations = [];
let kernelDownShown = false;
let kernelPollTimer = null;

async function pollHealth() {
  try {
    const res = await fetch('/healthz');
    if (res.status === 503) { showKernelDown(); return; }
    const j = await res.json();
    const light = $('#health-light');
    light.classList.remove('st-bad');
    light.classList.add('st-live');
    light.textContent = `● healthz ${j.db_mode || ''}`;
    healthDegradations = j.degradations || [];
    updateDegradeBanner();
    if (kernelDownShown) hideKernelDown();
  } catch {
    const light = $('#health-light');
    light.classList.remove('st-live');
    light.classList.add('st-bad');
    light.textContent = '● healthz 不可达';
  }
}

function showKernelDown() {
  if (kernelDownShown) return;
  kernelDownShown = true;
  $('#kernel-down').classList.remove('hidden');
  if (!kernelPollTimer) {
    const tick = async () => {
      $('#kernel-down-status').textContent = '检测中… ' + new Date().toLocaleTimeString();
      try {
        const res = await fetch('/healthz');
        if (res.ok) { hideKernelDown(); return; }
      } catch { /* 仍不可达 */ }
      kernelPollTimer = setTimeout(tick, 5000);
    };
    kernelPollTimer = setTimeout(tick, 3000);
  }
}
function hideKernelDown() {
  kernelDownShown = false;
  if (kernelPollTimer) { clearTimeout(kernelPollTimer); kernelPollTimer = null; }
  $('#kernel-down').classList.add('hidden');
  currentRefresh && currentRefresh();
}

function updateDegradeBanner() {
  const banner = $('#degrade-banner');
  const parts = [];
  for (const d of healthDegradations) {
    if (d === 'fts_unavailable') parts.push('FTS 全文检索不可用（签名过滤/日期过滤仍可用）');
    else parts.push('降级面：' + d);
  }
  banner.textContent = '⚠ ' + parts.join('；');
  banner.classList.toggle('hidden', parts.length === 0);
}
function noteMemoryDegraded(payload) {
  const banner = $('#degrade-banner');
  banner.classList.remove('hidden');
  banner.textContent = '⚠ 记忆库降级事件：' + compact(payload, 160);
  setTimeout(() => updateDegradeBanner(), 60000); // 60s 后回落到 healthz 口径
}

/* ============================================================
 * 5. 路由（哈希式：静态托管无 SPA fallback）
 * ============================================================ */

let currentRefresh = null; // 当前视图刷新函数（SSE/轮询兜底触发）
let currentRoute = { name: 'v1' };
let refreshDebounce = null;

function scheduleViewRefresh() {
  if (refreshDebounce) return;
  refreshDebounce = setTimeout(() => { refreshDebounce = null; currentRefresh && currentRefresh(); }, 800);
}

function parseHash() {
  const raw = location.hash.replace(/^#/, '');
  let m = raw.match(/^\/approval\/(.+)$/);
  if (m) return { name: 'approval', arg: decodeURIComponent(m[1]) };
  m = raw.match(/^\/task\/(.+)$/);
  if (m) return { name: 'task', arg: decodeURIComponent(m[1]) };
  if (raw.startsWith('/triggers')) return { name: 'triggers' };
  if (raw.startsWith('/errors')) return { name: 'errors' };
  if (raw.startsWith('approval-')) return { name: 'approval', arg: raw.slice('approval-'.length) }; // FRU-01 G-05 深链旧形态
  return { name: 'v1' };
}

function setTab(name) {
  document.querySelectorAll('.tabs a').forEach((a) => {
    a.classList.toggle('active', a.dataset.tab === name);
  });
}

let lastRouteKey = null;
async function route() {
  const key = location.hash || '#/';
  if (key === lastRouteKey) return;
  lastRouteKey = key;
  const r = parseHash();
  currentRoute = r;
  if (r.name === 'v1') await renderV1();
  else if (r.name === 'task') await renderTaskDetail(r.arg);
  else if (r.name === 'triggers') await renderTriggers();
  else if (r.name === 'errors') await renderErrors();
  else if (r.name === 'approval') {
    // 审批深链：底层渲染看板 + 打开全局审批抽屉（G-05）
    if (!$('#view').dataset.view) await renderV1();
    openApprovalDrawer(r.arg);
  }
}

/* ============================================================
 * 6. 全局壳层组件：预算条 G-02 / 运行时带 G-09 / 提交抽屉 G-01
 * ============================================================ */

async function refreshBudgetBar() {
  const el = $('#budget-bar');
  try {
    const costs = await api(`${API}/costs/summary`);
    const limit = costs.budget_global_daily_usd;
    const spent = costs.total_cost_usd_est || 0;
    const pct = limit ? Math.min(100, (spent / limit) * 100) : 0;
    el.classList.remove('st-warn', 'st-bad');
    let stateText = '';
    if (costs.state === 'exceeded_paused') { el.classList.add('st-warn'); stateText = ' · 已超限暂停（相关任务等待调额）'; }
    else if (costs.state === 'exceeded_aborted') { el.classList.add('st-bad'); stateText = ' · 已超限熔断'; }
    el.replaceChildren(
      h('div', null, limit == null
        ? `今日估算 ${fmtUsd(spent)} · 未配置全局日预算（BUDGET_GLOBAL_DAILY）${stateText}`
        : `预算 ${fmtUsd(spent)}/${fmtUsd(limit)}${stateText}`),
      h('div', { class: 'bar' }, h('i', { style: `width:${pct}%` })),
      h('div', { class: 'disclaimer', text: costs.metering_disclaimer || '金额为估算，token 数为准' }),
    );
    el.title = 'E1 全局日成本；' + (costs.metering_disclaimer || '');
  } catch { el.textContent = '预算：加载失败'; }
}

async function refreshRuntimeStrip() {
  try {
    const m = await api(`${API}/runtime/metrics`);
    const strip = $('#runtime-strip');
    strip.replaceChildren(
      h('span', { class: m.running_subagents >= m.max_concurrency ? 'hot' : '', text:
        `并发 ${m.running_subagents}/${m.max_concurrency}` +
        (m.running_subagents >= m.max_concurrency ? '（已达上限，排队将变慢）' : '') }),
      h('span', null, ` · 队列深度 ${m.queue_depth} · 活跃任务 ${m.active_tasks}`),
    );
    $('#data-asof').textContent = `数据截至 ${fmtClock(m.updated_at)}`;
  } catch { /* healthz 侧已有红灯 */ }
}

function bindNewTaskDrawer() {
  const drawer = $('#drawer-new-task');
  const open = () => { $('#nt-error').textContent = ''; drawer.classList.remove('hidden'); $('#nt-goal').focus(); };
  const close = () => drawer.classList.add('hidden');
  $('#btn-new-task').addEventListener('click', open);
  drawer.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
  drawer.addEventListener('click', (e) => { if (e.target === drawer) close(); });
  $('#nt-submit').addEventListener('click', async () => {
    const goal = $('#nt-goal').value.trim();
    const notes = $('#nt-notes').value.trim();
    const err = $('#nt-error');
    err.textContent = '';
    if (!goal) { err.textContent = 'GOAL_EMPTY：goal 不能为空白'; return; }
    if (goal.length > 8000) { err.textContent = 'GOAL_TOO_LONG：goal 超过 8000 字符'; return; }
    const btn = $('#nt-submit');
    btn.disabled = true;
    try {
      const res = await api(`${API}/tasks`, {
        method: 'POST',
        body: { goal, source: 'user', client_ref: `panel-${Date.now()}`, notes: notes || undefined },
        headers: { 'Idempotency-Key': uuid() }, // §1.3 幂等 24h 窗口
      });
      close();
      toast(`任务已提交 ${res.task_id}（${res.status}）${res.links && res.links.self ? '' : ''}`, 'ok');
      location.hash = `#/task/${encodeURIComponent(res.task_id)}`;
    } catch (e) {
      err.textContent = `${e.code || ''} ${e.message || ''}`.trim();
    } finally { btn.disabled = false; }
  });
}

function bindApprovalDrawer() {
  const drawer = $('#drawer-approval');
  drawer.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeApprovalDrawer));
  drawer.addEventListener('click', (e) => { if (e.target === drawer) closeApprovalDrawer(); });
}
function openApprovalDrawer(approvalId) {
  $('#drawer-approval').classList.remove('hidden');
  const body = $('#approval-body');
  body.replaceChildren(h('div', { class: 'loading', text: '加载审批渲染数据…' }));
  renderApprovalForm(body, approvalId, { mode: 'drawer' });
}
function closeApprovalDrawer() { $('#drawer-approval').classList.add('hidden'); }

/* ============================================================
 * 7. 视图一 V1：总览看板（四分区 2×2，FRU-01 §2）
 * ============================================================ */

const readFailures = {
  get() { try { return new Set(JSON.parse(localStorage.getItem(LS_READ_FAILURES) || '[]')); } catch { return new Set(); } },
  add(id) { const s = this.get(); s.add(id); localStorage.setItem(LS_READ_FAILURES, JSON.stringify([...s])); },
};
let showReadFailures = false;

async function renderV1() {
  setTab('v1');
  $('#view').dataset.view = 'v1';
  const view = $('#view');
  view.replaceChildren(h('div', { class: 'loading', text: '看板加载中…' }));
  currentRefresh = () => renderV1();

  const P = {
    running: api(`${API}/tasks?status=${ZONE1_STATUSES}&limit=50`),
    paused: api(`${API}/tasks?status=paused_for_approval&limit=50`),
    failed: api(`${API}/tasks?status=${ZONE4_STATUSES}&limit=50`),
    approvals: api(`${API}/approvals?status=waiting&limit=50`),
    executions: api(`${API}/executions?limit=200`),
    budget: api(`${API}/budget`),
    triggers: api(`${API}/triggers`),
    abortEvents: api(`${API}/events?types=task_aborted&limit=100`),
    transitionEvents: api(`${API}/events?types=state_transition&limit=200`),
  };
  const settled = {};
  for (const [k, p] of Object.entries(P)) settled[k] = await p.catch((e) => ({ __error: e }));

  const runningItems = itemsOf(settled.running);
  const pausedItems = itemsOf(settled.paused);
  const failedItems = itemsOf(settled.failed);
  const approvalItems = itemsOf(settled.approvals);
  const doneItems = itemsOf(settled.executions).filter((x) => x.status_now === 'done');
  const budget = settled.budget && !settled.budget.__error ? settled.budget : { paused_by_budget: [], tasks_at_risk: [] };
  const triggers = itemsOf(settled.triggers);

  // 富化：逐卡 A3（进度条/预算上限）、G3 触发器反向 join（下次触发）、中止来源、最近 state_transition 溯源
  const [details, triggerJoin, abortSource, lastTransition] = await Promise.all([
    enrichDetails(runningItems.slice(0, 24)),
    buildTriggerJoin(triggers),
    mapAbortSource(itemsOf(settled.abortEvents)),
    mapLastTransition(itemsOf(settled.transitionEvents)),
  ]);
  const failedErrors = await enrichFailedErrors(failedItems.slice(0, 12));

  view.replaceChildren(buildV1Grid({
    runningItems, pausedItems, approvalItems, doneItems, failedItems,
    budget, triggers, details, triggerJoin, abortSource, lastTransition, failedErrors,
    errors: Object.fromEntries(Object.entries(settled).filter(([, v]) => v.__error).map(([k, v]) => [k, v.__error])),
  }));
  refreshRuntimeStrip();
}

function itemsOf(v) { return v && !v.__error ? (v.items || []) : []; }

async function enrichDetails(cards) {
  const out = new Map();
  await Promise.all(cards.map(async (c) => {
    try { out.set(c.task_id, await api(`${API}/tasks/${encodeURIComponent(c.task_id)}`)); }
    catch { /* A3 拉不到 → 卡片只有状态徽章 */ }
  }));
  return out;
}

// G2 触发器反向映射（FRU-01 §2.1 契约缺口 #1）：G3 详情的 recent_fires 建 task→trigger join
async function buildTriggerJoin(triggers) {
  const taskToTrigger = new Map();
  await Promise.all(triggers.slice(0, 20).map(async (t) => {
    try {
      const d = await api(`${API}/triggers/${encodeURIComponent(t.trigger_id)}`);
      for (const f of d.recent_fires || []) {
        if (f.task_id && !taskToTrigger.has(f.task_id)) {
          taskToTrigger.set(f.task_id, { trigger: d, firedAt: f.fired_at });
        }
      }
    } catch { /* 单个触发器拉不到不影响其余 */ }
  }));
  return taskToTrigger;
}

async function mapAbortSource(events) {
  const m = new Map();
  for (const e of events) {
    if (e.task_id && e.payload && e.payload.source) m.set(e.task_id, e.payload);
  }
  return m;
}
async function mapLastTransition(events) {
  const m = new Map(); // correlation_id → 最近一条 state_transition 的 event_id（时间倒序列表首条）
  for (const e of events) {
    if (e.correlation_id && !m.has(e.correlation_id)) m.set(e.correlation_id, e);
  }
  return m;
}
async function enrichFailedErrors(cards) {
  const out = new Map();
  await Promise.all(cards.filter((c) => c.status === 'failed').map(async (c) => {
    try {
      const r = await api(`${API}/errors?task_id=${encodeURIComponent(c.task_id)}&limit=1`);
      if (r.items && r.items.length) out.set(c.task_id, r.items[0]);
    } catch { /* F1 拉不到 → 签名栏显示不可用 */ }
  }));
  return out;
}

function statusBadge(status) {
  const meta = STATUS_META[status] || { label: status, cls: 'st-pending' };
  return h('span', { class: 'badge ' + meta.cls, text: meta.label });
}
function riskBadge(tier) {
  const meta = RISK_META[tier];
  return meta ? h('span', { class: 'badge ' + meta.cls, text: meta.label }) : null;
}

function progressBlock(detail, lastTransition) {
  if (!detail || !Array.isArray(detail.groups) || detail.groups.length === 0) return null;
  const noBarStates = ['pending', 'planning', 'reviewing']; // FRU-01 §2.1：树未产出/已收敛不渲染进度条
  if (noBarStates.includes(detail.status)) return null;
  let total = 0; let done = 0; let failedN = 0;
  const groupLines = [];
  for (const g of detail.groups) {
    const subs = g.subtasks || [];
    const gTotal = subs.length;
    const gDone = subs.filter((s) => s.status === 'done').length;
    const gFail = subs.filter((s) => s.status === 'failed').length;
    total += gTotal; done += gDone; failedN += gFail;
    let line = `${g.group_id} ${gDone}/${gTotal}`;
    if (g.batch && g.batch.mode) {
      line += ` · 批量 ${gDone}/${g.batch.total_items} 项` +
        (g.batch.partial_ok ? '（部分成功可收敛）' : '（须全批成功）');
    }
    groupLines.push({ id: g.group_id, done: gDone, total: gTotal, line });
  }
  if (total === 0) return null;
  const pctDone = (done / total) * 100;
  const pctFail = (failedN / total) * 100;
  const tip = lastTransition
    ? `最近 state_transition：evt ${lastTransition.event_id}（${fmtTime(lastTransition.ts)}，${lastTransition.payload && lastTransition.payload.from}→${lastTransition.payload && lastTransition.payload.to}）`
    : '分组进度（done/total；failed 红格不计入分子）';
  const barEl = h('div', { class: 'bar' },
    h('i', { style: `width:${pctDone}%` }),
    h('i', { class: 'f', style: `width:${pctFail}%` }));
  const countEl = h('span', null, `${done}/${total}` + (failedN ? ` (+${failedN} 失败)` : ''));
  const groupBarsEl = h('div', { class: 'groupbars' });
  for (const gl of groupLines.slice(0, 4)) {
    groupBarsEl.append(h('div', { class: 'gb' },
      h('div', { class: 'bar' }, h('i', { style: `width:${gl.total ? (gl.done / gl.total) * 100 : 0}%` })),
      h('span', { text: gl.line })));
  }
  return h('div', {
    class: 'progress',
    title: tip,
    onclick: () => { location.hash = `#/task/${encodeURIComponent(detail.task_id)}`; },
  }, barEl, countEl, groupBarsEl);
}


function taskCard(t, ctx) {
  const detail = ctx.details && ctx.details.get(t.task_id);
  const lastEvt = ctx.lastTransition && ctx.lastTransition.get(t.correlation_id);
  const card = h('div', { class: 'card' });
  const head = h('div', { class: 'card-top' },
    statusBadge(t.status),
    h('span', { class: 'src-icon', text: SOURCE_META[t.source] || t.source }),
    riskBadge(t.risk_tier_max),
    h('span', { class: 'kv mono', text: t.task_id }),
  );
  // rework 态附返工指令摘要（A3 status_detail）
  if (t.status === 'rework' && detail && detail.status_detail) {
    head.append(h('span', { class: 'threshold', text: '返工指令：' + statusDetailText(detail.status_detail) }));
  }
  card.append(head);
  card.append(h('div', { class: 'goal', text: detail && detail.goal_summary ? detail.goal_summary : t.goal_summary,
                        onclick: () => { location.hash = `#/task/${encodeURIComponent(t.task_id)}`; } }));
  const p = progressBlock(detail, lastEvt);
  if (p) card.append(p);
  // 预算消耗（A2 cost_usd_est + A3 budget_usd；金额一律显示为估算）
  const budgetUsd = detail ? detail.budget_usd : null;
  const spent = t.cost_usd_est != null ? t.cost_usd_est : (detail && detail.cost_usd_est);
  if (budgetUsd != null || spent != null) {
    const pct = budgetUsd ? Math.min(100, (spent / budgetUsd) * 100) : 0;
    card.append(h('div', { class: 'progress' },
      h('div', { class: 'bar' }, h('i', { style: `width:${pct}%` })),
      h('span', { text: `成本 ${fmtUsd(spent)}${budgetUsd != null ? '/' + fmtUsd(budgetUsd) : ''}（估算）` })));
  }
  // 下次定时触发：仅 source=cron|webhook；join 不到则不显示（契约缺口 #1 口径）
  if (t.source === 'cron' || t.source === 'webhook') {
    const join = ctx.triggerJoin && ctx.triggerJoin.get(t.task_id);
    if (t.source === 'webhook') {
      card.append(h('div', { class: 'next-fire', text: '事件驱动（无固定时间）' }));
    } else if (join && join.trigger.next_fire_at) {
      card.append(h('div', { class: 'next-fire', text: `下次触发：${fmtTime(join.trigger.next_fire_at)}（cron ${join.trigger.schedule || ''} @${join.trigger.timezone || ''}）` }));
    }
  }
  const actions = h('div', { class: 'actions' },
    h('a', { href: `#/task/${encodeURIComponent(t.task_id)}`, text: '详情→' }),
    abortButton(t.task_id, t.status),
  );
  if (lastEvt) {
    actions.append(h('span', { class: 'kv', text: '溯源 evt ' + lastEvt.event_id, title: fmtTime(lastEvt.ts) }));
  }
  card.append(actions);
  return card;
}

function statusDetailText(sd) {
  if (sd == null) return '';
  if (typeof sd === 'string') return sd;
  if (sd.raw) return String(sd.raw);
  if (sd.instruction) return String(sd.instruction);
  return compact(sd, 120);
}

// T9 中止仅 running/reviewing/rework 合法（state.py TRANSITIONS：§3.2 未给
// pending/planning/paused_for_approval 的中止路径，设计缺口如实保留——不渲染假按钮）
const ABORTABLE_TASK_STATUSES = ['running', 'reviewing', 'rework'];
function abortButton(taskId, status) {
  const ok = ABORTABLE_TASK_STATUSES.includes(status);
  return h('button', {
    class: 'btn sm danger',
    text: '中止',
    disabled: ok ? null : '',
    title: ok ? 'T9 用户中止（不可恢复；已产出物按 aborted 归档）'
              : 'T9 仅 running/reviewing/rework 可中止（§3.2 转移表：pending/planning/paused 无中止路径）',
    onclick: ok ? () => abortTaskFlow(taskId) : null,
  });
}

function abortTaskFlow(taskId) {
  openConfirm({
    title: '中止任务（A5 · T9）',
    message: '不可恢复：已产出物按 aborted 归档。运行中子任务定点取消。',
    fields: [{ key: 'reason', label: '中止原因 reason（必填）', required: true }],
    confirmText: '确认中止',
    danger: true,
    onConfirm: async (v) => {
      try {
        const res = await api(`${API}/tasks/${encodeURIComponent(taskId)}/abort`, { method: 'POST', body: { reason: v.reason } });
        toast(`已中止 ${res.task_id}（transition ${res.transition}，evt ${res.event_id}）`, 'ok');
        closeModal();
        currentRefresh && currentRefresh();
      } catch (e) {
        if (e.code === 'ALREADY_TERMINAL') { toast('任务已在终态（409 ALREADY_TERMINAL），已刷新卡片'); closeModal(); currentRefresh && currentRefresh(); }
        else throw e;
      }
    },
  });
}

function approvalCard(a) {
  const card = h('div', { class: 'card warn' });
  card.append(h('div', { class: 'card-top' },
    statusBadge(a.status),
    riskBadge(a.risk_tier),
    h('span', { class: 'kv mono', text: a.approval_id }),
    h('span', { class: 'kv', text: a.action_type }),
  ));
  card.append(h('div', { class: 'goal', text: a.summary }));
  card.append(h('div', { class: 'meta' },
    h('span', null, '来源任务 ', h('a', { href: `#/task/${encodeURIComponent(a.correlation_id ? a.correlation_id : a.task_id)}`, text: a.correlation_id || a.task_id })),
  ));
  card.append(h('div', { class: 'meta' },
    h('span', { 'data-expires': a.wait_expires_at || '', text: `等待截止 ${fmtCountdown(a.wait_expires_at)}` }),
    h('span', { text: TIMEOUT_FALLBACK_META[a.timeout_fallback] || (a.timeout_fallback ? '兜底：' + a.timeout_fallback : '') }),
  ));
  card.append(h('div', { class: 'actions' },
    h('button', { class: 'btn sm primary', text: '去裁决→', onclick: () => openApprovalDrawer(a.approval_id) }),
  ));
  return card;
}

function budgetWaitCard(taskId, spentInfo) {
  return h('div', { class: 'card' },
    h('div', { class: 'card-top' },
      h('span', { text: '◇' }),
      statusBadge('paused_for_approval'),
      h('span', { class: 'kv mono', text: taskId }),
      spentInfo ? h('span', { class: 'kv', text: `已耗 ${fmtUsd(spentInfo.spent_usd_est)}/${fmtUsd(spentInfo.budget_usd)}` }) : null,
    ),
    h('div', { class: 'meta', text: '预算熔断暂停：等待调额（BUDGET_GLOBAL_DAILY 为环境配置，走部署流程，无 API 按钮）' }),
    h('div', { class: 'actions' }, h('a', { href: `#/task/${encodeURIComponent(taskId)}`, text: '详情→' })),
  );
}

function doneCard(x) {
  return h('div', { class: 'card' },
    h('div', { class: 'card-top' }, statusBadge('done'), h('span', { class: 'kv mono', text: x.task_id || x.correlation_id })),
    h('div', { class: 'goal', text: x.goal_summary || '（无摘要）' }),
    h('div', { class: 'meta' },
      h('span', { text: `完成于 ${fmtTime(x.last_event_at)}` }),
      h('span', { text: `今日 ${x.event_count_day} 事件` }),
      x.errors_day > 0 ? h('span', { class: 'threshold', text: `含 ${x.errors_day} 次错误登记` }) : null,
    ),
    h('div', { class: 'actions' },
      x.task_id ? h('a', { href: `#/task/${encodeURIComponent(x.task_id)}`, text: '详情→' }) : null,
      x.task_id ? h('a', { href: `#/task/${encodeURIComponent(x.task_id)}`, text: '时间线→' }) : null,
    ),
  );
}

function failedCard(t, ctx) {
  const errInfo = ctx.failedErrors && ctx.failedErrors.get(t.task_id);
  const abort = ctx.abortSource && ctx.abortSource.get(t.task_id);
  const card = h('div', { class: 'card bad' });
  const head = h('div', { class: 'card-top' }, statusBadge(t.status));
  if (t.status === 'aborted' && abort) {
    head.append(h('span', { class: 'kv', text: '中止来源：' + (abort.source === 'budget_exceeded' ? 'budget（预算熔断）' : abort.source) }));
  } else if (t.status === 'aborted') {
    head.append(h('span', { class: 'kv', text: '中止来源：—' }));
  }
  head.append(h('span', { class: 'kv mono', text: t.task_id }));
  card.append(head);
  card.append(h('div', { class: 'goal', text: t.goal_summary }));
  if (errInfo) {
    const threshold = (errInfo.occurrence_count_same_signature || 0) >= 2;
    card.append(h('div', { class: 'meta' },
      h('span', { class: 'mono', text: `最近签名 ${errInfo.error_signature}` }),
      h('span', { text: `×${errInfo.occurrence_count_same_signature}` }),
      threshold ? h('span', { class: 'threshold', text: '≥2 已达沉淀阈值' }) : null,
    ));
  } else {
    card.append(h('div', { class: 'meta', text: ctx.errors && ctx.errors.failed ? '签名查询不可用（' + (ctx.errors.failed.code || '') + '）' : '最近签名：—' }));
  }
  const readSet = readFailures.get();
  card.append(h('div', { class: 'actions' },
    h('a', { href: `#/task/${encodeURIComponent(t.task_id)}`, text: '详情→' }),
    h('a', { href: '#/errors', text: '账本→' }),
    h('button', { class: 'btn sm', text: '标记已阅', onclick: () => { readFailures.add(t.task_id); renderV1(); } }),
  ));
  if (readSet.has(t.task_id) && !showReadFailures) card.classList.add('dim');
  return card;
}

function buildV1Grid(d) {
  const wrap = h('div');
  // 首启引导（全板空态）
  const allEmpty = d.runningItems.length === 0 && d.approvalItems.length === 0 && d.pausedItems.length === 0 &&
    d.doneItems.length === 0 && d.failedItems.length === 0 && d.triggers.length === 0;
  if (allEmpty) {
    wrap.append(h('div', { class: 'onboarding' },
      h('h3', { text: '首次使用 · 三步开始' }),
      h('ol', null,
        h('li', null, '① 提交目标：右上「＋ 提交新任务」输入自然语言 goal（不做画布、不连线节点）。'),
        h('li', null, '② 系统规划拆解：编排器检索错误账本 → 规划器产出任务树（本面板只读展示）。'),
        h('li', null, '③ 审批 / 审计流：R2 不可逆动作弹出审批门等待裁决；全程事件可在任务详情时间线与 replay 审计回看。'),
      ),
      h('div', { class: 'muted small', text: '不提供演示假数据。' }),
    ));
  }
  if (d.errors && Object.keys(d.errors).length) {
    for (const [k, e] of Object.entries(d.errors)) {
      wrap.append(h('div', { class: 'banner', text: `⚠ ${k} 拉取失败：${e.code || ''} ${e.message || ''}（分区显示已缓存/空态）` }));
    }
  }

  // ① 进行中
  const pausedCovered = new Set([
    ...d.approvalItems.map((a) => a.correlation_id),
    ...(d.budget.paused_by_budget || []),
  ]);
  const leftoverPaused = d.pausedItems.filter((t) => !pausedCovered.has(t.correlation_id) && !pausedCovered.has(t.task_id));
  const z1 = zone('① 进行中', d.runningItems.length, h('div', null,
    d.runningItems.length === 0
      ? h('div', { class: 'empty' },
          '没有进行中的任务。',
          h('div', { class: 'actions' }, h('button', { class: 'btn sm primary', text: '＋ 提交新任务', onclick: () => $('#btn-new-task').click() })))
      : d.runningItems.map((t) => taskCard(t, d)),
  ));
  // ② 待审批
  const z2children = [];
  if (d.approvalItems.length === 0 && (d.budget.paused_by_budget || []).length === 0 && leftoverPaused.length === 0) {
    z2children.push(h('div', { class: 'empty', text: '没有等待裁决的动作。你不在时任务按超时兜底继续推进（常规类跳过该动作，付款类直接跳过）。' }));
  }
  z2children.push(...d.approvalItems.map(approvalCard));
  z2children.push(...(d.budget.paused_by_budget || []).map((tid) => {
    const risk = (d.budget.tasks_at_risk || []).find((r) => r.task_id === tid);
    return budgetWaitCard(tid, risk);
  }));
  z2children.push(...leftoverPaused.map((t) => h('div', { class: 'card' },
    h('div', { class: 'card-top' }, statusBadge(t.status), h('span', { class: 'kv mono', text: t.task_id })),
    h('div', { class: 'goal', text: t.goal_summary }),
    h('div', { class: 'meta', text: '等待裁决或调额中（详见任务详情）' }),
    h('div', { class: 'actions' }, h('a', { href: `#/task/${encodeURIComponent(t.task_id)}`, text: '详情→' })),
  )));
  const z2 = zone('② 待审批', d.approvalItems.length + (d.budget.paused_by_budget || []).length + leftoverPaused.length, h('div', null, z2children));

  // ③ 今日完成（D1 缺省 date=容器时区今日，客户端过滤 status_now=done）
  const z3 = zone('③ 今日完成', d.doneItems.length, h('div', null,
    d.doneItems.length === 0
      ? h('div', { class: 'empty', text: '今天还没有完成的任务。' })
      : d.doneItems.map(doneCard),
  ));

  // ④ 失败需关注（标记已阅折叠）
  const readSet = readFailures.get();
  const visibleFailed = showReadFailures ? d.failedItems : d.failedItems.filter((t) => !readSet.has(t.task_id));
  const hiddenCount = d.failedItems.length - visibleFailed.length;
  const z4children = [];
  if (d.failedItems.length === 0) z4children.push(h('div', { class: 'empty', text: '✓ 无失败任务' }));
  z4children.push(...visibleFailed.map((t) => failedCard(t, d)));
  if (hiddenCount > 0) {
    z4children.push(h('div', { class: 'pager' },
      `已折叠 ${hiddenCount} 个已阅项 · `,
      h('a', { href: 'javascript:;', text: showReadFailures ? '隐藏已阅' : '显示已阅', onclick: () => { showReadFailures = !showReadFailures; renderV1(); } }),
    ));
  }
  const z4 = zone('④ 失败需关注', d.failedItems.length, h('div', null, z4children));

  const grid = h('div', { class: 'v1-grid' }, z1, z2, z3, z4);
  wrap.append(grid);
  return wrap;
}

function zone(title, count, body) {
  return h('section', { class: 'zone' },
    h('div', { class: 'zone-head' }, h('h2', { text: title }), h('span', { class: 'count', text: String(count) }), h('span', { class: 'spacer' })),
    body,
  );
}

/* ============================================================
 * 8. 视图二 V2：任务详情（树/子任务/时间线/审批/成本/replay）
 * ============================================================ */

function summarizePayload(e) {
  const p = e.payload || {};
  if (p.truncated) return '载荷>64KB 已截断，存档引用 artifact_ref: ' + (p.artifact_ref || '');
  switch (e.event_type) {
    case 'task_submitted': return `goal 提交（source=${p.source || '?'}${p.client_ref ? ', client_ref=' + p.client_ref : ''}）`;
    case 'ledger_lookup': return `强制检索命中 ${(p.rule_ids || []).length} 条生效规则`;
    case 'plan_produced': return `规划产出 ${p.groups != null ? p.groups + ' 组' : ''} ${p.subtasks != null ? p.subtasks + ' 子任务' : ''}`;
    case 'state_transition': return `${p.from || ''}→${p.to || ''}（${p.transition || ''}）`;
    case 'approval_requested': return `等待裁决 ${p.action_type || ''}（risk=${p.risk_tier || ''}, ${p.approval_id || ''}）`;
    case 'approval_decision': return `裁决 ${p.decision || ''}（${p.approval_id || ''}）`;
    case 'approval_timeout_skip': return `超时兜底 ${p.fallback || p.degradation || 'skip'}（${p.approval_id || ''}）`;
    case 'llm_call': return `LLM ${p.model || ''} in=${p.tokens_in || 0} out=${p.tokens_out || 0}`;
    case 'tool_call': return `工具 ${p.tool || p.tool_name || ''} → ${p.status || ''}`;
    case 'subtask_started': return `子任务启动 ${p.subtask_id || ''}`;
    case 'subtask_stopped': return `子任务结束 ${p.subtask_id || ''}（${p.status || ''}）`;
    case 'rework_instruction': return `返工：${p.defect || p.instruction || compact(p, 100)}`;
    case 'review_verdict': return `验收结论 ${p.verdict || p.conclusion || ''}（置信度 ${p.confidence != null ? p.confidence : '—'}）`;
    case 'error_registered': return `错误登记 ${p.error_signature || ''}`;
    case 'rule_candidate': return `候选规则 r${p.rule_id}（${p.occurrences} 次）`;
    case 'budget_exceeded': return `预算超限 ${p.level || ''} ${p.exceeded_amount != null ? '+' + p.exceeded_amount : ''}`;
    case 'task_aborted': return `中止（${p.source || '?'}）：${p.reason || ''}`;
    case 'trigger_fired': return `触发器 ${p.trigger_id} → ${p.task_id || ''}`;
    case 'trigger_missed': return `停机错过，恢复后补跑（原定 ${p.missed_at || p.original_at || '—'}）`;
    case 'memory_degraded': return `记忆库降级 ${p.surface || compact(p, 80)}`;
    default: return compact(p, 120);
  }
}

// V2 路由参数兼容 task_id 与 correlation_id（审批卡/深链只有 correlation_id；
// A3 仅按 task_id 索引 → 404 时经 C1 事件反查主任务 id 再取 A3）
async function fetchTaskByIdOrCorr(idOrCorr) {
  try {
    return { task: await api(`${API}/tasks/${encodeURIComponent(idOrCorr)}`), arg: idOrCorr };
  } catch (e) {
    if (e.code !== 'TASK_NOT_FOUND') throw e;
  }
  const evs = await api(`${API}/events?correlation_id=${encodeURIComponent(idOrCorr)}&limit=10`);
  for (const ev of evs.items || []) {
    if (ev.task_id && String(ev.task_id).startsWith('task-')) {
      return { task: await api(`${API}/tasks/${encodeURIComponent(ev.task_id)}`), arg: ev.task_id };
    }
  }
  throw { status: 404, code: 'TASK_NOT_FOUND', message: '任务不存在（事件留存期 90 天）' };
}

async function renderTaskDetail(taskId) {
  setTab('v2');
  $('#view').dataset.view = 'task';
  const view = $('#view');
  view.replaceChildren(h('div', { class: 'loading', text: '任务详情加载中…' }));
  currentRefresh = () => renderTaskDetail(taskId);

  let task;
  let taskIdResolved = taskId;
  try {
    const r = await fetchTaskByIdOrCorr(taskId);
    task = r.task;
    taskIdResolved = r.arg;
  } catch (e) {
    if (e.code === 'TASK_NOT_FOUND') {
      view.replaceChildren(h('div', { class: 'panel' },
        h('h3', { text: '任务不存在（404 TASK_NOT_FOUND）' }),
        h('p', { class: 'muted', text: '事件/载荷留存期 90 天，过期归档（ARCH §7.2）。' }),
        h('a', { href: '#/', text: '← 返回看板' }),
      ));
      return;
    }
    view.replaceChildren(h('div', { class: 'panel' }, h('p', { class: 'error-text', text: e.code + ' ' + e.message })));
    return;
  }
  const corr = task.correlation_id;

  const [costs, timelinePage, approvalsAll, costsSummary] = await Promise.all([
    api(`${API}/tasks/${encodeURIComponent(taskIdResolved)}/costs`).catch((e) => ({ __error: e })),
    api(`${API}/executions/${encodeURIComponent(corr)}/timeline?limit=200`).catch((e) => ({ __error: e })),
    api(`${API}/approvals?status=waiting&limit=50`).catch((e) => ({ __error: e })),
    api(`${API}/costs/summary`).catch(() => null),
  ]);
  const waitingApprovals = (approvalsAll && !approvalsAll.__error ? approvalsAll.items : [])
    .filter((a) => a.correlation_id === corr);

  const page = h('div');

  // 页头 DT-01
  const head = h('div', { class: 'detail-head' },
    h('a', { href: '#/', text: '←返回看板' }),
    h('span', { class: 'mono', text: taskIdResolved }),
    statusBadge(task.status),
    riskBadge((task.groups || []).flatMap((g) => g.subtasks || []).map((s) => s.risk_tier_hint).find(Boolean)),
    h('span', { class: 'goal', text: task.goal_summary }),
    h('span', { class: 'kv', text: '更新于 ' + fmtTime(task.updated_at) }),
    h('span', { class: 'spacer' }),
    abortButton(taskIdResolved, task.status),
    h('button', { class: 'btn sm', text: 'replay 审计', onclick: () => openReplay(corr) }),
  );
  page.append(head);

  // 返工横幅 DT-08
  if (task.status === 'rework' && task.status_detail) {
    page.append(h('div', { class: 'rework-banner', text: '返工指令（T7 定点返工）：' + statusDetailText(task.status_detail) }));
  }

  const grid = h('div', { class: 'detail-grid' });
  const leftCol = h('div');
  const rightCol = h('div');

  // A 任务树与分组（只读投影）
  leftCol.append(buildTreePanel(task));
  // E 成本明细
  leftCol.append(buildCostPanel(costs, costsSummary));

  // C 执行时间线
  rightCol.append(buildTimelinePanel(corr, timelinePage));
  // D 审批面板（B1 按 correlation 过滤 → 内嵌 G-05 表单）
  rightCol.append(buildApprovalSection(waitingApprovals));

  grid.append(leftCol, rightCol);
  page.append(grid);
  view.replaceChildren(page);
  refreshRuntimeStrip();

  // 实时尾随（§1.3 临时第 2 条连接，correlation_id 过滤；离开页面由路由切换时 abort）
  if (window.__taskStreamCtl) window.__taskStreamCtl.abort();
  const ctl = new AbortController();
  window.__taskStreamCtl = ctl;
  const tlState = { items: (timelinePage && !timelinePage.__error ? timelinePage.items : []).slice() };
  sseFetch({ correlation_id: corr }, ctl.signal, {
    onFrame: (frame) => {
      if (frame.event === 'stream_resync' || frame.event === '__stream_limit') return;
      if (frame.data && frame.data.event_id) {
        if (!tlState.items.some((x) => x.event_id === frame.data.event_id)) tlState.items.push(frame.data);
        const body = $('#tl-body');
        if (body) body.replaceChildren(renderTimelineDays(tlState.items, tlState.typeFilter));
      }
    },
    onState: (mode) => {
      const note = $('#tl-live-note');
      if (note) {
        if (mode === 'live') note.textContent = '● 实时尾随中';
        else if (mode === 'polling') note.textContent = '实时尾随不可用，已按需拉取（手动刷新按钮可用）';
        else if (mode === 'reconnecting') note.textContent = '● 尾随重连中';
      }
    },
  });
}

function buildTreePanel(task) {
  const panel = h('div', { class: 'panel' }, h('h3', { text: 'A · 任务树与分组（只读投影，不可编辑）' }));
  const groups = task.groups || [];
  if (['pending', 'planning'].includes(task.status) && groups.length === 0) {
    panel.append(h('div', { class: 'empty', text: '规划尚未产出任务树——规划器拆解中（超时兜底：planning>10m 重试 1 次，再超时转 failed，ARCH §3.2 T2）。' }));
    return panel;
  }
  if (groups.length === 0) { panel.append(h('div', { class: 'empty', text: '该任务无分组数据。' })); return panel; }
  const groupById = new Map(groups.map((g) => [g.group_id, g]));
  const groupUnlocked = (gid) => {
    const g = groupById.get(gid);
    if (!g) return true;
    const subs = g.subtasks || [];
    return subs.length > 0 && subs.every((s) => s.status === 'done');
  };
  for (const g of groups) {
    const deps = g.depends_on || [];
    const unmet = deps.filter((dep) => !groupUnlocked(dep));
    const gEl = h('div', { class: 'tree-group' + (unmet.length ? ' locked' : '') });
    const gHead = h('div', { class: 'g-head' },
      h('span', { class: 'name', text: `${g.group_id} ${g.name || ''}` }),
      deps.length ? h('span', { class: 'kv', text: '依赖:' + deps.join(',') + (unmet.length ? '（未解锁）' : '（已解锁）') }) : h('span', { class: 'kv', text: '依赖:—' }),
    );
    if (g.batch && g.batch.mode) {
      gHead.append(h('span', { class: 'batch-note', text: `批量 ${g.batch.total_items} 项 · ${g.batch.partial_ok ? 'partial_ok 部分成功可收敛' : '须全批成功'}` }));
    }
    const subs = g.subtasks || [];
    const gDone = subs.filter((s) => s.status === 'done').length;
    gHead.append(h('span', { class: 'kv', text: `${gDone}/${subs.length}` }));
    gEl.append(gHead);
    for (const s of subs) {
      gEl.append(h('div', { class: 'subtask-row', onclick: () => openSubtaskDrawer(task.task_id, s) },
        h('span', { class: 'sid', text: s.subtask_id }),
        statusBadge(s.status),
        h('span', { class: 'obj', text: s.objective || '' }),
        s.attempts > 1 ? h('span', { class: 'threshold', text: `×${s.attempts} 次重派` }) : null,
        h('span', { class: 'kv', text: `brief v${s.brief_version}` }),
        s.risk_tier_hint ? riskBadge(s.risk_tier_hint) : null,
        h('span', { class: 'kv', text: fmtUsd(s.cost_usd_est) }),
        s.deliverable_path ? h('span', { class: 'kv mono', title: s.deliverable_path, text: '📄 ' + s.deliverable_path.split('/').pop() }) : null,
      ));
    }
    panel.append(gEl);
  }
  return panel;
}

function openSubtaskDrawer(taskId, sub) {
  const body = h('div', { class: 'drawer-body' });
  body.append(h('div', { class: 'card-top' },
    h('span', { class: 'mono', text: sub.subtask_id }),
    statusBadge(sub.status),
    riskBadge(sub.risk_tier_hint),
  ));
  body.append(h('p', { text: sub.objective || '' }));
  body.append(h('div', { class: 'meta' },
    h('span', { text: `attempts ${sub.attempts} · brief v${sub.brief_version} · ${fmtUsd(sub.cost_usd_est)}` }),
    sub.deliverable_path ? h('div', { class: 'mono small', text: '产出路径：' + sub.deliverable_path }) : null,
  ));
  body.append(h('h3', { text: 'brief 版本（A4）——brief 即子代理的全部世界（ARCH §4.2），主对话原文不在此' }));
  const briefBox = h('div', null, h('div', { class: 'loading', text: 'brief 加载中…' }));
  body.append(briefBox);
  openModal(h('div', { class: 'modal-card' },
    h('h3', { text: '子任务 ' + sub.subtask_id }),
    body,
    h('div', { class: 'row' }, h('button', { class: 'btn', text: '关闭', onclick: closeModal })),
  ));
  // A4 实际路由（server.py 6 段形态，以实际路由代码为准）：
  // GET /api/v1/tasks/{subtask_id}/subtasks/briefs
  api(`${API}/tasks/${encodeURIComponent(sub.subtask_id)}/subtasks/briefs`).then((r) => {
    briefBox.replaceChildren(...(r.items || []).map((v) => h('div', { class: 'rule-row' },
      h('div', { class: 'r-text', text: `v${v.version} · ${fmtTime(v.created_at)}` }),
      renderBrief(v.brief || {}),
    )));
    if (!r.items || r.items.length === 0) briefBox.replaceChildren(h('div', { class: 'empty', text: '尚无 brief 版本（未派发）。' }));
  }).catch((e) => briefBox.replaceChildren(h('div', { class: 'error-text', text: e.code + ' ' + e.message })));
}

function renderBrief(b) {
  const box = h('div');
  const rows = [
    ['objective', b.objective], ['self_contained_context（必要摘录）', b.self_contained_context],
    ['acceptance_criteria', Array.isArray(b.acceptance_criteria) ? b.acceptance_criteria.join('；') : b.acceptance_criteria],
    ['allowed_tools', Array.isArray(b.allowed_tools) ? b.allowed_tools.join(', ') : b.allowed_tools],
    ['prevention_rules', Array.isArray(b.prevention_rules) ? b.prevention_rules.map((r) => `r${r.rule_id} ${r.rule_text}`).join('；') : b.prevention_rules],
    ['max_iterations', b.max_iterations], ['budget_usd', b.budget_usd], ['task_type', b.task_type],
    ['memory_refs', Array.isArray(b.memory_refs) ? b.memory_refs.join(', ') : b.memory_refs],
    ['deliverable_path（路径文本，不内联内容）', b.deliverable_path],
  ];
  for (const [k, v] of rows) {
    if (v == null || v === '') continue;
    box.append(h('div', { class: 'kv' }, h('strong', { text: k + '：' }), h('span', { text: String(v) })));
  }
  return box;
}

function buildCostPanel(costs, costsSummary) {
  const panel = h('div', { class: 'panel' }, h('h3', { text: 'E · 成本明细（E2）' }));
  if (costs && costs.__error) {
    panel.append(h('div', { class: 'empty', text: costs.__error.code === 'TASK_NOT_FOUND' ? '任务不存在。' : '成本明细拉取失败：' + costs.__error.code }));
    return panel;
  }
  if (!costs) { panel.append(h('div', { class: 'empty', text: '成本明细不可用。' })); return panel; }
  const subs = costs.subtasks || [];
  if (subs.length === 0) panel.append(h('div', { class: 'empty', text: '尚无子任务计量（未进入 running）。' }));
  for (const s of subs) {
    const pct = s.max_llm_calls ? Math.min(100, (s.llm_calls / s.max_llm_calls) * 100) : 0;
    panel.append(h('div', { class: 'cost-line' },
      h('span', { class: 'mono', text: s.subtask_id }),
      h('div', { class: 'bar' }, h('i', { style: `width:${pct}%` })),
      h('span', { text: `${s.llm_calls}/${s.max_llm_calls != null ? s.max_llm_calls : '?'} 次 · ${s.tokens_total} tok · ${fmtUsd(s.cost_usd_est)}` }),
    ));
  }
  panel.append(h('div', { class: 'cost-line' },
    h('strong', { text: `任务 ${fmtUsd(costs.task_cost_usd_est)}/${fmtUsd(costs.budget_usd)}` }),
    h('span', { class: costs.finalized ? 'st-done badge' : 'kv', text: costs.finalized ? '已固化（T11）' : '估算进行中（done 时 T11 固化）' }),
  ));
  const disclaimer = costs.metering_disclaimer || (costsSummary && costsSummary.metering_disclaimer);
  if (disclaimer) panel.append(h('div', { class: 'muted small', text: disclaimer }));
  return panel;
}

function renderTimelineDays(items, typeFilter) {
  const days = new Map();
  for (const e of items) {
    if (typeFilter && typeFilter !== 'all' && e.event_type !== typeFilter) continue;
    const day = fmtDay(e.ts);
    if (!days.has(day)) days.set(day, []);
    days.get(day).push(e);
  }
  const box = h('div');
  if (days.size === 0) { box.append(h('div', { class: 'empty', text: '该日无事件。' })); return box; }
  for (const [day, evs] of days) {
    const stateChanges = evs.filter((e) => e.event_type === 'state_transition').length;
    const errors = evs.filter((e) => e.event_type === 'error_registered').length;
    const dayBox = h('div', { class: 'tl-day' });
    dayBox.append(h('div', {
      class: 'tl-day-head',
      text: `${day} · ${evs.length} 事件 · ${stateChanges} 状态变化 · ${errors} 错误`,
      onclick: () => { const rows = dayBox.querySelectorAll('.tl-row'); rows.forEach((r) => r.classList.toggle('hidden')); },
    }));
    for (const e of evs) {
      dayBox.append(h('div', { class: 'tl-row' },
        h('span', { class: 'ts', text: fmtClock(e.ts) }),
        h('span', { class: 'comp', text: e.component }),
        h('span', { class: 'etype', text: e.event_type }),
        h('span', { class: 'pl', text: summarizePayload(e) }),
        h('span', { class: 'eid', title: '点击复制 event_id', text: 'evt ' + e.event_id,
                    onclick: () => copyText(e.event_id, 'event_id') }),
      ));
    }
    box.append(dayBox);
  }
  return box;
}

function buildTimelinePanel(corr, timelinePage) {
  const panel = h('div', { class: 'panel' });
  panel.append(h('h3', null,
    h('span', { text: 'C · 执行时间线（D2）' }),
    h('span', { class: 'spacer' }),
    h('span', { id: 'tl-live-note', class: 'kv', text: '● 尾随连接中…' }),
  ));
  const typeFilter = localStorage.getItem('agentmesh.tlType') || 'all';
  const select = h('select', null,
    h('option', { value: 'all', text: '全部类型' }),
    ICON_EVENT_TYPES.map((t) => {
      const o = h('option', { value: t, text: t });
      if (t === typeFilter) o.selected = true;
      return o;
    }),
  );
  select.addEventListener('change', () => {
    localStorage.setItem('agentmesh.tlType', select.value);
    currentRefresh();
  });
  const toolbar = h('div', { class: 'toolbar', style: 'padding:6px 0;box-shadow:none;border-radius:0' },
    h('span', { class: 'kv', text: 'types 过滤' }), select,
    h('button', { class: 'btn sm', text: '手动刷新', onclick: () => currentRefresh() }),
    h('span', { class: 'kv', text: '按浏览器时区分组；日期基准说明见容器 TZ' }),
  );
  panel.append(toolbar);
  const body = h('div', { id: 'tl-body' });
  panel.append(body);
  if (timelinePage && timelinePage.__error) {
    body.replaceChildren(h('div', { class: 'empty', text: '时间线拉取失败：' + timelinePage.__error.code + ' ' + timelinePage.__error.message }));
    return panel;
  }
  const items = (timelinePage.items || []).slice();
  body.replaceChildren(renderTimelineDays(items, typeFilter));
  // G-07 游标分页：加载更多（cursor 原样回传）
  let cursor = timelinePage.next_cursor;
  let hasMore = !!timelinePage.has_more;
  if (hasMore) {
    const more = h('div', { class: 'pager' }, h('a', {
      href: 'javascript:;',
      text: '加载更早事件…',
      onclick: async (ev) => {
        ev.preventDefault();
        if (!cursor) return;
        try {
          const next = await api(`${API}/executions/${encodeURIComponent(corr)}/timeline?limit=200&cursor=${encodeURIComponent(cursor)}`);
          items.push(...(next.items || []));
          body.replaceChildren(renderTimelineDays(items, typeFilter));
          cursor = next.next_cursor;
          hasMore = !!next.has_more;
          if (!hasMore) more.replaceChildren(h('span', { text: '已取完' }));
        } catch (e) { toast(e.code + ' ' + e.message, 'err'); }
      },
    }));
    panel.append(more);
  }
  return panel;
}

function buildApprovalSection(waitingApprovals) {
  const panel = h('div', { class: 'panel' }, h('h3', { text: 'D · 审批面板（B2 渲染数据驱动，三按钮）' }));
  if (waitingApprovals.length === 0) {
    panel.append(h('div', { class: 'empty', text: '当前无待裁决动作。' }));
    return panel;
  }
  for (const a of waitingApprovals) {
    const slot = h('div', { class: 'appr' }, h('div', { class: 'loading', text: '审批 ' + a.approval_id + ' 加载中…' }));
    panel.append(slot);
    renderApprovalForm(slot, a.approval_id, { mode: 'inline' });
  }
  return panel;
}

// ---- 审批表单（G-05 / DT-05 通用；B2 数据 + B3 三按钮路由）----
async function renderApprovalForm(container, approvalId, opts) {
  let data;
  try {
    data = await api(`${API}/approvals/${encodeURIComponent(approvalId)}`);
  } catch (e) {
    container.replaceChildren(h('div', { class: 'error-text', text: e.code + ' ' + e.message }));
    return;
  }
  const el = h('div', { class: 'appr' + (data.status !== 'waiting' ? ' readonly' : '') });
  el.append(h('div', { class: 'a-head' },
    statusBadge(data.status),
    riskBadge(data.risk_tier),
    h('span', { class: 'mono', text: data.approval_id }),
    h('span', { class: 'kv', text: data.action_type }),
    h('span', { class: 'kv', text: '来源子任务 ' + (data.evidence && data.evidence.subtask_id || data.task_id) }),
  ));
  el.append(h('div', { class: 'a-summary' }, h('strong', { text: data.title || '' })));

  // 非等待态：只读 + 历史裁决说明
  if (data.status === 'decided' || data.status === 'expired') {
    el.append(h('div', { class: 'verdict-banner info', text:
      data.status === 'decided' ? '该审批已被裁决——面板转只读，展示历史记录。' : '该审批已过期——超时兜底已执行，任务已继续推进非风险部分。' }));
    container.replaceChildren(el);
    return;
  }

  // 证据栏（哪个子任务、基于什么结论、引用产出链接）
  const ev = data.evidence || {};
  const evidence = h('div', { class: 'evidence' },
    h('div', { class: 'ev-title', text: '证据栏（触发依据）' }),
    h('div', { text: ev.summary || '' }),
    (ev.conclusion_event_ids || []).length ? h('div', { class: 'ev-ids' },
      h('span', { class: 'kv', text: '结论事件（可复制，可到时间线溯源）:' }),
      ev.conclusion_event_ids.map((eid) => h('a', { href: 'javascript:;', class: 'mono', text: eid, onclick: () => copyText(eid, 'event_id') })),
    ) : null,
    (ev.artifact_refs || []).length ? h('div', { class: 'kv', text: '产出引用：' + ev.artifact_refs.join(' , ') }) : null,
  );
  el.append(evidence);

  // 草稿表单（可编辑字段 + 系统注入项置灰）
  const edited = {}; // 本地副本：提交时组装 edited_payload
  const original = {};
  const formBox = h('div');
  for (const f of (data.form && data.form.fields) || []) {
    original[f.name] = f.value;
    edited[f.name] = f.value;
    const isText = f.type === 'text';
    const input = h(isText ? 'textarea' : 'input', isText ? { rows: '4' } : { type: 'text' });
    input.value = f.value == null ? '' : String(f.value);
    if (!f.editable) { input.disabled = true; }
    else {
      input.addEventListener('input', () => { edited[f.name] = input.value; });
    }
    formBox.append(h('div', { class: 'field' },
      h('label', { text: (f.label || f.name) + (f.editable ? '' : '（不可编辑）') }),
      input,
      f.editable ? null : h('span', { class: 'sys-note', text: '系统注入上下文项' }),
    ));
  }
  el.append(formBox);

  // 重生成批注框（默认折叠）
  let regenBox = null;
  const commentInput = h('textarea', { rows: '2', placeholder: '必填：说明为何重出草稿（退回动作生成步）' });

  // 等待期 + 兜底说明
  el.append(h('div', { class: 'expire-note' },
    h('span', { 'data-expires': data.wait_expires_at || '', text: `等待截止 ${fmtCountdown(data.wait_expires_at)}` }),
  ));
  el.append(h('div', { class: 'fallback-note', text: TIMEOUT_FALLBACK_META[data.timeout_fallback] || (data.timeout_fallback ? '兜底：' + data.timeout_fallback : '') }));

  const errLine = h('div', { class: 'error-text' });
  const buttons = h('div', { class: 'a-actions' });
  const submit = async (action) => {
    errLine.textContent = '';
    // 客户端预检（FRU-01 §3.2 提交校验）
    let body;
    if (action === 'approve') body = { action: 'approve' };
    else if (action === 'use_edited') {
      const editableNames = new Set(((data.form && data.form.fields) || []).filter((f) => f.editable).map((f) => f.name));
      const changed = {};
      for (const [k, v] of Object.entries(edited)) {
        if (!editableNames.has(k)) { errLine.textContent = 'FIELD_NOT_EDITABLE：字段 ' + k + ' 不可编辑'; return; }
        if (String(v) !== String(original[k])) changed[k] = v;
      }
      if (Object.keys(changed).length === 0) { errLine.textContent = 'EDITED_PAYLOAD_REQUIRED：未修改任何字段——按原文执行请用「批准」'; return; }
      body = { action: 'use_edited', edited_payload: changed };
    } else if (action === 'regenerate') {
      const comment = String(commentInput.value || '').trim();
      if (!comment) { errLine.textContent = 'COMMENT_REQUIRED：重生成必须先填批注'; return; }
      body = { action: 'regenerate', comment };
    }
    try {
      const res = await api(`${API}/approvals/${encodeURIComponent(approvalId)}/decision`, { method: 'POST', body });
      toast(`裁决已提交：${res.decision}（effective=${res.effective_payload}，transition ${res.transition}）`, 'ok');
      if (opts.mode === 'drawer') closeApprovalDrawer();
      currentRefresh && currentRefresh();
    } catch (e) {
      if (e.code === 'APPROVAL_ALREADY_DECIDED') {
        toast('该审批已被裁决（409）——刷新为只读', 'err');
        renderApprovalForm(container, approvalId, opts);
      } else if (e.code === 'APPROVAL_TIMEOUT_APPLIED') {
        el.querySelector('.a-actions').replaceChildren(
          h('div', { class: 'verdict-banner warn' },
            '等待期已到，兜底已执行（动作按 timeout_fallback 跳过），任务已继续推进非风险部分。',
            e.details && e.details.event_id ? h('div', null, '兜底事件：', h('a', { href: 'javascript:;', class: 'mono', text: e.details.event_id, onclick: () => copyText(e.details.event_id, 'event_id') })) : null),
        );
      } else {
        errLine.textContent = `${e.code}: ${e.message}`;
      }
    }
  };

  const semantics = data.button_semantics || {};
  for (const b of data.buttons || ['approve', 'use_edited', 'regenerate']) {
    if (b === 'approve') {
      buttons.append(h('button', { class: 'btn primary', text: '✓ 批准（按原文执行）', title: semantics.approve || '', onclick: () => submit('approve') }));
    } else if (b === 'use_edited') {
      buttons.append(h('button', { class: 'btn', text: '✎ 采用编辑版', title: semantics.use_edited || '', onclick: () => submit('use_edited') }));
    } else if (b === 'regenerate') {
      buttons.append(h('button', { class: 'btn', text: '↻ 重生成（需批注）', title: semantics.regenerate || '', onclick: () => {
        if (!regenBox) {
          regenBox = h('div', { class: 'regenerate-box' },
            h('label', { text: '重生成批注 comment（必填，旧 approval_id 永不复用，新表单经 SSE approval_requested / B1 到达）' }),
            commentInput,
          );
          el.insertBefore(regenBox, buttons);
        }
        commentInput.focus();
      } }));
    }
  }
  buttons.append(errLine);
  el.append(buttons);
  container.replaceChildren(el);
}

function openReplay(corr) {
  const body = h('div');
  body.append(h('div', { class: 'loading', text: 'replay 加载中…' }));
  openModal(h('div', { class: 'modal-card', style: 'width:900px' },
    h('h3', { text: 'replay 审计视图（D3）' }),
    h('p', { class: 'muted small', text: '审计视图，非重新执行——side_effects 恒为 none（ARCH §9.3 不变量 3）。' }),
    body,
    h('div', { class: 'row' }, h('button', { class: 'btn', text: '关闭', onclick: closeModal })),
  ));
  api(`${API}/executions/${encodeURIComponent(corr)}/replay`).then((r) => {
    body.replaceChildren(
      h('div', { class: 'kv', text: `correlation ${r.correlation_id} · span ${fmtTime(r.span && r.span.from)} → ${fmtTime(r.span && r.span.to)} · 终态 ${r.terminal_status || '（未终态）'} · side_effects=${r.side_effects}` }),
      h('table', { class: 'steps-table' },
        h('tr', null, h('th', { text: 'seq' }), h('th', { text: 'ts' }), h('th', { text: 'component' }), h('th', { text: 'event_type' }), h('th', { text: 'digest' })),
        (r.steps || []).map((s) => h('tr', null,
          h('td', { text: String(s.seq) }),
          h('td', { text: fmtTime(s.ts) }),
          h('td', { text: s.component }),
          h('td', { text: s.event_type + (s.authorization_changed ? ' ⚠授权已变更' : '') }),
          h('td', { text: s.digest }),
        )),
      ),
      (r.steps || []).length === 0 ? h('div', { class: 'empty', text: '无步骤（任务尚未产生事件）。' }) : null,
    );
  }).catch((e) => body.replaceChildren(h('div', { class: 'error-text', text: e.code + ' ' + e.message })));
}

/* ============================================================
 * 9. 视图三 V3：定时与长期任务（触发器 CRUD + 长跑可见性）
 * ============================================================ */

const missedTriggers = new Set(); // SSE trigger_missed 帧 → 行黄标（会话内）

async function renderTriggers() {
  setTab('v3');
  $('#view').dataset.view = 'triggers';
  const view = $('#view');
  view.replaceChildren(h('div', { class: 'loading', text: '触发器加载中…' }));
  currentRefresh = () => renderTriggers();

  const list = await api(`${API}/triggers`).catch((e) => ({ __error: e, items: [] }));
  const triggers = list.items || [];
  // 列表形态的 recent_fires 为空数组（server.py/triggers.py _public_trigger）→ 逐个取 G3 详情
  const details = await Promise.all(triggers.slice(0, 20).map((t) =>
    api(`${API}/triggers/${encodeURIComponent(t.trigger_id)}`).catch(() => null)));
  // 长跑任务可见性：server source 过滤为单值等值 → cron/webhook 各拉一次
  const [cronTasks, hookTasks, budget] = await Promise.all([
    api(`${API}/tasks?source=cron&limit=50`).catch(() => ({ items: [] })),
    api(`${API}/tasks?source=webhook&limit=50`).catch(() => ({ items: [] })),
    api(`${API}/budget`).catch(() => ({ tasks_at_risk: [] })),
  ]);

  const page = h('div');
  const toolbar = h('div', { class: 'toolbar' },
    h('button', { class: 'btn primary', text: '＋ 新建触发器', onclick: () => openTriggerForm(null) }),
    h('span', { class: 'spacer' }),
    h('span', { class: 'kv', text: `触发器 ${triggers.length} · 启用 ${triggers.filter((t) => t.enabled).length}` }),
  );
  page.append(toolbar);
  if (list.__error) page.append(h('div', { class: 'banner', text: '⚠ 触发器列表拉取失败：' + list.__error.code }));

  if (triggers.length === 0) {
    page.append(h('div', { class: 'empty' }, '还没有触发器——定时汇总、webhook 响应类任务在这里配置。',
      h('div', null, h('button', { class: 'btn sm primary', text: '＋ 新建触发器', onclick: () => openTriggerForm(null) }))));
  }
  triggers.forEach((t, i) => page.append(triggerRow(t, details[i])));

  // 长跑任务可见性区块（TR-06）
  const longrun = [...(cronTasks.items || []), ...(hookTasks.items || [])]
    .filter((t) => !['done', 'failed', 'aborted'].includes(t.status));
  page.append(h('div', { class: 'section-title', text: '长跑任务可见性（cron/webhook 产出的在跑任务）' }));
  if (longrun.length === 0) page.append(h('div', { class: 'empty', text: '当前无触发器产出的在跑任务。' }));
  for (const t of longrun) {
    const risk = (budget.tasks_at_risk || []).find((r) => r.task_id === t.task_id);
    page.append(h('div', { class: 'card' },
      h('div', { class: 'card-top' },
        statusBadge(t.status),
        h('span', { class: 'src-icon', text: SOURCE_META[t.source] || t.source }),
        h('span', { class: 'mono', text: t.task_id }),
        risk ? h('span', { class: 'threshold', text: `预算接近上限 ${fmtUsd(risk.spent_usd_est)}/${fmtUsd(risk.budget_usd)}` }) : null,
      ),
      h('div', { class: 'goal', text: t.goal_summary }),
      h('div', { class: 'actions' }, h('a', { href: `#/task/${encodeURIComponent(t.task_id)}`, text: '详情→' }),
        abortButton(t.task_id, t.status)),
    ));
  }
  // 暂停/续跑口径声明（TR-07，契约缺口 #2 如实声明）
  page.append(h('div', { class: 'pause-declare' },
    h('strong', { text: '暂停 / 续跑口径：' }),
    '定时类 = 触发器停用 / 启用（G4，next_fire_at 停算 / 即时重算）；单次类 = 中止（A5 · T9，不可恢复）+ 重新提交（A1）。用户级 pause/resume 端点契约尚不存在（九态无用户暂停态），面板不提供假暂停按钮。'));
  view.replaceChildren(page);
  refreshRuntimeStrip();
}

function triggerRow(t, detail) {
  const row = h('div', { class: 'trg-row' + (t.enabled ? '' : ' disabled-row') });
  const head = h('div', { class: 't-head' },
    h('span', { text: '▣' }),
    h('span', { class: 'badge ' + (t.type === 'cron' ? 'type-cron' : 'type-webhook'), text: t.type }),
    h('span', { class: 'tid', text: t.trigger_id }),
    t.type === 'cron' && t.schedule ? h('span', { class: 'mono', text: `${t.schedule}（${t.timezone || '容器 TZ'}）` }) : null,
    h('span', { class: 'kv', text: t.enabled ? '启用 ●' : '已停用 ○' }),
    missedTriggers.has(t.trigger_id) ? h('span', { class: 'missed-flag', text: '停机期间错过，恢复后已补跑一次（不按倍数追赶）' }) : null,
  );
  row.append(head);
  if (t.type === 'cron') {
    row.append(h('div', { class: 't-body' }, '下次触发：',
      t.enabled && t.next_fire_at ? h('strong', { text: fmtTime(t.next_fire_at) })
        : h('span', { class: 'muted', text: t.enabled ? '—（计算中）' : '—（已停用）' }),
    ));
  } else {
    row.append(h('div', { class: 't-body' }, '下次触发：—（事件驱动，next_fire_at 恒为 null）'));
    if (t.ingest_path) {
      row.append(h('div', { class: 't-body mono' }, '入口 POST ' + t.ingest_path + ' ',
        h('button', { class: 'btn sm', text: '复制', onclick: () => copyText(location.origin + t.ingest_path, 'ingest URL') }),
        h('span', { class: 'kv', text: ' 调用方须带 X-Agentmesh-Signature: sha256=… HMAC 头（ICON §7.6）' })),
      );
    }
    row.append(h('div', { class: 't-body' }, 'secret 模式：' + (t.secret_mode || '—') +
      (t.secret_ref ? `（密文库引用：${t.secret_ref}）` : '') + ' · 永不显示 secret 值'));
  }
  const tplFull = t.goal_template || '';
  const tplShort = tplFull.length > 120 ? tplFull.slice(0, 120) + '…' : tplFull;
  const tplSpan = h('span', { class: 'template', text: tplShort });
  const tplBtn = tplFull.length > 120 ? h('button', { class: 'btn sm', text: '展开', onclick: (e) => {
    const full = tplSpan.textContent === tplShort;
    tplSpan.textContent = full ? tplFull : tplShort;
    e.target.textContent = full ? '收起' : '展开';
  } }) : null;
  row.append(h('div', { class: 't-body' }, '模板：', tplSpan, ' ', tplBtn));

  // recent_fires 小表（TR-04）
  const fires = (detail && detail.recent_fires) || [];
  if (fires.length) {
    row.append(h('table', { class: 'fires-table' },
      h('tr', null, h('th', { text: 'fired_at' }), h('th', { text: 'task_id' }), h('th', { text: 'task_status' })),
      fires.map((f) => h('tr', null,
        h('td', { text: fmtTime(f.fired_at) }),
        h('td', null, f.task_id ? h('a', { href: `#/task/${encodeURIComponent(f.task_id)}`, text: f.task_id }) : '—'),
        h('td', { text: f.task_status || '—' }),
      )),
    ));
  }

  const actions = h('div', { class: 't-actions' });
  actions.append(h('button', {
    class: 'btn sm', text: t.enabled ? '停用' : '启用',
    onclick: () => {
      const disabling = t.enabled;
      const doPatch = () => patchTrigger(t.trigger_id, { enabled: !t.enabled });
      if (disabling) {
        openConfirm({
          title: '停用触发器（G4）',
          message: 'webhook 入口将返回 404 TRIGGER_DISABLED；已入队任务不受影响。cron 停算 next_fire_at。',
          confirmText: '停用',
          onConfirm: async () => { await doPatch(); closeModal(); },
        });
      } else doPatch();
    },
  }));
  actions.append(h('button', { class: 'btn sm', text: '编辑', onclick: () => openTriggerForm(t) }));
  if (t.type === 'webhook') {
    const refMode = t.secret_mode === 'ref' || t.secret_ref;
    actions.append(h('button', {
      class: 'btn sm', text: '轮换 secret', disabled: refMode ? '' : null,
      title: refMode ? '引用模式轮换走密文库流程（引用不变，响应 409 SECRET_REF_IMMUTABLE）' : '生成新随机 secret，旧 secret 立即失效',
      onclick: () => {
        if (refMode) { toast('secret_ref 模式轮换走密文库流程（CRED §9.1），API 面返回 409 SECRET_REF_IMMUTABLE'); return; }
        openConfirm({
          title: '轮换 webhook secret（G4）',
          message: '旧 secret 立即失效；新 secret 只在响应中出现这一次。',
          confirmText: '轮换',
          onConfirm: async () => { await patchTrigger(t.trigger_id, { rotate_secret: true }); closeModal(); },
        });
      },
    }));
  }
  actions.append(h('button', {
    class: 'btn sm danger', text: '删除',
    onclick: () => openConfirm({
      title: '删除触发器（G5）',
      message: '历史任务不受影响（任务与触发器解耦，审计靠 trigger_fired 事件留存）。',
      confirmText: '删除', danger: true,
      onConfirm: async () => {
        await api(`${API}/triggers/${encodeURIComponent(t.trigger_id)}`, { method: 'DELETE' });
        closeModal();
        toast('触发器已删除；历史任务不受影响', 'ok');
        renderTriggers();
      },
    }),
  }));
  row.append(actions);
  return row;
}

async function patchTrigger(triggerId, body) {
  try {
    const res = await api(`${API}/triggers/${encodeURIComponent(triggerId)}`, { method: 'PATCH', body });
    if (res && res.secret_once) showSecretOnce(res.secret_once);
    else toast('触发器已更新', 'ok');
    renderTriggers();
  } catch (e) {
    if (e.code === 'SECRET_REF_IMMUTABLE') toast('409 SECRET_REF_IMMUTABLE：引用模式轮换走密文库流程', 'err');
    else toast(`${e.code}: ${e.message}`, 'err');
  }
}

function showSecretOnce(secret) {
  openModal(h('div', { class: 'modal-card' },
    h('h3', { text: '新 secret（只显示这一次）' }),
    h('p', { class: 'muted small', text: '关闭后无法再次查看；丢失即轮换（服务端无读取端点）。面板绝不持久化该值。' }),
    h('div', { class: 'once-secret', text: secret }),
    h('div', { class: 'row' },
      h('button', { class: 'btn', text: '复制', onclick: () => copyText(secret, 'secret_once') }),
      h('button', { class: 'btn primary', text: '我已保存，关闭', onclick: closeModal }),
    ),
  ));
}

function openTriggerForm(existing) {
  const isEdit = !!existing;
  const errLine = h('div', { class: 'error-text' });
  const typeCron = h('input', { type: 'radio', name: 'trg-type', value: 'cron' });
  const typeHook = h('input', { type: 'radio', name: 'trg-type', value: 'webhook' });
  if (!isEdit || existing.type === 'cron') typeCron.checked = true; else typeHook.checked = true;
  const schedule = h('input', { type: 'text', placeholder: '0 9 * * *（标准 5 段 cron）' });
  const timezone = h('input', { type: 'text', placeholder: 'IANA 名，留空=容器 TZ（如 Asia/Shanghai）' });
  const template = h('textarea', { rows: '4', placeholder: '≤8000 字符；webhook 支持 {{payload.<dotted.path>}} 占位——缺键不拒绝事件，占位符保留原样并标 template_degraded' });
  schedule.value = isEdit && existing.schedule || '';
  timezone.value = isEdit && existing.timezone || '';
  template.value = isEdit ? existing.goal_template || '' : '';
  const secretGen = h('input', { type: 'radio', name: 'trg-secret', value: 'generated', checked: '' });
  const secretRef = h('input', { type: 'radio', name: 'trg-secret', value: 'ref' });
  const secretRefInput = h('input', { type: 'text', placeholder: 'credentials.enc 中的 key_name' });
  const webhookFields = h('div', null,
    h('label', null, 'secret 模式（二选一）'),
    h('label', null, secretGen, ' generated（服务端生成 32 字节随机 secret，创建后一次性展示）'),
    h('label', null, secretRef, ' secret_ref（引用密文库条目；凭证通道未接线时将返回 SECRET_REF_NOT_FOUND）'),
    secretRefInput,
  );

  const showCronFields = !isEdit || existing.type === 'cron';
  const modal = h('div', { class: 'modal-card' },
    h('h3', { text: isEdit ? '编辑触发器（G4 字段级 PATCH）' : '新建触发器（G1）' }),
    isEdit ? h('div', { class: 'kv mono', text: existing.trigger_id }) :
      h('div', { class: 'row', style: 'justify-content:flex-start' }, h('label', null, typeCron, ' cron'), h('label', null, typeHook, ' webhook')),
    showCronFields ? h('div', null,
      h('label', { text: 'schedule（5 段 cron 表达式）' }), schedule,
      h('label', { text: 'timezone（IANA；时区语义按容器 TZ 解析，触发器可覆盖）' }), timezone,
    ) : null,
    isEdit ? null : webhookFields,
    h('label', { text: 'goal_template' }), template,
    errLine,
    h('div', { class: 'row' },
      h('button', { class: 'btn', text: '取消', onclick: closeModal }),
      h('button', {
        class: 'btn primary', text: isEdit ? '保存（PATCH 给哪个改哪个）' : '创建',
        onclick: async () => {
          errLine.textContent = '';
          try {
            if (isEdit) {
              const body = {};
              if (existing.type === 'cron' && schedule.value.trim()) body.schedule = schedule.value.trim();
              if (template.value && template.value !== existing.goal_template) body.goal_template = template.value;
              await api(`${API}/triggers/${encodeURIComponent(existing.trigger_id)}`, { method: 'PATCH', body });
              toast('触发器已更新', 'ok');
            } else {
              const type = typeCron.checked ? 'cron' : 'webhook';
              const body = { type, goal_template: template.value, enabled: true };
              if (type === 'cron') {
                body.schedule = schedule.value.trim();
                if (timezone.value.trim()) body.timezone = timezone.value.trim();
              } else if (secretRef.checked && secretRefInput.value.trim()) {
                body.secret_ref = secretRefInput.value.trim();
              }
              if (!body.goal_template || !body.goal_template.trim()) throw { code: 'TEMPLATE_REQUIRED', message: 'goal_template 必填' };
              const res = await api(`${API}/triggers`, { method: 'POST', body, headers: { 'Idempotency-Key': uuid() } });
              if (res.secret_once) showSecretOnce(res.secret_once);
              else toast('触发器已创建', 'ok');
            }
            closeModal();
            renderTriggers();
          } catch (e) {
            errLine.textContent = `${e.code || ''}: ${e.message || ''}`.trim();
          }
        },
      }),
    ),
  );
  openModal(modal);
}

/* ============================================================
 * 10. 视图四 V4：错误账本（签名聚合 + 规则沉淀状态）
 * ============================================================ */

let v4TypeFilter = '';

async function renderErrors() {
  setTab('v4');
  $('#view').dataset.view = 'errors';
  const view = $('#view');
  view.replaceChildren(h('div', { class: 'loading', text: '错误账本加载中…' }));
  currentRefresh = () => renderErrors();

  const [errorsRes, rulesRes, health] = await Promise.all([
    api(`${API}/errors?limit=200`).catch((e) => ({ __error: e })),
    api(`${API}/errors/rules`).catch((e) => ({ __error: e })), // server status 过滤仅单值 → 全量拉取后分组
    fetch('/healthz').then((r) => (r.ok ? r.json() : {})).catch(() => ({})),
  ]);
  const ftsDown = (health.degradations || []).includes('fts_unavailable');
  const rows = errorsRes.items || [];
  const rules = rulesRes.items || [];

  const page = h('div');
  // 工具栏（ER-02 搜索 + ER-07 降级提示）
  const searchInput = h('input', { type: 'search', placeholder: 'FTS5 关键词（空格分词，尾缀 * 前缀匹配）' });
  const searchBtn = h('button', { class: 'btn', text: '搜索' });
  const searchNote = h('div', { class: 'search-degraded-note' });
  if (ftsDown) { searchInput.disabled = true; searchNote.textContent = '全文检索不可用（healthz fts_unavailable）——签名过滤/日期过滤仍可用'; }
  searchBtn.addEventListener('click', () => runErrorSearch(searchInput, searchNote, page));
  searchInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') runErrorSearch(searchInput, searchNote, page); });
  const typeSelect = h('select', null,
    h('option', { value: '', text: '按类型（全部）' }),
    [...new Set(rows.map((r) => r.error_type))].sort().map((t) => h('option', { value: t, text: t })),
  );
  if (v4TypeFilter) typeSelect.value = v4TypeFilter;
  typeSelect.addEventListener('change', () => { v4TypeFilter = typeSelect.value; renderErrors(); });
  page.append(h('div', { class: 'toolbar' },
    searchInput, searchBtn, typeSelect, h('span', { class: 'spacer' }),
    h('span', { class: 'kv', text: `明细 ${rows.length} 条（聚合为客户端尽力视图；契约无服务端聚合端点，缺口 #3）` }),
  ));
  page.append(searchNote);

  // A 区聚合（FRU-01 §5.1 算法：signature_hash 等值分组）
  const sourceErrIds = new Set(rules.flatMap((r) => r.source_error_ids || []));
  const groups = new Map();
  for (const r of rows) {
    if (v4TypeFilter && r.error_type !== v4TypeFilter) continue;
    const g = groups.get(r.signature_hash) || { sample: r, count: 0, latest: r.occurred_at, roles: new Set(), tasks: new Set(), errorIds: [] };
    g.count = Math.max(g.count, r.occurrence_count_same_signature || 1);
    if (r.occurred_at > g.latest) { g.latest = r.occurred_at; g.sample = r; }
    g.roles.add(r.role); g.tasks.add(r.task_id); g.errorIds.push(r.id);
    groups.set(r.signature_hash, g);
  }
  const sorted = [...groups.values()].sort((a, b) => (a.latest < b.latest ? 1 : -1));

  const aggBox = h('div');
  if (rows.length === 0) aggBox.append(h('div', { class: 'empty', text: '账本干净——还没有登记过任何错误。' }));
  for (const g of sorted) {
    const pendingCheck = g.count >= 2 && !g.errorIds.some((id) => sourceErrIds.has(id));
    const cardEl = h('div', { class: 'agg-card' },
      h('div', { class: 'sig', text: g.sample.error_signature }),
      g.sample.param_pattern ? h('div', { class: 'pat', text: '[' + g.sample.param_pattern + ']' }) : null,
      h('div', { class: 'a-meta' },
        h('span', { text: `×${g.count}` }),
        h('span', { text: '最近 ' + fmtTime(g.latest) }),
        h('span', { text: [...g.roles].join(' / ') }),
        h('span', { text: `${g.tasks.size} 个任务` }),
        pendingCheck ? h('span', { class: 'threshold', text: '同签名≥2 次，待沉淀检查（客户端推导口径）' }) : null,
      ),
      h('div', { class: 'actions' },
        h('a', { href: 'javascript:;', text: `查看 ${g.errorIds.length} 条记录→`, onclick: (e) => { e.preventDefault(); toggleAggDetail(cardEl, g.sample.signature_hash); } }),
        h('a', { href: 'javascript:;', text: '详情→', onclick: (e) => { e.preventDefault(); openErrorDetail(g.sample.id); } }),
      ),
      h('div', { class: 'agg-detail' }),
    );
    aggBox.append(cardEl);
  }

  // B 区规则沉淀状态（ER-04/ER-05）
  const candidates = rules.filter((r) => r.status === 'candidate');
  const actives = rules.filter((r) => r.status === 'active');
  const retires = rules.filter((r) => r.status === 'retired');
  const rulesBox = h('div');
  const pendingN = candidates.filter((r) => !r.reviewed_by).length;
  if (pendingN > 0) {
    page.append(h('div', { class: 'banner' },
      `⚠ ${pendingN} 条候选规则待人工审核（同签名≥2 次触发沉淀检查） `,
      h('a', { href: 'javascript:;', text: '去审核→', onclick: () => rulesBox.scrollIntoView({ behavior: 'smooth' }) })));
  }
  const ruleGroup = (title, list, extraNote) => {
    const box = h('div', { class: 'rule-group' }, h('h4', { text: `${title}（${list.length}）` }));
    if (extraNote) box.append(h('span', { class: 'kv', text: extraNote }));
    if (list.length === 0) box.append(h('div', { class: 'empty', text: '无' }));
    for (const r of list) box.append(ruleRow(r));
    return box;
  };
  if (rules.length === 0) {
    rulesBox.append(h('div', { class: 'empty', text: '尚无沉淀规则；错误累计同签名 ≥2 次会自动生成候选规则。' }));
  } else {
    rulesBox.append(ruleGroup('⚑ candidate —— 待人工审核', candidates));
    rulesBox.append(ruleGroup('● active —— 参与检索注入', actives));
    rulesBox.append(ruleGroup('○ retired —— 废止（可复活）', retires));
  }

  page.append(h('div', { class: 'err-grid' },
    h('div', { class: 'panel' }, h('h3', { text: 'A · 错误签名聚合列表' }), aggBox),
    h('div', { class: 'panel' }, h('h3', { text: 'B · 规则沉淀状态（F4/F5）' }), rulesBox),
  ));
  if (errorsRes.__error) page.append(h('div', { class: 'banner bad', text: '⚠ 错误列表拉取失败：' + errorsRes.__error.code }));
  view.replaceChildren(page);
  refreshRuntimeStrip();
}

function ruleRow(r) {
  const row = h('div', { class: 'rule-row' });
  row.append(h('div', { class: 'r-text', text: `r${r.id}「${r.rule_text}」` }));
  row.append(h('div', { class: 'r-meta' },
    r.match_keywords ? h('span', { text: '关键词: ' + r.match_keywords }) : null,
    h('span', { text: 'task_types: ' + (r.task_types || '*') }),
    h('span', { text: `×${r.occurrences}` }),
    h('span', { text: '风险: ' + (r.risk_level || '—') }),
    r.reviewed_by ? h('span', { text: '审核人: ' + r.reviewed_by }) : h('span', { text: '未审核' }),
    r.auto_activated ? h('span', { class: 'candidate-flag', text: '低风险白名单自动生效' }) : null,
  ));
  const actions = h('div', { class: 'r-actions' });
  const review = (action, fields, title) => {
    openConfirm({
      title,
      fields,
      confirmText: '提交审核',
      onConfirm: async (v) => {
        const body = { action };
        if (v.reviewer) body.reviewer = v.reviewer;
        if (v.reason) body.reason = v.reason;
        const res = await api(`${API}/errors/rules/${r.id}/review`, { method: 'POST', body });
        toast(`规则 r${r.id} → ${res.status}；${res.export_note || ''}`, 'ok');
        closeModal();
        renderErrors();
      },
    });
  };
  if (r.status === 'candidate') {
    // candidate 不提供废止按钮（retire 一个 candidate → 400 INVALID_TRANSITION，前端直接禁用）
    actions.append(h('button', { class: 'btn sm primary', text: '通过✓', onclick: () =>
      review('approve', [{ key: 'reviewer', label: '审核人 reviewer（必填，单用户部署为操作者标识）', required: true }], `人工审核通过 r${r.id}（candidate→active）`) }));
  } else if (r.status === 'active') {
    actions.append(h('button', { class: 'btn sm danger', text: '废止', onclick: () =>
      review('retire', [
        { key: 'reason', label: '废止原因 reason（必填，retire_reason）', required: true },
        { key: 'reviewer', label: '操作者 reviewer（必填）', required: true },
      ], `废止规则 r${r.id}（active→retired）`) }));
  } else if (r.status === 'retired') {
    actions.append(h('button', { class: 'btn sm', text: '复活（再审核）', onclick: () =>
      review('approve', [{ key: 'reviewer', label: '审核人 reviewer（必填）', required: true }], `重新审核启用 r${r.id}（retired→active）`) }));
    if (r.retire_reason) row.append(h('div', { class: 'kv', text: '废止原因：' + r.retire_reason }));
  }
  row.append(actions);
  return row;
}

async function toggleAggDetail(cardEl, signatureHash) {
  const slot = cardEl.querySelector('.agg-detail');
  if (slot.dataset.open) { slot.replaceChildren(); slot.dataset.open = ''; return; }
  slot.dataset.open = '1';
  slot.replaceChildren(h('div', { class: 'loading', text: '明细加载中…' }));
  try {
    const r = await api(`${API}/errors?signature_hash=${encodeURIComponent(signatureHash)}&limit=50`);
    slot.replaceChildren(...(r.items || []).map((e) => h('div', { class: 'err-detail-row' },
      h('div', null, `#${e.id} · ${fmtTime(e.occurred_at)} · ${e.role} · task ${e.task_id || '—'} `,
        h('a', { href: 'javascript:;', text: '详情→', onclick: (ev) => { ev.preventDefault(); openErrorDetail(e.id); } })),
      e.root_cause ? h('div', { class: 'kv', text: '根因: ' + e.root_cause }) : null,
      e.fix_applied ? h('div', { class: 'kv', text: '修复: ' + e.fix_applied }) : null,
    )));
    if (!r.items || r.items.length === 0) slot.replaceChildren(h('div', { class: 'empty', text: '无明细。' }));
  } catch (e) {
    slot.replaceChildren(h('div', { class: 'error-text', text: '明细查询不可用：' + e.code }));
  }
}

async function openErrorDetail(errorId) {
  const body = h('div');
  body.append(h('div', { class: 'loading', text: '加载中…' }));
  openModal(h('div', { class: 'modal-card', style: 'width:760px' },
    h('h3', { text: '错误详情（F2）' }),
    body,
    h('div', { class: 'row' }, h('button', { class: 'btn', text: '关闭', onclick: closeModal })),
  ));
  try {
    const e = await api(`${API}/errors/${errorId}`);
    const rows = [
      ['error_signature', e.error_signature], ['signature_hash', e.signature_hash],
      ['error_type @ module', `${e.error_type} @ ${e.module}`], ['param_pattern', e.param_pattern],
      ['task_id', e.task_id], ['role', e.role], ['occurred_at', fmtTime(e.occurred_at)],
      ['occurrence_count_same_signature', e.occurrence_count_same_signature],
      ['root_cause', e.root_cause], ['fix_applied', e.fix_applied],
      ['prevention_suggestion', e.prevention_suggestion],
    ];
    body.replaceChildren(
      ...rows.filter(([, v]) => v != null && v !== '').map(([k, v]) => h('div', { class: 'kv' }, h('strong', { text: k + '：' }), h('span', { text: String(v) }))),
      h('label', { text: `raw_error（≤4000 字符，已过 write_guard 脱敏${e.raw_error_truncated ? '；列表侧 truncated=true' : ''}）` }),
      h('pre', { class: 'mono small', style: 'white-space:pre-wrap;background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:8px', text: e.raw_error || '（空）' }),
    );
  } catch (err) {
    body.replaceChildren(h('div', { class: 'error-text', text: err.code + ' ' + err.message }));
  }
}

async function runErrorSearch(input, note, page) {
  const q = input.value.trim();
  if (!q) { note.textContent = 'EMPTY_QUERY：搜索词不能为空（前端拦截）'; return; }
  note.textContent = '搜索中…';
  try {
    const r = await api(`${API}/errors/search?q=${encodeURIComponent(q)}&limit=50`);
    const found = r.items || [];
    if (found.length === 0 && r.matched_by === 'fts' && !r.degraded) {
      note.textContent = '0 命中——中文关键词命中是已知分词边界（unicode61 按空白切词），请改用签名哈希/错误类型过滤';
    } else {
      note.textContent = `FTS 命中 ${found.length} 条（matched_by=${r.matched_by}）`;
    }
    const box = h('div', { class: 'panel' }, h('h3', { text: `搜索结果：${q}` }));
    box.append(...found.map((e) => h('div', { class: 'err-detail-row' },
      h('div', null, `#${e.id} · ${e.error_signature} · ${fmtTime(e.occurred_at)} `,
        h('a', { href: 'javascript:;', text: '详情→', onclick: (ev) => { ev.preventDefault(); openErrorDetail(e.id); } })),
    )));
    if (found.length === 0) box.append(h('div', { class: 'empty', text: '无命中。' }));
    const old = page.querySelector('.search-results');
    if (old) old.replaceWith(box); else page.insertBefore(box, page.querySelector('.err-grid'));
    box.classList.add('search-results');
  } catch (e) {
    note.textContent = `${e.code}: ${e.message}`;
  }
}

/* ============================================================
 * 11. SSE → 视图刷新映射（OV-07 / TR-08 / ER-08）与启动
 * ============================================================ */

const REFRESH_ON = {
  state_transition: ['v1', 'task'],
  approval_requested: ['v1', 'task'],
  approval_decision: ['v1', 'task'],
  approval_timeout_skip: ['v1', 'task'],
  budget_exceeded: ['v1'],
  task_aborted: ['v1'],
  error_registered: ['v1', 'v4'],
  rule_candidate: ['v4'],
  trigger_fired: ['v1', 'v3'],
  trigger_missed: ['v3'],
  task_submitted: ['v3'],
};

function wireSseRouting() {
  eventBus.on('*', (frame) => {
    if (frame.event === 'memory_degraded') noteMemoryDegraded(frame.data && frame.data.payload || {});
    if (frame.event === 'trigger_missed' && frame.data && frame.data.payload && frame.data.payload.trigger_id) {
      missedTriggers.add(frame.data.payload.trigger_id);
    }
    const targets = REFRESH_ON[frame.event];
    if (!targets) return;
    if (currentRoute && targets.includes(currentRoute.name)) scheduleViewRefresh();
    // 任务详情的审批面板由全局流刷新（approval_requested 携带新表单到达）
  });
}

function tickCountdowns() {
  document.querySelectorAll('[data-expires]').forEach((el) => {
    const iso = el.getAttribute('data-expires');
    if (iso) el.textContent = `等待截止 ${fmtCountdown(iso)}`;
  });
}

function bindGate() {
  const save = async () => {
    const t = $('#token-input').value.trim();
    if (!t) { $('#token-error').textContent = '令牌不能为空'; return; }
    setToken(t);
    try {
      await api(`${API}/runtime/metrics`); // 便宜端点验证令牌
      $('#token-gate').classList.add('hidden');
      await startApp();
    } catch (e) {
      setToken('');
      if (e.status !== 401) $('#token-error').textContent = e.message || String(e);
    }
  };
  $('#token-save').addEventListener('click', save);
  $('#token-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
  $('#btn-logout').addEventListener('click', () => { setToken(''); location.hash = '#/'; location.reload(); });
  $('#kernel-retry').addEventListener('click', () => { hideKernelDown(); pollHealth(); });
}

async function startApp() {
  $('#app').classList.remove('hidden');
  await pollHealth();
  refreshBudgetBar();
  refreshRuntimeStrip();
  openGlobalStream();
  wireSseRouting();
  if (!location.hash) location.hash = '#/';
  await route();
  setInterval(tickCountdowns, 30000);
  setInterval(refreshRuntimeStrip, 30000);
  setInterval(refreshBudgetBar, 60000);
  setInterval(pollHealth, 30000);
}

async function boot() {
  bindGate();
  bindNewTaskDrawer();
  bindApprovalDrawer();
  window.addEventListener('hashchange', () => {
    if (window.__taskStreamCtl) window.__taskStreamCtl.abort();
    route();
  });
  if (TOKEN) {
    try {
      await api(`${API}/runtime/metrics`);
      await startApp();
    } catch (e) {
      if (e.status !== 401 && !kernelDownShown) showTokenGate('令牌校验失败：' + (e.message || e.code));
    }
  } else {
    showTokenGate('');
  }
}

document.addEventListener('DOMContentLoaded', boot);
})();
