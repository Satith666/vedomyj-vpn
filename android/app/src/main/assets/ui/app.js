"use strict";
/* VEDOMYJ VPN для Android — интерфейс. Движок — в Java (window.Pult.call). Состояние опрашивается раз в секунду. */
(function () {
  const P = window.Pult;
  const $ = (s, el) => (el || document).querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const icon = (n, cls) => `<svg class="i${cls ? " " + cls : ""}"><use href="#i-${n}"/></svg>`;

  let lang = "ru";
  function t(key, vars) {
    const d = window.I18N[lang] || window.I18N.ru;
    let s = d[key] != null ? d[key] : (window.I18N.ru[key] != null ? window.I18N.ru[key] : key);
    if (vars) for (const k in vars) s = s.split("{" + k + "}").join(vars[k]);
    return s;
  }

  // ---------- связь с движком ----------
  function call(action, args) {
    const raw = P.call(action, JSON.stringify(args || {}));
    const r = JSON.parse(raw);
    if (!r.ok) throw new Error(r.error || "error");
    return r.result;
  }
  function act(action, args) {
    try {
      return call(action, args);
    } catch (e) {
      toast(e.message, "error");
      return undefined;
    }
  }

  // ---------- подсказки ----------
  let toastTimer = 0;
  function toast(text, kind) {
    const el = $("#toast");
    el.textContent = text;
    el.className = "toast" + (kind ? " " + kind : "");
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, kind === "error" ? 6500 : 3200);
  }

  // ---------- шторка снизу ----------
  let sheetClose = null;
  function openSheet(html, mount, onClose) {
    const sh = $("#sheet");
    sh.innerHTML = html;
    sh.hidden = false;
    $("#sheetBack").hidden = false;
    sheetClose = onClose || null;
    if (mount) mount(sh);
  }
  function closeSheet() {
    if ($("#sheet").hidden) return false;
    $("#sheet").hidden = true;
    $("#sheetBack").hidden = true;
    $("#sheet").innerHTML = "";
    const f = sheetClose;
    sheetClose = null;
    if (f) f();
    return true;
  }

  // ---------- состояние ----------
  let S = null;
  let lastJson = "";
  let lastMsg = -1;
  function poll() {
    let st;
    try { st = call("state"); } catch (e) { return; }
    const js = JSON.stringify(st);
    if (js === lastJson) return;
    lastJson = js;
    const first = S === null;
    S = st;
    if (lang !== st.lang) { lang = st.lang; document.documentElement.lang = lang; render(); }
    applyTheme();
    const m = st.message || {};
    if (first) lastMsg = m.id || 0;
    else if (m.id && m.id !== lastMsg) { lastMsg = m.id; if (m.text) toast(m.text, m.kind); }
    $("#problems").hidden = !(st.problems && st.problems.length);
    const famWait = ((st.family || {}).helpers || []).some((h) => h.pending);
    $("#familyBtn").classList.toggle("wait", famWait);
    $("#familyTxt").textContent = t("fam_btn");
    if (first) render(); else update();
    warpWatch();
    nwWatch();
  }

  // «Создать бесплатный WARP»: регистрация идёт в фоне — когда готово, сразу показать, как передать его в AmneziaWG
  let warpWait = null;
  function warpWatch() {
    if (warpWait === null || !S) return;
    if (S.warp && S.warp !== warpWait) { warpWait = null; awgSheet(S.warp); }
    else if (!S.task || S.task.kind !== "update") warpWait = null; // не получилось — ошибку уже показали
  }

  let themeApplied = "";
  function applyTheme() {
    const pref = (S && S.settings.theme) || "auto";
    const dark = pref === "dark" || (pref === "auto" && !(window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches));
    const th = dark ? "dark" : "light";
    document.documentElement.dataset.theme = th;
    if (themeApplied !== th) { themeApplied = th; act("theme", { dark }); }
  }

  // ---------- навигация ----------
  const stack = ["home"];
  const scrolls = []; // где был каждый экран в стеке — «Назад» возвращает туда же, а не наверх
  function go(name) { closeSheet(); scrolls[stack.length - 1] = window.scrollY; stack.push(name); render(); window.scrollTo(0, 0); }
  function back() {
    if (closeSheet()) return true;
    if (stack.length > 1) {
      stack.pop();
      render();
      const y = scrolls[stack.length - 1] || 0;
      window.scrollTo(0, y);
      requestAnimationFrame(() => window.scrollTo(0, y)); // после того как экран дорисуется
      return true;
    }
    return false;
  }
  window.pultBack = back;
  window.pultGo = go; // проверка интерфейса (coretest/ui_walk.js) открывает экраны напрямую

  function render() {
    if (!S) return;
    const name = stack[stack.length - 1];
    const v = VIEWS[name];
    const sub = name !== "home";
    $("#back").hidden = !sub;
    $("#brand").hidden = sub;
    $("#title").hidden = !sub;
    $("#title").textContent = sub ? t(v.title) : "";
    $("#settingsBtn").hidden = sub;
    $("#familyBtn").hidden = sub;
    document.querySelector(".topbar").classList.toggle("sub", sub);
    $("#view").innerHTML = v.render();
    if (v.mount) v.mount();
    if (v.update) v.update();
  }
  function update() {
    const v = VIEWS[stack[stack.length - 1]];
    if (v.update) v.update();
  }

  function setHtml(sel, html) {
    const el = $(sel);
    if (el && el.innerHTML !== html) el.innerHTML = html;
  }

  // ---------- главная ----------
  let showAll = false;
  function pingCls(ms) { return ms < 0 ? "none" : ms < 150 ? "good" : ms < 400 ? "mid" : "bad"; }

  function heroHtml() {
    const busy = S.busy && S.busy.title;
    const on = S.status === "on";
    const weak = on && S.delay < 0;
    const switching = S.conn && S.conn.title && S.conn.kind === "connect";
    const cls = S.status === "connecting" ? "busy" : weak ? "weak" : on ? "on" : switching ? "busy" : "";
    const srv = S.server;
    let line, sub;
    if (S.status === "connecting") { line = t("st_connecting"); sub = S.conn && S.conn.title ? S.conn.title : ""; }
    else if (weak) { line = t("st_weak"); sub = t("st_weak_sub"); }
    else if (on) {
      line = t("st_on");
      sub = (srv ? srv.name : "") + (S.delay > 0 ? " · " + S.delay + " " + t("ms") : "");
    }
    else if (S.method === "off" && S.filter_on) { line = t("st_novpn"); sub = t("st_novpn_sub"); }
    else { line = t("st_off"); sub = S.filter_on ? t("st_off_filter") : t("st_off_sub"); }
    return `<button class="power ${cls}" data-act="toggle" aria-label="${esc(on ? t("st_on") : t("st_off"))}">
        <svg class="ring" viewBox="0 0 148 148"><circle class="bg" cx="74" cy="74" r="70"/><circle class="fg" cx="74" cy="74" r="70"/></svg>
        ${icon("power")}</button>
      <div><div class="status-line ${cls}">${esc(line)}</div><div class="status-sub">${esc(sub)}</div></div>`;
  }

  function rate(bps) {
    if (bps >= 1048576) return (bps / 1048576).toFixed(1).replace(".", lang === "ru" ? "," : ".") + " " + t("mb_s");
    return Math.round(Math.max(0, bps) / 1024) + " " + t("kb_s");
  }
  function speedHtml() {
    const live = S.status === "on" || S.filter_on;
    const sp = S.speed || {};
    const tst = S.speed_test;
    const running = S.task && S.task.kind === "speed";
    const left = live ? `<span class="spd"><b>↓</b> ${esc(rate(sp.down || 0))}</span><span class="spd"><b>↑</b> ${esc(rate(sp.up || 0))}</span>`
      : (tst ? `<span class="spd">${esc(t("speed_last", { v: String(tst.mbps).replace(".", lang === "ru" ? "," : ".") }))}</span>` : "");
    const res = live && tst ? `<span class="spd muted">${esc(t("speed_short", { v: String(tst.mbps).replace(".", lang === "ru" ? "," : ".") }))}</span>` : "";
    const btn = running ? `<span class="spd muted">${esc(t("speed_running"))}</span>`
      : `<button class="link-btn" data-act="speed-test">${esc(t("speed_test"))}</button>`;
    return left + res + btn;
  }

  function busyHtml() {
    const b = S.task || {};
    if (!b.title) return "";
    return `<span>${esc(b.title)}…</span><button class="link-btn" data-act="stop">${esc(t("stop"))}</button>`;
  }

  function modeHtml() {
    const m = S.settings.mode === "smart" ? "smart" : "vpn";
    const note = m === "vpn" ? (S.settings.ru_direct ? t("mode_vpn_note_ru") : t("mode_vpn_note")) : t("mode_smart_note");
    return `<div class="seg" role="group">
        <button data-act="mode" data-v="vpn" aria-pressed="${m === "vpn"}">${esc(t("mode_vpn"))}</button>
        <button data-act="mode" data-v="smart" aria-pressed="${m === "smart"}">${esc(t("mode_smart"))}</button></div>
      <p class="hint seg-note">${esc(note)}</p>
      <div class="card eng-card">${navRow('data-act="engine"', "swap", t("eng_title"), engName((S.engine || {}).pick || "auto"))}</div>`;
  }

  // ---------- новый главный экран (как на ПК): путь трафика, способ, три переключателя ----------
  function routeHtml() {
    const on = S.status === "on", busy = S.status === "connecting";
    const accel = (S.dpi || {}).active && (on || S.filter_on);
    const node = (ic, name, sub, live) => `<div class="rt-node${live ? " live" : ""}"><span class="rt-ico">${icon(ic)}</span>
      <span class="rt-text"><b>${esc(name)}</b><small>${esc(sub)}</small></span></div>`;
    const line = `<span class="rt-line${busy ? " busy" : on || S.filter_on ? " on" : ""}" aria-hidden="true"></span>`;
    const parts = [node("phone", t("rt_phone"), "", true)];
    if (accel) parts.push(node("swap", t("rt_accel"), "", true));
    if (on && S.server) parts.push(node("server", t("rt_server"), S.server.name, true));
    parts.push(node("globe", t("rt_net"), on ? "VPN" : t("rt_direct"), on || S.filter_on));
    return `<div class="route" aria-label="${esc(t("rt_title"))}">${parts.join(line)}</div>`;
  }

  const METHODS = ["auto", "server", "awg", "off"];
  function methodHtml() {
    const m = S.method || "auto";
    const E = (S.engine || {}).counts || {};
    const sel = S.settings.selected ? (S.servers || []).find((x) => x.key === S.settings.selected) : null;
    const subs = {
      auto: t("m_auto_sub"),
      server: sel ? sel.name : S.server && S.status === "on" ? S.server.name : t("m_server_none"),
      awg: E.awg ? t("m_awg_ready") : t("m_awg_warp"),
      off: t("m_off_sub"),
    };
    const pick = (S.engine || {}).pick || "auto";
    if (pick !== "auto" && pick !== "awg") subs.server += " · " + t("eng_" + pick);
    const empty = { awg: false, server: !(S.servers || []).some((x) => x.usable), auto: false, off: false };
    const dd = { server: "m_dd_server", awg: "m_dd_awg", off: "m_dd_off" };
    return `<div class="card-head"><h2>${esc(t("method_title"))}</h2></div><div class="methods" role="radiogroup">${METHODS.map((id) =>
      `<div class="m-wrap seg-group${id === m ? " sel" : ""}${dd[id] ? " has-dd" : ""}"><button class="m-opt${id === m ? " sel" : ""}${empty[id] && id !== m ? " m-empty" : ""}" role="radio" aria-checked="${id === m}" data-act="method" data-v="${id}">
        <span class="m-dot" aria-hidden="true"></span><span class="m-text"><b>${esc(t("m_" + id))}</b><small>${esc(subs[id])}</small></span></button>${dd[id]
        ? `<button class="m-dd" data-act="m-dd" data-v="${id}" aria-label="${esc(t(dd[id]))}">${icon("chev", "down")}</button>` : ""}</div>`).join("")}</div>`;
  }

  // «Не работает» и «Белые списки» — ряд из двух одинаковых кнопок под «Способом»
  function nwRowHtml() {
    const w = S.wl || {};
    const sub = !w.on ? t("wl_sub_off") : !w.servers ? t("wl_sub_noservers") : w.manual ? t("wl_sub_manual") : t("wl_sub_auto");
    return `<div class="nw-row"><button class="nw-cell" data-act="nw-open">${icon("alert")}<span class="nw-text"><b>${esc(t("nw_btn"))}</b><small>${esc(t("nw_btn_sub"))}</small></span></button>
      <button class="nw-cell wl-cell${w.on ? " on" : ""}" role="checkbox" aria-checked="${!!w.on}" data-act="wl-flip"><span class="wl-box" aria-hidden="true">${w.on ? icon("check") : ""}</span>
        <span class="nw-text"><b>${esc(t("wl_name"))}</b><small>${esc(sub)}</small></span></button></div>`;
  }

  // AmneziaWG ▾: конфиги, бесплатный WARP, ускорение без VPN
  function awgListSheet() {
    const awgs = (S.servers || []).filter((x) => x.kind === "awg");
    const rows = awgs.map((x) => `<button class="row" data-act="awg" data-key="${esc(x.key)}">${icon("server")}<span class="main"><span class="title"><span>${esc(x.name)}</span></span>
        <span class="meta">${esc(x.note || t("awg_row"))}</span></span>${icon("chev", "chev")}</button>`).join("");
    openSheet(`<h2>${esc(t("m_dd_awg"))}</h2><div class="menu">${rows}
      <button class="row" data-act="warp-sheet">${icon("plus")}<span class="main"><span class="title"><span>${esc(t(awgs.length ? "dd_awg_more" : "dd_awg_new"))}</span></span></span></button>
      <button class="row" data-nav="dpi">${icon("swap")}<span class="main"><span class="title"><span>${esc(t("dd_novpn_head"))}</span></span>
        <span class="meta">${esc(t("dd_novpn_sub"))}</span></span>${icon("chev", "chev")}</button></div>`);
  }

  // «Не работает»: сервис из списка, приложение или сайт → проверка всеми путями → итог и «Отменить»
  let nw = null;
  let nwApps = null;
  function nwOpen() {
    nw = { tab: "service", sel: "", route: "proxy", q: "", waiting: false, done: false, targets: act("nw_targets", {}) || { services: [], known_apps: {} } };
    openSheet(`<div id="nwBox" class="stack"></div>`, () => nwDraw(), () => { nw = null; });
  }
  function nwPickHtml() {
    const T = nw.targets;
    const opt = (v, label) => `<button class="nw-opt" role="radio" aria-checked="${nw.sel === v}" data-act="nw-sel" data-v="${esc(v)}">${esc(label)}</button>`;
    if (nw.tab === "site") {
      return `<label class="field">${esc(t("nw_site_label"))}<input id="nwSite" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="youtube.com" value="${esc(nw.q)}"></label>`;
    }
    if (nw.tab === "service") return `<div class="nw-opts" role="radiogroup">${T.services.map((x) => opt(x.name, x.name)).join("")}</div>`;
    if (!nwApps) return `<p class="hint">${esc(t("apps_loading"))}</p>`;
    const known = T.known_apps || {};
    const q = nw.q.trim().toLowerCase();
    const list = nwApps.filter((a) => !q || a.name.toLowerCase().includes(q) || a.pkg.includes(q))
      .sort((a, b) => (known[b.pkg] ? 1 : 0) - (known[a.pkg] ? 1 : 0)).slice(0, 40);
    const sel = nwApps.find((a) => a.pkg === nw.sel);
    const route = sel && !known[sel.pkg] ? `<p class="hint">${esc(t("nw_app_route"))}</p><div class="seg" role="radiogroup">${[["proxy", t("nw_via_vpn")], ["direct", t("nw_direct")]].map(([v, l]) =>
      `<button data-act="nw-route" data-v="${v}" aria-pressed="${nw.route === v}">${esc(l)}</button>`).join("")}</div>` : "";
    return `<input type="search" id="nwQ" placeholder="${esc(t("search"))}" value="${esc(nw.q)}">
      <div class="nw-opts" role="radiogroup">${list.map((a) => opt(a.pkg, a.name)).join("")}</div>${route}`;
  }
  function nwResHtml() {
    const last = (S.nw || {}).last;
    if (nw.waiting) return `<div class="nw-res busy">${esc(((S.task || {}).title || t("nw_running")) + "…")}</div>`;
    if (!nw.done || !last) return "";
    const steps = (last.steps || []).length ? `<details class="more"><summary>${esc(t("nw_steps"))}</summary><ul class="nw-steps">${last.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></details>` : "";
    return `<div class="nw-res${last.changed ? " ok" : ""}"><p>${esc(last.undone ? t("nw_undone") : last.verdict)}</p>${steps}
      ${last.can_undo ? `<button class="btn wide" data-act="nw-undo">${icon("refresh")}${esc(t("nw_undo"))}</button>` : ""}</div>`;
  }
  function nwDraw() {
    const box = $("#nwBox");
    if (!box || !nw) return;
    box.innerHTML = `<h2>${esc(t("nw_title"))}</h2>
      <div class="seg three" role="radiogroup">${["service", "app", "site"].map((k) => `<button data-act="nw-tab" data-v="${k}" aria-pressed="${nw.tab === k}">${esc(t("nw_tab_" + k))}</button>`).join("")}</div>
      ${nwPickHtml()}<p class="hint">${esc(t("nw_hint"))}</p><div id="nwRes">${nwResHtml()}</div>
      <button class="btn primary wide" data-act="nw-go" ${nw.waiting ? "disabled" : ""}>${icon("check")}${esc(t("nw_go"))}</button>`;
    const q = $("#nwQ");
    if (q) q.addEventListener("input", () => { nw.q = q.value; const pos = q.selectionStart; nwDraw(); const q2 = $("#nwQ"); if (q2) { q2.focus(); q2.setSelectionRange(pos, pos); } });
    const site = $("#nwSite");
    if (site) site.addEventListener("input", () => { nw.q = site.value; });
  }
  function nwWatch() {
    if (!nw || !nw.waiting) return;
    const kind = (S.task || {}).kind;
    if (kind === "nw") { setHtml("#nwRes", nwResHtml()); return; }
    nw.waiting = false;
    nw.done = true;
    nwDraw();
  }

  function togglesHtml() {
    const st = S.settings, D = S.dpi || {}, A = S.ads || {};
    const accelSub = !D.enabled ? t("tile_ads_off") : taskOf("dpi") ? t("tile_dpi_busy") : D.active ? t("tile_dpi_on")
      : D.tested_at ? t("tile_dpi_none") : t("tile_dpi_wait");
    const ads = !A.enabled ? t("tile_ads_off") : A.paused_until ? t("tile_ads_paused") : A.mode ? t("tile_ads_on") : t("tile_ads_nolists");
    const row = (title, text, on, attrs) => `<div class="switch-row"><div class="main"><b>${esc(title)}</b><span>${esc(text)}</span></div>
      <button class="switch" role="switch" aria-checked="${!!on}" ${attrs}></button></div>`;
    return row(t("accel_name"), accelSub, D.enabled, 'data-act="accel"')
      + row(t("tile_ads"), ads, A.enabled, 'data-act="ads-flip"')
      + row(t("tile_dns"), st.dns_encrypted ? t("tile_dns_on") : t("tile_dns_off"), st.dns_encrypted, 'data-act="flip" data-k="dns_encrypted"');
  }

  // ---------- «Движок»: какие VPN использовать ----------
  const ENGINES = ["auto", "xray", "hy2", "awg"];
  function engName(id) { return t("eng_" + id) + (id === "auto" ? "" : " · " + (((S.engine || {}).counts || {})[id] || 0)); }
  function engineSheet() {
    const E = S.engine || {};
    const c = E.counts || {};
    const rows = ENGINES.map((id) => `<button class="row" data-act="engine-set" data-v="${id}">
        <span class="main"><span class="title"><span>${esc(t("eng_" + id))}</span>${id === "auto" ? "" : `<i class="tag">${c[id] || 0}</i>`}</span>
        <span class="meta">${esc(t("eng_" + id + "_sub"))}</span></span>${(E.pick || "auto") === id ? icon("check", "check") : "<span></span>"}</button>`).join("");
    openSheet(`<h2>${esc(t("eng_title"))}</h2><div class="menu">${rows}</div>
      ${c.singbox ? `<p class="hint">${esc(t("eng_sb_note", { n: c.singbox }))}</p>` : ""}`);
  }

  // AmneziaWG на телефоне включает своё приложение: файл конфига → AmneziaWG
  let awgCur = null;
  function awgSheet(key) {
    try { awgCur = call("awg_info", { key: key || "" }); } catch (e) { toast(e.message, "error"); return; }
    openSheet(`<h2>${esc(awgCur.name)}</h2><p class="hint">${esc(t("awg_text"))}</p>
      ${awgCur.note ? `<div class="problem"><p>${esc(awgCur.note)}</p></div>` : ""}
      <ol class="steps"><li>${esc(t("awg_step1"))}</li><li>${esc(t("awg_step2"))}</li><li>${esc(t("awg_step3"))}</li></ol>
      <div class="menu">
        <button class="row" data-act="awg-save">${icon("file")}<span class="main"><span class="title"><span>${esc(t("awg_save"))}</span></span></span></button>
        <button class="row" data-act="awg-open">${icon("send")}<span class="main"><span class="title"><span>${esc(t("awg_open"))}</span></span></span></button>
        <button class="row" data-act="awg-copy">${icon("copy")}<span class="main"><span class="title"><span>${esc(t("awg_copy"))}</span></span>
          <span class="meta">${esc(t("awg_copy_note"))}</span></span></button>
        ${awgCur.warp ? `<button class="row" data-act="warp-qr">${icon("qr")}<span class="main"><span class="title"><span>${esc(t("warp_qr"))}</span></span>
          <span class="meta">${esc(t("warp_qr_note"))}</span></span></button>` : ""}
        ${awgCur.warp ? `<button class="row" data-act="warp-next">${icon("refresh")}<span class="main"><span class="title"><span>${esc(t("warp_next"))}</span></span>
          <span class="meta">${esc(t("warp_next_note"))}</span></span></button>` : ""}
      </div>`);
  }

  // AmneziaWG выбран, а конфигов нет: создать бесплатный WARP или вставить свой
  function warpStartSheet() {
    openSheet(`<h2>${esc(t("awg_start_title"))}</h2><p class="hint">${esc(t("awg_start_text"))}</p>
      <p class="hint">${esc(t("warp_note"))}</p>
      <div class="menu">
        <button class="row" data-act="warp-create">${icon("plus")}<span class="main"><span class="title"><span>${esc(t("warp_create"))}</span></span></span></button>
        <button class="row" data-act="warp-own">${icon("file")}<span class="main"><span class="title"><span>${esc(t("awg_paste_own"))}</span></span></span></button>
      </div>`);
  }

  function tilesHtml() {
    const st = S.settings;
    const A = S.ads || {};
    const D = S.dpi || {};
    const R = S.routes || {};
    const ads = !A.enabled ? t("tile_ads_off") : A.paused_until ? t("tile_ads_paused") : A.filter_on && S.status !== "on" ? t("tile_ads_novpn")
      : A.mode ? t("tile_ads_on") : t("tile_ads_nolists");
    const dpi = !D.enabled ? t("tile_ads_off") : taskOf("dpi") ? t("tile_dpi_busy") : D.active ? t("tile_dpi_on")
      : D.tested_at ? t("tile_dpi_none") : t("tile_dpi_wait");
    const own = (R.services || []).filter((x) => x.choice !== "auto").length + (R.sites || []).length;
    const tile = (cls, act, ic, title, sub, extra) =>
      `<button class="tile${cls ? " on" : ""}" ${act} ${extra || ""}>${icon(ic)}<span class="tile-text"><b>${esc(title)}</b><span>${esc(sub)}</span></span></button>`;
    return tile(A.enabled && !A.paused_until, 'data-nav="ads"', "ban", t("tile_ads"), ads)
      + tile(D.active, 'data-nav="dpi"', "swap", t("tile_dpi"), dpi)
      + tile(st.dns_encrypted, 'data-act="flip" data-k="dns_encrypted"', "lock", t("tile_dns"),
        st.dns_encrypted ? t("tile_dns_on") : t("tile_dns_off"), `aria-pressed="${!!st.dns_encrypted}"`)
      + tile(own > 0, 'data-nav="routes"', "list", t("tile_routes"), own ? t("tile_routes_n", { n: own }) : t("tile_routes_sub"))
      + tile(S.share.on, 'data-nav="share"', "wifi", t("tile_share"), S.share.on ? t("tile_share_on") : t("tile_share_off"))
      + tile(false, 'data-nav="vps"', "server", t("tile_vps"), t("tile_vps_sub"));
  }

  function serverRow(s) {
    if (s.kind === "awg") {
      return `<div class="row" data-act="awg" data-key="${esc(s.key)}">
        <div class="main"><div class="title"><span>${esc(s.name)}</span><i class="tag">AmneziaWG</i>${s.manual ? `<i class="tag">${esc(t("tag_mine"))}</i>` : ""}</div>
        <div class="meta${s.note ? " warn" : ""}">${esc(s.note || t("awg_row"))}</div></div>
        <span class="ping none"></span><span></span>
        <button class="icon-btn" data-act="server-menu" data-key="${esc(s.key)}" aria-label="…">${icon("more")}</button></div>`;
    }
    const tags = [];
    if (s.current) tags.push(`<i class="tag cur">${esc(t("tag_now"))}</i>`);
    if (s.mask) tags.push(`<i class="tag">${esc(t("tag_mask"))}</i>`);
    if (s.wl) tags.push(`<i class="tag warn">${esc(t("tag_wl"))}</i>`);
    if (s.cut) tags.push(`<i class="tag warn">${esc(t("tag_cut"))}</i>`);
    if (s.manual) tags.push(`<i class="tag">${esc(t("tag_mine"))}</i>`);
    const ping = !s.usable ? "" : s.ok ? `${s.ping}` : (s.tested ? t("no_answer") : t("not_tested"));
    const pc = !s.usable ? "none" : s.ok ? pingCls(s.ping) : "none";
    const meta = !s.usable ? `<div class="meta warn">${esc(s.note)}</div>` : (s.sub ? `<div class="meta">${esc(s.sub)}</div>` : "");
    return `<div class="row${s.current ? " current" : ""}${s.usable ? "" : " off"}" data-act="server" data-key="${esc(s.key)}">
        <div class="main"><div class="title"><span>${esc(s.name)}</span>${tags.join("")}</div>${meta}</div>
        <span class="ping ${pc}">${esc(ping)}</span>
        ${s.selected ? icon("check", "check") : ""}
        <button class="icon-btn" data-act="server-menu" data-key="${esc(s.key)}" aria-label="…">${icon("more")}</button></div>`;
  }

  function serversHtml() {
    const list = S.servers || [];
    if (!list.length) {
      return `<div class="empty"><h2>${esc(t("empty_title"))}</h2><p class="hint">${esc(t("empty_text"))}</p>
        <button class="btn primary wide" data-act="add">${icon("plus")}${esc(t("add_sub"))}</button></div>`;
    }
    const auto = !S.settings.selected;
    const max = 25;
    const shown = showAll ? list : list.slice(0, max);
    let html = `<div class="card-head"><h2>${esc(t("servers"))}</h2><span class="count">${list.length}</span><span class="grow"></span>
        <button class="icon-btn" data-act="test" aria-label="${esc(t("test"))}">${icon("refresh")}</button>
        <button class="icon-btn" data-act="add" aria-label="${esc(t("add"))}">${icon("plus")}</button></div>
      <div class="row" data-act="auto"><div class="main"><div class="title"><span>${esc(t("auto"))}</span></div>
        <div class="meta">${esc(t("auto_sub"))}</div></div>${auto ? icon("check", "check") : ""}<span class="icon-btn"></span></div>`;
    html += shown.map(serverRow).join("");
    if (list.length > max) {
      html += `<div class="more-list"><button class="link-btn" data-act="show-all">${esc(showAll ? t("show_less") : t("show_all", { n: list.length }))}</button></div>`;
    }
    return html;
  }

  function subsHtml() {
    const subs = S.subs || [];
    if (!subs.length) return "";
    return `<div class="card-head"><h2>${esc(t("subs"))}</h2><span class="grow"></span>
        <button class="icon-btn" data-act="refresh-subs" aria-label="${esc(t("refresh"))}">${icon("refresh")}</button></div>`
      + subs.map((s) => {
        const title = s.title || s.name || t("subs");
        const meta = s.error ? `<div class="meta warn">${esc(s.error)}</div>`
          : `<div class="meta">${esc(s.fetched ? [t("sub_servers", { n: s.count }), s.usage].filter(Boolean).join(" · ") : t("sub_never"))}</div>`;
        return `<div class="row" data-act="sub-menu" data-id="${esc(s.id)}"><div class="main"><div class="title"><span>${esc(title)}</span></div>${meta}</div>
          <button class="icon-btn" data-act="sub-menu" data-id="${esc(s.id)}" aria-label="…">${icon("more")}</button></div>`;
      }).join("");
  }

  const VIEWS = {};
  VIEWS.home = {
    render() {
      return `<section class="hero" id="hero"></section><div id="route"></div><div class="speed-row" id="speed"></div><div class="busy-row" id="busy"></div>
        <div id="health"></div>
        <section class="card ww" id="ww" hidden></section>
        <section class="card" id="method"></section><div id="nwrow"></div><section class="card toggles" id="toggles"></section>
        <section class="card" id="servers"></section><section class="card" id="subs"></section>`;
    },
    update() {
      setHtml("#hero", heroHtml());
      setHtml("#speed", speedHtml());
      setHtml("#busy", S.task && S.task.kind === "speed" ? "" : busyHtml());
      setHtml("#health", healthStrip());
      const ww = whatWorksHtml();
      setHtml("#ww", ww);
      $("#ww").hidden = !ww;
      setHtml("#route", routeHtml());
      setHtml("#method", methodHtml());
      setHtml("#nwrow", nwRowHtml());
      setHtml("#toggles", togglesHtml());
      setHtml("#servers", serversHtml());
      const subs = subsHtml();
      setHtml("#subs", subs);
      $("#subs").hidden = !subs;
    },
  };

  // ---------- состояние: данные, способ, защита ----------
  function healthItems() {
    const L = S.ladder || {};
    const on = S.status === "on";
    const d = L.data;
    let data;
    if (!on) data = { cls: "idle", value: t("h_off") };
    else if (L.step || (S.conn && S.conn.title)) data = { cls: "warn", value: t("h_searching") };
    else if (!d || d.inconclusive) data = { cls: "idle", value: t("h_not_checked") };
    else data = d.ok ? { cls: "good", value: t("h_data_ok") } : { cls: "bad", value: t("h_data_bad") };
    const way = !on ? { cls: "idle", value: "—" } : { cls: "good", value: L.way || t("h_way_plain") };
    const c = S.certs;
    const certs = !c ? { cls: "idle", value: t("h_not_checked") } : c.errors ? { cls: "bad", value: t("h_certs_bad") }
      : c.warnings && !c.acked ? { cls: "warn", value: t("h_certs_warn") } : { cls: "good", value: t("h_certs_ok") };
    const l = S.leaks;
    const leaks = !l ? { cls: "idle", value: t("h_not_checked") } : l.errors ? { cls: "bad", value: t("h_leaks_bad") }
      : { cls: "good", value: t("h_leaks_ok") };
    return [Object.assign(data, { label: t("h_data") }), Object.assign(way, { label: t("h_way") }),
      Object.assign(certs, { label: t("h_certs") }), Object.assign(leaks, { label: t("h_leaks") })];
  }

  function healthVerdict() {
    const items = healthItems();
    const probs = S.problems || [];
    const bad = items.filter((i) => i.cls === "bad").length;
    const warn = items.filter((i, k) => i.cls === "warn" && k > 0).length + probs.length;
    if (bad) return { cls: "bad", title: t("v_bad"), sub: probs[0] ? probs[0].title : t("v_bad_sub"), short: t("v_bad_short") };
    if (warn) return { cls: "warn", title: t("v_warn", { n: warn }), sub: probs[0] ? probs[0].title : t("v_warn_sub"), short: t("v_warn_short", { n: warn }) };
    if (S.status !== "on") return { cls: "idle", title: t("v_off"), sub: t("v_off_sub"), short: t("v_off_short") };
    return { cls: "good", title: t("v_good"), sub: t("v_good_sub"), short: t("v_good_short") };
  }

  function healthStrip() {
    return `<button class="health" data-nav="status" aria-label="${esc(t("status_title"))}">${healthItems().map((i) =>
      `<span class="h-cell"><small>${esc(i.label)}</small><b><i class="dot ${i.cls}"></i>${esc(i.value)}</b></span>`).join("")}</button>`;
  }

  function kv(label, value, extra) {
    return `<div class="st-row"><span class="st-k">${esc(label)}</span><span class="st-v">${value}</span>${extra || "<span></span>"}</div>`;
  }

  VIEWS.status = {
    title: "status_title",
    render() { return `<div id="statusBox" class="stack"></div>`; },
    update() {
      const L = S.ladder || {};
      const on = S.status === "on";
      const v = healthVerdict();
      const it = healthItems();
      const dot = (c) => `<i class="dot ${c}"></i>`;
      const d = L.data;
      const busy = (S.task && S.task.title) || (S.conn && S.conn.title);
      const dataTxt = !on ? esc(t("h_off")) : !d || d.inconclusive ? esc(t(d ? "st_data_na" : "h_not_checked"))
        : `${dot(d.ok ? "good" : "bad")}${esc(d.ok ? t("st_data_ok", { ms: d.ms }) : t("st_data_bad", { e: d.error || "" }))} <span class="muted">· ${esc(ago(d.at))}</span>`;
      const last = L.last ? `${dot(L.last.ok ? "good" : "bad")}${esc(L.last.text)} <span class="muted">· ${esc(ago(L.last.at))}</span>`
        : `<span class="muted">${esc(t("st_last_none"))}</span>`;
      const srv = S.server;
      setHtml("#statusBox", `<section class="verdict ${v.cls}">
          <span class="verdict-mark">${icon(v.cls === "good" ? "check" : v.cls === "idle" ? "power" : "alert")}</span>
          <div class="main"><b>${esc(v.title)}</b><span>${esc(v.sub)}</span></div></section>
        ${taskOf("health") ? `<div class="busy-row"><span class="spinner"></span><span>${esc(taskOf("health"))}…</span></div>`
          : `<button class="btn primary wide" data-act="health-run" ${busy ? "disabled" : ""}>${icon("refresh")}${esc(t("st_check_all"))}</button>`}
        <section class="card"><div class="card-head"><h2>${esc(t("st_conn"))}</h2></div><div class="st-kv">
          ${kv(t("st_server"), on && srv ? esc(srv.name) : `<span class="muted">${esc(t("h_off"))}</span>`)}
          ${kv(t("h_way"), on ? `${dot("good")}${esc(L.way || t("st_way_plain"))}` : "—")}
          ${kv(t("h_data"), dataTxt, on && !busy ? `<button class="link-btn" data-act="data-run">${esc(t("st_data_check"))}</button>` : "")}
          ${kv(t("st_net"), esc(S.settings.net_memory === false ? t("st_mem_off") : L.net_known ? t("st_mem_known") : t("st_mem_new")))}
          ${kv(t("st_last"), last)}
          ${kv(t("st_journal"), journalSummary())}
        </div>${journalHtml()}</section>
        <section class="card"><div class="card-head"><h2>${esc(t("st_protect"))}</h2></div><div class="st-kv">
          ${kv(t("h_certs"), `${dot(it[2].cls)}${esc(it[2].value)}`)}
          ${kv(t("h_leaks"), `${dot(it[3].cls)}${esc(it[3].value)}`)}
        </div></section>
        ${certsHtml()}
        ${leaksHtml()}
        <section class="card">
          ${navRow('data-nav="errors"', "alert", t("errors_title"), S.errors_count ? t("errors_n", { n: S.errors_count }) : t("errors_none"))}
          ${navRow('data-nav="check"', "shield", t("s_check"), S.check ? t("check_sum", { e: S.check.errors, w: S.check.warnings }) : t("s_check_text"))}
        </section>`);
    },
  };

  // журнал подключения: кто (ты или автоматика) и почему подключал, переключал и отключал VPN
  function journalSummary() {
    const J = S.journal || {};
    return `<i class="dot ${(J.auto_hour || 0) >= 3 ? "warn" : "good"}"></i>${esc(t("journal_auto", { h: J.auto_hour || 0, d: J.auto_day || 0 }))}`;
  }

  function journalHtml() {
    const items = (S.journal && S.journal.items) || [];
    if (!items.length) return "";
    const time = (ts) => new Date(ts * 1000).toLocaleString(lang === "en" ? "en-GB" : "ru-RU",
      { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
    return `<details class="journal-box"><summary>${esc(t("journal_title"))}</summary>
      <p class="muted small">${esc(t("journal_hint"))}</p><ul class="journal">${items.map((it) => `<li class="j-${esc(it.kind)}">
        <time>${esc(time(it.t))}</time><b>${esc(it.kind_text)}</b>${it.server ? `<span>${esc(it.server)}</span>` : ""}
        <span class="muted">${esc(it.who === "user" ? t("journal_you") : it.who || t("journal_app"))}${it.why ? ` — ${esc(it.why)}` : ""}</span></li>`).join("")}</ul></details>`;
  }

  // лестница не нашла рабочего способа: что открывается напрямую и когда следующая попытка
  function whatWorksHtml() {
    const L = S.ladder || {};
    const w = L.what_works;
    if (!w) return "";
    const mins = L.retry_at ? Math.max(1, Math.round((L.retry_at - Date.now()) / 60000)) : 0;
    const items = (w.items || []).map((x) => `<span class="ww-item ${x.ok ? "ok" : "bad"}">${icon(x.ok ? "check" : "ban")}${esc(x.name)}</span>`).join("");
    const busy = S.conn && S.conn.title;
    return `<div class="card-body"><b>${esc(t("ww_title"))}</b>
      <p class="hint">${esc(mins ? t("ww_retry_in", { n: mins }) : t("ww_retry_soon"))}</p>
      ${items ? `<div class="ww-list"><span class="hint">${esc(t("ww_direct"))}</span>${items}</div>` : ""}
      <p class="hint">${esc(t(w.hint === "wifi" ? "ww_hint_wl" : "ww_hint"))}</p>
      ${busy ? "" : `<button class="btn primary wide" data-act="ladder-retry">${icon("refresh")}${esc(t("ww_try_now"))}</button>`}</div>`;
  }

  // ---------- добавить: подписка, серверы, настройки ----------
  function openAdd(text) {
    openSheet(`<h2>${esc(t("add_title"))}</h2>
      <textarea id="addText" placeholder="${esc(t("add_ph"))}" spellcheck="false" autocapitalize="off"></textarea>
      <div class="btns"><button class="btn" data-act="add-paste">${icon("paste")}${esc(t("paste"))}</button>
        <button class="btn" data-act="scan">${icon("scan")}${esc(t("scan"))}</button>
        <button class="btn" data-act="pick-file">${icon("file")}${esc(t("file"))}</button></div>
      <p class="detect" id="addDetect"></p>
      <input id="addName" placeholder="${esc(t("name_ph"))}" hidden>
      <button class="btn primary wide" id="addGo" data-act="add-go" disabled>${esc(t("add"))}</button>`, (sh) => {
      const ta = $("#addText", sh);
      ta.value = text || "";
      ta.addEventListener("input", detect);
      detect();
      if (!text) ta.focus();
    });
  }
  function detect() {
    const ta = $("#addText");
    if (!ta) return;
    const text = ta.value.trim();
    const out = $("#addDetect");
    const go = $("#addGo");
    $("#addName").hidden = true;
    go.textContent = t("add");
    if (!text) { out.textContent = ""; go.disabled = true; return; }
    let r;
    try { r = call("import_preview", { text }); } catch (e) { r = { kind: "unknown", error: e.message }; }
    out.className = "detect";
    go.disabled = false;
    if (r.kind === "family") { out.textContent = t("det_family"); go.textContent = t("fam_open"); return; }
    if (r.kind === "subscription") { out.textContent = t("det_sub"); $("#addName").hidden = false; }
    else if (r.kind === "servers") { out.textContent = t("det_servers", { n: r.servers }); go.disabled = !r.servers; }
    else if (r.kind === "settings") {
      out.textContent = t("det_settings", { s: r.subscriptions, v: r.servers }) + (r.skipped ? t("det_settings_skip", { n: r.skipped }) : "");
      go.textContent = t("apply_settings");
    } else if (r.kind === "wifi") { out.textContent = t("det_wifi"); out.className = "detect bad"; go.disabled = true; }
    else { out.textContent = r.error || t("det_unknown"); out.className = "detect bad"; go.disabled = true; }
  }

  function serverMenu(key) {
    const s = (S.servers || []).find((x) => x.key === key);
    if (!s) return;
    openSheet(`<h2>${esc(s.name)}</h2><div class="menu">
        ${s.usable && !s.current ? `<button class="row" data-act="select" data-key="${esc(key)}">${icon("swap")}<span class="main">${esc(t("m_connect_this"))}</span></button>` : ""}
        ${s.kind === "awg" ? `<button class="row" data-act="awg" data-key="${esc(key)}">${icon("send")}<span class="main">${esc(t("awg_to_app"))}</span></button>` : ""}
        <button class="row" data-act="server-qr" data-key="${esc(key)}">${icon("qr")}<span class="main">${esc(t("m_qr"))}</span></button>
        <button class="row" data-act="server-copy" data-key="${esc(key)}">${icon("copy")}<span class="main">${esc(t("m_copy_link"))}</span></button>
        ${s.manual ? `<button class="row" data-act="server-del" data-key="${esc(key)}">${icon("trash")}<span class="main">${esc(t("m_delete"))}</span></button>` : ""}
      </div>`);
  }

  function subMenu(id) {
    const s = (S.subs || []).find((x) => x.id === id);
    if (!s) return;
    openSheet(`<h2>${esc(s.title || s.name || t("subs"))}</h2>${s.error ? `<div class="problem"><p>${esc(s.error)}</p></div>` : ""}<div class="menu">
        <button class="row" data-act="refresh-subs">${icon("refresh")}<span class="main">${esc(t("m_refresh"))}</span></button>
        <button class="row" data-act="sub-qr" data-id="${esc(id)}">${icon("qr")}<span class="main">${esc(t("m_qr"))}</span></button>
        <button class="row" data-act="sub-copy" data-id="${esc(id)}">${icon("copy")}<span class="main">${esc(t("m_copy_link"))}</span></button>
        <button class="row" data-act="sub-del" data-id="${esc(id)}">${icon("trash")}<span class="main">${esc(t("m_delete"))}</span></button>
      </div>`);
  }

  function showQr(title, text, note) {
    const img = act("qr", { text });
    if (!img) return;
    openSheet(`<h2>${esc(title)}</h2><div class="qr"><img alt="" src="${esc(img)}"></div>${note ? `<p class="hint">${esc(note)}</p>` : ""}`);
  }

  // ---------- раздача ----------
  let shareTab = "android";
  function wifiQrText(ssid, pass) {
    const e = (v) => String(v).replace(/([\\;,:"])/g, "\\$1");
    return `WIFI:T:WPA;S:${e(ssid)};P:${e(pass)};;`;
  }
  function tgLink(sh) {
    return `tg://socks?server=${encodeURIComponent(sh.ip)}&port=${sh.socks}&user=${encodeURIComponent(sh.user)}&pass=${encodeURIComponent(sh.pass)}`;
  }
  let shareQrCache = {};
  function qrImg(text) {
    if (!shareQrCache[text]) {
      try { shareQrCache[text] = call("qr", { text }); } catch (e) { return ""; }
    }
    return `<div class="qr"><img alt="" src="${esc(shareQrCache[text])}"></div>`;
  }
  VIEWS.share = {
    title: "share_title",
    render() { return `<div id="shareBox" class="stack"></div>`; },
    update() {
      const sh = S.share;
      let html = `<p class="hint">${esc(t("share_intro"))}</p>`;
      if (!sh.on) {
        if (S.status !== "on") html += `<div class="note info">${esc(t("share_vpn_off"))}</div>`;
        html += `<div class="option"><h3>${esc(t("opt_local"))}</h3><p class="hint">${esc(t("opt_local_text"))}</p>
            <button class="btn primary" data-act="hotspot-local">${icon("wifi")}${esc(t("opt_local_btn"))}</button></div>
          <div class="option"><h3>${esc(t("opt_system"))}</h3><p class="hint">${esc(t("opt_system_text"))}</p>
            <div class="btns"><button class="btn" data-act="hotspot-settings">${esc(t("opt_system_open"))}</button>
            <button class="btn" data-act="hotspot-system">${esc(t("opt_system_done"))}</button></div></div>`;
      } else {
        if (sh.ssid) {
          html += `<section class="card"><div class="card-head"><h2>${esc(t("share_network"))}</h2></div><div class="card-body">
            <dl class="kv"><dt>${esc(t("wifi_name"))}</dt><dd>${esc(sh.ssid)}</dd><span></span>
              <dt>${esc(t("wifi_pass"))}</dt><dd>${esc(sh.wifi_pass)}</dd>
              <button class="icon-btn" data-act="copy" data-text="${esc(sh.wifi_pass)}" aria-label="${esc(t("copy"))}">${icon("copy")}</button></dl>
            ${qrImg(wifiQrText(sh.ssid, sh.wifi_pass))}<p class="hint">${esc(t("wifi_qr_note"))}</p></div></section>`;
        }
        html += `<section class="card"><div class="card-head"><h2>${esc(t("share_proxy"))}</h2></div><div class="card-body">`;
        if (!sh.ip) {
          html += `<p class="hint">${esc(t("proxy_wait"))}</p>`;
        } else {
          html += `<dl class="kv"><dt>${esc(t("proxy_addr"))}</dt><dd>${esc(sh.ip)}</dd>
                <button class="icon-btn" data-act="copy" data-text="${esc(sh.ip)}" aria-label="${esc(t("copy"))}">${icon("copy")}</button>
              <dt>${esc(t("proxy_http"))}</dt><dd>${esc(sh.http)}</dd><span></span>
              <dt>${esc(t("proxy_socks"))}</dt><dd>${esc(sh.socks)}</dd><span></span>
              <dt>${esc(t("proxy_user"))}</dt><dd>${esc(sh.user)}</dd><span></span>
              <dt>${esc(t("proxy_pass"))}</dt><dd>${esc(sh.pass)}</dd>
                <button class="icon-btn" data-act="new-pass" aria-label="${esc(t("new_pass"))}">${icon("refresh")}</button></dl>`;
          const vars = { ip: esc(sh.ip), http: esc(sh.http), socks: esc(sh.socks) };
          const tabs = [["android", "Android"], ["iphone", "iPhone"], ["windows", "Windows"], ["telegram", "Telegram"]];
          html += `<h3>${esc(t("how_title"))}</h3><div class="tabs" role="tablist">${tabs.map(([k, n]) =>
            `<button role="tab" data-act="share-tab" data-v="${k}" aria-selected="${shareTab === k}">${n}</button>`).join("")}</div>
            <ol class="steps">${t("how_" + shareTab, vars)}</ol>`;
          if (shareTab === "telegram") html += qrImg(tgLink(sh));
          html += `<details class="more"><summary>${esc(t("share_more"))}</summary><p>${esc(t("share_more_text"))}</p></details>`;
        }
        html += `</div></section><button class="btn danger wide" data-act="hotspot-stop">${esc(t("share_stop"))}</button>`;
      }
      setHtml("#shareBox", html);
    },
  };

  // ---------- перенос настроек ----------
  let tfSubs = false;
  let tfServers = false;
  VIEWS.transfer = {
    title: "transfer_title",
    render() { return `<div id="tfBox" class="stack"></div>`; },
    mount() { this.draw(); },
    draw() {
      const text = act("export", { subs: tfSubs, servers: tfServers }) || "";
      let qr = "";
      if (text.length <= 1800) {
        try { qr = `<div class="qr"><img alt="" src="${esc(call("qr", { text }))}"></div>`; } catch (e) { qr = ""; }
      }
      $("#tfBox").innerHTML = `<section class="card"><div class="card-head"><h2>${esc(t("send_title"))}</h2></div>
          <div class="switch-row"><div class="main"><b>${esc(t("with_subs"))}</b><span>${esc(t("with_subs_note"))}</span></div>
            <button class="switch" role="switch" aria-checked="${tfSubs}" data-act="tf-subs"></button></div>
          <div class="switch-row"><div class="main"><b>${esc(t("with_servers"))}</b></div>
            <button class="switch" role="switch" aria-checked="${tfServers}" data-act="tf-servers"></button></div>
          <div class="card-body">${qr || `<p class="hint">${esc(t("qr_too_long"))}</p>`}
            <div class="btns"><button class="btn" data-act="tf-save">${icon("file")}${esc(t("save_file"))}</button>
              <button class="btn" data-act="tf-send">${icon("send")}${esc(t("send"))}</button></div></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("receive_title"))}</h2></div><div class="card-body">
          <div class="btns"><button class="btn" data-act="scan">${icon("scan")}${esc(t("scan"))}</button>
            <button class="btn" data-act="pick-file">${icon("file")}${esc(t("open_file"))}</button>
            <button class="btn" data-act="paste-open">${icon("paste")}${esc(t("paste"))}</button></div>
          <p class="hint">${esc(t("transfer_note"))}</p></div></section>`;
      this.text = text;
    },
  };

  // ---------- свой сервер ----------
  VIEWS.vps = {
    title: "vps_title",
    render() {
      return `<p class="hint">${esc(t("vps_intro"))}</p>
        <label class="field">${esc(t("vps_host"))}<input id="vpsHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="203.0.113.10"></label>
        <div class="field-row"><label class="field">${esc(t("vps_user"))}<input id="vpsUser" autocapitalize="off" spellcheck="false" value="root"></label>
          <label class="field">${esc(t("vps_port"))}<input id="vpsPort" inputmode="numeric" value="22"></label></div>
        <label class="field">${esc(t("vps_pass"))}<input id="vpsPass" type="password" autocomplete="off"></label>
        <label class="field">${esc(t("vps_name"))}<input id="vpsName" placeholder="${esc(t("vps_name_ph"))}"></label>
        <div id="vpsStatus"></div>
        <details class="more"><summary>${esc(t("share_more"))}</summary><p>${esc(t("vps_more_text"))}</p></details>
        <div id="vpsMine"></div>`;
    },
    update() {
      const b = S.busy || {};
      const running = b.kind === "vps";
      setHtml("#vpsStatus", running
        ? `<div class="note info"><b>${esc(t("vps_running"))}</b><br>${esc(b.title)}… <button class="link-btn" data-act="stop">${esc(t("stop"))}</button></div>`
        : `<button class="btn primary wide" data-act="vps-go" ${b.title ? "disabled" : ""}>${icon("server")}${esc(t("vps_go"))}</button>`);
      setHtml("#vpsMine", vpsMineHtml(!!b.title));
      const nf = S.vps_friend_new;
      if (nf && nf.id && nf.id !== vpsFriendShown) {
        vpsFriendShown = nf.id;
        vpsFriendQr(nf.id, nf.name);
      }
    },
  };
  let vpsFriendShown = "";
  function bytesText(n) {
    const u = [t("u_b"), t("u_kb"), t("u_mb"), t("u_gb"), t("u_tb")];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
  }
  function vpsLines(st) {
    if (!st || !st.ts) return [t("vps_st_never"), ""];
    const up = st.uptime_s >= 86400 ? t("vps_up_d", { n: Math.floor(st.uptime_s / 86400) }) : t("vps_up_h", { n: Math.floor(st.uptime_s / 3600) });
    const d = [t("vps_st_load", { v: (st.load || "").split(" ")[0] || "?" }), t("vps_st_mem", { v: st.mem_mb }), t("vps_st_disk", { v: st.disk }),
      t("vps_st_traffic", { v: bytesText((st.rx || 0) + (st.tx || 0)) }), up].join(", ");
    return [`${st.xray === "active" ? t("vps_st_ok") : t("vps_st_down")}, ${t("vps_st_conns", { n: st.conns })} · ${ago(st.ts * 1000)}`,
      d.charAt(0).toUpperCase() + d.slice(1)];
  }
  function vpsMineHtml(busy) {
    const list = S.vps || [];
    let html = `<section class="card"><div class="card-head"><h2>${esc(t("vps_own"))}</h2></div><div class="card-body">
      <p class="hint">${esc(t("vps_own_text"))}</p>`;
    if (!list.length) {
      return html + `<button class="btn wide" data-act="vps-add" ${busy ? "disabled" : ""}>${icon("plus")}${esc(t("vps_add_btn"))}</button></div></section>`;
    }
    html += list.map((h) => {
      const st = h.status || {};
      const down = st.ts && st.xray !== "active";
      const [l1, l2] = vpsLines(st);
      const fr = (h.friends || []).map((f) => `<div class="vps-friend"><div class="main"><b>${esc(f.name)}</b><span>${esc(t("vps_friend_made", { d: new Date(f.ts * 1000).toLocaleDateString(lang === "en" ? "en-GB" : "ru-RU") }))}</span></div>
          <button class="icon-btn" data-act="vps-qr" data-f="${esc(f.id)}" data-n="${esc(f.name)}" aria-label="${esc(t("m_qr"))}">${icon("qr")}</button>
          <button class="icon-btn" data-act="vps-fdel" data-id="${esc(h.id)}" data-f="${esc(f.id)}" data-n="${esc(f.name)}" aria-label="${esc(t("vps_friend_del"))}" ${busy ? "disabled" : ""}>${icon("trash")}</button></div>`).join("");
      return `<div class="vps-item"><div class="vps-head"><div class="main"><b>${esc(h.name)}</b>
          <span class="${down ? "bad" : ""}">${esc(l1)}</span>${l2 ? `<small>${esc(l2)}</small>` : ""}</div>
          <button class="icon-btn" data-act="vps-forget" data-id="${esc(h.id)}" aria-label="${esc(t("vps_forget"))}">${icon("trash")}</button></div>
        <div class="btns"><button class="btn" data-act="vps-check" data-id="${esc(h.id)}" ${busy ? "disabled" : ""}>${icon("refresh")}${esc(t("vps_check"))}</button>
          <button class="btn" data-act="vps-friend" data-id="${esc(h.id)}" ${busy ? "disabled" : ""}>${icon("plus")}${esc(t("vps_friend_add"))}</button>
          ${h.bridge_of ? `<span class="hint">${esc(t("vps_is_bridge"))}</span>` : `<button class="btn" data-act="vps-bridge" data-id="${esc(h.id)}" ${busy ? "disabled" : ""}>${icon("server")}${esc(t("vps_bridge_btn"))}</button>`}</div>
        ${fr ? `<div class="vps-friends">${fr}</div>` : ""}</div>`;
    }).join("");
    return html + `<p class="hint">${esc(t("vps_pass_note"))}</p></div></section>`;
  }
  /* Пароль от сервера — для одного действия: в поле шторки, никуда не сохраняется. */
  function vpsPassSheet(title, text, extra, go) {
    openSheet(`<h2>${esc(title)}</h2>${text ? `<p class="hint">${esc(text)}</p>` : ""}${extra || ""}
      <label class="field">${esc(t("vps_pass"))}<input id="vpPass" type="password" autocomplete="off"></label>
      <button class="btn primary wide" id="vpGo">${esc(t("vps_do"))}</button>`, (sh) => {
      $("#vpGo", sh).addEventListener("click", () => {
        const pass = $("#vpPass", sh);
        const r = go(pass.value, sh);
        pass.value = "";
        if (r !== undefined) closeSheet();
      });
      const first = $("input", sh);
      if (first) first.focus();
    });
  }
  function vpsFriendQr(id, name) {
    const link = act("vps_friend_link", { friend: id });
    if (link) showQr(t("qr_friend", { name }), link, t("qr_friend_hint") + " " + t("qr_friend_warn"));
  }

  // ---------- настройки ----------
  function sw(key, title, text) {
    const v = !!S.settings[key];
    return `<div class="switch-row"><div class="main"><b>${esc(t(title))}</b>${text ? `<span>${esc(t(text))}</span>` : ""}</div>
      <button class="switch" role="switch" aria-checked="${v}" data-act="flip" data-k="${key}"></button></div>`;
  }
  function navRow(nav, ic, title, text) {
    return `<button class="row" ${nav}>${icon(ic)}<span class="main"><span class="title"><span>${esc(title)}</span></span>
      ${text ? `<span class="meta">${esc(text)}</span>` : ""}</span>${icon("chev", "chev")}</button>`;
  }
  // ---------- Семья: настраивать VPN родителей на расстоянии ----------
  const FAM_M = ["auto", "server", "awg", "off"];
  VIEWS.family = {
    title: "fam_title",
    render() {
      return `<div class="stack"><p class="hint pad">${esc(t("fam_intro"))}</p><div id="famPending" class="stack"></div>
        <section class="card" id="famMail"></section>
        <section class="card pad-card"><h2>${esc(t("fam_paste_title"))}</h2><p class="hint">${esc(t("fam_paste_hint"))}</p>
          <div class="btns"><button class="btn primary" data-act="fam-paste">${icon("paste")}${esc(t("paste"))}</button>
            <button class="btn" data-act="scan">${icon("scan")}${esc(t("scan"))}</button>
            <button class="btn" data-act="pick-file">${icon("file")}${esc(t("file"))}</button></div></section>
        <section class="card" id="famDevices"></section><section class="card" id="famHelpers"></section></div>`;
    },
    update() {
      const F = S.family || { helpers: [], devices: [] };
      setHtml("#famPending", F.helpers.filter((h) => h.pending).map((h) => `<section class="card pad-card fam-pending">
          <h2>${esc(t("fam_pending_title", { n: h.name }))}</h2><ul class="fam-list">${h.pending.summary.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
          <div class="btns"><button class="btn primary" data-act="fam-apply" data-pair="${esc(h.pair)}">${icon("check")}${esc(t("fam_install"))}</button>
            <button class="btn" data-act="fam-decline" data-pair="${esc(h.pair)}">${esc(t("fam_decline"))}</button></div></section>`).join(""));
      const M = F.dht || { on: true };
      const mailNow = M.error ? t("fam_mail_err") : M.ok_at ? t("fam_mail_ok", { a: ago(M.ok_at * 1000) }) : t("fam_mail_wait");
      setHtml("#famMail", swRow("fam-dht", !!M.on, t("fam_mail_title"), t("fam_mail_desc"))
        + (M.on && (F.devices.length || F.helpers.length) ? `<div class="switch-row sub"><div class="main"><span>${esc(mailNow)}</span></div>
          <button class="link-btn" data-act="fam-check">${esc(t("fam_mail_check"))}</button></div>` : ""));
      const mailText = (mm) => !mm || !M.on ? "" : " · " + t("fam_mail_" + mm.state);
      const devs = F.devices.map((d) => {
        const sn = d.snap;
        const st = !sn ? t("fam_dev_wait") : [sn.status === "on" ? t("fam_st_on", { s: sn.server || "" }) : sn.status === "awg"
          ? t("fam_st_awg", { s: sn.server || "" }) : t("fam_st_off"), t("m_" + (sn.method || "auto")), "v" + (sn.ver || "?"), ago(d.snap_at * 1000)].join(" · ");
        const last = d.sent && d.sent.length ? d.sent[d.sent.length - 1] : null;
        return `<button class="row" data-act="fam-device" data-pair="${esc(d.pair)}">${icon("phone")}<span class="main"><span class="title"><span>${esc(d.name)}</span></span>
          <span class="meta">${esc(st)}</span>${last ? `<span class="meta">${esc(t("fam_last", { s: t("fam_sent_" + last.state) + (last.state === "sent" ? mailText(d.mail) : "") + " · " + ago(last.at * 1000) }))}</span>` : ""}</span>${icon("chev", "chev")}</button>`;
      }).join("");
      setHtml("#famDevices", `<div class="card-head"><h2>${esc(t("fam_devices_title"))}</h2></div>${devs || `<p class="hint pad">${esc(t("fam_devices_empty"))}</p>`}
        <div class="pad"><button class="btn wide" data-act="fam-invite">${icon("plus")}${esc(t("fam_invite_btn"))}</button></div>`);
      const helps = F.helpers.map((h) => `<div class="choice-row fam-helper"><div class="main"><b>${esc(t("fam_helper_by", { n: h.name }))}</b>
          <span class="hint">${esc(t("fam_helper_note"))}</span></div></div>
        <div class="choice-row"><b>${esc(t("fam_mode"))}</b><div class="chips"><button data-act="fam-mode" data-pair="${esc(h.pair)}" data-v="ask" aria-pressed="${h.mode !== "auto"}">${esc(t("fam_mode_ask_s"))}</button>
          <button data-act="fam-mode" data-pair="${esc(h.pair)}" data-v="auto" aria-pressed="${h.mode === "auto"}">${esc(t("fam_mode_auto_s"))}</button></div></div>
        <div class="pad btns"><button class="btn" data-act="fam-report" data-pair="${esc(h.pair)}">${icon("send")}${esc(t("fam_report"))}</button>
          <button class="btn" data-act="fam-remove" data-pair="${esc(h.pair)}">${esc(t("fam_disconnect"))}</button></div>`).join("");
      setHtml("#famHelpers", `<div class="card-head"><h2>${esc(t("fam_helpers_title"))}</h2></div>${helps || `<p class="hint pad">${esc(t("fam_helpers_empty"))}</p>`}`);
    },
  };

  function famDhtOn() { return ((S.family || {}).dht || {}).on !== false; }

  /* Приглашение или посылка: отправить в мессенджер, скопировать, сохранить файлом, QR-код. */
  let famTextCur = "";
  function famTextSheet(title, hint, text) {
    famTextCur = text;
    let qr = "";
    try { qr = call("qr", { text }); } catch (e) { qr = ""; }
    openSheet(`<h2>${esc(title)}</h2><p class="hint">${esc(hint)}</p>
      ${qr ? `<img class="fam-qr" src="${esc(qr)}" alt="QR">` : ""}
      <div class="menu">
        <button class="row" data-act="fam-share">${icon("send")}<span class="main"><span class="title"><span>${esc(t("fam_share"))}</span></span></span></button>
        <button class="row" data-act="fam-copy">${icon("copy")}<span class="main"><span class="title"><span>${esc(t("fam_copy"))}</span></span></span></button>
        <button class="row" data-act="fam-save">${icon("file")}<span class="main"><span class="title"><span>${esc(t("fam_save_file"))}</span></span></span></button>
      </div>`);
  }

  function famInviteSheet() {
    const F = S.family || {};
    openSheet(`<h2>${esc(t("fam_invite_title"))}</h2><p class="hint">${esc(t("fam_invite_text"))}</p>
      ${F.me ? "" : `<label class="field">${esc(t("fam_me_label"))}<input id="famMe" maxlength="40" placeholder="${esc(t("fam_me_ph"))}"></label>`}
      <label class="field">${esc(t("fam_dev_label"))}<input id="famDev" maxlength="40" placeholder="${esc(t("fam_dev_ph"))}"></label>
      <button class="btn primary wide" data-act="fam-invite-go">${esc(t("fam_invite_make"))}</button>`);
  }

  let famAcceptText = "";
  function famAcceptSheet(info, text) {
    famAcceptText = text;
    openSheet(`<h2>${esc(t("fam_accept_title", { n: info.helper }))}</h2>
      <ul class="fam-list"><li>${esc(t("fam_accept_can"))}</li><li>${esc(t("fam_accept_cannot"))}</li><li>${esc(t("fam_accept_off"))}</li></ul>
      <div class="choice-row"><b>${esc(t("fam_mode"))}</b><div class="chips" id="famAccMode"><button data-act="fam-chip" data-v="ask" aria-pressed="true">${esc(t("fam_mode_ask_s"))}</button>
        <button data-act="fam-chip" data-v="auto" aria-pressed="false">${esc(t("fam_mode_auto_s"))}</button></div></div>
      <button class="btn primary wide" data-act="fam-allow">${icon("check")}${esc(t("fam_allow"))}</button>`);
  }

  function famReceive(text) {
    let x;
    try { x = call("family_receive", { text }); } catch (e) { toast(e.message, "error"); return; }
    if (x.kind === "invite") famAcceptSheet(x, text);
    else if (x.kind === "packet") { toast(x.auto ? t("fam_auto_applying", { n: x.from }) : t("fam_got_packet", { n: x.from }), "ok"); if (stack[stack.length - 1] !== "family") go("family"); }
    else if (x.kind === "report") toast(t("fam_got_report", { n: x.name }), "ok");
    else if (x.kind === "old") toast(t("fam_old", { n: x.name }), "info");
    poll();
  }

  /* Настроить устройство из семьи: снимок его программы и что поменять → «Отправить». */
  let famDev = null;
  function famDeviceSheet(pair) {
    famDev = ((S.family || {}).devices || []).find((x) => x.pair === pair);
    if (!famDev) return;
    const sn = famDev.snap;
    const cur = (v) => sn ? (v ? t("on") : t("off")) : t("fam_unknown");
    const tri = (key, label, v) => `<div class="choice-row fam-tri"><div class="main"><b>${esc(label)}</b><span class="hint">${esc(t("fam_now", { v: cur(v) }))}</span></div>
      <div class="chips" data-fam-set="${key}"><button data-act="fam-chip" data-v="" aria-pressed="true">${esc(t("fam_keep_s"))}</button>
        <button data-act="fam-chip" data-v="on" aria-pressed="false">${esc(t("on"))}</button><button data-act="fam-chip" data-v="off" aria-pressed="false">${esc(t("off"))}</button></div></div>`;
    const subs = sn ? sn.subs.map((x) => `<label class="check-row"><input type="checkbox" data-fam-sub="${esc(x.id)}" data-url="${esc(x.url)}" data-name="${esc(x.name)}">
      <span>${esc(t("fam_remove_x", { n: x.name || t("fam_sub") }))} · ${esc(t("fam_sub_meta", { n: x.n }))}</span></label>`).join("") : "";
    const mans = sn ? sn.manual.map((x) => `<label class="check-row"><input type="checkbox" data-fam-srv="${esc(x.id)}"><span>${esc(t("fam_remove_x", { n: x.name }))}</span></label>`).join("") : "";
    openSheet(`<h2>${esc(t("fam_device_title", { n: famDev.name }))}</h2>
      <p class="hint">${esc(sn ? t("fam_snap_from", { a: ago(famDev.snap_at * 1000) }) : t("fam_no_snap"))}</p>
      ${sn && sn.problems && sn.problems.length ? `<div class="problem"><p>${esc(t("fam_dev_problems", { p: sn.problems.join("; ") }))}</p></div>` : ""}
      <h3>${esc(t("fam_subs"))}</h3>${subs || `<p class="hint">${esc(t(sn ? "fam_no_subs" : "fam_no_snap_short"))}</p>`}
      <label class="field">${esc(t("fam_sub_new"))}<input id="famSubUrl" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="https://…"></label>
      <h3>${esc(t("fam_servers"))}</h3>${mans}
      <label class="field">${esc(t("fam_servers_new"))}<textarea id="famSrv" spellcheck="false" autocapitalize="off" placeholder="vless://…"></textarea></label>
      <h3>${esc(t("fam_mode_title"))}</h3>
      <div class="fam-methods chips" data-fam-method><button data-act="fam-chip" data-v="" aria-pressed="true">${esc(t("fam_keep_s"))}</button>
        ${FAM_M.map((m) => `<button data-act="fam-chip" data-v="${m}" aria-pressed="false">${esc(t("m_" + m))}</button>`).join("")}</div>
      <p class="hint">${esc(t("fam_now", { v: sn ? t("m_" + (sn.method || "auto")) : t("fam_unknown") }))}</p>
      ${tri("block_ads", t("tile_ads"), sn && sn.set.block_ads)}${tri("dns_encrypted", t("tile_dns"), sn && sn.set.dns_encrypted)}${tri("accel", t("accel_name"), sn && sn.set.accel)}
      <h3>${esc(t("fam_actions"))}</h3>
      <label class="check-row"><input type="checkbox" id="famUpd"><span>${esc(t("fam_do_update"))}</span></label>
      <label class="check-row"><input type="checkbox" id="famRe"><span>${esc(t("fam_do_reconnect"))}</span></label>
      <label class="check-row"><input type="checkbox" id="famWarp"><span>${esc(t("fam_do_warp"))}</span></label>
      <button class="btn primary wide" data-act="fam-send">${icon("send")}${esc(t("fam_send"))}</button>
      ${famDev.invite ? `<button class="btn wide" data-act="fam-invite-again">${icon("qr")}${esc(t("fam_invite_again"))}</button>` : ""}
      <button class="btn wide" data-act="fam-remove" data-pair="${esc(famDev.pair)}">${icon("trash")}${esc(t("fam_remove"))}</button>`);
  }

  VIEWS.settings = {
    title: "settings",
    render() { return `<div id="setBox" class="stack"></div>`; },
    update() {
      const st = S.settings;
      const chips = (k, opts) => `<div class="chips">${opts.map(([v, l]) =>
        `<button data-act="set" data-k="${k}" data-v="${v}" aria-pressed="${(k === "lang" ? lang : st[k]) === v}">${esc(l)}</button>`).join("")}</div>`;
      const apps = (st.excluded_apps || []).length;
      setHtml("#setBox", `<section class="card">
          <div class="choice-row"><b>${esc(t("lang"))}</b>${chips("lang", [["ru", "RU"], ["en", "EN"]])}</div>
          <div class="choice-row"><b>${esc(t("theme"))}</b>${chips("theme", [["auto", t("th_auto")], ["dark", t("th_dark")], ["light", t("th_light")]])}</div>
        </section>
        <section class="card"><div class="card-head"><h2>${esc(t("s_conn"))}</h2></div>${modeHtml()}
          ${navRow('data-nav="share"', "wifi", t("tile_share"), S.share.on ? t("tile_share_on") : t("tile_share_off"))}
          ${navRow('data-nav="vps"', "server", t("tile_vps"), t("tile_vps_sub"))}</section>
        <section class="card"><div class="card-head"><h2>${esc(t("s_automation"))}</h2></div>
          ${sw("ru_direct", "s_ru", "s_ru_text")}${sw("block_quic", "s_quic", "s_quic_text")}
          ${sw("autopilot", "s_auto", "s_auto_text")}
          ${sw("mask_auto", "s_mask", "s_mask_text")}${sw("whitelist_auto", "s_wl", "s_wl_text")}
          ${sw("dns_encrypted", "s_dns", "s_dns_text")}${sw("ads_ask_sites", "s_ads_ask", "s_ads_ask_text")}
          ${sw("sub_alerts", "s_sub_alerts", "s_sub_alerts_text")}
          ${sw("net_profiles", "s_net", "s_net_text")}
          ${navRow('data-nav="pro"', "gear", t("pro_title"), (S.collect || {}).on ? t("collect_running_short") : t("s_pro_text"))}</section>
        <section class="card"><div class="card-head"><h2>${esc(t("s_protect"))}</h2></div>
          ${sw("app_lock", "s_app_lock", "s_app_lock_text")}${sw("encrypt_data", "s_encrypt", "s_encrypt_text")}
          ${sw("cert_watch", "s_certs", "s_certs_text")}</section>
        <section class="card">
          ${navRow('data-nav="status"', "shield", t("status_title"), healthVerdict().short)}
          ${navRow('data-nav="apps"', "apps", t("s_apps"), apps ? t("s_apps_n", { n: apps }) : t("s_apps_text"))}
          ${navRow('data-nav="ads"', "ban", t("ads_title"), (S.ads || {}).enabled ? t("tile_ads_on") : t("s_ads_text"))}
          ${navRow('data-nav="dpi"', "swap", t("dpi_title"), t("s_dpi_text"))}
          ${navRow('data-nav="routes"', "list", t("routes_title"), t("s_routes_text"))}
          ${navRow('data-nav="transfer"', "qr", t("s_transfer"), t("s_transfer_text"))}
          ${navRow('data-act="always-on"', "shield", t("s_always"), t("s_always_text"))}
          ${navRow('data-nav="check"', "shield", t("s_check"), S.check ? t("check_sum", { e: S.check.errors, w: S.check.warnings }) : t("s_check_text"))}
          ${navRow('data-nav="log"', "list", t("s_log"), "")}
          ${navRow('data-nav="errors"', "alert", t("errors_title"), S.errors_count ? t("errors_n", { n: S.errors_count }) : t("errors_none"))}
          ${navRow('data-act="report"', "copy", t("s_report"), "")}
        </section>
        ${appUpdateHtml()}
        <p class="about">${esc(t("about", { v: S.version, core: (S.core || "").replace(/^.*?(\d+\.\d+\.\d+).*$/, "$1") || "—" }))}</p>`);
    },
  };

  // ---------- профессиональные: защита, память маршрутов, автоматика, сбор ошибок ----------
  const PRO_GROUPS = [
    ["pg_protect", [["fuses_enabled", "s_fuses"], ["guard_rollback", "s_guard"], ["safe_start", "s_safe"]]],
    ["pg_memory", [["net_memory", "s_netmem"]]],
    ["pg_auto", [["autopilot", "s_auto"], ["fp_auto", "s_fp"], ["mask_auto", "s_mask"], ["data_watch", "s_dwatch"],
      ["stall_check", "s_stall16"], ["warp_fallback", "s_warpfb"], ["whitelist_auto", "s_wl"]]],
  ];
  function leftText(sec) {
    const h = Math.floor(sec / 3600), m = Math.ceil((sec % 3600) / 60);
    return h ? t("left_hm", { h, m }) : t("dur_m", { n: Math.max(1, m) });
  }
  function proExtra(key) {
    const pro = S.pro || {};
    if (key === "fuses_enabled" && pro.keys && pro.keys.fuses_enabled !== false) {
      const f = pro.fuses || [];
      const left = (sec) => sec >= 3600 ? t("left_h", { n: Math.ceil(sec / 3600) }) : t("left_m", { n: Math.max(1, Math.ceil(sec / 60)) });
      return `<div class="switch-row sub"><div class="main"><span>${esc(f.length ? f.map((x) => `${x.kind} — ${left(x.left)}`).join("; ") : t("fuses_none"))}</span></div>
        ${f.length ? `<button class="link-btn" data-act="fuses-clear">${esc(t("fuses_clear"))}</button>` : ""}</div>`;
    }
    if (key === "net_memory" && S.settings.net_memory !== false && (S.ladder || {}).count) {
      return `<div class="switch-row sub"><div class="main"><span>${esc(t("netmem_n", { n: S.ladder.count }))}</span></div>
        <button class="link-btn" data-act="netmem-clear">${esc(t("netmem_clear"))}</button></div>`;
    }
    return "";
  }
  function collectHtml() {
    const c = S.collect || {};
    const body = c.on
      ? `<p class="hint">${esc(t("collect_running", { left: leftText(c.left || 0), n: c.events || 0 }))}</p>
         <button class="btn primary wide" data-act="collect-stop">${icon("stop")}${esc(t("collect_stop"))}</button>`
      : `<p class="hint">${esc(t("collect_desc"))}</p>
         <div class="btns four">${[1, 6, 24, 72].map((h) => `<button class="btn${h === 24 ? " primary" : ""}" data-act="collect-start" data-h="${h}">${esc(t("collect_for", { h }))}</button>`).join("")}</div>`;
    const rep = c.report_ok ? `<p class="hint">${esc(t("collect_last", { f: c.report }))}</p>
      <div class="btns two"><button class="btn" data-act="collect-send">${icon("send")}${esc(t("collect_send"))}</button>
        <button class="btn" data-act="collect-copy">${icon("copy")}${esc(t("collect_copy"))}</button></div>` : "";
    return `<section class="card"><div class="card-head"><h2>${esc(t("pg_collect"))}</h2></div><div class="card-body stack">${body}${rep}</div></section>`;
  }
  VIEWS.pro = {
    title: "pro_title",
    render() { return `<div id="proBox" class="stack"></div>`; },
    update() {
      const pro = S.pro || {};
      setHtml("#proBox", `<p class="hint">${esc(t("pro_intro"))}</p>
        ${pro.safe_mode ? `<div class="problem"><p>${esc(t("pro_safe_mode"))}</p></div>` : ""}
        ${PRO_GROUPS.map(([g, items]) => `<section class="card"><div class="card-head"><h2>${esc(t(g))}</h2></div>
          ${items.map(([k, title]) => sw(k, title, title + "_text") + proExtra(k)).join("")}</section>`).join("")}
        ${collectHtml()}
        <button class="btn wide" data-act="pro-reset">${icon("refresh")}${esc(t("pro_reset"))}</button>`);
    },
  };

  // ---------- приложения без VPN ----------
  let appsList = null;
  let appsSel = null;
  VIEWS.apps = {
    title: "apps_title",
    render() {
      return `<p class="hint">${esc(t("apps_hint"))}</p><input type="search" id="appsSearch" placeholder="${esc(t("search"))}">
        <section class="card" id="appsBox"><p class="hint empty">${esc(t("apps_loading"))}</p></section>
        <button class="btn primary wide" data-act="apps-save">${esc(t("save"))}</button>`;
    },
    mount() {
      appsSel = new Set(S.settings.excluded_apps || []);
      setTimeout(() => {
        appsList = act("apps") || [];
        this.draw();
      }, 30);
      $("#appsSearch").addEventListener("input", () => this.draw());
    },
    draw() {
      if (!appsList || !$("#appsBox")) return;
      const q = ($("#appsSearch").value || "").trim().toLowerCase();
      const rows = appsList.filter((a) => !q || a.name.toLowerCase().includes(q) || a.pkg.includes(q)).map((a) =>
        `<div class="switch-row"><div class="main"><b>${esc(a.name)}</b><span>${esc(a.pkg)}</span></div>
          <button class="switch" role="switch" aria-checked="${appsSel.has(a.pkg)}" data-act="app-flip" data-pkg="${esc(a.pkg)}"></button></div>`);
      $("#appsBox").innerHTML = rows.join("");
    },
  };

  // ---------- свои правила ----------
  VIEWS.rules = {
    title: "rules_title",
    render() {
      const st = S.settings;
      const area = (k, title) => `<label class="field">${esc(t(title))}<textarea id="r_${k}" spellcheck="false" autocapitalize="off">${esc(st[k] || "")}</textarea></label>`;
      return `<p class="hint">${esc(t("rules_hint"))}</p>${area("proxy_list", "r_proxy")}${area("direct_list", "r_direct")}${area("block_list", "r_block")}
        <button class="btn primary wide" data-act="rules-save">${esc(t("save"))}</button>`;
    },
  };

  // ---------- общие кусочки для новых экранов ----------
  // перерисовать, только если человек сейчас не выбирает и не печатает внутри (иначе список закроется под пальцем)
  function safeHtml(sel, html) {
    const el = $(sel);
    if (!el) return;
    const a = document.activeElement;
    if (a && el.contains(a) && /^(SELECT|INPUT|TEXTAREA)$/.test(a.tagName)) return;
    setHtml(sel, html);
  }
  function ago(ts) {
    if (!ts) return t("never");
    const m = Math.max(0, Math.round((Date.now() - ts) / 60000));
    if (m < 1) return t("ago_now");
    if (m < 60) return t("ago_min", { n: m });
    if (m < 48 * 60) return t("ago_h", { n: Math.round(m / 60) });
    return t("ago_d", { n: Math.round(m / 1440) });
  }
  function swRow(act, on, title, text, extra) {
    return `<div class="switch-row"><div class="main"><b>${esc(title)}</b>${text ? `<span>${esc(text)}</span>` : ""}</div>
      <button class="switch" role="switch" aria-checked="${!!on}" data-act="${act}" ${extra || ""}></button></div>`;
  }
  function taskOf(kind) { return S.task && S.task.kind === kind ? S.task.title : ""; }

  // ---------- свои маршруты: сервисы, сайты, свои прокси ----------
  function routeOptions(value, withAuto) {
    const R = S.routes || {};
    const o = (v, label) => `<option value="${esc(v)}"${v === value ? " selected" : ""}>${esc(label)}</option>`;
    let html = (withAuto ? o("auto", t("rt_auto")) : "") + o("proxy", t("rt_proxy")) + o("warp", t("rt_warp")) + o("direct", t("rt_direct"))
      + o("dpi", t("rt_dpi")) + o("block", t("rt_block"));
    const servers = (S.servers || []).filter((s) => s.usable);
    if (servers.length) html += `<optgroup label="${esc(t("rt_server_group"))}">${servers.map((s) => o("server:" + s.key, s.name)).join("")}</optgroup>`;
    const prox = R.proxies || [];
    html += `<optgroup label="${esc(t("rt_proxy_group"))}">${prox.map((p) => o("custom:" + p.id, p.title)).join("")}
      ${o("custom:new", t("rt_proxy_new"))}</optgroup>`;
    // выбранный сервер пропал из подписки — всё равно показать выбор
    if (value && value.startsWith("server:") && !servers.some((s) => "server:" + s.key === value)) html += o(value, t("rt_server_gone"));
    return html;
  }

  function proxyStatus(p) {
    const c = p.check || {};
    if (!c.at) return `<span class="meta">${esc(t("px_not_checked"))}</span>`;
    if (!c.ok) return `<span class="meta warn">${esc(t("px_bad"))}${c.error ? ": " + esc(c.error) : ""}</span>`;
    const tt = c.tiktok === "ok" ? t("px_tt_ok") : c.tiktok === "region" ? t("px_tt_region") : c.tiktok ? t("px_tt_bad") : "";
    return `<span class="meta good">${esc(t("px_ok", { cc: c.loc || "?" }))}${tt ? " · " + esc(tt) : ""}${c.chain ? " · " + esc(t("px_chain_on")) : ""}</span>`;
  }

  VIEWS.routes = {
    title: "routes_title",
    render() {
      return `<p class="hint">${esc(t("routes_hint"))}</p>
        <section class="card"><div class="card-head"><h2>${esc(t("repair_title"))}</h2></div>
          <div class="card-body"><p class="hint">${esc(t("repair_text"))}</p>
            <div class="form-row"><input id="repairHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="example.com">
              <button class="btn primary" data-act="repair">${esc(t("repair_btn"))}</button></div></div>
          <div id="rtRepair"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("rt_services"))}</h2></div><div id="rtServices"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("rt_sites"))}</h2></div>
          <div class="card-body">
            <input id="siteHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="${esc(t("rt_site_ph"))}">
            <div class="form-row"><select id="siteTarget"></select>
              <button class="btn primary" data-act="site-add">${esc(t("add"))}</button></div></div>
          <div id="rtSites"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("rt_proxies"))}</h2></div>
          <div id="rtProxies"></div>
          <div class="card-body" id="pxForm">
            <p class="hint">${esc(t("px_hint"))}</p>
            <input id="pxRaw" autocapitalize="off" spellcheck="false" placeholder="socks5://login:password@1.2.3.4:1080">
            <div class="form-row"><input id="pxName" placeholder="${esc(t("px_name_ph"))}">
              <select id="pxKind"><option value="auto">${esc(t("px_auto"))}</option><option value="socks">SOCKS5</option><option value="http">HTTP</option></select></div>
            ${swRow("px-chain-new", true, t("px_chain"), t("px_chain_text"), 'id="pxChain"')}
            <button class="btn wide" data-act="px-add">${icon("plus")}${esc(t("px_add"))}</button></div></section>
        ${navRow('data-nav="rules"', "list", t("s_rules"), t("rt_lists_text"))}`;
    },
    mount() {
      const sel = $("#siteTarget");
      sel.innerHTML = routeOptions("proxy", false);
    },
    update() {
      const R = S.routes || { services: [], sites: [], proxies: [] };
      const svc = (R.services || []).map((s) => `<div class="route-row"><div class="main"><b>${esc(s.name)}</b>
          ${s.warn ? `<span class="meta warn">${esc(s.warn)}</span>` : ""}</div>
          <select data-change="route-svc" data-name="${esc(s.name)}" aria-label="${esc(s.name)}">${routeOptions(s.choice, true)}</select></div>`).join("");
      safeHtml("#rtServices", svc);
      const rp = S.repair;
      const fixing = taskOf("repair");
      const rstate = (x) => x.fix === "proxy" ? `<span class="ok-text">${esc(t("repair_fix_vpn"))}</span>`
        : x.fix === "server" ? `<span class="ok-text">${esc(t("repair_fix_server", { name: x.server || "?" }))}</span>`
        : x.fix === "direct" ? `<span class="ok-text">${esc(t("repair_fix_direct"))}</span>`
        : `<span class="${x.state === "ok" || x.state === "small" ? "ok-text" : x.state === "skip" ? "" : "warn-text"}">${esc(t("repair_s_" + (x.state || "skip")))}</span>`;
      safeHtml("#rtRepair", fixing ? `<div class="busy-row"><span class="spinner"></span><span>${esc(fixing)}…</span></div>`
        : rp ? `<div class="card-body"><p><b>${esc(rp.site)}</b>: ${esc(rp.verdict)}</p></div>${(rp.hosts || []).map((x) =>
          `<div class="row"><div class="main"><div class="title"><span class="mono">${esc(x.host)}</span></div>
            <span class="meta">${rstate(x)}${x.detail ? " · " + esc(x.detail) : ""}</span></div></div>`).join("")}` : "");
      const sites = (R.sites || []).map((s) => `<div class="route-row"><div class="main"><b class="mono">${esc(s.site)}</b>
          ${s.warn ? `<span class="meta warn">${esc(s.warn)}</span>` : ""}</div>
          <select data-change="route-site" data-site="${esc(s.site)}" aria-label="${esc(s.site)}">${routeOptions(s.value, true)}</select></div>`).join("");
      safeHtml("#rtSites", sites || `<p class="hint pad">${esc(t("rt_sites_empty"))}</p>`);
      const checking = taskOf("proxy");
      const px = (R.proxies || []).map((p) => `<div class="row px-row"><div class="main"><div class="title"><span>${esc(p.title)}</span>
            ${p.used && p.used.length ? `<i class="tag">${esc(t("px_used", { n: p.used.length }))}</i>` : ""}</div>
            <span class="meta">${esc(p.label)}${p.auth ? " · " + esc(t("px_auth")) : ""}</span>${proxyStatus(p)}</div>
          <button class="icon-btn" data-act="px-check" data-id="${esc(p.id)}" aria-label="${esc(t("test"))}" ${checking ? "disabled" : ""}>${icon("refresh")}</button>
          <button class="icon-btn" data-act="px-menu" data-id="${esc(p.id)}" aria-label="…">${icon("more")}</button></div>`).join("");
      safeHtml("#rtProxies", (checking ? `<div class="busy-row">${esc(checking)}…</div>` : "") + px);
      if (!$("#siteTarget").options.length) $("#siteTarget").innerHTML = routeOptions("proxy", false);
    },
  };

  function proxyMenu(id) {
    const p = ((S.routes || {}).proxies || []).find((x) => x.id === id);
    if (!p) return;
    openSheet(`<h2>${esc(p.title)}</h2><p class="hint">${esc(p.label)}</p>
      <label class="field">${esc(t("px_name"))}<input id="pxRename" value="${esc(p.name || "")}" placeholder="${esc(t("px_name_ph"))}"></label>
      ${swRow("px-chain", p.chain, t("px_chain"), t("px_chain_text"), `data-id="${esc(id)}"`)}
      ${p.check && p.check.ip ? `<button class="btn wide" data-act="px-report" data-ip="${esc(p.check.ip)}">${icon("shield")}${esc(t("px_report"))}</button>` : ""}
      <div class="btns"><button class="btn" data-act="px-save" data-id="${esc(id)}">${esc(t("save"))}</button>
        <button class="btn danger" data-act="px-del" data-id="${esc(id)}">${icon("trash")}${esc(t("m_delete"))}</button></div>`);
  }

  // ---------- блокировка рекламы ----------
  const ADS_LEVELS = ["light", "normal", "pro", "pro_plus"];
  VIEWS.ads = {
    title: "ads_title",
    render() {
      const A = S.ads || {};
      return `<div id="adsTop" class="stack"></div>
        <section class="card" id="adsChk"></section>
        <div id="adsSus"></div>
        <section class="card"><div class="card-head"><h2>${esc(t("ads_level"))}</h2></div><div class="card-body" id="adsLevel"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("ads_lists"))}</h2></div><div id="adsLists"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("ads_check"))}</h2></div><div class="card-body">
          <div class="form-row"><input id="adsHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="example.com">
            <button class="btn" data-act="ads-lookup">${esc(t("ads_check_btn"))}</button></div>
          <div id="adsLookup"></div></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("ads_journal"))}</h2></div><div id="adsJournal"></div></section>
        <section class="card"><div class="card-head"><h2>${esc(t("ads_own"))}</h2></div><div class="card-body">
          <label class="field">${esc(t("ads_custom"))}<textarea id="adsCustom" spellcheck="false" autocapitalize="off" placeholder="ads.example.com">${esc(A.custom || "")}</textarea></label>
          <label class="field">${esc(t("ads_allow"))}<textarea id="adsAllow" spellcheck="false" autocapitalize="off" placeholder="shop.example.com">${esc(A.allow || "")}</textarea></label>
          <button class="btn wide" data-act="ads-save">${esc(t("save"))}</button></div></section>
        <details class="more card-pad"><summary>${esc(t("ads_dns_title"))}</summary><p>${esc(t("ads_dns_text"))}</p>
          <div class="btns"><button class="btn" data-act="copy" data-text="dns.adguard-dns.com">${icon("copy")}dns.adguard-dns.com</button>
            <button class="btn" data-act="check-fix" data-v="private_dns">${esc(t("ads_dns_open"))}</button></div></details>
        <p class="hint">${esc(t("ads_limits"))}</p>`;
    },
    update() {
      const A = S.ads || {};
      const busy = taskOf("ads");
      let status;
      if (!A.enabled) status = t("ads_off");
      else if (A.paused_until) status = t("ads_paused", { time: new Date(A.paused_until).toTimeString().slice(0, 5) });
      else if (!A.mode) status = t("ads_wait_lists");
      else if (S.status === "on") status = t("ads_on_vpn");
      else if (A.filter_on) status = t("ads_on_novpn");
      else if (A.without_vpn) status = t("ads_on_waiting");
      else status = t("ads_on_vpn_only");
      const needStart = A.enabled && A.without_vpn && S.status !== "on" && !A.filter_on && A.mode && !A.paused_until;
      const pause = !A.enabled ? "" : A.paused_until
        ? `<button class="btn wide" data-act="ads-pause" data-v="0">${esc(t("ads_resume"))}</button>`
        : `<div class="pause-row"><span>${esc(t("ads_pause"))}</span>${[5, 30, 60].map((m) =>
            `<button class="btn small" data-act="ads-pause" data-v="${m}">${esc(t("ads_min", { n: m }))}</button>`).join("")}</div>`;
      safeHtml("#adsTop", `<section class="card">
          ${swRow("ads-flip", A.enabled, t("ads_main"), status)}
          ${swRow("ads-novpn", A.without_vpn, t("ads_novpn"), t("ads_novpn_text"))}
          ${needStart ? `<div class="card-body"><div class="note">${esc(t(A.need_permission ? "ads_need_perm" : "ads_stopped"))}</div>
            <button class="btn primary wide" data-act="filter-start">${icon("shield")}${esc(t("ads_start"))}</button></div>` : ""}
          ${pause ? `<div class="card-body">${pause}</div>` : ""}</section>
        ${busy ? `<div class="busy-row"><span class="spinner"></span><span>${esc(busy)}…</span></div>` : ""}`);
      const sus = A.suspects || [];
      safeHtml("#adsSus", sus.length ? `<section class="card warn-card"><div class="card-head"><h2>${esc(t("ads_sus_title"))}</h2></div>
          <div class="card-body"><p class="hint">${esc(t("ads_sus_hint"))}</p></div>
          ${sus.map((x) => `<div class="row"><div class="main"><div class="title"><span class="mono">${esc(x.site)}</span></div>
            <span class="meta">${esc(t(x.threat ? "ads_sus_threat" : "ads_sus_list", { list: (x.lists || []).join(", ") }))}</span></div>
            <div class="btns"><button class="btn small ${x.threat ? "" : "primary"}" data-act="ads-site" data-site="${esc(x.site)}" data-v="1">${esc(t("ads_site_allow"))}</button>
            <button class="btn small" data-act="ads-site" data-site="${esc(x.site)}" data-v="0">${esc(t("ads_site_keep"))}</button></div></div>`).join("")}</section>` : "");
      safeHtml("#adsLevel", `<div class="seg four" role="group">${ADS_LEVELS.map((l) =>
          `<button data-act="ads-level" data-v="${l}" aria-pressed="${A.level === l}">${esc(t("ads_lv_" + l))}</button>`).join("")}</div>
        <p class="hint">${esc(t("ads_lv_" + (A.level || "normal") + "_text"))}</p>`);
      const counts = A.counts || {};
      const n = (id) => counts[id] ? " · " + t("ads_n", { n: counts[id] }) : "";
      setHtml("#adsChk", adsCheckHtml(A, busy));
      safeHtml("#adsLists", ["popups", "threats", "ru", "m_ads", "m_privacy", "m_malware"].map((id) =>
          swRow("ads-list", (A.lists || {})[id], t("ads_l_" + id), t("ads_l_" + id + "_text") + n(id), `data-id="${id}"`)).join("")
        + `<div class="card-body"><p class="hint">${esc(A.total ? t("ads_total", { n: A.total, ago: ago(A.updated_at) }) : t("ads_no_lists"))}
          ${A.missing && A.missing.length ? " " + esc(t("ads_missing")) : ""}</p>
          <button class="btn wide" data-act="ads-update" ${busy ? "disabled" : ""}>${icon("refresh")}${esc(t("ads_update"))}</button></div>`);
      const top = (A.top || []).map((x) => `<div class="row"><div class="main"><div class="title"><span class="mono">${esc(x.host)}</span></div>
          <span class="meta">${esc(t("ads_times", { n: x.n }))}</span></div>
          ${x.domain ? `<button class="btn small" data-act="ads-allow" data-host="${esc(x.host)}">${esc(t("ads_allow_btn"))}</button>` : ""}</div>`).join("");
      safeHtml("#adsJournal", `<div class="card-body"><p class="big-num">${esc(String(A.today || 0))}</p>
          <p class="hint">${esc(t("ads_today"))}</p></div>${top || `<p class="hint pad">${esc(t("ads_journal_empty"))}</p>`}`);
    },
  };

  // «Почему реклама проходит?» — пункты с «Исправить» (Engine.adsCheckNow)
  const ADS_FIX_LABEL = { ads_on: "fix_turn_on", ads_resume: "ads_resume", ads_update: "fix_download", ads_apply: "fix_apply",
    ads_without_vpn: "fix_turn_on", apps: "fix_where" };
  function adsCheckHtml(A, busy) {
    const c = A.check;
    const ic = { ok: "check", info: "shield", warn: "alert", error: "ban" };
    const running = taskOf("ads_check");
    const rows = c ? c.items.map((x) => `<div class="check-item ${x.level === "warn" ? "warn" : x.level}">${icon(ic[x.level] || "alert")}
        <div class="main"><b>${esc(x.title)}</b>${x.detail ? `<span>${esc(x.detail)}</span>` : ""}
        ${x.fix && ADS_FIX_LABEL[x.fix] && x.level !== "ok" ? `<button class="btn small${x.level === "error" ? " primary" : ""}" data-act="ads-fix" data-v="${x.fix}">${esc(t(ADS_FIX_LABEL[x.fix]))}</button>` : ""}</div></div>`).join("") : "";
    const sum = c ? (c.errors || c.warnings ? t("ads_chk_sum", { e: c.errors, w: c.warnings }) : t("ads_chk_ok")) : t("ads_chk_hint");
    return `<div class="card-head"><h2>${esc(t("ads_chk_title"))}</h2></div><div class="card-body"><p class="hint">${esc(running ? running + "…" : sum)}</p>
      <button class="btn${c ? "" : " primary"} wide" data-act="ads-check" ${running || busy ? "disabled" : ""}>${icon("refresh")}${esc(t("ads_chk_btn"))}</button></div>${rows}`;
  }

  // ---------- обход замедлений ----------
  VIEWS.dpi = {
    title: "dpi_title",
    render() {
      const D = S.dpi || {};
      return `<p class="hint">${esc(t("dpi_hint"))}</p><div id="dpiTop" class="stack"></div>
        <section class="card"><div class="card-head"><h2>${esc(t("dpi_methods"))}</h2></div><div id="dpiList"></div></section>
        <section class="card"><div class="card-body">
          <label class="field">${esc(t("dpi_custom"))}<textarea id="dpiCustom" spellcheck="false" autocapitalize="off" placeholder="rutracker.org">${esc(D.custom || "")}</textarea></label>
          <button class="btn wide" data-act="dpi-save">${esc(t("save"))}</button></div></section>
        <p class="hint">${esc(t("dpi_limits"))}</p>`;
    },
    update() {
      const D = S.dpi || {};
      const busy = taskOf("dpi");
      const cur = (D.strategies || []).find((s) => s.id === D.strategy);
      let status;
      if (!D.enabled) status = t("dpi_off");
      else if (D.active) status = t("dpi_works", { m: cur ? cur.title : "", ago: ago(D.tested_at) });
      else if (D.tested_at) status = t("dpi_none");
      else status = t("dpi_not_yet");
      safeHtml("#dpiTop", `<section class="card">
          ${swRow("dpi-flip", D.enabled, t("dpi_main"), status, 'data-k="dpi_enabled"')}
          ${swRow("dpi-flip", D.youtube, "YouTube", "", 'data-k="dpi_youtube"')}
          ${swRow("dpi-flip", D.discord, "Discord", "", 'data-k="dpi_discord"')}
          ${swRow("dpi-flip", D.without_vpn, t("dpi_novpn"), t("dpi_novpn_text"), 'data-k="dpi_without_vpn"')}</section>
        ${busy ? `<section class="card check-busy"><span class="spinner"></span><span class="main">${esc(busy)}…</span>
            <button class="link-btn" data-act="stop">${esc(t("stop"))}</button></section>`
          : `<button class="btn ${D.active ? "" : "primary "}wide" data-act="dpi-pick" ${D.enabled ? "" : "disabled"}>${icon("refresh")}${esc(t("dpi_pick"))}</button>`}`);
      const res = {};
      (D.results || []).forEach((r) => { res[r.id] = r; });
      safeHtml("#dpiList", (D.strategies || []).map((s) => {
        const r = res[s.id];
        const meta = !r ? t("dpi_untested") : r.ok ? t("dpi_ok", { k: r.kbps > 0 ? r.kbps : "?" }) : (r.detail || t("dpi_fail"));
        return `<button class="row" data-act="dpi-choose" data-id="${esc(s.id)}" ${busy ? "disabled" : ""}><span class="main">
          <span class="title"><span>${esc(s.title)}</span>${s.id === D.strategy ? `<i class="tag ${D.active ? "good" : "warn"}">${esc(t(D.active ? "dpi_used" : "dpi_chosen"))}</i>` : ""}</span>
          <span class="meta${r && !r.ok ? " warn" : ""}">${esc(meta)}</span></span>${s.id === D.strategy ? icon("check", "check") : ""}</button>`;
      }).join(""));
    },
  };

  // ---------- проверка программы ----------
  VIEWS.check = {
    title: "check_title",
    render() { return `<div id="checkBox" class="stack"></div>`; },
    update() {
      const c = S.check;
      const running = S.busy && S.busy.kind === "check";
      const mark = { ok: "check", info: "list", warn: "alert", error: "ban" };
      const list = c ? c.items.map((i) => `<div class="check-item ${esc(i.level)}">${icon(mark[i.level] || "check")}
          <div class="main"><b>${esc(i.title)}</b>${i.detail ? `<span>${esc(i.detail)}</span>` : ""}
          ${i.fix ? `<button class="btn small" data-act="check-fix" data-v="${esc(i.fix)}">${esc(t("fix_" + i.fix))}</button>` : ""}</div></div>`).join("") : "";
      const sum = c ? (c.errors ? "bad" : c.warnings ? "mid" : "good") : "";
      setHtml("#checkBox", `<p class="hint">${esc(t("check_hint"))}</p>
        ${running ? `<section class="card check-busy"><span class="spinner"></span><span class="main">${esc(S.busy.title)}…</span>
            <button class="link-btn" data-act="stop">${esc(t("stop"))}</button></section>`
          : `<button class="btn ${c ? "" : "primary "}wide" data-act="check-run">${icon("shield")}${esc(t(c ? "check_again" : "check_run"))}</button>`}
        ${c ? `<section class="card"><div class="check-sum ${sum}">${esc(t("check_sum", { e: c.errors, w: c.warnings }))}</div>${list}</section>
          <button class="btn primary wide" data-act="check-send">${icon("send")}${esc(t("check_send"))}</button>
          <div class="btns two"><button class="btn" data-act="check-save">${icon("file")}${esc(t("check_save"))}</button>
            <button class="btn" data-act="check-copy">${icon("copy")}${esc(t("copy"))}</button></div>
          <p class="hint">${esc(t("check_private"))}</p>` : ""}
        `);
    },
  };

  function appUpdateHtml() {
    const u = S.app_update || {};
    if (!u.configured) return "";
    const st = u.state || {};
    const busy = taskOf("app_update");
    return `<section class="card">${sw("app_update", "s_app_update", "s_app_update_text")}
      <div class="card-body">${busy ? `<div class="busy-row"><span class="spinner"></span><span>${esc(busy)}…</span></div>`
        : st.ready ? `<p class="hint">${esc(t("au_ready", { v: st.version }))}</p><button class="btn primary wide" data-act="au-install">${esc(t("au_install"))}</button>`
        : `<button class="btn wide" data-act="au-check">${esc(t("au_check"))}</button>${st.version && !st.newer ? `<p class="hint">${esc(t("au_latest"))}</p>` : ""}`}</div></section>`;
  }

  function leaksHtml() {
    const L = S.leaks;
    const busy = taskOf("leaks");
    const mark = { ok: "check", info: "list", warn: "alert", error: "ban" };
    const list = L ? L.items.map((i) => `<div class="check-item ${esc(i.state)}">${icon(mark[i.state] || "check")}
        <div class="main"><b>${esc(i.title)}</b>${i.detail ? `<span>${esc(i.detail)}</span>` : ""}${i.fix ? `<span>${esc(i.fix)}</span>` : ""}</div></div>`).join("") : "";
    return `<section class="card"><div class="card-head"><h2>${esc(t("leaks_title"))}</h2></div>
      <div class="card-body"><p class="hint">${esc(t("leaks_hint"))}</p>
        ${busy ? `<div class="busy-row"><span class="spinner"></span><span>${esc(busy)}…</span></div>`
          : `<button class="btn wide" data-act="leak-run" ${S.status === "on" ? "" : "disabled"}>${icon("shield")}${esc(t("leaks_run"))}</button>`}</div>
      ${L ? `<div class="check-sum ${L.errors ? "bad" : "good"}">${esc(L.errors ? t("leaks_bad", { n: L.errors }) : t("leaks_ok"))}</div>${list}` : ""}</section>`;
  }

  function certsHtml() {
    const C = S.certs;
    const busy = taskOf("certs");
    const mark = { ok: "check", info: "list", warn: "alert", error: "ban" };
    const list = C ? C.items.map((i) => `<div class="check-item ${esc(i.state)}">${icon(mark[i.state] || "check")}
        <div class="main"><b>${esc(i.title)}</b>${i.detail ? `<span>${esc(i.detail)}</span>` : ""}${i.fix ? `<span>${esc(i.fix)}</span>` : ""}</div></div>`).join("") : "";
    const ack = C && C.russian_root && C.russian_root.length && !C.acked
      ? `<div class="card-body"><button class="btn wide" data-act="cert-ack">${icon("check")}${esc(t("certs_ack"))}</button></div>` : "";
    const sum = C ? `<div class="check-sum ${C.errors ? "bad" : C.warnings ? "mid" : "good"}">${esc(C.errors || C.warnings
      ? t("certs_found", { e: C.errors, w: C.warnings }) : t("certs_none"))}</div>` : "";
    return `<section class="card" id="certsCard"><div class="card-head"><h2>${esc(t("certs_title"))}</h2></div>
      <div class="card-body"><p class="hint">${esc(t("certs_hint"))}</p>
        ${busy ? `<div class="busy-row"><span class="spinner"></span><span>${esc(busy)}…</span></div>`
          : `<button class="btn wide" data-act="cert-run">${icon("lock")}${esc(t("certs_run"))}</button>`}</div>
      ${sum}${list}${ack}</section>`;
  }

  // ---------- журнал ошибок ----------
  let errorsData = null;
  VIEWS.errors = {
    title: "errors_title",
    render() { return `<div id="errBox" class="stack"></div>`; },
    mount() { this.load(); },
    load() {
      errorsData = act("errors_list") || { items: [], repo: "" };
      this.draw();
    },
    draw() {
      const d = errorsData || { items: [], repo: "" };
      const items = d.items || [];
      const cls = { crash: "error", problem: "warn", check: "info" };
      const mark = { crash: "ban", problem: "alert", check: "list" };
      const rows = items.map((e) => `<div class="check-item ${cls[e.kind] || "info"}">${icon(mark[e.kind] || "alert")}
          <div class="main"><b>${esc(e.title)}${e.count > 1 ? ` ×${e.count}` : ""}</b>
          <span>${esc(t("err_kind_" + e.kind))} · ${esc(ago(e.last * 1000))} · ${esc(t("err_version", { v: e.version }))}${e.where ? " · " + esc(e.where) : ""}</span>
          ${e.detail ? `<span>${esc(e.detail)}</span>` : ""}
          ${e.trace ? `<details class="more"><summary>${esc(t("err_trace"))}</summary><pre class="log">${esc(e.trace)}</pre></details>` : ""}</div></div>`).join("");
      const repo = d.repo
        ? `<p class="hint">${esc(t("err_repo_is", { r: d.repo }))} <button class="link-btn" data-act="err-repo-change">${esc(t("err_repo_change"))}</button></p>`
        : `<section class="card"><div class="card-head"><h2>${esc(t("err_repo"))}</h2></div><div class="card-body">
            <p class="hint">${esc(t("err_repo_hint"))}</p>
            <div class="form-row"><input id="errRepo" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="https://github.com/name/vedomyj-vpn">
              <button class="btn primary" data-act="err-repo">${esc(t("save"))}</button></div></div></section>`;
      setHtml("#errBox", `<p class="hint">${esc(t("err_intro"))}</p>
        ${items.length ? `<button class="btn primary wide" data-act="err-report">${icon(d.repo ? "send" : "copy")}${esc(t(d.repo ? "err_report" : "err_copy"))}</button>
          <div class="btns two">${d.repo ? `<button class="btn" data-act="err-copy">${icon("copy")}${esc(t("err_copy"))}</button>` : ""}
            <button class="btn" data-act="err-clear">${icon("trash")}${esc(t("err_clear"))}</button></div>` : ""}
        ${repo}
        <section class="card">${items.length ? rows : `<div class="card-body"><p class="hint">${esc(t("err_empty"))}</p></div>`}</section>`);
    },
  };

  // ---------- журнал ----------
  VIEWS.log = {
    title: "log_title",
    render() {
      return `<div class="btns"><button class="btn" data-act="log-refresh">${icon("refresh")}${esc(t("refresh"))}</button>
        <button class="btn" data-act="log-copy">${icon("copy")}${esc(t("copy"))}</button></div><pre class="log" id="logBox"></pre>`;
    },
    mount() { this.load(); },
    load() {
      const lines = act("log") || [];
      $("#logBox").textContent = lines.slice().reverse().join("\n");
    },
  };

  // ---------- действия ----------
  const ACTIONS = {
    back() { back(); },
    toggle() {
      if (S.status === "off" && S.method === "off") { // «Без VPN»: кнопка включает и выключает ускорение
        if (S.filter_on) act("disconnect"); else act("filter_start");
      } else if (S.status === "off" && (S.engine || {}).pick === "awg") awgSheet("");
      else if (S.status === "off") act("connect");
      else act("disconnect");
      poll();
    },
    method(el) {
      const m = el.dataset.v;
      if (m === S.method) return;
      if (m === "awg" && !(((S.engine || {}).counts || {}).awg)) { warpStartSheet(); return; }
      if (act("method", { method: m }) === undefined) return;
      if (m === "off") {
        if (S.status === "on") act("disconnect");
        act("filter_start");
      } else if (m === "awg") awgSheet("");
      else if (m === "auto" && S.status === "on") act("select", { key: "" });
      poll();
    },
    accel() {
      const on = !(S.dpi || {}).enabled;
      act("dpi_set", { values: { dpi_enabled: on } });
      poll();
    },
    engine() { engineSheet(); },
    "m-dd"(el) {
      const v = el.dataset.v;
      if (v === "server") engineSheet();
      else if (v === "awg") awgListSheet();
      else go("dpi");
    },
    "warp-sheet"() { closeSheet(); warpStartSheet(); },
    "wl-flip"() {
      const on = !(S.wl && S.wl.on);
      if (act("wl_set", { on }) === undefined) return;
      toast(t(on ? "wl_on_toast" : "wl_off_toast"), "ok");
      poll();
    },
    "nw-open"() { nwOpen(); },
    "nw-tab"(el) {
      nw.tab = el.dataset.v; nw.sel = ""; nw.q = ""; nw.done = false;
      if (nw.tab === "app" && !nwApps) setTimeout(() => { nwApps = act("apps") || []; nwDraw(); }, 30);
      nwDraw();
    },
    "nw-sel"(el) { nw.sel = el.dataset.v; nw.done = false; nwDraw(); },
    "nw-route"(el) { nw.route = el.dataset.v; nwDraw(); },
    "nw-go"() {
      const value = nw.tab === "site" ? (($("#nwSite") || {}).value || "").trim() : nw.sel;
      if (!value) { toast(t(nw.tab === "site" ? "nw_need_site" : "nw_need_pick"), "error"); return; }
      const known = (nw.targets.known_apps || {})[value];
      const target = nw.tab === "app" && !known ? nw.route : "";
      if (act("nw_fix", { kind: nw.tab, value, target }) === undefined) return;
      nw.waiting = true; nw.done = false;
      nwDraw();
      poll();
    },
    "nw-undo"() {
      if (act("nw_undo", {}) === undefined) return;
      nw.waiting = true; nw.done = false;
      nwDraw();
      poll();
    },
    "engine-set"(el) {
      const v = el.dataset.v;
      act("engine_pick", { pick: v });
      closeSheet();
      poll();
      if (v === "awg") awgSheet("");
      else if (v !== "auto" && !(((S.engine || {}).counts || {})[v])) toast(t("eng_none"), "info");
    },
    awg(el) { awgSheet(el.dataset.key); },
    "fam-paste"() { const text = act("paste"); if (text) famReceive(text); else toast(t("fam_paste_empty"), "info"); },
    "fam-invite"() { famInviteSheet(); },
    "fam-invite-go"() {
      const me = $("#famMe");
      if (me) {
        if (!me.value.trim()) { toast(t("fam_me_need"), "error"); return; }
        if (act("family_me", { name: me.value.trim() }) === undefined) return;
      }
      const dev = $("#famDev").value.trim();
      if (!dev) { toast(t("fam_dev_need"), "error"); return; }
      const r = act("family_invite", { device: dev });
      if (r) { famTextSheet(t("fam_invite_ready", { n: dev }), t("fam_invite_send"), r.text); poll(); }
    },
    "fam-dht"(el) { act("family_dht", { on: el.getAttribute("aria-checked") !== "true" }); poll(); },
    "fam-check"() { if (act("family_check") !== undefined) toast(t("fam_mail_checking"), "info"); poll(); },
    "fam-invite-again"() { if (famDev && famDev.invite) famTextSheet(t("fam_invite_ready", { n: famDev.name }), t("fam_invite_send"), famDev.invite); },
    "fam-share"() { act("share_text", { text: famTextCur }); },
    "fam-copy"() { act("copy", { text: famTextCur }); toast(t("fam_copied"), "ok"); },
    "fam-save"() { act("save_file", { text: famTextCur + "\n", name: famTextCur.indexOf("://i/") > 0 ? "VEDOMYJ-family-invite.txt" : "VEDOMYJ-family.txt", mime: "text/plain" }); },
    "fam-chip"(el) {
      const box = el.closest(".chips");
      box.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === el)));
    },
    "fam-allow"() {
      const mode = ($('#famAccMode [aria-pressed="true"]') || {}).dataset ? $('#famAccMode [aria-pressed="true"]').dataset.v : "ask";
      const r = act("family_accept", { text: famAcceptText, mode });
      if (r) { famTextSheet(t("fam_accepted_title"), t(famDhtOn() ? "fam_reply_hint_dht" : "fam_reply_hint", { n: "" }), r.reply); poll(); }
    },
    "fam-apply"(el) { if (act("family_apply", { pair: el.dataset.pair }) !== undefined) toast(t("fam_installing"), "info"); poll(); },
    "fam-decline"(el) { const r = act("family_decline", { pair: el.dataset.pair }); if (r) famTextSheet(t("fam_declined_title"), t("fam_reply_hint", { n: "" }), r.text); poll(); },
    "fam-report"(el) { const r = act("family_report", { pair: el.dataset.pair }); if (r) famTextSheet(t("fam_report_title"), t("fam_reply_hint", { n: "" }), r.text); },
    "fam-mode"(el) { act("family_mode", { pair: el.dataset.pair, mode: el.dataset.v }); poll(); },
    "fam-remove"(el) {
      const F = S.family || {};
      const x = (F.devices || []).concat(F.helpers || []).find((y) => y.pair === el.dataset.pair);
      if (!x) return;
      openSheet(`<h2>${esc(t("fam_remove_ask", { n: x.name }))}</h2>
        <button class="btn primary wide" data-act="fam-remove-yes" data-pair="${esc(x.pair)}">${esc(t("fam_remove_yes"))}</button>`);
    },
    "fam-remove-yes"(el) { act("family_remove", { pair: el.dataset.pair }); closeSheet(); poll(); },
    "fam-device"(el) { famDeviceSheet(el.dataset.pair); },
    "fam-send"() {
      if (!famDev) return;
      const sh = $("#sheet");
      const ops = [];
      sh.querySelectorAll("[data-fam-sub]:checked").forEach((x) => ops.push({ op: "sub_remove", id: x.dataset.famSub, url: x.dataset.url, name: x.dataset.name }));
      const url = $("#famSubUrl").value.trim();
      if (url) ops.push({ op: "sub_add", url, name: "" });
      sh.querySelectorAll("[data-fam-srv]:checked").forEach((x) => ops.push({ op: "server_remove", id: x.dataset.famSrv }));
      const srv = $("#famSrv").value.trim();
      if (srv) ops.push({ op: "servers_add", text: srv });
      const meth = sh.querySelector('[data-fam-method] [aria-pressed="true"]').dataset.v;
      if (meth) ops.push({ op: "method", method: meth });
      const values = {};
      sh.querySelectorAll("[data-fam-set]").forEach((box) => { const v = box.querySelector('[aria-pressed="true"]').dataset.v; if (v) values[box.dataset.famSet] = v === "on"; });
      if (Object.keys(values).length) ops.push({ op: "set", values });
      if ($("#famUpd").checked) ops.push({ op: "sub_update" });
      if ($("#famWarp").checked) ops.push({ op: "warp_create" });
      if ($("#famRe").checked) ops.push({ op: "reconnect" });
      if (!ops.length) ops.push({ op: "report" });
      const r = act("family_send", { pair: famDev.pair, ops });
      if (r) { famTextSheet(t("fam_sent_title", { n: famDev.name }), t(famDhtOn() ? "fam_sent_hint_dht" : "fam_sent_hint", { n: famDev.name }), r.text); poll(); }
    },
    "warp-create"() {
      closeSheet();
      warpWait = S.warp || "";
      if (act("warp_create") === undefined) warpWait = null;
      else toast(t("warp_creating"), "info");
      poll();
    },
    "warp-own"() { closeSheet(); openAdd(""); },
    "warp-qr"() {
      let text;
      try { text = call("warp_share"); } catch (e) { toast(e.message, "error"); return; }
      showQr(t("warp_qr"), text, t("warp_qr_warn"));
    },
    "warp-next"() {
      if (!awgCur) return;
      let r;
      try { r = call("warp_next", { key: awgCur.key }); } catch (e) { toast(e.message, "error"); return; }
      awgSheet(r.key);
      toast(t("warp_next_done", { l: r.label }), "ok");
    },
    "awg-save"() {
      if (awgCur) act("save_file", { text: awgCur.conf + "\n", name: awgCur.file, mime: "application/octet-stream" });
    },
    "awg-open"() {
      if (act("awg_open") === "store") toast(t("awg_store"), "info");
    },
    "awg-copy"() {
      if (awgCur) { act("copy", { text: awgCur.conf }); toast(t("awg_copied"), "ok"); }
    },
    stop() { act("stop_task"); },
    mode(el) { act("settings", { values: { mode: el.dataset.v } }); },
    flip(el) {
      const k = el.dataset.k;
      act("settings", { values: { [k]: !S.settings[k] } });
      poll();
    },
    set(el) {
      act("settings", { values: { [el.dataset.k]: el.dataset.v } });
      poll();
      if (el.dataset.k === "lang") { lang = el.dataset.v; render(); }
    },
    test() { act("test"); },
    add() { openAdd(""); },
    "add-paste"() {
      const text = act("paste");
      if (text) { $("#addText").value = text; detect(); }
    },
    scan() { act("scan"); },
    "pick-file"() { act("pick_file"); },
    "paste-open"() { openAdd(act("paste") || ""); },
    "add-go"() {
      const text = $("#addText").value.trim();
      let r;
      try {
        r = call("import_preview", { text });
        if (r.kind === "family") { closeSheet(); famReceive(text); return; }
        if (r.kind === "subscription") call("add_sub", { url: text, name: $("#addName").value.trim() });
        else if (r.kind === "servers") call("add_servers", { text });
        else if (r.kind === "settings") toast(call("import_apply", { text }), "ok");
      } catch (e) {
        toast(e.message, "error");
        return;
      }
      closeSheet();
      if (stack.length > 1 && r.kind !== "settings") { stack.length = 1; render(); }
    },
    "show-all"() { showAll = !showAll; update(); },
    auto() { act("select", { key: "" }); },
    server(el) {
      const s = (S.servers || []).find((x) => x.key === el.dataset.key);
      if (s && s.usable && !s.selected) act("select", { key: s.key });
    },
    "server-menu"(el) { serverMenu(el.dataset.key); },
    select(el) { act("select", { key: el.dataset.key }); closeSheet(); },
    "server-qr"(el) {
      const link = act("server_link", { key: el.dataset.key });
      if (link) showQr(t("m_qr"), link, "");
    },
    "server-copy"(el) {
      const link = act("server_link", { key: el.dataset.key });
      if (link && act("copy", { text: link })) { toast(t("copied")); closeSheet(); }
    },
    "server-del"(el) { act("remove_server", { key: el.dataset.key }); closeSheet(); },
    "refresh-subs"() { act("refresh_subs"); closeSheet(); },
    "sub-menu"(el) { subMenu(el.dataset.id); },
    "sub-qr"(el) {
      const link = act("sub_link", { id: el.dataset.id });
      if (link) showQr(t("m_qr"), link, t("with_subs_note"));
    },
    "sub-copy"(el) {
      const link = act("sub_link", { id: el.dataset.id });
      if (link && act("copy", { text: link })) { toast(t("copied")); closeSheet(); }
    },
    "sub-del"(el) { act("remove_sub", { id: el.dataset.id }); closeSheet(); },
    problems() {
      const list = S.problems || [];
      openSheet(`<h2>${esc(t("problems_title"))}</h2>` + (list.length ? list.map((p) =>
        `<div class="problem"><b>${esc(p.title)}</b><p>${esc(p.detail)}</p></div>`).join("") : `<p class="hint">${esc(t("no_problems"))}</p>`)
        + `<button class="btn wide" data-act="check-open">${icon("shield")}${esc(t("s_check"))}</button>`
        + `<button class="btn wide" data-act="report">${icon("copy")}${esc(t("s_report"))}</button>`);
    },
    "check-open"() { go("check"); },
    "check-run"() { act("check"); poll(); },
    "check-save"() {
      const text = act("check_text");
      if (text) act("save_file", { text, name: (S.check && S.check.file) || "vedomyj-check.txt", mime: "text/plain" });
    },
    "check-send"() {
      const text = act("check_text");
      if (text) act("share_report", { text, name: (S.check && S.check.file) || "" });
    },
    "check-fix"(el) { act("fix", { what: el.dataset.v }); },
    "health-run"() {
      if (act("health_check", {}) !== undefined) poll();
    },
    "data-run"() {
      if (act("data_check", {}) !== undefined) poll();
    },
    "ladder-retry"() {
      if (act("ladder_retry", {}) !== undefined) { toast(t("ww_trying"), "ok"); poll(); }
    },
    "fuses-clear"() {
      if (act("fuses_clear", {}) !== undefined) { toast(t("fuses_cleared"), "ok"); poll(); }
    },
    "collect-start"(el) {
      if (act("collect_start", { hours: Number(el.dataset.h) || 24 }) !== undefined) { toast(t("collect_started"), "ok"); poll(); }
    },
    "collect-stop"() {
      if (act("collect_stop", {}) !== undefined) { toast(t("collect_saved"), "ok"); poll(); }
    },
    "collect-send"() {
      const text = act("collect_text", {});
      if (text != null) act("share_report", { text, name: (S.collect || {}).report || "" });
    },
    "collect-copy"() {
      const text = act("collect_text", {});
      if (text != null && act("copy", { text })) toast(t("collect_copied"), "ok");
    },
    "pro-reset"() {
      openSheet(`<h2>${esc(t("pro_reset"))}</h2><p class="hint">${esc(t("pro_reset_text"))}</p>
        <div class="btns two"><button class="btn" id="prNo">${esc(t("cancel_btn"))}</button>
          <button class="btn primary" id="prYes">${esc(t("pro_reset"))}</button></div>`, (sh) => {
        $("#prNo", sh).addEventListener("click", () => closeSheet());
        $("#prYes", sh).addEventListener("click", () => {
          closeSheet();
          if (act("pro_reset", {}) !== undefined) { toast(t("pro_reset_done"), "ok"); poll(); }
        });
      });
    },
    "netmem-clear"() {
      if (act("net_memory_clear", {}) !== undefined) { toast(t("netmem_cleared"), "ok"); poll(); }
    },
    "cert-run"() {
      if (act("cert_check", {}) !== undefined) poll();
    },
    "cert-ack"() {
      if (act("cert_ack", {}) !== undefined) { poll(); toast(t("certs_acked"), "ok"); }
    },
    "err-report"() {
      const x = act("errors_issue", {});
      if (!x) return;
      if (x.url) { act("open_url", { url: x.url }); toast(t("err_opened"), "ok"); }
      else if (act("copy", { text: x.title + "\n\n" + x.body })) toast(t("err_copied"), "ok");
    },
    "err-copy"() {
      const x = act("errors_issue", {});
      if (x && act("copy", { text: x.title + "\n\n" + x.body })) toast(t("err_copied"), "ok");
    },
    "err-clear"() {
      if (act("errors_clear", {}) !== undefined) { VIEWS.errors.load(); poll(); }
    },
    "err-repo-change"() {
      errorsData = Object.assign({}, errorsData, { repo: "" });
      VIEWS.errors.draw();
    },
    "err-repo"() {
      const v = ($("#errRepo") || {}).value || "";
      const r = act("errors_repo", { repo: v.trim() });
      if (r !== undefined) { toast(t("err_repo_saved", { r }), "ok"); VIEWS.errors.load(); }
    },
    "check-copy"() {
      const text = act("check_text");
      if (text && act("copy", { text })) toast(t("report_copied"), "ok");
    },
    report() {
      const text = act("report");
      if (text != null && act("copy", { text })) toast(t("report_copied"), "ok");
    },
    copy(el) { if (act("copy", { text: el.dataset.text })) toast(t("copied")); },
    "hotspot-local"() { act("hotspot_local"); },
    "hotspot-settings"() { act("hotspot_settings"); },
    "hotspot-system"() { act("hotspot_system"); },
    "hotspot-stop"() { act("hotspot_stop"); },
    "new-pass"() { act("share_new_pass"); },
    "share-tab"(el) { shareTab = el.dataset.v; update(); },
    "tf-subs"() { tfSubs = !tfSubs; VIEWS.transfer.draw(); },
    "tf-servers"() { tfServers = !tfServers; VIEWS.transfer.draw(); },
    "tf-save"() { act("save_file", { text: VIEWS.transfer.text, name: "vedomyj-vpn-settings.json" }); },
    "tf-send"() { act("share_text", { text: VIEWS.transfer.text }); },
    "vps-add"() {
      vpsPassSheet(t("vps_add_btn"), t("vps_add_text"),
        `<label class="field">${esc(t("vps_host"))}<input id="vaHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="203.0.113.10"></label>
        <div class="field-row"><label class="field">${esc(t("vps_user"))}<input id="vaUser" autocapitalize="off" spellcheck="false" value="root"></label>
          <label class="field">${esc(t("vps_port"))}<input id="vaPort" inputmode="numeric" value="22"></label></div>
        <label class="field">${esc(t("vps_name"))}<input id="vaName" placeholder="${esc(t("vps_name_ph"))}"></label>`,
        (pw, sh) => act("vps_add", { host: $("#vaHost", sh).value, port: $("#vaPort", sh).value, user: $("#vaUser", sh).value,
          password: pw, name: $("#vaName", sh).value }));
    },
    "vps-bridge"(el) {
      const via = el.dataset.id;
      vpsPassSheet(t("vps_bridge_btn"), t("vps_bridge_text"),
        `<label class="field">${esc(t("vps_bridge_host"))}<input id="vbHost" inputmode="url" autocapitalize="off" spellcheck="false" placeholder="203.0.113.20"></label>
        <div class="field-row"><label class="field">${esc(t("vps_user"))}<input id="vbUser" autocapitalize="off" spellcheck="false" value="root"></label>
          <label class="field">${esc(t("vps_port"))}<input id="vbPort" inputmode="numeric" value="22"></label></div>
        <label class="field">${esc(t("vps_name"))}<input id="vbName" placeholder="${esc(t("vps_bridge_name"))}"></label>`,
        (pw, sh) => act("vps_bridge", { host: $("#vbHost", sh).value, port: $("#vbPort", sh).value, user: $("#vbUser", sh).value,
          password: pw, via, name: $("#vbName", sh).value }));
    },
    "vps-check"(el) {
      const id = el.dataset.id;
      vpsPassSheet(t("vps_check"), "", "", (pw) => act("vps_status", { id, password: pw }));
    },
    "vps-friend"(el) {
      const id = el.dataset.id;
      vpsPassSheet(t("vps_friend_add"), t("vps_friend_text"),
        `<label class="field">${esc(t("vps_friend_name"))}<input id="vfName" maxlength="30" placeholder="${esc(t("vps_friend_ph"))}"></label>`,
        (pw, sh) => act("vps_friend_add", { id, password: pw, name: $("#vfName", sh).value }));
    },
    "vps-fdel"(el) {
      const id = el.dataset.id, f = el.dataset.f;
      vpsPassSheet(t("vps_friend_del"), t("vps_friend_del_text", { name: el.dataset.n }), "",
        (pw) => act("vps_friend_remove", { id, password: pw, friend: f }));
    },
    "vps-qr"(el) { vpsFriendQr(el.dataset.f, el.dataset.n); },
    "vps-forget"(el) {
      const id = el.dataset.id;
      openSheet(`<h2>${esc(t("vps_forget"))}</h2><p class="hint">${esc(t("vps_forget_text"))}</p>
        <button class="btn danger wide" id="vfOk">${esc(t("vps_forget_ok"))}</button>`, (sh) => {
        $("#vfOk", sh).addEventListener("click", () => { act("vps_forget", { id }); closeSheet(); poll(); });
      });
    },
    "vps-go"() {
      const pass = $("#vpsPass");
      const r = act("vps", { host: $("#vpsHost").value, port: $("#vpsPort").value, user: $("#vpsUser").value,
        password: pass.value, name: $("#vpsName").value });
      if (r) pass.value = "";
    },
    "always-on"() { act("vpn_settings"); },
    "app-flip"(el) {
      const p = el.dataset.pkg;
      if (appsSel.has(p)) appsSel.delete(p); else appsSel.add(p);
      el.setAttribute("aria-checked", String(appsSel.has(p)));
    },
    "apps-save"() {
      if (act("settings", { values: { excluded_apps: Array.from(appsSel) } })) { toast(t("saved_ok"), "ok"); back(); }
    },
    "rules-save"() {
      const values = {};
      ["proxy_list", "direct_list", "block_list"].forEach((k) => { values[k] = $("#r_" + k).value; });
      if (act("settings", { values })) { toast(t("saved_ok"), "ok"); back(); }
    },
    // свои маршруты и прокси
    "au-check"() {
      if (act("app_update_check", {}) !== undefined) poll();
    },
    "au-install"() {
      act("install_update", {});
    },
    "leak-run"() {
      if (act("leak_test", {}) !== undefined) poll();
    },
    repair() {
      const host = $("#repairHost").value.trim();
      if (!host) { toast(t("repair_need"), "err"); return; }
      if (act("repair_site", { host }) !== undefined) poll();
    },
    "site-add"() {
      const host = $("#siteHost").value.trim();
      const target = $("#siteTarget").value;
      if (target === "custom:new") { focusProxyForm(); return; }
      if (target === "warp" && !((S.warp_auto || {}).own)) { // своего WARP нет: программа создаст его и поставит маршрут
        if (act("warp_route", { host }) !== undefined) { $("#siteHost").value = ""; toast(t("warp_route_making"), "info"); poll(); }
        return;
      }
      if (act("route_site", { host, target, main: false }) !== undefined) { $("#siteHost").value = ""; toast(t("saved_ok"), "ok"); poll(); }
    },
    "px-chain-new"(el) { el.setAttribute("aria-checked", String(el.getAttribute("aria-checked") !== "true")); },
    "px-add"() {
      const r = act("add_proxy", { raw: $("#pxRaw").value.trim(), name: $("#pxName").value.trim(), kind: $("#pxKind").value,
        chain: $("#pxChain").getAttribute("aria-checked") === "true" });
      if (r) { $("#pxRaw").value = ""; $("#pxName").value = ""; toast(t("px_added"), "ok"); poll(); }
    },
    "px-check"(el) { act("check_proxy", { id: el.dataset.id }); poll(); },
    "px-menu"(el) { proxyMenu(el.dataset.id); },
    "px-chain"(el) { el.setAttribute("aria-checked", String(el.getAttribute("aria-checked") !== "true")); },
    "px-save"(el) {
      const ch = $('#sheet [data-act="px-chain"]');
      if (act("update_proxy", { id: el.dataset.id, name: $("#pxRename").value, chain: ch.getAttribute("aria-checked") === "true" }) !== undefined) {
        closeSheet(); poll();
      }
    },
    "px-del"(el) { act("remove_proxy", { id: el.dataset.id }); closeSheet(); poll(); },
    "px-report"(el) { act("open_url", { url: "https://scamalytics.com/ip/" + encodeURIComponent(el.dataset.ip) }); },
    // реклама
    "ads-flip"() {
      const on = !(S.ads || {}).enabled;
      const r = act("ads_set", { values: { block_ads: on } });
      if (r && on && r.filter) act("filter_start"); // разрешение VPN — сразу, пока человек на экране
      poll();
    },
    "ads-novpn"() {
      const on = !(S.ads || {}).without_vpn;
      const r = act("ads_set", { values: { ads_without_vpn: on } });
      if (r && on && r.filter) act("filter_start");
      poll();
    },
    "filter-start"() { act("filter_start"); poll(); },
    "ads-level"(el) { act("ads_set", { values: { ads_level: el.dataset.v } }); poll(); },
    "ads-list"(el) {
      const lists = Object.assign({}, (S.ads || {}).lists);
      lists[el.dataset.id] = !lists[el.dataset.id];
      act("ads_set", { values: { ads_lists: lists } });
      poll();
    },
    "ads-update"() { act("ads_update"); poll(); },
    "ads-check"() { if (act("ads_check", {}) !== undefined) poll(); },
    "ads-fix"(el) {
      const f = el.dataset.v;
      if (f === "ads_on") act("ads_set", { values: { block_ads: true } });
      else if (f === "ads_resume") act("ads_pause", { minutes: 0 });
      else if (f === "ads_update") act("ads_update");
      else if (f === "ads_apply") act("filter_start");
      else if (f === "ads_without_vpn") act("ads_set", { values: { ads_without_vpn: true } });
      else if (f === "apps") { go("apps"); return; }
      poll();
    },
    "ads-pause"(el) { act("ads_pause", { minutes: Number(el.dataset.v) }); poll(); },
    "ads-site"(el) {
      const allow = el.dataset.v === "1";
      const r = act("ads_site", { site: el.dataset.site, allow });
      if (r !== undefined) toast(t(allow ? "ads_site_allowed" : "ads_site_kept", { h: r }), "ok");
      poll();
    },
    "ads-allow"(el) {
      if (act("ads_allow", { host: el.dataset.host }) !== undefined) toast(t("ads_allowed", { h: el.dataset.host }), "ok");
      poll();
    },
    "ads-lookup"() {
      const host = $("#adsHost").value.trim();
      const r = host ? act("ads_lookup", { host }) : undefined;
      if (!r) return;
      const names = { main: t("ads_l_main"), popups: t("ads_l_popups"), threats: t("ads_l_threats"), ru: t("ads_l_ru") };
      let html;
      if (r.allowed) html = `<p class="ok-line">${esc(t("ads_lk_allowed", { h: r.host }))}</p>`;
      else if (r.protected && (r.lists || []).length) html = `<p class="ok-line">${esc(t("ads_lk_protected", { h: r.host, why: r.lists.map((x) => names[x.id]).join(", ") }))}</p>`;
      else if (r.blocked) {
        const why = (r.lists || []).map((x) => names[x.id] + (x.match !== r.host ? " (" + x.match + ")" : ""));
        if (r.custom) why.push(t("ads_lk_own") + (r.custom !== r.host ? " (" + r.custom + ")" : ""));
        html = `<p class="warn-line">${esc(t("ads_lk_blocked", { h: r.host, why: why.join(", ") }))}</p>
          <button class="btn small" data-act="ads-allow" data-host="${esc(r.host)}">${esc(t("ads_allow_btn"))}</button>`;
      } else html = `<p class="ok-line">${esc(t("ads_lk_free", { h: r.host }))}</p>`;
      if (r.user_rule === "block") html += `<p class="warn-line">${esc(t("ads_lk_rule"))}</p>`;
      if (!r.enabled) html += `<p class="hint">${esc(t("ads_lk_off"))}</p>`;
      else if (r.mode === "geo") html += `<p class="hint">${esc(t("ads_lk_geo"))}</p>`;
      $("#adsLookup").innerHTML = html;
    },
    "ads-save"() {
      if (act("ads_set", { values: { ads_custom: $("#adsCustom").value, ads_allow: $("#adsAllow").value } })) toast(t("saved_ok"), "ok");
      poll();
    },
    // обход замедлений
    "dpi-flip"(el) {
      const k = el.dataset.k;
      const cur = { dpi_enabled: "enabled", dpi_youtube: "youtube", dpi_discord: "discord", dpi_without_vpn: "without_vpn" }[k];
      const v = !(S.dpi || {})[cur];
      act("dpi_set", { values: { [k]: v } });
      if (k === "dpi_without_vpn" && v && S.status !== "on") act("filter_start");
      poll();
    },
    "dpi-pick"() { act("dpi_pick"); poll(); },
    "speed-test"() { act("speed_test"); poll(); },
    "dpi-choose"(el) { act("dpi_set", { values: { dpi_strategy: el.dataset.id } }); poll(); },
    "dpi-save"() { if (act("dpi_set", { values: { dpi_custom: $("#dpiCustom").value } }) !== undefined) toast(t("saved_ok"), "ok"); },
    "log-refresh"() { VIEWS.log.load(); },
    "log-copy"() { if (act("copy", { text: $("#logBox").textContent })) toast(t("copied")); },
  };

  document.addEventListener("click", (ev) => {
    const el = ev.target.closest("[data-act], [data-nav]");
    if (!el || el.disabled) return;
    if (el.dataset.nav) { go(el.dataset.nav); return; }
    const f = ACTIONS[el.dataset.act];
    if (f) f(el);
  });
  $("#sheetBack").addEventListener("click", closeSheet);

  // выбор в выпадающих списках (маршруты сервисов и сайтов)
  function focusProxyForm() {
    const f = $("#pxRaw");
    if (!f) return;
    f.scrollIntoView({ block: "center" });
    f.focus();
    toast(t("px_first"));
  }
  const CHANGES = {
    "route-svc"(el) {
      const v = el.value;
      el.blur();
      if (v === "custom:new") { focusProxyForm(); return; }
      if (v === "warp" && !((S.warp_auto || {}).own)) { act("warp_route", { name: el.dataset.name }); toast(t("warp_route_making"), "info"); poll(); return; }
      act("route_service", { name: el.dataset.name, target: v });
      poll();
    },
    "route-site"(el) {
      const v = el.value;
      el.blur();
      if (v === "custom:new") { focusProxyForm(); return; }
      if (v === "warp" && !((S.warp_auto || {}).own)) { act("warp_route", { host: el.dataset.site }); toast(t("warp_route_making"), "info"); poll(); return; }
      act("route_site", { host: el.dataset.site, target: v, main: false });
      poll();
    },
  };
  document.addEventListener("change", (ev) => {
    const el = ev.target.closest("[data-change]");
    if (el && CHANGES[el.dataset.change]) CHANGES[el.dataset.change](el);
  });

  // ---------- события от приложения ----------
  window.pultEvent = function (ev) {
    if (!ev) return;
    if (ev.type === "open_page" && VIEWS[ev.page]) {
      if (stack[stack.length - 1] !== ev.page) go(ev.page);
    } else if ((ev.type === "incoming" || ev.type === "scan" || ev.type === "file") && (ev.text || "").includes("vedomyj-family://")) {
      closeSheet();
      famReceive(ev.text);
    } else if (ev.type === "incoming" || ev.type === "scan" || ev.type === "file") {
      const ta = $("#addText");
      if (ta && !$("#sheet").hidden) { ta.value = ev.text; detect(); } else openAdd(ev.text);
    } else if (ev.type === "saved") {
      toast(t("saved"), "ok");
    } else if (ev.type === "error") {
      toast(ev.text, "error");
    } else if (ev.type === "hotspot") {
      if (ev.text) toast(ev.text, "error");
      poll();
    }
  };

  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    if (mq.addEventListener) mq.addEventListener("change", applyTheme);
  }
  poll();
  setInterval(poll, 1000);
})();
