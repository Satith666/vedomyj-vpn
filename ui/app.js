"use strict";
/* VEDOMYJ VPN — интерфейс. Тексты — в i18n.js (функция t), данные приходят из /api/state и потока /api/events. */

/* ---------- связь с программой ---------- */

const TOKEN = new URLSearchParams(location.search).get("t") || sessionStorage.getItem("pult-token") || "";
sessionStorage.setItem("pult-token", TOKEN);
if (location.search) history.replaceState(null, "", "/");

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-Token": TOKEN, ...(options.headers || {}) },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function act(action, args = {}, { quiet = false } = {}) {
  try {
    const r = await api("/api/action", { method: "POST", body: JSON.stringify({ action, args }) });
    if (!r.ok && !quiet) toast(r.error, "error");
    return r;
  } catch (e) {
    if (!quiet) toast(t("no_link_conn", { e: e.message }), "error");
    return { ok: false, error: e.message };
  }
}

/* ---------- состояние ---------- */

let S = null;
let page = "home";
let logs = [];
let connections = [];
let query = "";
let trafficFilter = "all";
let trafficQuery = "";
const dirty = new Set();
const openDetails = new Set();
const openFeats = new Set();
let pendingAdd = null;
let checkReport = null;
let siteResult = null;
let repairResult = null;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------- иконки ---------- */

const ICON_PATHS = {
  wifi: '<path d="M2 9a15 15 0 0 1 20 0"/><path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 16a5 5 0 0 1 7 0"/><path d="M12 19.5h.01"/>',
  qr: '<rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><path d="M14 14h2.5v2.5M20 14v.01M14 20h.01M17 20h3v-3"/>',
  download: '<path d="M12 4v11"/><path d="m7.5 10.5 4.5 4.5 4.5-4.5"/><path d="M5 20h14"/>',
  power: '<path d="M12 3v8"/><path d="M6.3 6.3a8 8 0 1 0 11.4 0"/>',
  sliders: '<path d="M4 7h9"/><path d="M18 7h2"/><circle cx="15.5" cy="7" r="2.2"/><path d="M4 17h3"/><path d="M12 17h8"/><circle cx="9.5" cy="17" r="2.2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 3v2.5M12 18.5V21M3 12h2.5M18.5 12H21M5.6 5.6l1.8 1.8M16.6 16.6l1.8 1.8M5.6 18.4l1.8-1.8M16.6 7.4l1.8-1.8"/>',
  services: '<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><path d="m14 16.5 2 2 3.5-4"/>',
  routes: '<path d="M6 20V4"/><path d="M6 13h6a5 5 0 0 0 5-5V5"/><path d="m14 7 3-3 3 3"/>',
  traffic: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  updates: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
  log: '<path d="M5 6h14M5 12h14M5 18h9"/>',
  bolt: '<path d="M13 3 5 14h6l-1 7 8-11h-6z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v5h-5"/>',
  signal: '<path d="M5 18v-3M10 18v-6M15 18V9M20 18V6"/>',
  speed: '<path d="M4 16a8 8 0 1 1 16 0"/><path d="m12 16 4-5"/>',
  sort: '<path d="M7 4v16M4 17l3 3 3-3"/><path d="M14 6h6M14 12h4M14 18h2"/>',
  more: '<circle cx="5.5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="18.5" cy="12" r="1.2"/>',
  down: '<path d="m8 10 4 4 4-4"/>',
  right: '<path d="m10 8 4 4-4 4"/>',
  back: '<path d="m15 6-6 6 6 6"/>',
  search: '<circle cx="11" cy="11" r="6"/><path d="m20 20-4.5-4.5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  copy: '<rect x="8" y="8" width="11" height="11" rx="2"/><path d="M5 15V6a1 1 0 0 1 1-1h9"/>',
  trash: '<path d="M5 7h14M10 7V5h4v2M7 7l1 12h8l1-12"/>',
  edit: '<path d="M4 20h4l10-10-4-4L4 16z"/><path d="m13 7 4 4"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  exit: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 16l-4-4 4-4M6 12h10"/>',
  vpn: '<path d="M12 3 5 6v5c0 4.5 3 8.4 7 10 4-1.6 7-5.5 7-10V6z"/>',
  direct: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  block: '<circle cx="12" cy="12" r="8"/><path d="M6.5 6.5l11 11"/>',
  stop: '<rect x="7" y="7" width="10" height="10" rx="2"/>',
  alert: '<path d="M12 4 2.5 20h19z"/><path d="M12 10v4.5M12 17.5v.5"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  swap: '<path d="M4 8h12l-3-3"/><path d="M20 16H8l3 3"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  shield: '<path d="M12 3 5 6v5c0 4.6 3 8.2 7 10 4-1.8 7-5.4 7-10V6z"/><path d="m9 12 2 2 4-4.2"/>',
  key: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H20M17 12v3M20 12v2.5"/>',
  split: '<path d="M3 12h6M15 12h6"/><path d="m9 7 6 10"/>',
  monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.5 3.5 5.5 3.5 8.5s-1 6-3.5 8.5c-2.5-2.5-3.5-5.5-3.5-8.5s1-6 3.5-8.5z"/>',
  game: '<path d="M7 9h10a4 4 0 0 1 4 4v1a3 3 0 0 1-5.3 1.9L14 14h-4l-1.7 1.9A3 3 0 0 1 3 14v-1a4 4 0 0 1 4-4z"/><path d="M8 11v3M6.5 12.5h3"/>',
};

const icon = (name, extra = "") => `<svg class="i ${extra}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name] || ""}</svg>`;

/* ---------- форматирование ---------- */

function pingClass(ms) {
  if (ms == null) return "";
  return ms < 100 ? "good" : ms < 250 ? "warn" : "bad";
}

function rate(bps) {
  bps = bps || 0;
  const u = LANG === "en" ? ["B/s", "KB/s", "MB/s"] : ["Б/с", "КБ/с", "МБ/с"];
  if (bps < 1024) return [Math.round(bps), u[0]];
  if (bps < 1024 * 1024) return [Math.round(bps / 1024), u[1]];
  return [(bps / 1024 / 1024).toFixed(1).replace(".", LANG === "en" ? "." : ","), u[2]];
}

function bytes(n) {
  const u = LANG === "en" ? ["B", "KB", "MB", "GB", "TB"] : ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}

function ago(ts, pfx = "updated") {
  if (!ts) return t(pfx + "_never");
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return t(pfx + "_now");
  if (s < 3600) return t(pfx + "_min", { n: Math.round(s / 60) });
  if (s < 86400) return t(pfx + "_h", { n: Math.round(s / 3600) });
  return t(pfx + "_d", { n: Math.round(s / 86400) });
}

const cap = s => s ? s[0].toUpperCase() + s.slice(1) : s;
const dateStr = ts => new Date(ts * 1000).toLocaleDateString(LANG === "en" ? "en-GB" : "ru-RU");
const cc = code => code ? `<span class="cc">${esc(code)}</span>` : `<span class="cc none">—</span>`;

function countryName(code) {
  if (!code) return "";
  try { return new Intl.DisplayNames([LANG], { type: "region" }).of(code.toUpperCase()) || code; } catch { return code; }
}

const sw = (checked, attrs = "", disabled = false) =>
  `<button type="button" class="switch-ctl" role="switch" aria-checked="${!!checked}" ${attrs} ${disabled ? "disabled" : ""}></button>`;
const soonBadge = () => `<span class="soon">${t("soon")}</span>`;

/* Короткий текст и кнопка «Подробнее»; раскрытое состояние запоминается между обновлениями. */
function details(id, short, full) {
  const open = openDetails.has(id);
  return `<div class="details"><p>${short}${full ? ` <button class="link-btn" data-more="${id}" aria-expanded="${open}">${open ? t("less") : t("more")}</button>` : ""}</p>${
    full ? `<div class="more-body" ${open ? "" : "hidden"}>${full}</div>` : ""}</div>`;
}

/* ---------- уведомления ---------- */

function toast(text, kind = "info", ms) {
  if (!text) return;
  const firstLine = text.split("\n")[0];
  const long = text.length > 140 || text.includes("\n");
  const short = long ? firstLine.slice(0, 120) + (firstLine.length > 120 ? "…" : "") : text;
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<div class="toast-text">${esc(short)}${long ? ` <button class="link-btn" type="button">${t("more")}</button>` : ""}</div>
    <button class="icon-btn" aria-label="${t("close")}">${icon("x")}</button>`;
  $("#toasts").append(el);
  const close = () => el.remove();
  el.querySelector(".icon-btn").addEventListener("click", close);
  if (long) el.querySelector(".link-btn").addEventListener("click", () => { close(); infoModal(text); });
  setTimeout(close, ms || (kind === "error" || long ? 9000 : 4500));
}

/* Вопрос во всплывающем окне: текст и кнопки [{label, primary, run}] — висит, пока не ответят (или 30 с). */
function askToast(text, buttons, ms = 30000) {
  const el = document.createElement("div");
  el.className = "toast info ask";
  el.innerHTML = `<div class="toast-text">${esc(text)}<div class="toast-actions">${buttons.map((b, i) =>
    `<button class="btn btn-small ${b.primary ? "btn-primary" : ""}" type="button" data-i="${i}">${esc(b.label)}</button>`).join("")}</div></div>
    <button class="icon-btn" aria-label="${t("close")}">${icon("x")}</button>`;
  $("#toasts").append(el);
  const close = () => el.remove();
  el.querySelector(".icon-btn").addEventListener("click", close);
  el.querySelectorAll("[data-i]").forEach(b => b.addEventListener("click", () => { close(); buttons[+b.dataset.i].run(); }));
  setTimeout(close, ms);
}

const vpnSiteAnswer = (site, direct) => act("vpn_site", { site, direct }).then(r => {
  if (r.ok) { toast(t(direct ? "vpn_site_directed" : "vpn_site_kept", { h: r.result }), "ok", 3500); scheduleRefresh(50); }
});

const adsSiteAnswer = (site, allow) => act("ads_site", { site, allow }).then(r => {
  if (r.ok) { toast(t(allow ? "ads_site_allowed" : "ads_site_kept", { h: r.result }), "ok", 3500); scheduleRefresh(50); }
});

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (message) toast(message, "ok", 3500);
}

/* ---------- окна и меню ---------- */

function openModal(html, onMount, cls = "") {
  closeMenu();
  const ov = $("#overlay");
  ov.innerHTML = `<div class="modal ${cls}" role="dialog" aria-modal="true">${html}</div>`;
  ov.hidden = false;
  const modal = ov.firstElementChild;
  modal.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", closeModal));
  onMount && onMount(modal);
  const first = modal.querySelector("input, textarea, .btn-primary");
  first && first.focus();
  return modal;
}

function closeModal() {
  const ov = $("#overlay");
  ov.hidden = true;
  ov.innerHTML = "";
  pendingAdd = null;
}

function infoModal(text) {
  openModal(`<p class="modal-text">${esc(text)}</p>
    <div class="modal-actions"><button class="btn" id="mCopy">${icon("copy")}${t("copy")}</button>
    <button class="btn btn-primary" data-close>${t("close")}</button></div>`, m => {
    m.querySelector("#mCopy").addEventListener("click", () => copy(text, t("saved")));
  });
}

function confirmModal(title, text, okText, danger = true) {
  return new Promise(resolve => {
    openModal(`<h2>${esc(title)}</h2><p class="modal-text">${esc(text)}</p>
      <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button>
      <button class="btn ${danger ? "btn-danger" : "btn-primary"}" id="mOk">${esc(okText)}</button></div>`, m => {
      m.querySelector("#mOk").addEventListener("click", () => { closeModal(); resolve(true); });
      m.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", () => resolve(false)));
    });
  });
}

/* «Подробнее»: что это, когда выбирать, что учесть. Тексты — ключи i_<id>_… в i18n.js. */
function infoVars() {
  const st = (S && S.settings) || {};
  return { socks: st.socks_port || 10808, http: st.http_port || 10809 };
}

function infoBlocks(id) {
  const v = infoVars();
  return [["what", "info_what"], ["when", "info_when"], ["note", "info_note"]]
    .filter(([k]) => STRINGS.ru[`i_${id}_${k}`])
    .map(([k, label]) => `<div class="info-sec"><b>${t(label)}</b><span>${esc(t(`i_${id}_${k}`, v))}</span></div>`).join("");
}

function detailModal(id) {
  openModal(`<div class="modal-head"><h2>${esc(t(`i_${id}_name`))}</h2>${SOON.has(id) ? soonBadge() : ""}
      <button class="icon-btn plain" data-close aria-label="${t("close")}">${icon("x")}</button></div>
    ${infoBlocks(id)}
    <div class="modal-actions"><button class="btn btn-primary" data-close>${t("got_it")}</button></div>`);
}

function placePopover(pop, anchor, matchWidth) {
  const r = anchor.getBoundingClientRect();
  const compact = anchor.classList.contains("dd-compact");  // маленькая кнопка справа — список выравниваем по её правому краю
  if (matchWidth) pop.style.width = Math.min(innerWidth - 16, Math.max(r.width, compact ? 330 : 260)) + "px";
  else pop.style.width = "";
  const w = pop.offsetWidth, h = pop.offsetHeight;
  pop.style.left = Math.max(8, Math.min(matchWidth && !compact ? r.left : r.right - w, innerWidth - w - 8)) + "px";
  pop.style.top = (r.bottom + h + 8 > innerHeight && r.top - h - 6 > 8 ? r.top - h - 6 : r.bottom + 6) + "px";
}

/* Меню привязано к своей кнопке: едет вместе с ней при прокрутке и после перерисовки (главная обновляется каждую
   секунду — кнопка заменяется новой), а когда кнопка уходит за край экрана — закрывается. */
function popAnchorSel(el) {
  const d = el.dataset;
  if (d.dd) return `[data-dd="${CSS.escape(d.dd)}"]`;
  if (d.menu) return `[data-menu="${CSS.escape(d.menu)}"]` + (d.key ? `[data-key="${CSS.escape(d.key)}"]`
    : d.id ? `[data-id="${CSS.escape(d.id)}"]` : "");
  return "";
}

function syncPopover() {
  const pop = $("#popover");
  if (pop.hidden || !pop._anchor) return;
  let a = pop._anchor;
  if (!a.isConnected) {
    a = pop._sel ? document.querySelector(pop._sel) : null;
    if (!a) return closeMenu();
    a.setAttribute("aria-expanded", "true");
    pop._anchor = a;
  }
  const r = a.getBoundingClientRect();
  const box = ($(".main") || document.documentElement).getBoundingClientRect();
  if (!r.width || r.bottom < box.top || r.top > box.bottom) return closeMenu();
  placePopover(pop, a, pop.classList.contains("dd-pop"));
}

document.addEventListener("scroll", e => {
  const pop = $("#popover");
  if (!pop.hidden && !(e.target instanceof Node && pop.contains(e.target))) syncPopover();
}, true);
addEventListener("resize", () => syncPopover());

function openMenu(anchor, items) {
  const pop = $("#popover");
  pop.className = "popover";
  pop.innerHTML = items.map((it, i) =>
    `<button class="menu-item ${it.danger ? "danger" : ""}" data-i="${i}">${icon(it.icon)}${esc(it.label)}</button>`).join("");
  pop.hidden = false;
  placePopover(pop, anchor, false);
  anchor.setAttribute("aria-expanded", "true");
  pop._sel = popAnchorSel(anchor);
  pop.onclick = e => {
    const b = e.target.closest("button[data-i]");
    if (!b) return;
    closeMenu();
    items[+b.dataset.i].run();
  };
  pop._anchor = anchor;
}

function closeMenu() {
  const pop = $("#popover");
  if (pop._anchor) pop._anchor.setAttribute("aria-expanded", "false");
  pop.hidden = true;
  pop._anchor = null;
  pop._sel = "";
}

/* Выпадающий список как в Happ: пункты, у каждого — «Подробнее». */
function openDropdown(anchor, groups, onPick) {
  const pop = $("#popover");
  pop.className = "popover dd-pop";
  const row = it => `<div class="dd-item ${it.sel ? "is-sel" : ""} ${it.off ? "is-off" : ""} ${it.sub ? "dd-sub" : ""}" role="option"
      aria-selected="${!!it.sel}" ${it.off ? 'aria-disabled="true"' : `data-pick="${it.id}" tabindex="0"`}>
      <span class="dd-label">${esc(it.label)}${it.off ? " " + soonBadge() : ""}</span>
      <button type="button" class="dd-more" data-info="${it.info}">${t("more")}</button></div>`;
  pop.innerHTML = `<div class="dd" role="listbox">${groups.map(g => g.head
    ? `<div class="dd-sep"></div><div class="dd-head"><span class="dd-label">${esc(g.head)}${g.off ? " " + soonBadge() : ""}</span>
        <button type="button" class="dd-more" data-info="${g.info}">${t("more")}</button></div>${g.items.map(row).join("")}`
    : g.items.map(row).join("")).join("")}</div>`;
  pop.hidden = false;
  placePopover(pop, anchor, true);
  anchor.setAttribute("aria-expanded", "true");
  pop._anchor = anchor;
  pop._sel = popAnchorSel(anchor);
  pop.onclick = e => {
    const more = e.target.closest("[data-info]");
    if (more) { e.stopPropagation(); closeMenu(); return detailModal(more.dataset.info); }
    const it = e.target.closest("[data-pick]");
    if (it) { closeMenu(); onPick(it.dataset.pick); }
  };
}

/* ---------- страницы и шапка ---------- */

const PAGES = {
  home: { back: null }, more: { back: "home", title: "nav_more" }, features: { back: "more", title: "nav_features" },
  zapret: { back: "more", title: "nav_zapret" }, byedpi: { back: "more", title: "nav_byedpi" },
  services: { back: "more", title: "nav_services" }, routes: { back: "more", title: "nav_routes" },
  traffic: { back: "more", title: "nav_traffic" }, updates: { back: "more", title: "nav_updates" },
  settings: { back: "more", title: "nav_settings" }, log: { back: "more", title: "nav_log" },
  tips: { back: "more", title: "nav_tips" }, manual: { back: "more", title: "nav_manual" },
  share: { back: "more", title: "nav_share" }, ads: { back: "more", title: "nav_ads" },
  errors: { back: "more", title: "nav_errors" }, status: { back: "home", title: "nav_status" },
};

function renderTop() {
  const meta = PAGES[page] || PAGES.home;
  const back = $("#backBtn");
  back.hidden = !meta.back;
  back.innerHTML = icon("back");
  back.setAttribute("aria-label", t("back"));
  $("#brand").hidden = !!meta.title;
  $("#topTitle").hidden = !meta.title;
  $("#topTitle").textContent = meta.title ? t(meta.title) : "";
  $("#brandName").textContent = t("app");
  const lb = $("#langBtn");
  lb.textContent = LANG === "ru" ? "EN" : "RU";
  lb.title = t("lang_switch");
  lb.setAttribute("aria-label", t("lang_switch"));
  const more = $("#moreBtn");
  more.hidden = page !== "home";
  more.innerHTML = `${icon("sliders")}<span>${t("nav_more")}</span>`;
  document.title = t("app");
  document.documentElement.lang = LANG;
}

function go(p) {
  if (!PAGES[p]) p = "home";
  page = p;
  dirty.clear();
  closeMenu();
  renderPage(true);
  $("#main").scrollTop = 0;
  if (p === "traffic") loadConnections();
  if (p === "log") loadLogs();
  if (p === "errors") loadErrors();
}

function renderTheme() {
  const theme = (S && S.theme) || localStorage.getItem("pult-theme") || "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("pult-theme", theme);
}

function renderProblemsBadge() {
  const btn = $("#problemsBtn");
  const n = ((S && S.problems) || []).length;
  btn.hidden = !n;
  if (!n) return;
  const err = S.problems.some(p => p.level === "error");
  btn.className = `problems-btn ${err ? "error" : ""}`;
  btn.title = t("problems_n", { n });
  btn.setAttribute("aria-label", t("problems_n", { n }));
  btn.innerHTML = `${icon("alert")}<span>${n}</span>`;
}

function problemsModal() {
  const list = (S && S.problems) || [];
  const body = list.length ? list.map(p => `<div class="problem ${p.level}">
      <div class="problem-head">${icon("alert")}<b>${esc(p.title)}</b>
        <button class="btn btn-small btn-ghost" data-dismiss="${esc(p.key)}">${t("problem_hide")}</button></div>
      ${p.where ? `<div class="hint">${esc(t("problem_where", { w: p.where }))}</div>` : ""}
      ${p.fix ? `<div>${esc(t("problem_fix", { f: p.fix }))}</div>` : ""}
      ${p.detail ? details("prob-" + p.key, "", `<pre class="pre">${esc(p.detail)}</pre>`) : ""}
    </div>`).join("") : `<p class="modal-text">${t("problems_none")}</p>`;
  openModal(`<h2>${t("problems")}</h2><div class="problems-list">${body}</div>
    <div class="modal-actions"><button class="btn" id="mReport">${icon("copy")}${t("problem_copy")}</button>
    <button class="btn btn-primary" data-close>${t("close")}</button></div>`, m => {
    m.querySelector("#mReport").addEventListener("click", async () => {
      const r = await act("problem_report");
      if (r.ok) copy(r.result, t("report_copied"));
    });
    m.querySelectorAll("[data-dismiss]").forEach(b => b.addEventListener("click", async () => {
      await act("dismiss_problem", { key: b.dataset.dismiss }, { quiet: true });
      b.closest(".problem").remove();
    }));
  }, "modal-wide");
}

/* ---------- главная ---------- */

/* Функции, которые появятся в следующих обновлениях: видны, но пока не включаются. */
const SOON = new Set([]);

const busy = kind => S.busy_kind === kind;
const stopBtn = (small = false) => `<button type="button" class="btn btn-stop ${small ? "btn-small" : ""}" data-act="stop">${icon("stop")}${t("stop")}</button>`;

function homeSkeleton() {
  return `
    <section class="hero" id="hero" aria-label="${t("connection")}"></section>
    <section class="stack" aria-labelledby="dpiTitle" style="gap:8px">
      <div class="dpi-head"><h2 class="section-title" id="dpiTitle">${t("dpi_title")}</h2><span id="dpiCombo"></span></div>
      <div class="dpi" id="dpi"></div>
    </section>
    <section class="stack" aria-labelledby="srvTitle" style="gap:10px">
      <div class="srv-head">
        <h2 id="srvTitle">${t("servers")}</h2>
        <label class="search">${icon("search")}<input id="q" type="search" placeholder="${t("search")}" value="${esc(query)}" aria-label="${t("search_server")}"></label>
        <span class="srv-tools" id="srvTools"></span>
      </div>
      <div class="stack" id="subs" style="gap:10px"></div>
    </section>`;
}

/* Живые цифры главного экрана (пинг, скорость, выход) и цвет кнопки. Обновляются каждые 2 секунды —
   только они: кнопки и меню не пересоздаются, поэтому нажатие не «проваливается» между обновлениями,
   а анимация кольца не начинается заново. */
function heroLive() {
  const live = S.live || {};
  const awgOn = !!(S.awg && S.awg.active);
  const on = S.connected || awgOn;
  const connecting = busy("connect") || !!S.conn_busy; // подключение идёт своей очередью, параллельно с долгими задачами
  let cls = on ? (live.ping == null && !awgOn ? "is-weak" : "is-on") : "";
  if (connecting) cls = "is-busy";
  const ping = S.connected ? live.ping : null;
  const [down, downU] = rate(live.proxy_down);
  const exit = S.connected ? (live.exit_loc ? countryName(live.exit_loc) : "…") : "—";
  const stats = `<div class="${S.connected ? pingClass(ping) : ""}"><dt>${t("stat_ping")}</dt><dd>${S.connected && ping != null ? `${ping}<small>${t("ms")}</small>` : "—"}</dd></div>
          <div><dt>${t("stat_speed")}</dt><dd>${S.connected ? `${down}<small>${downU}</small>` : "—"}</dd></div>
          <div><dt>${t("stat_exit")}</dt><dd>${esc(exit)}</dd></div>`;
  return { cls: cls ? `power ${cls}` : "power", stats };
}

function updateHeroLive() {
  const box = $("#hero");
  if (!box) return;
  const { cls, stats } = heroLive();
  const power = box.querySelector(".power");
  if (power && power.className !== cls) power.className = cls;
  const dl = box.querySelector("#heroStats");
  if (dl && dl._html !== stats) { dl.innerHTML = stats; dl._html = stats; }
}

function renderHero() {
  queueMicrotask(syncPopover);  // открытое меню остаётся у своей (новой) кнопки
  const box = $("#hero");
  if (!box) return;
  const awgOn = !!(S.awg && S.awg.active);
  const on = S.connected || awgOn;
  const connecting = busy("connect") || !!S.conn_busy;
  const stateText = connecting ? (on ? t("st_switching") : t("st_connecting")) : on ? t("st_connected")
    : S.kill_on ? t("st_killed") : t("st_disconnected");
  const best = S.servers.find(s => s.key === S.best);
  let line;
  const pick = (S.engine && S.engine.pick) || "auto";
  const pickAwg = pick === "awg" && !S.connected;
  const awgSrv = awgOn ? S.servers.find(s => s.key === S.awg.active) : null;
  if (awgOn) line = `${cc(awgSrv ? awgSrv.cc : "")}<b>${esc(S.awg.name)}</b><span>AmneziaWG</span><span class="awg-chip" title="${esc(t("awg_all_tip"))}">${t("awg_all")}</span>`;
  else if (on && S.current) line = `${cc(S.current.cc)}<b>${esc(S.current.name)}</b><span>${esc(S.current.protocol)}</span>`;
  else if (pickAwg) line = S.awg && !S.awg.client ? `<span>${t("awg_need_client")}</span><button type="button" class="btn btn-small" data-act="awg_download">${icon("download")}${t("awg_download")}</button>`
    : S.awg && S.awg.count ? `<span>${t("awg_ready")}</span>` : `<span>${t("awg_none")}</span>`;
  else if (best) line = `<span>${t("best_server")}</span>${cc(best.cc)}<b>${esc(best.name)}</b>`;
  else line = `<span>${S.servers.length ? t("press_check") : t("add_sub_hint")}</span>`;
  if (!on && S.filter_on) line += `<span class="ads-chip">${icon("block")}${t("ads_chip")}</span>`;
  if (!on && S.kill_on) line = `<span class="kill-chip">${icon("lock")}${t("kill_chip")}</span>`;
  if (on && S.vpn_until) line += `<span class="timer-chip">${t("vpn_until", { n: Math.max(1, Math.round((S.vpn_until - Date.now() / 1000) / 60)) })}</span>`;
  const st = S.settings;
  const conn = connLabel();
  const autoBtn = busy("auto") ? stopBtn() : `<button class="btn btn-primary hero-act" data-act="auto">${icon("bolt")}${t("auto")}</button>`;
  const tile = (id, ic, name, sub, on2, attrs) => `<button type="button" class="tile ${on2 ? "on" : ""} ${SOON.has(id) ? "soon-tile" : ""}" ${attrs}
      title="${esc(t(`i_${id}_desc`))}">${icon(ic)}<span class="tile-text"><b>${esc(name)}</b><span>${esc(sub)}</span></span></button>`;
  const backup = S.backup ? t("tile_backup", { name: S.backup.name }) : t("on");
  const html = `
    <div class="hero-top">
      <button class="power" data-act="toggle" aria-label="${on ? t("disconnect") : t("connect")}">
        <svg class="ring-svg" viewBox="0 0 120 120" aria-hidden="true"><circle class="ring-bg" cx="60" cy="60" r="54"/><circle class="ring" cx="60" cy="60" r="54"/></svg>
        <span class="glyph">${icon("power")}</span>
      </button>
      <div class="hero-main">
        <div class="hero-state">${stateText}</div>
        <div class="hero-server ${pickAwg && S.awg && !S.awg.client ? "awg-need" : ""}">${line}</div>
        <dl class="stats" id="heroStats"></dl>
      </div>
      ${autoBtn}
    </div>
    ${healthStrip()}
    <div class="selects">
      <div class="sel-wrap"><span class="sel-label" id="lblRoute">${t("sel_route")}</span>
        <button type="button" class="dd-btn" data-dd="route" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lblRoute">
          <b>${S.mode === "vpn" ? t("i_global_name") : t("i_smart_name")}</b><span>— ${S.mode === "vpn" ? t(S.ru_direct ? "rt_global_sub" : "rt_global_all") : t("rt_smart_sub")}</span>${icon("down")}</button></div>
      <div class="sel-wrap"><span class="sel-label" id="lblConn">${t("sel_conn")}</span>
        <button type="button" class="dd-btn" data-dd="conn" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lblConn">
          <b>${esc(conn.name)}</b><span>— ${esc(conn.sub)}</span>${icon("down")}</button></div>
      <div class="sel-wrap"><span class="sel-label" id="lblEngine">${t("sel_engine")}</span>
        <button type="button" class="dd-btn" data-dd="engine" aria-haspopup="listbox" aria-expanded="false" aria-labelledby="lblEngine">
          <b>${esc(t(`i_eng_${pick}_name`))}</b><span>— ${esc(engineSub(pick))}</span>${icon("down")}</button></div>
    </div>
    <div class="tiles">
      ${tile("autopilot", "swap", t("i_autopilot_name"), st.autopilot ? backup : t("off"), st.autopilot, `data-act="tile_autopilot" aria-pressed="${!!st.autopilot}"`)}
      ${tile("multi", "layers", t("i_multi_name"), !st.multi_enabled ? t("off")
        : S.multi.map.length ? t("multi_n", { n: S.multi.map.length }) : t("multi_none"),
        st.multi_enabled, `data-act="tile_set" data-key="multi_enabled" aria-pressed="${!!st.multi_enabled}"`)}
      ${tile("ads", "block", t("i_ads_name"), adsSide(), st.block_ads, `data-act="tile_ads" aria-pressed="${!!st.block_ads}"`)}
      ${tile("dns", "lock", t("i_dns_name"), st.dns_encrypted ? t("on") : t("off"), st.dns_encrypted,
        `data-act="tile_set" data-key="dns_encrypted" aria-pressed="${!!st.dns_encrypted}"`)}
    </div>${whatWorksHtml()}`;
  // пересобираем только если что-то правда поменялось: иначе кнопка под курсором не пересоздаётся
  if (box._html !== html) { box.innerHTML = html; box._html = html; }
  updateHeroLive();
}

/* Лестница не нашла ни одного рабочего способа: что открывается напрямую и когда следующая попытка. */
function whatWorksHtml() {
  const L = S.ladder || {};
  const w = L.what_works;
  if (!w || S.connected && !S.problems.some(p => p.key === "no_working")) return "";
  const items = (w.items || []).map(x => `<span class="ww-item ${x.ok ? "ok" : "bad"}">${icon(x.ok ? "check" : "x")}${esc(x.name)}</span>`).join("");
  const mins = L.retry_at ? Math.max(1, Math.round((L.retry_at - Date.now() / 1000) / 60)) : 0;
  return `<div class="what-works" role="status">
    <div><b>${t("ww_title")}</b> <span class="hint">${esc(mins ? t("ww_retry_in", { n: mins }) : t("ww_retry_soon"))}</span></div>
    ${items ? `<div class="ww-list"><span class="hint">${t("ww_direct")}</span>${items}</div>` : ""}
    <span class="hint">${t(w.hint === "wifi" ? "ww_hint_wl" : "ww_hint")}</span>
    <div class="toolbar">${busy("connect") || S.conn_busy ? "" : `<button class="btn btn-small btn-primary" data-act="ladder_retry">${icon("refresh")}${t("ww_try_now")}</button>`}</div>
  </div>`;
}

/* Состояние zapret или ByeDPI одной строкой: точка-цвет и текст. */
function dpiStatus(which) {
  const d = S.dpi;
  if (S.busy && new RegExp(which, "i").test(S.busy)) return { cls: "busy", text: S.busy + "…" };
  if (!d.supported) return { cls: "", text: t("dpi_st_win") };
  const x = d[which];
  const on = which === "zapret" ? x.enabled : x.role !== "off";
  if (!on) return { cls: "", text: t("dpi_st_off") };
  if (x.running) return { cls: "ok", text: t("dpi_st_running") };
  if (!x.installed || !x.strategy) return { cls: "warn", text: t("dpi_st_setup") };
  if (which === "zapret" && d.byedpi.running && d.byedpi.role !== "off") return { cls: "", text: t(d.byedpi.role === "main" ? "dpi_st_standby" : "dpi_st_replaced") };
  if (which === "byedpi" && x.role === "backup" && d.zapret.enabled) return { cls: "", text: t("dpi_st_backup") };
  return { cls: "warn", text: x.error || t("dpi_st_fail") };
}

const dpiOn = which => which === "zapret" ? S.dpi.zapret.enabled : S.dpi.byedpi.role !== "off";

/* Способ обхода целиком: zb — Zapret, запасной ByeDPI; bz — наоборот; z, b — только один; off — выключено. */
function dpiCombo() {
  const z = dpiOn("zapret"), b = dpiOn("byedpi");
  if (z && b) return S.dpi.byedpi.role === "main" ? "bz" : "zb";
  return z ? "z" : b ? "b" : "off";
}
const DPI_COMBOS = {
  zb: { zapret_enabled: true, byedpi_role: "backup" }, bz: { zapret_enabled: true, byedpi_role: "main" },
  z: { zapret_enabled: true, byedpi_role: "off" }, b: { zapret_enabled: false, byedpi_role: "main" },
  off: { zapret_enabled: false, byedpi_role: "off" },
};

function dpiComboBtn(compact = false) {
  const c = dpiCombo();
  return `<button type="button" class="dd-btn ${compact ? "dd-compact" : ""}" data-dd="dpi" aria-haspopup="listbox" aria-expanded="false"
      aria-label="${esc(t("sel_dpi"))}" ${S.dpi.supported ? "" : "disabled"}><b>${esc(t(`i_dpi_${c}_name`))}</b>${compact ? "" : `<span>— ${esc(t(`dpi_${c}_sub`))}</span>`}${icon("down")}</button>`;
}

function dpiDropdown(anchor) {
  const c = dpiCombo();
  openDropdown(anchor, [
    { items: ["zb", "bz", "z", "b", "off"].map(id => ({ id, label: t(`i_dpi_${id}_name`), info: `dpi_${id}`, sel: c === id })) },
  ], id => {
    if (id === c) return;
    const v = DPI_COMBOS[id];
    S.dpi.zapret.enabled = v.zapret_enabled;
    S.dpi.byedpi.role = v.byedpi_role;
    renderPage(true);
    act("set_dpi", v).then(() => scheduleRefresh(50));
  });
}

function renderDpi() {
  const box = $("#dpi");
  if (!box || !S.dpi) return;
  const card = (id, ic) => {
    const st = dpiStatus(id);
    const on = dpiOn(id) && S.dpi.supported;
    return `<div class="dpi-card ${on ? "on" : ""}">
      <span class="dpi-ico">${icon(ic)}</span>
      <button type="button" class="dpi-text" data-nav="${id}"><b>${t(`i_${id}_name`)}</b><span><i class="dot ${st.cls}"></i><em>${esc(st.text)}</em></span></button>
      ${sw(on, `data-act="dpi_toggle" data-which="${id}" aria-label="${esc(t(`i_${id}_name`))}"`, !S.dpi.supported)}
    </div>`;
  };
  box.innerHTML = card("zapret", "key") + card("byedpi", "split");
  const combo = $("#dpiCombo");
  if (combo) combo.innerHTML = dpiComboBtn(true);
}

function renderSrvTools() {
  const box = $("#srvTools");
  if (!box) return;
  const ib = (act, ic, label, extra = "") => `<button type="button" class="icon-btn ${extra}" data-act="${act}" title="${esc(label)}" aria-label="${esc(label)}">${icon(ic)}</button>`;
  box.innerHTML = [
    busy("test") ? ib("stop", "stop", t("stop"), "stop") : ib("test", "signal", t("check_all")),
    busy("speed") ? ib("stop", "stop", t("stop"), "stop") : ib("speed_top", "speed", t("measure")),
    ib("update_sub", "refresh", t("update_all_subs")),
    `<button type="button" class="icon-btn" data-menu="sort" title="${esc(t("sort"))}" aria-label="${esc(t("sort"))}" aria-expanded="false">${icon("sort")}</button>`,
    `<button type="button" class="icon-btn accent" data-menu="add" title="${esc(t("add"))}" aria-label="${esc(t("add"))}" aria-expanded="false">${icon("plus")}</button>`,
  ].join("");
}

function sortServers(list) {
  const sort = (S && S.sort) || "ping";
  const rank = s => !s.supported ? 4 : s.ok ? 0 : !s.tested ? 2 : 3;
  const out = list.slice();
  if (sort === "name") out.sort((a, b) => a.name.localeCompare(b.name, LANG));
  else if (sort === "ping") out.sort((a, b) => rank(a) - rank(b) || (a.ping ?? 1e9) - (b.ping ?? 1e9));
  return out;
}

function pingCell(s) {
  switch (s.code) {
    case "testing": return `<span class="ping testing">${t("code_testing")}</span>`;
    case "speed": return `<span class="ping testing">${t("code_speed")}</span>`;
    case "unsupported": return `<span class="ping fail" title="${esc(s.note)}">${t("code_unsupported")}</span>`;
    case "untested": return `<span class="ping">—</span>`;
    case "awg": return `<span class="ping" title="${esc(t("awg_untested_tip"))}">${s.current ? t("on") : "—"}</span>`;
    case "ok": case "unstable":
      return `<span class="ping ${pingClass(s.ping)}" title="${esc(t("ping_tip", { d: s.delay ?? "—", j: s.jitter ?? "—" }))}">${s.ping} ${t("ms")}</span>`;
    default: return `<span class="ping fail" title="${esc(s.error || "")}">${t("code_" + s.code)}</span>`;
  }
}

function serverRow(s) {
  if (s.stub) return "";
  const backup = S.backup && S.connected && !s.current && S.backup.name === s.name && S.settings.autopilot;
  const tags = [
    s.current ? `<i class="tag cur">${t("tag_current")}</i>` : "",
    s.best && !s.current ? `<i class="tag best">${t("tag_best")}</i>` : "",
    backup ? `<i class="tag">${t("tag_backup")}</i>` : "",
    s.game ? `<i class="tag">${t("tag_games")}</i>` : "",
    s.code === "unstable" ? `<i class="tag warn">${t("tag_unstable")}</i>` : "",
    s.insecure ? `<i class="tag warn" title="${esc(t("tag_insecure_tip"))}">${t("tag_insecure")}</i>` : "",
    s.mask ? `<i class="tag" title="${esc(t("tag_mask_tip"))}">${t("tag_mask")}</i>` : "",
    s.fp ? `<i class="tag" title="${esc(t("tag_fp_tip"))}">${esc(s.fp)}</i>` : "",
    s.kind === "singbox" ? `<i class="tag" title="${esc(t("tag_bridge_tip"))}">${t("tag_bridge")}</i>` : "",
    s.wl ? `<i class="tag" title="${esc(t("tag_wl_tip"))}">${t("tag_wl")}</i>` : "",
  ].join("");
  return `<div class="srv ${s.current ? "is-current" : ""} ${s.supported ? "" : "is-off"}" data-key="${s.key}"
      title="${esc(s.endpoint || s.note || "")}" tabindex="${s.supported ? 0 : -1}" role="button">
    ${cc(s.cc)}
    <span class="srv-name"><span>${esc(s.name)}</span>${tags}</span>
    <span class="proto">${esc(s.protocol)}</span>
    ${pingCell(s)}
    <button class="icon-btn plain" data-menu="srv" data-key="${s.key}" aria-label="${t("srv_menu")}" aria-expanded="false">${icon("more")}</button>
  </div>`;
}

function subSection(sub, servers) {
  const collapsed = (S.collapsed || []).includes(sub.id);
  const u = sub.usage || {};
  const meta = [t("servers_n", { n: sub.count, w: plural(sub.count, t("srv1"), t("srv2"), t("srv5")) })];
  if (u.total) meta.push(t("used_of", { used: bytes((u.download || 0) + (u.upload || 0)), total: bytes(u.total) }));
  if (u.expire) meta.push(t("until", { date: dateStr(u.expire) }));
  if (sub.id !== "manual") meta.push(ago(sub.last_update));
  const pct = u.total ? Math.min(100, Math.round(((u.download || 0) + (u.upload || 0)) / u.total * 100)) : 0;
  const real = servers.filter(s => !s.stub);
  const rows = real.length ? real.map(serverRow).join("") : `<div class="empty-row">${query ? t("nothing_found") : t("no_servers")}</div>`;
  let err = "";
  if (sub.error) {
    const lines = sub.error.split("\n");
    err = `<div class="sub-msg error">${details("suberr-" + sub.id, esc(lines[0]), lines.length > 1 ? `<pre class="pre">${esc(lines.slice(1).join("\n"))}</pre>` : "")}</div>`;
  }
  const notice = (sub.notices || []).length ? `<div class="sub-msg">${details("subnote-" + sub.id,
    `<b>${t("provider_msg")}</b> ${sub.notices.map(esc).join("; ")}`, sub.count ? "" : esc(t("provider_msg_hint")))}</div>` : "";
  return `<section class="sub ${collapsed ? "collapsed" : ""}" data-sub="${sub.id}">
    <header class="sub-head">
      <button class="icon-btn plain sub-toggle" data-toggle="${sub.id}" aria-expanded="${!collapsed}" aria-label="${t("toggle_sub")}">${icon("down")}</button>
      <div class="sub-title"><b>${esc(sub.name)}</b><span class="sub-meta">${esc(meta.join(" · "))}</span></div>
      ${u.total ? `<span class="usage-bar" title="${pct}%"><i style="width:${pct}%"></i></span>` : ""}
      <button class="icon-btn plain" data-menu="sub" data-id="${sub.id}" aria-label="${t("sub_menu")}" aria-expanded="false">${icon("more")}</button>
    </header>
    ${err}${notice}
    <div class="srv-list">${rows}</div>
  </section>`;
}

function renderSubs() {
  const box = $("#subs");
  if (!box) return;
  if (!S.subs.length) {
    box.innerHTML = `<section class="card empty">
      <h2>${t("empty_title")}</h2>
      ${details("empty", esc(t("empty_text")), esc(t("empty_more")))}
      <form class="empty-form" id="emptyForm">
        <input class="input" id="emptyUrl" placeholder="https://…" autocomplete="off" aria-label="${t("link")}">
        <button class="btn btn-primary" type="submit">${t("add")}</button>
      </form>
      <span class="toolbar"><button class="link-btn" data-act="add_server_modal">${t("single_server_link")}</button>
        <button class="link-btn" data-act="vps_modal">${t("own_vps_link")}</button></span>
    </section>`;
    $("#emptyForm").addEventListener("submit", e => {
      e.preventDefault();
      const url = $("#emptyUrl").value.trim();
      if (url) startAddSub(url, "");
    });
    return;
  }
  const q = query.toLowerCase();
  box.innerHTML = S.subs.map(sub => {
    let list = S.servers.filter(s => s.sub === sub.id);
    if (q) list = list.filter(s => (s.name + " " + s.cc + " " + s.protocol).toLowerCase().includes(q));
    return subSection(sub, sortServers(list));
  }).join("");
}

function renderHome(full) {
  if (full || !$("#hero")) {
    $("#page").innerHTML = homeSkeleton();
    $("#q").addEventListener("input", e => { query = e.target.value; renderSubs(); });
  }
  renderHero();
  renderDpi();
  renderSrvTools();
  if (!(document.activeElement && document.activeElement.id === "emptyUrl")) renderSubs();
}

function routeDropdown(anchor) {
  openDropdown(anchor, [{ items: [
    { id: "vpn", label: t("i_global_name"), info: "global", sel: S.mode === "vpn" },
    { id: "smart", label: t("i_smart_name"), info: "smart", sel: S.mode !== "vpn" },
  ] }], id => {
    if (id === S.mode) return;
    S.mode = id;
    renderHero();
    act("set_mode", { mode: id });
  });
}

const TUN_IDS = { auto: "tun_auto", xray: "tun_xray", singbox: "tun_singbox", tun2proxy: "tun_t2p" };
const CONN_SETTINGS = {
  proxy: { tun_enabled: false, system_proxy: true }, ports: { tun_enabled: false, system_proxy: false },
  tun_auto: { tun_enabled: true, tun_engine: "auto", system_proxy: true },
  tun_xray: { tun_enabled: true, tun_engine: "xray", system_proxy: true },
  tun_singbox: { tun_enabled: true, tun_engine: "singbox", system_proxy: true },
  tun_t2p: { tun_enabled: true, tun_engine: "tun2proxy", system_proxy: true },
};

function connMode() {
  if (S.tun && S.tun.enabled) return TUN_IDS[S.tun.engine] || "tun_auto";
  return S.settings.system_proxy ? "proxy" : "ports";
}

/* Подпись на кнопке «Подключение»: что выбрано и что реально работает. */
function connLabel() {
  const m = connMode();
  if (!m.startsWith("tun_")) return { name: t(`i_${m}_name`), sub: m === "proxy" ? t("cn_proxy_sub") : t("cn_ports_sub", infoVars()) };
  const tn = S.tun;
  const engineName = tn.active ? t(`i_${TUN_IDS[tn.active]}_name`) : "";
  let sub;
  if (S.connected && !tn.active) sub = t("cn_tun_failed");
  else if (tn.engine === "auto") sub = engineName ? t("cn_tun_auto", { e: engineName }) : t("i_tun_auto_name");
  else sub = t(`i_${m}_name`);
  return { name: "TUN", sub };
}

function connDropdown(anchor) {
  const m = connMode();
  const off = !S.tun || !S.tun.supported;
  openDropdown(anchor, [
    { items: [
      { id: "proxy", label: t("i_proxy_name"), info: "proxy", sel: m === "proxy" },
      { id: "ports", label: t("i_ports_name"), info: "ports", sel: m === "ports" },
    ] },
    { head: t("i_tun_name"), info: "tun", off, items: ["tun_auto", "tun_xray", "tun_singbox", "tun_t2p"].map(id =>
      ({ id, label: t(`i_${id}_name`), info: id, sub: true, off, sel: m === id })) },
  ], id => {
    if (id === m) return;
    const v = CONN_SETTINGS[id];
    Object.assign(S.settings, { system_proxy: v.system_proxy });
    S.tun = Object.assign({}, S.tun, { enabled: v.tun_enabled, engine: v.tun_engine || S.tun.engine });
    renderHero();
    act("save_settings", v).then(r => {
      if (!r.ok) return;
      if (v.tun_enabled) toast(t(S.connected ? "tun_on_admin" : "tun_on_later"), "info", 7000);
      else if (m.startsWith("tun_")) toast(t("tun_off"), "ok", 4000);
      else toast(v.system_proxy ? t("sysproxy_on") : t("sysproxy_off", infoVars()), "ok", 5000);
    });
  });
}

/* ---------- «Движок»: какие VPN использовать ---------- */

const ENGINES = ["auto", "xray", "hy2", "singbox", "awg"];

function engineSub(id) {
  const n = ((S.engine || {}).counts || {})[id] || 0;
  if (id === "awg" && S.awg && S.awg.active) return t("eng_awg_on");
  if (id === "auto") return t("eng_auto_sub");
  return n ? t("servers_n", { n, w: plural(n, t("srv1"), t("srv2"), t("srv5")) }) : t("eng_none");
}

function engineDropdown(anchor) {
  const pick = (S.engine && S.engine.pick) || "auto";
  const counts = (S.engine || {}).counts || {};
  openDropdown(anchor, [{ items: ENGINES.map(id => ({ id, info: `eng_${id}`, sel: pick === id,
    label: id === "auto" ? t("i_eng_auto_name") : `${t(`i_eng_${id}_name`)} (${counts[id] || 0})` })) }], id => {
    if (id === pick) return;
    S.engine = Object.assign({}, S.engine, { pick: id });
    renderHero();
    act("engine_pick", { pick: id }).then(r => {
      if (!r.ok) return;
      if (id !== "auto" && !counts[id]) toast(t(id === "awg" ? "eng_awg_add" : "eng_add"), "info", 7000);
      else if (id === "awg" && S.awg && !S.awg.client) toast(t("awg_need_client"), "info", 7000);
      else if (id === "singbox" && S.engine && !S.engine.singbox) toast(t("eng_sb_download"), "info", 6000);
    });
  });
}

/* ---------- «Дополнительно» ---------- */

const ownRulesCount = () => ["proxy_list", "direct_list", "block_list"]
  .reduce((n, k) => n + (S.settings[k] || "").split("\n").filter(l => l.trim() && !l.trim().startsWith("#")).length, 0);

function servicesSummary() {
  const done = S.services.filter(s => s.results && s.results.current);
  if (!done.length) return "";
  const ok = done.filter(s => ["ok", "slow"].includes(s.results.current.state)).length;
  return t("n_of_m", { n: ok, m: done.length });
}

function geoText() {
  const u = S.updates;
  if (u.geo_age == null) return t("geo_none");
  return u.geo_age < 1 ? t("geo_today") : t("geo_days", { n: Math.floor(u.geo_age) });
}

function dpiSide(which) {
  if (!S.dpi) return "";
  const st = dpiStatus(which);
  return `<span class="side-state"><i class="dot ${st.cls}"></i>${esc(st.cls === "busy" ? t("dpi_st_working") : st.text)}</span>`;
}

function renderMore() {
  const row = (nav, ic, name, desc, side = "", accent = false) => `<button type="button" class="list-row" data-nav="${nav}">
      <span class="list-ico ${accent ? "accent" : ""}">${icon(ic)}</span>
      <span class="list-text"><b>${esc(name)}</b><span>${esc(desc)}</span></span>
      <span class="list-side">${side}</span>${icon("right", "chev")}</button>`;
  const featOn = FEATURES.flatMap(g => g.items).filter(f => !SOON.has(f.id) && f.get && f.get()).length;
  const hv = healthVerdict();
  $("#page").innerHTML = `
    <section class="list-card"><h2>${t("more_state")}</h2>
      ${row("status", "shield", t("nav_status"), t("more_status"), `<span class="dot ${hv.cls}"></span>${esc(hv.short)}`, true)}
      ${row("errors", "alert", t("nav_errors"), t("more_errors"), S.errors_count ? esc(t("errors_n", { n: S.errors_count })) : "")}
    </section>
    <section class="list-card"><h2>${t("more_dpi")}</h2>
      ${row("zapret", "key", t("i_zapret_name"), t("i_zapret_desc"), dpiSide("zapret"), true)}
      ${row("byedpi", "split", t("i_byedpi_name"), t("i_byedpi_desc"), dpiSide("byedpi"), true)}
    </section>
    <section class="list-card"><h2>${t("more_help")}</h2>
      ${row("tips", "check", t("nav_tips"), t("more_tips"), "", true)}
      ${row("manual", "monitor", t("nav_manual"), t("more_manual"), esc(`127.0.0.1:${S.settings.socks_port}`))}
    </section>
    <section class="list-card"><h2>${t("more_sites")}</h2>
      ${row("ads", "block", t("nav_ads"), t("more_ads"), esc(adsSide()), true)}
      ${row("services", "services", t("nav_services"), t("more_services"), esc(servicesSummary()))}
      ${row("routes", "routes", t("nav_routes"), t("more_routes"), esc(t("rules_n", { n: ownRulesCount() })))}
      ${row("traffic", "traffic", t("nav_traffic"), t("more_traffic"))}
    </section>
    <section class="list-card"><h2>${t("more_program")}</h2>
      ${row("share", "qr", t("nav_share"), t("more_share"))}
      ${row("features", "sliders", t("nav_features"), t("more_features"), esc(t("enabled_n", { n: featOn })))}
      ${row("updates", "updates", t("nav_updates"), t("more_updates"))}
      ${row("log", "log", t("nav_log"), t("more_log"))}
      ${row("settings", "gear", t("nav_settings"), t("more_settings"))}
    </section>
    <div class="more-foot">
      <button class="btn btn-small" data-act="theme">${icon(S.theme === "light" ? "moon" : "sun")}${S.theme === "light" ? t("theme_dark") : t("theme_light")}</button>
      <button class="btn btn-small" data-act="lang_toggle">${LANG === "ru" ? "English" : "Русский"}</button>
      <span class="grow"></span><span>${esc(t("version_v", { v: S.version }))}</span>
    </div>`;
}

/* ---------- функции ---------- */

const setting = key => () => !!S.settings[key];
const saveSetting = key => value => act("save_settings", { [key]: value }).then(r => r.ok && scheduleRefresh(50));

const autoFlag = key => value => act("auto_flags", { [key]: value }).then(r => r.ok && scheduleRefresh(50));

const FEATURES = [
  { title: "fg_auto", items: [
    { id: "auto_routes", get: () => S.settings.auto_routes !== false, set: autoFlag("auto_routes") },
    { id: "auto_stall", get: () => S.settings.auto_stall !== false, set: autoFlag("auto_stall") },
    { id: "ask_direct", get: () => S.settings.auto_ask_direct !== false, set: autoFlag("auto_ask_direct") },
    { id: "ads_ask", get: () => S.settings.ads_ask_sites !== false, set: autoFlag("ads_ask_sites") },
    { id: "failover", get: () => S.settings.failover !== false, set: autoFlag("failover") },
    { id: "net_profiles", get: () => !!(S.net && S.net.enabled), set: autoFlag("net_profiles"), extra: () => netExtra() },
    { id: "sub_alerts", get: () => S.settings.sub_alerts !== false, set: autoFlag("sub_alerts") },
    { id: "app_update", get: () => !!(S.app_update && S.app_update.auto), set: autoFlag("app_update") },
    { id: "smart_notices", get: () => S.settings.smart_notices !== false, set: autoFlag("smart_notices") },
  ] },
  { title: "fg_conn", items: [
    { id: "autopilot", get: setting("autopilot"), set: saveSetting("autopilot") },
    { id: "fp_auto", get: () => S.settings.fp_auto !== false, set: autoFlag("fp_auto") },
    { id: "data_watch", get: () => S.settings.data_watch !== false, set: autoFlag("data_watch") },
    { id: "net_memory", get: () => S.settings.net_memory !== false, set: autoFlag("net_memory"), extra: () => netMemoryExtra() },
    { id: "multi", get: setting("multi_enabled"), set: saveSetting("multi_enabled") },
    { id: "tun", get: () => !!(S.tun && S.tun.enabled),
      set: v => act("save_settings", { tun_enabled: v, system_proxy: true }).then(r => r.ok && scheduleRefresh(50)) },
    { id: "hotkey", get: () => !!(S.hotkey && S.hotkey.enabled), set: autoFlag("hotkey_enabled"),
      extra: () => hotkeyExtra() },
    { id: "connect_start", get: setting("auto_connect_on_start"), set: saveSetting("auto_connect_on_start") },
    { id: "autostart", get: setting("autostart"), set: saveSetting("autostart") },
    { id: "lan", get: setting("allow_lan"), set: saveSetting("allow_lan") },
    { id: "bg", get: setting("background"), set: saveSetting("background") },
  ] },
  { title: "fg_russia", items: [
    { id: "ru_direct", get: () => !!S.ru_direct, set: saveSetting("ru_direct") },
    { id: "whitelist", get: () => S.settings.whitelist_auto !== false, set: saveSetting("whitelist_auto") },
    { id: "nodpi", nav: "zapret" },
    { id: "mask", get: () => S.settings.mask_auto !== false, set: saveSetting("mask_auto") },
    { id: "quic", get: () => S.settings.block_quic !== false, set: saveSetting("block_quic") },
  ] },
  { title: "fg_protect", items: [
    { id: "dns", get: setting("dns_encrypted"), set: saveSetting("dns_encrypted") },
    { id: "ads", get: setting("block_ads"), set: v => adsSet({ enabled: v }) },
    { id: "leak", get: setting("leak_protection"), set: saveSetting("leak_protection") },
    { id: "kill_switch", get: () => !!S.settings.kill_switch, set: autoFlag("kill_switch") },
    { id: "certs", get: () => S.settings.cert_watch !== false, set: autoFlag("cert_watch") },
  ] },
  { title: "fg_games", items: [{ id: "games", get: setting("game_mode"), set: saveSetting("game_mode") }] },
  { title: "fg_updates", items: [
    { id: "autoupd", nav: "updates" },
  ] },
];

function netExtra() {
  const n = S.net || {};
  if (!n.enabled) return "";
  let now;
  if (n.kind === "wifi") now = t(n.profile === "public" ? "net_now_public" : "net_now_home", { ssid: n.ssid }) + (n.open ? " " + t("net_open") : "");
  else if (n.kind === "wired") now = t("net_now_wired");
  else now = t("net_now_none");
  const btn = n.kind === "wifi"
    ? (n.profile === "public" ? `<button class="btn btn-small" data-act="net_mark" data-kind="home">${t("net_mark_home")}</button>`
      : `<button class="btn btn-small" data-act="net_mark" data-kind="public">${t("net_mark_public")}</button>`) : "";
  const marked = [...(n.trusted || []).map(x => [x, "home"]), ...(n.untrusted || []).map(x => [x, "public"])];
  const list = marked.length ? `<div class="net-list">${marked.map(([x, k]) => `<span class="net-tag ${k}">${esc(x)} · ${t(k === "home" ? "net_home" : "net_public")}
      <button class="icon-btn plain" data-act="net_forget" data-ssid="${esc(x)}" aria-label="${esc(t("site_remove"))}: ${esc(x)}">${icon("x")}</button></span>`).join("")}</div>` : "";
  return `<div class="net-now"><span class="hint">${esc(now)}</span>${btn}</div>${list}`;
}

function netMemoryExtra() {
  const L = S.ladder || {};
  if (S.settings.net_memory === false) return "";
  return `<div class="net-now"><span class="hint">${esc(L.count ? t("netmem_n", { n: L.count }) : t("netmem_none"))}</span>
    ${L.count ? `<button class="btn btn-small btn-ghost" data-act="net_memory_clear">${t("netmem_clear")}</button>` : ""}</div>`;
}

function hotkeyExtra() {
  const h = S.hotkey || {};
  const warn = h.enabled && h.supported && h.key && !h.ok ? `<span class="route-warn">${icon("alert", "inline-ico")}${esc(t("hotkey_busy"))}</span>` : "";
  return `<form class="hotkey-form" data-form="hotkey"><input class="input" id="hotkeyInput" value="${esc(h.value || "Ctrl+Alt+V")}" aria-label="${esc(t("i_hotkey_name"))}" spellcheck="false" autocomplete="off">
    <button class="btn btn-small" type="submit">${t("save")}</button></form>${warn}`;
}

function renderFeatures() {
  const row = f => {
    const soon = SOON.has(f.id);
    const open = openFeats.has(f.id);
    const control = f.nav ? `<button class="btn btn-small" data-nav="${f.nav}">${t("configure")}</button>`
      : sw(!soon && f.get(), `data-fset="${f.id}" aria-label="${esc(t(`i_${f.id}_name`))}"`, soon);
    return `<div class="feat-row ${open ? "open" : ""}">
      <div class="feat-text"><b>${esc(t(`i_${f.id}_name`))}</b> ${soon ? soonBadge() : ""}
        <div class="desc">${esc(t(`i_${f.id}_desc`, infoVars()))} <button class="link-btn" data-feat="${f.id}" aria-expanded="${open}">${open ? t("less") : t("more")}</button></div>
        ${f.extra ? f.extra() : ""}</div>
      ${control}
      ${open ? `<div class="feat-more">${infoBlocks(f.id === "nodpi" ? "zapret" : f.id).replace(/<div class="info-sec">/g, "<div>")}</div>` : ""}
    </div>`;
  };
  $("#page").innerHTML = `<p class="page-intro">${t("features_intro")}</p>
    ${FEATURES.map(g => `<section class="list-card"><h2>${t(g.title)}</h2>${g.items.map(row).join("")}</section>`).join("")}`;
  const hf = $('[data-form="hotkey"]');
  if (hf) hf.addEventListener("submit", e => {
    e.preventDefault();
    act("hotkey_set", { value: $("#hotkeyInput").value }).then(r => { if (r.ok) { toast(t("hotkey_saved", { k: r.result }), "ok", 3000); scheduleRefresh(50); } });
  });
}

/* ---------- zapret и ByeDPI ---------- */

const kbps = v => rate((v || 0) * 1024).join(" ");

function dpiCell(r) {
  if (!r) return `<span class="state skip">—</span>`;
  if (r.ok) return `<span class="state ok">${t("dpi_open")}<span class="ms">${kbps(r.kbps || 0)}</span></span>`;
  const slow = r.kbps > 0 && /замедл|throttl/i.test(r.detail || "");
  return `<span class="state ${slow ? "slow" : "blocked"}" title="${esc(r.detail || "")}">${t(slow ? "dpi_slow" : "dpi_closed")}</span>`;
}

function dpiStatusCard(which) {
  const d = S.dpi;
  const x = d[which];
  const st = dpiStatus(which);
  const picking = S.busy && new RegExp(which, "i").test(S.busy);
  const on = dpiOn(which) && d.supported;
  const stratName = which === "zapret" ? x.strategy : (x.strategy_name || x.strategy);
  const meta = [
    stratName ? t("dpi_strategy", { s: stratName }) : "",
    x.version ? t("dpi_version", { v: x.version }) : (d.supported ? t("dpi_not_installed") : ""),
    x.tested_at ? t("dpi_tested", { when: ago(x.tested_at).replace(/^\S+\s/, "") }) : "",
  ].filter(Boolean);
  const last = d.last && d.last.mode === which ? d.last : null;
  const control = sw(on, `data-act="dpi_toggle" data-which="${which}" aria-label="${esc(t(`i_${which}_name`))}"`, !d.supported);
  const combo = dpiCombo();
  const roleHint = !on ? "" : combo === "zb" ? t(which === "zapret" ? "role_main_z" : "role_backup_b")
    : combo === "bz" ? t(which === "zapret" ? "role_backup_z" : "role_main_b") : t("role_only");
  return `<section class="card card-pad dpi-status">
    <div class="dpi-status-top">
      <span class="dpi-ico">${icon(which === "zapret" ? "key" : "split")}</span>
      <div class="dpi-status-text"><b>${t(`i_${which}_name`)}</b><span class="dpi-line"><i class="dot ${st.cls}"></i>${esc(st.text)}</span></div>
      ${control}
    </div>
    ${roleHint ? `<p class="hint">${roleHint}</p>` : ""}
    ${meta.length ? `<div class="dpi-meta">${meta.map(m => `<span>${esc(m)}</span>`).join("")}</div>` : ""}
    ${last ? `<div class="dpi-last"><span>YouTube ${dpiCell(last.youtube)}</span><span>Discord ${dpiCell(last.discord)}</span></div>` : ""}
    ${!d.supported ? `<p class="hint">${t("dpi_win_only")}</p>` : `<div class="toolbar">
      ${picking ? stopBtn() : `<button class="btn btn-primary" data-act="pick_${which}" ${S.busy ? "disabled" : ""}>${icon("bolt")}${t("dpi_pick")}</button>`}
      <button class="btn" data-act="check_dpi" ${S.busy || !x.running ? "disabled" : ""}>${icon("check")}${t("dpi_check")}</button>
    </div>`}
    ${which === "zapret" && d.supported ? `<p class="hint">${icon("alert", "inline-ico")}${t("zapret_admin")}</p>` : ""}
    ${S.mode === "vpn" ? `<p class="hint">${t("dpi_global_note")}</p>` : ""}
  </section>`;
}

function dpiResults(which) {
  const x = S.dpi[which];
  const cur = x.strategy;
  if (!x.results.length) return `<section class="card card-pad"><b>${t("dpi_results")}</b><p class="hint">${t(which === "zapret" ? "dpi_results_none" : "byedpi_results_none")}</p></section>`;
  const key = r => which === "zapret" ? r.name : r.args;
  const works = r => !!(r.youtube?.ok || r.discord?.ok);
  const row = r => {
    const isCur = key(r) === cur;
    const btn = isCur ? `<span class="tag ${x.running ? "best" : ""}">${t(x.running ? "dpi_current" : "dpi_chosen")}</span>`
      : `<button class="btn btn-small" data-act="select_${which}" data-val="${esc(key(r))}" ${S.busy || !S.dpi.supported ? "disabled" : ""}>${t("dpi_select")}</button>`;
    return `<div class="t-row dpi-row ${works(r) ? "" : "dim"}">
      <span class="dpi-name"><b>${esc(r.name)}</b>${which === "byedpi" ? `<code>${esc(r.args)}</code>` : ""}</span>
      ${dpiCell(r.youtube)}${dpiCell(r.discord)}<span class="dpi-act">${btn}</span></div>`;
  };
  const good = x.results.filter(r => works(r) || key(r) === cur);
  const rest = x.results.filter(r => !good.includes(r));
  const restId = "dpi-rest-" + which;
  const open = openDetails.has(restId) || !good.length;
  return `<h2 class="section-title">${t("dpi_results")}</h2>
    <div class="table">
      <div class="t-row dpi-row t-head"><span>${t("dpi_col_name")}</span><span>YouTube</span><span>Discord</span><span></span></div>
      ${good.map(row).join("")}
      ${open ? rest.map(row).join("") : ""}
      ${rest.length && good.length ? `<button type="button" class="t-more" data-act="dpi_rest" data-id="${restId}">${
        open ? t("dpi_rest_hide") : t("dpi_rest_show", { n: rest.length })}</button>` : ""}
    </div>`;
}

function dpiSites() {
  const s = S.dpi.sites;
  const keep = $("#dpiCustom") ? $("#dpiCustom").value : s.custom;
  return `<section class="list-card"><h2>${t("dpi_sites")}</h2>
    <div class="feat-row"><div class="feat-text"><b>YouTube</b><div class="desc">${t("dpi_site_yt")}</div></div>
      ${sw(s.youtube, `data-act="dpi_site" data-key="dpi_youtube" aria-label="YouTube"`)}</div>
    <div class="feat-row"><div class="feat-text"><b>Discord</b><div class="desc">${t("dpi_site_dc")}</div></div>
      ${sw(s.discord, `data-act="dpi_site" data-key="dpi_discord" aria-label="Discord"`)}</div>
    <div class="feat-row dpi-custom"><div class="feat-text"><b>${t("dpi_custom")}</b><div class="desc">${t("dpi_custom_hint")}</div>
      <textarea class="input" id="dpiCustom" rows="3" placeholder="example.com" aria-label="${esc(t("dpi_custom"))}">${esc(keep)}</textarea>
      <div class="toolbar"><button class="btn btn-small" data-act="dpi_custom_save">${t("save")}</button></div></div></div>
  </section>`;
}

function dpiChain(which) {
  const ap = S.settings.autopilot;
  const steps = which === "zapret" ? ["chain_z1", "chain_z2", "chain_z3"] : ["chain_b1", "chain_z3"];
  return `<section class="card card-pad stack" style="gap:8px"><b>${t("dpi_chain")}</b>
    <ol class="chain">${steps.map(k => `<li>${t(k)}</li>`).join("")}</ol>
    <p class="hint">${t(ap ? "chain_on" : "chain_off")}</p>
    ${ap ? "" : `<div><button class="btn btn-small" data-act="tile_autopilot">${t("chain_enable")}</button></div>`}
  </section>`;
}

function dpiUpdates(which) {
  const x = S.dpi[which];
  return `<section class="card"><div class="upd-row">
    <span class="list-ico">${icon("updates")}</span>
    <span class="list-text"><b>${t("dpi_updates")}</b><span style="display:block">${esc(x.version ? t("dpi_version", { v: x.version }) : t("dpi_not_installed"))}</span></span>
    ${hoursSelect("dpi_update_hours")}
    <button class="btn btn-small" data-act="update_dpi" ${S.busy || !S.dpi.supported ? "disabled" : ""}>${icon("refresh")}${t("update_now")}</button>
  </div></section>`;
}

function dpiComboRow() {
  return `<div class="sel-wrap"><span class="sel-label">${t("sel_dpi")}</span>${dpiComboBtn()}</div>`;
}

function renderZapret(full) {
  if (!full && document.activeElement && document.activeElement.id === "dpiCustom") return;
  if (!S.dpi) return;
  $("#page").innerHTML = `<p class="page-intro">${esc(t("i_zapret_what"))}</p>
    ${dpiComboRow()}
    ${dpiStatusCard("zapret")}
    ${dpiResults("zapret")}
    ${dpiSites()}
    ${dpiChain("zapret")}
    ${dpiUpdates("zapret")}
    <section class="card card-pad stack" style="gap:10px">${infoBlocks("zapret")}</section>`;
}

function renderByedpi(full) {
  const f = document.activeElement && document.activeElement.id;
  if (!full && (f === "byedpiCustom" || f === "dpiCustom")) return;
  if (!S.dpi) return;
  const b = S.dpi.byedpi;
  const keep = $("#byedpiCustom") ? $("#byedpiCustom").value : b.custom;
  const testing = S.busy && /ByeDPI/i.test(S.busy) && S.busy_kind === "dpi_pick" && /сво|custom/i.test(S.busy);
  $("#page").innerHTML = `<p class="page-intro">${esc(t("i_byedpi_what"))}</p>
    ${dpiComboRow()}
    ${dpiStatusCard("byedpi")}
    ${dpiResults("byedpi")}
    <section class="card card-pad stack" style="gap:8px"><b>${t("byedpi_custom")}</b>
      <span class="hint">${t("byedpi_custom_hint")}</span>
      <div class="empty-form">
        <input class="input mono" id="byedpiCustom" placeholder="--disorder 1 --tlsrec 1+s" autocomplete="off" spellcheck="false" value="${esc(keep)}" aria-label="${esc(t("byedpi_custom"))}">
        ${testing ? stopBtn() : `<button class="btn" data-act="byedpi_test" ${S.busy || !S.dpi.supported ? "disabled" : ""}>${t("byedpi_test")}</button>`}
        <button class="btn btn-primary" data-act="byedpi_use" ${S.busy || !S.dpi.supported ? "disabled" : ""}>${t("dpi_turn_on")}</button>
      </div>
    </section>
    <p class="hint">${t("byedpi_apps")}</p>
    ${dpiChain("byedpi")}
    ${dpiUpdates("byedpi")}
    <section class="card card-pad stack" style="gap:10px">${infoBlocks("byedpi")}</section>`;
}

/* ---------- блокировка рекламы ---------- */

const ADS_LEVELS = ["light", "normal", "pro", "pro_plus"];
const ADS_LISTS = ["popups", "threats", "ru", "telemetry"];
const hhmm = ts => new Date(ts * 1000).toLocaleTimeString(LANG === "ru" ? "ru-RU" : "en-GB", { hour: "2-digit", minute: "2-digit" });

/* Коротко о состоянии: для плитки на главной и пункта в «Дополнительно». */
function adsSide() {
  const a = S.ads || {};
  if (!a.enabled) return t("off");
  if (a.paused_until) return t("ads_paused_until", { time: hhmm(a.paused_until) });
  if (busy("ads")) return t("ads_loading");
  if (!a.ready) return t("ads_basic");
  return a.today ? t("ads_today_n", { n: a.today }) : t("on");
}

function adsStatus() {
  const a = S.ads;
  if (!a.enabled) return { cls: "", text: t("ads_st_off") };
  if (a.paused_until) return { cls: "warn", text: t("ads_paused_until", { time: hhmm(a.paused_until) }) };
  if (S.connected) return { cls: "ok", text: t("ads_st_vpn") };
  if (S.filter_on) return { cls: "ok", text: t("ads_st_novpn") };
  return { cls: "warn", text: a.without_vpn ? t("ads_st_starting") : t("ads_st_waiting") };
}

function renderAds(full) {
  const a = S.ads;
  if (!a) return;
  const f = document.activeElement && document.activeElement.id;
  if (!full && (f === "adsCustom" || f === "adsAllow" || f === "adsHost")) return;
  const keep = id => $(`#${id}`) ? $(`#${id}`).value : null;
  const custom = keep("adsCustom") ?? a.custom, allow = keep("adsAllow") ?? a.allow;
  const st = adsStatus();
  const loading = busy("ads");
  const meta = [
    a.ready ? t("ads_total", { n: a.total.toLocaleString(LANG === "ru" ? "ru-RU" : "en-US") }) : t("ads_basic_long"),
    a.updated_at ? t("ads_updated", { when: ago(a.updated_at).replace(/^\S+\s/, "") }) : "",
  ].filter(Boolean);
  const level = lv => `<button type="button" role="radio" aria-checked="${a.level === lv}" data-act="ads_level" data-v="${lv}">${t("ads_lv_" + lv)}</button>`;
  const listRow = id => `<div class="feat-row">
      <span class="list-text"><b>${t("ads_l_" + id)}</b><span>${t("ads_l_" + id + "_d")}${a.lists[id] && a.counts[id] ? ` ${t("ads_count", { n: a.counts[id].toLocaleString(LANG === "ru" ? "ru-RU" : "en-US") })}` : ""}</span></span>
      ${sw(a.lists[id], `data-act="ads_list" data-id="${id}" aria-label="${esc(t("ads_l_" + id))}"`, !a.enabled)}</div>`;
  const recent = a.recent.length ? a.recent.slice(0, 25).map(x => `<div class="t-row ads-row">
      <span class="conn-host" title="${esc(x.host)}">${esc(x.host)}</span><span class="conn-num">${esc(x.time)}</span>
      <button class="btn btn-small" data-act="ads_allow" data-host="${esc(x.host)}">${t("ads_allow_btn")}</button></div>`).join("")
    : `<div class="empty-row">${a.enabled ? t("ads_journal_empty") : t("ads_journal_off")}</div>`;
  const pause = a.paused_until
    ? `<button class="btn btn-small" data-act="ads_pause" data-m="0">${t("ads_resume")}</button>`
    : [5, 30, 60].map(m => `<button class="btn btn-small" data-act="ads_pause" data-m="${m}" ${a.enabled ? "" : "disabled"}>${t("ads_pause_m", { n: m })}</button>`).join("");
  $("#page").innerHTML = `<p class="page-intro">${esc(t("ads_intro"))} <button class="link-btn" data-info="ads">${t("more")}</button></p>
    <section class="card card-pad dpi-status">
      <div class="dpi-status-top">
        <span class="dpi-ico">${icon("block")}</span>
        <div class="dpi-status-text"><b>${t("i_ads_name")}</b><span class="dpi-line"><i class="dot ${st.cls}"></i>${esc(st.text)}</span></div>
        ${sw(a.enabled, `data-act="ads_toggle" aria-label="${esc(t("i_ads_name"))}"`)}
      </div>
      <div class="dpi-meta">${meta.map(m => `<span>${esc(m)}</span>`).join("")}${a.enabled && a.today ? `<span>${esc(t("ads_today_n", { n: a.today }))}</span>` : ""}</div>
      <div class="ads-pause"><span class="hint">${t("ads_pause_hint")}</span><span class="grow"></span>${pause}</div>
    </section>
    ${(a.suspects || []).length ? `<section class="card ads-suspects">
      <div class="card-head"><b>${t("ads_sus_title")}</b><span class="hint">${t("ads_sus_hint")}</span></div>
      ${a.suspects.map(x => `<div class="t-row sus-row">
        <span class="list-text"><b>${esc(x.site)}</b><span>${esc(t(x.threat ? "ads_sus_threat" : "ads_sus_list", { list: x.lists.join(", ") }))}. ${esc(cap(ago(x.at, "ago")))}</span></span>
        <div class="auto-actions"><button class="btn btn-small ${x.threat ? "" : "btn-primary"}" data-act="ads_site_allow" data-site="${esc(x.site)}">${t("ads_site_allow")}</button>
          <button class="btn btn-small btn-ghost" data-act="ads_site_keep" data-site="${esc(x.site)}">${t("ads_site_keep")}</button></div></div>`).join("")}
    </section>` : ""}
    <section class="card">
      <div class="feat-row first">
        <span class="list-text"><b>${t("ads_novpn")}</b><span>${t("ads_novpn_d")}</span></span>
        ${sw(a.without_vpn, `data-act="ads_novpn" aria-label="${esc(t("ads_novpn"))}"`, !a.enabled)}</div>
      <div class="feat-row">
        <span class="list-text"><b>${t("ads_level")}</b><span>${t("ads_lv_" + a.level + "_d")}</span></span>
        <span class="seg" role="radiogroup" aria-label="${esc(t("ads_level"))}">${ADS_LEVELS.map(level).join("")}</span></div>
      ${ADS_LISTS.map(listRow).join("")}
      <div class="feat-row">
        <span class="list-text"><b>${t("ads_lists_upd")}</b><span>${esc(a.updated_at ? t("ads_updated", { when: ago(a.updated_at).replace(/^\S+\s/, "") }) : t("ads_never"))}</span></span>
        ${loading ? stopBtn(true) : `<button class="btn btn-small" data-act="ads_update" ${a.enabled && !S.busy ? "" : "disabled"}>${icon("refresh")}${t("update_now")}</button>`}</div>
    </section>
    <section class="card card-pad stack" style="gap:10px">
      <b>${t("ads_check")}</b><span class="hint">${t("ads_check_hint")}</span>
      <form class="toolbar" data-form="ads_lookup"><input class="input grow" id="adsHost" spellcheck="false" placeholder="example.com" value="${esc(adsLookupHost)}">
        <button class="btn" type="submit">${t("ads_check_btn")}</button></form>
      <div id="adsLookup">${adsLookupHtml()}</div>
    </section>
    <section class="card">
      <div class="card-head"><b>${t("ads_journal")}</b><span class="hint">${t("ads_journal_hint")}</span></div>
      <div class="table site-table">${recent}</div>
    </section>
    <section class="card card-pad stack" style="gap:12px">
      <div class="lists two">
        <div><h3>${t("ads_custom")}</h3><span class="hint">${t("ads_custom_hint")}</span>
          <textarea class="input" id="adsCustom" rows="6" spellcheck="false" placeholder="ads.example.com">${esc(custom)}</textarea></div>
        <div><h3>${t("ads_allow")}</h3><span class="hint">${t("ads_allow_hint")}</span>
          <textarea class="input" id="adsAllow" rows="6" spellcheck="false" placeholder="sberbank.ru">${esc(allow)}</textarea></div>
      </div>
      <div class="toolbar"><span class="grow"></span><button class="btn btn-primary" data-act="ads_save_lists" ${a.enabled ? "" : "disabled"}>${t("save_apply")}</button></div>
    </section>
    <section class="card card-pad stack" style="gap:6px">
      <b>${t("ads_limits")}</b>
      <span class="hint">${t("ads_limits_text")}</span>
    </section>`;
  $('[data-form="ads_lookup"]').addEventListener("submit", e => {
    e.preventDefault();
    adsLookupHost = $("#adsHost").value.trim();
    if (adsLookupHost) runAdsLookup();
  });
}

function runAdsLookup() {
  return act("ads_lookup", { host: adsLookupHost }).then(r => {
    if (!r.ok) return;
    adsLookupRes = r.result;
    const box = $("#adsLookup");
    if (box) box.innerHTML = adsLookupHtml();
  });
}

const adsSet = changes => act("ads_set", changes).then(r => { if (r.ok) scheduleRefresh(50); return r; });

let adsLookupHost = "";
let adsLookupRes = null;
function adsLookupHtml() {
  const r = adsLookupRes;
  if (!r) return "";
  const names = { main: t("ads_l_main"), popups: t("ads_l_popups"), threats: t("ads_l_threats"), ru: t("ads_l_ru"), telemetry: t("ads_l_telemetry") };
  let html;
  if (r.allowed) html = `<p class="ok-line">${esc(t("ads_lk_allowed", { h: r.host }))}</p>`;
  else if (r.protected && (r.lists || []).length) html = `<p class="ok-line">${esc(t("ads_lk_protected", { h: r.host, why: r.lists.map(x => names[x.id]).join(", ") }))}</p>`;
  else if (r.blocked) {
    const why = (r.lists || []).map(x => names[x.id] + (x.match !== r.host ? ` (${x.match})` : ""));
    if (r.custom) why.push(t("ads_lk_own") + (r.custom !== r.host ? ` (${r.custom})` : ""));
    html = `<p class="warn-line">${esc(t("ads_lk_blocked", { h: r.host, why: why.join(", ") }))}</p>
      <div class="toolbar"><button class="btn btn-small" data-act="ads_allow" data-host="${esc(r.host)}">${t("ads_allow_btn")}</button></div>`;
  } else html = `<p class="ok-line">${esc(t("ads_lk_free", { h: r.host }))}</p>`;
  if (r.user_rule === "block") html += `<p class="warn-line">${esc(t("ads_lk_rule"))}</p>`;
  if (!r.enabled) html += `<p class="hint">${esc(t("ads_lk_off"))}</p>`;
  else if (r.mode === "geo") html += `<p class="hint">${esc(t("ads_lk_geo"))}</p>`;
  return html;
}

/* ---------- поделиться: файл настроек и QR-код ---------- */

let shareItems = null;
let shareSel = "";
let shareQr = null;

const shareLabel = it => it.kind === "sub" ? t("qr_sub", { name: it.name })
  : it.kind === "server" ? t("qr_server", { name: it.name })
  : it.kind === "friend" ? t("qr_friend", { name: it.name }) : t("qr_tg");
const shareHint = kind => t(`qr_${kind}_hint`);
const shareWarn = kind => kind === "telegram" ? "" : t(`qr_${kind}_warn`);

function renderShare(full) {
  if (!full && $("#sharePage")) return;
  $("#page").innerHTML = `<div id="sharePage" class="stack">
    <p class="page-intro">${t("share_intro")}</p>
    <section class="card card-pad stack" style="gap:10px">
      <b>${t("share_file")}</b>
      <span class="hint">${t("share_file_text")}</span>
      <label class="check-row"><input type="checkbox" id="shSubs"><span><b>${t("share_subs")}</b><small>${t("share_subs_hint")}</small></span></label>
      <label class="check-row"><input type="checkbox" id="shServers"><span><b>${t("share_servers")}</b><small>${t("share_servers_hint")}</small></span></label>
      <div class="toolbar">
        <button class="btn btn-primary" data-act="export_settings">${icon("download")}${t("share_save")}</button>
        <button class="btn" data-act="import_pick">${icon("folder")}${t("share_open")}</button>
        <input type="file" id="shFile" accept=".json,application/json" hidden>
      </div>
    </section>
    <section class="card card-pad stack" style="gap:10px" id="qrBox"><b>${t("share_qr")}</b></section>
    <section class="card card-pad stack" style="gap:10px" id="vpsBox"><b>${t("vps_own")}</b></section>
  </div>`;
  loadShareItems();
  loadVps();
}

/* ---------- свой сервер: состояние и ключи для друзей ---------- */

let vpsList = null;

async function loadVps() {
  const r = await act("vps_list", {}, { quiet: true });
  vpsList = r.ok ? r.result : [];
  renderVpsBox();
}

/* [главное, подробности]: работает ли Xray и когда проверено; нагрузка, память, диск, трафик */
function vpsStatusLines(st) {
  if (!st || !st.ts) return [t("vps_st_never"), ""];
  const up = st.uptime_s >= 86400 ? t("vps_up_d", { n: Math.floor(st.uptime_s / 86400) }) : t("vps_up_h", { n: Math.floor(st.uptime_s / 3600) });
  return [`${st.xray === "active" ? t("vps_st_ok") : t("vps_st_down")}, ${t("vps_st_conns", { n: st.conns })} · ${ago(st.ts, "ago")}`,
    cap([t("vps_st_load", { v: st.load.split(" ")[0] || "?" }), t("vps_st_mem", { v: st.mem_mb }), t("vps_st_disk", { v: st.disk }),
      t("vps_st_traffic", { v: bytes(st.rx + st.tx) }), up].join(", "))];
}

function renderVpsBox() {
  const box = $("#vpsBox");
  if (!box || !vpsList) return;
  const busyNow = S && S.busy;
  const head = `<b>${t("vps_own")}</b><span class="hint">${t("vps_own_text")}</span>`;
  if (!vpsList.length) {
    box.innerHTML = `${head}<div class="toolbar"><button class="btn" data-act="vps_add">${icon("plus")}${t("vps_add_btn")}</button></div>`;
    return;
  }
  box.innerHTML = head + vpsList.map(h => {
    const st = h.status || {};
    const down = st.ts && st.xray !== "active";
    const lines = vpsStatusLines(st);
    const friends = h.friends.map(f => `<div class="vps-friend">
        <span class="list-text"><b>${esc(f.name)}</b><span>${esc(t("vps_friend_made", { d: dateStr(f.ts) }))}</span></span>
        <button class="btn btn-small" data-vqr="${esc(f.id)}" data-vname="${esc(f.name)}">${icon("qr")}${t("vps_qr")}</button>
        <button class="icon-btn plain" data-vdel="${esc(f.id)}" data-vid="${esc(h.id)}" data-vname="${esc(f.name)}" title="${esc(t("vps_friend_del"))}" aria-label="${esc(t("vps_friend_del"))}" ${busyNow ? "disabled" : ""}>${icon("trash")}</button>
      </div>`).join("");
    return `<div class="vps-item">
      <div class="vps-head"><span class="list-ico">${icon(down ? "alert" : "vpn")}</span>
        <span class="list-text"><b>${esc(h.name)}</b><span class="${down ? "bad" : ""}">${esc(lines[0])}</span>${lines[1] ? `<small>${esc(lines[1])}</small>` : ""}</span>
        <button class="icon-btn plain" data-vmore="${esc(h.id)}" aria-label="${esc(t("vps_actions"))}">${icon("more")}</button></div>
      <div class="toolbar">
        <button class="btn btn-small" data-vstat="${esc(h.id)}" ${busyNow ? "disabled" : ""}>${icon("refresh")}${t("vps_check")}</button>
        <button class="btn btn-small" data-vfriend="${esc(h.id)}" ${busyNow ? "disabled" : ""}>${icon("plus")}${t("vps_friend_add")}</button>
      </div>
      ${friends ? `<div class="vps-friends">${friends}</div>` : ""}
    </div>`;
  }).join("") + `<p class="hint" style="margin:0">${icon("lock", "inline-ico soft")}${t("vps_pass_note")}</p>`;
  box.querySelectorAll("[data-vstat]").forEach(b => b.addEventListener("click", async () => {
    const r = await act("vps_status", { id: b.dataset.vstat });
    if (r.ok) toast(t("vw_started"), "info", 9000);
  }));
  box.querySelectorAll("[data-vfriend]").forEach(b => b.addEventListener("click", () => vpsFriendModal(b.dataset.vfriend)));
  box.querySelectorAll("[data-vqr]").forEach(b => b.addEventListener("click", () =>
    qrModal("friend:" + b.dataset.vqr, t("qr_friend", { name: b.dataset.vname }), "friend")));
  box.querySelectorAll("[data-vdel]").forEach(b => b.addEventListener("click", async () => {
    if (!await confirmModal(t("vps_friend_del"), t("vps_friend_del_text", { name: b.dataset.vname }), t("delete"))) return;
    const r = await act("vps_friend_remove", { id: b.dataset.vid, friend: b.dataset.vdel });
    if (r.ok) toast(t("vw_started"), "info", 9000);
  }));
  box.querySelectorAll("[data-vmore]").forEach(b => b.addEventListener("click", () => openMenu(b, [
    { icon: "trash", label: t("vps_forget"), run: async () => {
      if (!await confirmModal(t("vps_forget"), t("vps_forget_text"), t("vps_forget_ok"))) return;
      await act("vps_forget", { id: b.dataset.vmore });
      loadVps();
    } }])));
}

function vpsFriendModal(id) {
  openModal(`<h2>${t("vps_friend_add")}</h2><p class="modal-text">${t("vps_friend_text")}</p>
    <label class="field"><span>${t("vps_friend_name")}</span><input class="input" id="fName" maxlength="30" placeholder="${esc(t("vps_friend_ph"))}"></label>
    <div class="modal-error" id="mErr" hidden></div>
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button>
      <button class="btn btn-primary" id="mOk">${t("vps_friend_go")}</button></div>`, m => {
    m.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", closeModal));
    m.querySelector("#mOk").addEventListener("click", async () => {
      const r = await act("vps_friend_add", { id, name: $("#fName").value.trim() }, { quiet: true });
      if (!r.ok) return showModalError(r.error);
      closeModal();
      toast(t("vw_started"), "info", 12000);
    });
  });
}

function vpsAddModal() {
  openModal(`<h2>${t("vps_add_btn")}</h2><p class="modal-text">${t("vps_add_text")}</p>
    <div class="form-grid" style="padding:0">
      <label class="field"><span>${t("vw_host")}</span><input class="input" id="aHost" placeholder="203.0.113.10" autocomplete="off" spellcheck="false"></label>
      <label class="field"><span>${t("vw_port")}</span><input class="input" id="aPort" value="22" inputmode="numeric"></label>
      <label class="field"><span>${t("vw_user")}</span><input class="input" id="aUser" value="root" autocomplete="off" spellcheck="false"></label>
      <label class="field"><span>${t("vps_name")}</span><input class="input" id="aName" placeholder="${t("vps_default_name")}"></label>
    </div>
    <p class="hint" style="margin:0">${icon("lock", "inline-ico soft")}${t("vps_pass_note")}</p>
    <div class="modal-error" id="mErr" hidden></div>
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button>
      <button class="btn btn-primary" id="mOk">${t("vps_add_go")}</button></div>`, m => {
    m.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", closeModal));
    m.querySelector("#mOk").addEventListener("click", async () => {
      const host = $("#aHost").value.trim();
      if (!host) return showModalError(t("vw_need_host"));
      const r = await act("vps_add", { host, port: $("#aPort").value.trim() || "22", user: $("#aUser").value.trim() || "root",
        name: $("#aName").value.trim() }, { quiet: true });
      if (!r.ok) return showModalError(r.error);
      closeModal();
      toast(t("vw_started"), "info", 12000);
    });
  });
}

async function loadShareItems() {
  const r = await act("share_items", {}, { quiet: true });
  shareItems = r.ok ? r.result : [];
  if (!shareItems.some(i => i.id === shareSel)) shareSel = (shareItems.find(i => i.kind !== "telegram" || i.ready) || {}).id || "";
  shareQr = null;
  renderQrBox();
  if (shareSel) loadQr(shareSel);
}

async function loadQr(id) {
  const r = await act("share_qr", { id });
  shareQr = r.ok ? { id, ...r.result } : null;
  renderQrBox();
}

function renderQrBox() {
  const box = $("#qrBox");
  if (!box || !shareItems) return;
  const kindIcon = { sub: "vpn", server: "globe", telegram: "monitor", friend: "key" };
  const cur = shareItems.find(i => i.id === shareSel);
  const list = shareItems.map(it => {
    const off = it.kind === "telegram" && !it.ready;
    return `<button type="button" role="radio" class="qr-item" data-qr="${esc(it.id)}" aria-checked="${it.id === shareSel}" ${off ? "disabled" : ""}>
      <span class="list-ico">${icon(kindIcon[it.kind])}</span>
      <span class="list-text"><b>${esc(shareLabel(it))}</b><span>${esc(off ? t("qr_tg_need_lan") : shareHint(it.kind))}</span></span></button>`;
  }).join("");
  const tgOff = shareItems.find(i => i.kind === "telegram" && !i.ready);
  box.innerHTML = `<b>${t("share_qr")}</b><span class="hint">${t("share_qr_text")}</span>
    <div class="qr-wrap">
      <div class="qr-list" role="radiogroup" aria-label="${esc(t("share_qr"))}">${list}
        ${tgOff ? `<button class="link-btn" data-nav="manual">${t("qr_tg_enable")}</button>` : ""}</div>
      <div class="qr-view">
        <div class="qr-img ${shareQr && shareQr.id === shareSel ? "" : "empty"}">${shareQr && shareQr.id === shareSel ? shareQr.svg : ""}</div>
        ${cur && shareWarn(cur.kind) ? `<p class="qr-warn">${icon("alert", "inline-ico")}<span>${t(`qr_${cur.kind}_warn`)}</span></p>` : ""}
        ${shareQr && shareQr.id === shareSel ? `<button class="btn btn-small" data-act="qr_copy">${icon("copy")}${t("qr_copy")}</button>` : ""}
      </div>
    </div>`;
}

function qrModal(id, title, kind) {
  act("share_qr", { id }).then(r => {
    if (!r.ok) return;
    openModal(`<div class="modal-head"><h2>${esc(title)}</h2>
        <button class="icon-btn plain" data-close aria-label="${t("close")}">${icon("x")}</button></div>
      <div class="qr-img qr-modal">${r.result.svg}</div>
      <p class="hint">${esc(shareHint(kind))}</p>
      ${shareWarn(kind) ? `<p class="qr-warn">${icon("alert", "inline-ico")}<span>${shareWarn(kind)}</span></p>` : ""}
      <div class="modal-actions"><button class="btn" id="mCopy">${icon("copy")}${t("qr_copy")}</button>
        <button class="btn btn-primary" data-close>${t("close")}</button></div>`, m => {
      m.querySelector("#mCopy").addEventListener("click", () => copy(r.result.text, t("link_copied")));
    });
  });
}

async function exportSettings() {
  const r = await act("export_settings", { subs: $("#shSubs").checked, servers: $("#shServers").checked });
  if (!r.ok) return;
  const blob = new Blob([JSON.stringify(r.result, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const d = new Date();
  const day = [d.getFullYear(), d.getMonth() + 1, d.getDate()].map(n => String(n).padStart(2, "0")).join("-");
  a.download = `VedomyjVPN-settings-${day}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  toast(t("share_saved"), "ok", 6000);
}

async function importFile(file) {
  if (!file) return;
  if (file.size > 1_500_000) return toast(t("share_bad_file"), "error");
  let data;
  try { data = JSON.parse(await file.text()); } catch { return toast(t("share_bad_file"), "error"); }
  const p = await act("import_preview", { data });
  if (!p.ok) return;
  const n = p.result;
  const text = [t("import_settings_n", { n: n.settings }),
    n.subscriptions ? t("import_subs_n", { n: n.subscriptions }) : "",
    n.servers ? t("import_servers_n", { n: n.servers }) : "",
    n.skipped ? t("import_skipped_n", { n: n.skipped }) : ""].filter(Boolean).join("\n");
  if (!await confirmModal(t("import_q"), text, t("import_apply"), false)) return;
  const r = await act("import_settings", { data });
  if (r.ok) toast(t("import_started"), "info", 4000);
}

/* ---------- сервисы ---------- */

const ROUTE_KEYS = { proxy: "r_proxy", byedpi: "r_byedpi", direct: "r_direct", block: "r_block", lists: "r_lists" };
function multiFor(name) {
  const m = S.multi && S.multi.enabled && S.multi.map.find(x => x.service === name);
  return m ? ` <i class="tag" title="${esc(t("multi_via_tip"))}">${esc(t("multi_via", { name: m.server }))}</i>` : "";
}

/* Теги ядра для своих маршрутов: multiN — Мультисервер, pinN — выбранный сервер, customN — свой прокси */
const routeGroup = r => /^(multi|pin)\d/.test(r || "") ? "proxy" : /^custom\d/.test(r || "") ? "custom"
  : r === "adblock" ? "block" : r;
const routeLabel = r => r === "adblock" ? t("r_adblock") : routeGroup(r) === "custom" ? t("r_custom")
  : t(ROUTE_KEYS[routeGroup(r)] || "r_direct");

function stateCell(r, column) {
  if (!r) {
    if (column !== "direct" && !S.connected) return `<span class="state skip">${t("s_need_conn")}</span>`;
    return `<span class="state skip">${busy("services") ? t("s_checking") : "—"}</span>`;
  }
  if (r.state === "skip") return `<span class="state skip">${t("s_need_conn")}</span>`;
  const ms = r.ms && (r.state === "ok" || r.state === "slow") ? `<span class="ms">${r.ms} ${t("ms")}</span>` : "";
  return `<span class="state ${r.state}" title="${esc(r.detail || "")}">${t("s_" + r.state)}${ms}</span>`;
}

/* Варианты подключения для сервиса или сайта. autoText — подпись «как по умолчанию» (null — без этого пункта). */
function routeOptions(value, autoText) {
  const opt = (v, label) => `<option value="${esc(v)}" ${v === value ? "selected" : ""}>${esc(label)}</option>`;
  const servers = (S.servers || []).filter(x => x.supported && !x.stub);
  const proxies = (S.routes && S.routes.proxies) || [];
  // в закрытом списке видна только сама строка — поэтому у сервера и прокси в подписи есть «Сервер:» / «Прокси:»
  let srv = servers.map(x => opt(`server:${x.key}`, t("route_srv_item", { name: x.name + (x.current ? ` (${t("route_main")})` : "") }))).join("");
  if (value.startsWith("server:") && !servers.some(x => `server:${x.key}` === value)) srv = opt(value, t("route_gone_server")) + srv;
  let px = proxies.map(p => opt(`custom:${p.id}`, t("route_px_item", { name: p.name || p.label }))).join("");
  if (value.startsWith("custom:") && !proxies.some(p => `custom:${p.id}` === value)) px = opt(value, t("route_gone_proxy")) + px;
  px += `<option value="custom:new">${esc(t("route_add_proxy"))}</option>`;
  return `${autoText != null ? opt("auto", autoText) : ""}${opt("proxy", t("route_vpn"))}
    ${opt("direct", t("route_direct"))}${opt("dpi", t("route_dpi"))}${opt("block", t("route_block"))}
    ${srv ? `<optgroup label="${esc(t("route_group_server"))}">${srv}</optgroup>` : ""}
    <optgroup label="${esc(t("route_group_proxy"))}">${px}</optgroup>`;
}

function routeSelect(s) {
  const autoText = s.choice === "auto" ? t("route_auto", { r: routeLabel(s.route) }) : t("route_default");
  return `<div class="route-cell"><select class="input route-select" data-svc="${esc(s.name)}" data-cur="${esc(s.choice)}" aria-label="${t("col_route")}: ${esc(svcName(s.name))}">
    ${routeOptions(s.choice || "auto", autoText)}</select>
    ${s.warn ? `<span class="route-warn" title="${esc(s.warn)}">${icon("alert", "inline-ico")}${esc(s.warn)}</span>` : ""}</div>`;
}

function renderServices() {
  const rows = list => list.map(s => `<div class="t-row svc-row">
      <span class="svc-name">${esc(svcName(s.name))}${multiFor(s.name)}</span>
      ${stateCell(s.results.direct, "direct")}${stateCell(s.results.vpn, "vpn")}${stateCell(s.results.current, "current")}
      ${routeSelect(s)}</div>`).join("");
  $("#page").innerHTML = `
    <section class="card card-pad stack" style="gap:8px" id="siteBox"></section>
    ${details("head-services", esc(t("services_short")), esc(t("services_more")))}
    <div class="toolbar">
      ${busy("services") ? stopBtn() : `<button class="btn btn-primary" data-act="check_services">${icon("services")}${t("check_services")}</button>`}
      <button class="btn" data-act="autofix">${icon("routes")}${t("autofix")}</button>
      ${busy("speed") ? stopBtn() : `<button class="btn" data-act="speed_current">${icon("speed")}${t("measure_conn")}</button>`}
    </div>
    <section class="card card-pad"><b>${t("tg_title")}</b>
      ${details("tg", esc(t("tg_short")), esc(t("tg_more", { port: S.settings.socks_port })) +
        `<div style="margin-top:8px"><button class="btn btn-small" data-act="telegram_proxy">${t("tg_manual")}</button></div>`)}
    </section>
    <div class="table">
      <div class="t-row svc-row t-head"><span>${t("col_service")}</span><span>${t("col_direct")}</span><span>${t("col_vpn")}</span><span>${t("col_now")}</span><span>${t("col_route")}</span></div>
      <div class="t-group">${t("group_foreign")}</div>${rows(S.services.filter(s => !s.russian))}
      <div class="t-group">${t("group_russian")}</div>${rows(S.services.filter(s => s.russian))}
    </div>
    <div class="legend">
      <span class="state ok">${t("s_ok")}</span><span class="state slow">${t("s_slow")}</span>
      <span class="state region">${t("legend_region")}</span><span class="state blocked">${t("s_blocked")}</span>
    </div>`;
  renderSiteBox();
}

function renderSiteBox() {
  const box = $("#siteBox");
  if (!box) return;
  const keep = $("#siteUrl") ? $("#siteUrl").value : "";
  const r = siteResult;
  const col = (key, label) => r && r.results[key] ? `<span><span class="hint">${label}:</span> ${stateCell(r.results[key], key)}</span>` : "";
  box.innerHTML = `<b>${t("site_title")}</b>
    <span class="hint">${t("site_text")}</span>
    <form class="empty-form" id="siteForm">
      <input class="input" id="siteUrl" placeholder="example.com" autocomplete="off" aria-label="${t("site_title")}" value="${esc(keep)}">
      ${busy("site") ? stopBtn() : `<button class="btn btn-primary" type="submit">${t("site_check")}</button>`}
      ${busy("repair") ? stopBtn() : `<button class="btn" type="button" id="siteRepair" title="${esc(t("repair_hint"))}" ${S.busy ? "disabled" : ""}>${t("repair_btn")}</button>`}
    </form>
    <span class="hint">${t("repair_text")}</span>
    ${r ? `<div class="site-res"><div class="toolbar" style="gap:6px 16px"><b>${esc(r.host)}</b>
        ${col("direct", t("col_direct"))}${col("vpn", t("col_vpn"))}${col("other", t("col_other"))}${col("current", t("col_now"))}${col("after", t("col_after"))}</div>
      <div>${esc(r.verdict)}</div>
      ${r.site && S.connected ? `<div class="toolbar" style="gap:6px 12px"><span class="hint">${t("site_route_pick")}</span>
        <div class="route-cell"><select class="input route-select" data-site="${esc(r.site)}" data-cur="${esc(r.route || "auto")}" aria-label="${esc(t("site_route_pick"))} ${esc(r.site)}">
          ${routeOptions(r.route || "auto", t("route_default"))}</select></div></div>` : ""}</div>` : ""}
    ${vpnSuspectsHtml()}
    ${repairHtml()}`;
  $("#siteForm").addEventListener("submit", e => {
    e.preventDefault();
    const url = $("#siteUrl").value.trim();
    if (!url) return toast(t("site_need"), "error", 3000);
    siteResult = null;
    act("check_site", { url });
  });
  const rb = $("#siteRepair");
  if (rb) rb.addEventListener("click", () => {
    const url = $("#siteUrl").value.trim();
    if (!url) return toast(t("site_need"), "error", 3000);
    if (!S.connected) return toast(t("repair_need_vpn"), "error", 4000);
    repairResult = null;
    siteResult = null;
    act("repair_site", { url });
  });
}

function vpnSuspectsHtml() {
  const list = S.vpn_suspects || [];
  if (!list.length) return "";
  return `<div class="site-res"><b>${t("vpn_sus_title")}</b><span class="hint">${t("vpn_sus_hint")}</span>
    ${list.map(x => `<div class="t-row sus-row">
      <span class="list-text"><b>${esc(x.site)}</b><span>${esc(x.detail || "")}${x.detail ? ". " : ""}${esc(cap(ago(x.at, "ago")))}</span></span>
      <div class="auto-actions"><button class="btn btn-small btn-primary" data-act="vpn_site_direct" data-site="${esc(x.site)}">${t("vpn_site_direct")}</button>
        <button class="btn btn-small btn-ghost" data-act="vpn_site_keep" data-site="${esc(x.site)}">${t("vpn_site_keep")}</button></div></div>`).join("")}</div>`;
}

function repairHtml() {
  const r = repairResult;
  if (!r) return "";
  const state = x => {
    if (x.fix === "proxy") return `<span class="state ok">${t("repair_fix_vpn")}</span>`;
    if (x.fix === "direct") return `<span class="state ok">${t("repair_fix_direct")}</span>`;
    if (x.fix === "server") return `<span class="state ok">${esc(t("repair_fix_server", { name: x.server || "?" }))}</span>`;
    const cls = { ok: "ok", small: "ok", stall: "slow", fail: "blocked", blocked: "blocked", skip: "skip" }[x.state] || "skip";
    return `<span class="state ${cls}">${esc(t("repair_s_" + (x.state || "skip")))}</span>`;
  };
  const rows = r.hosts.map(x => `<div class="t-row repair-row">
      <span class="site-host" title="${esc(x.host)}">${esc(x.host)}</span>
      <span class="list-text"><b>${state(x)}</b><span>${esc(x.detail || "")}</span></span>
      ${x.state === "blocked" && x.route === "adblock" ? `<button class="btn btn-small" data-act="ads_allow" data-host="${esc(x.host)}">${t("ads_allow_btn")}</button>` : "<span></span>"}
    </div>`).join("");
  return `<div class="site-res stack" style="gap:8px"><div><b>${esc(r.site)}</b> — ${esc(r.verdict)}</div>
    <div class="table site-table repair-table">${rows}</div></div>`;
}

/* ---------- свои правила ---------- */

const countLines = v => v.split("\n").filter(l => l.trim() && !l.trim().startsWith("#")).length;
const LIST_KEYS = { proxy_list: "list_proxy", direct_list: "list_direct", block_list: "list_block" };

/* Основной домен сайта (как в программе): music.yandex.ru → yandex.ru, bbc.co.uk остаётся как есть */
function mainDomain(host) {
  host = String(host || "").toLowerCase();
  if (/^[\d.]+$/.test(host) || host.includes(":")) return host;
  const l = host.split(".").filter(Boolean);
  if (l.length <= 2) return l.join(".");
  const short = ["co", "com", "net", "org", "gov", "edu", "ac", "msk", "spb"];
  return l.slice(l[l.length - 1].length === 2 && short.includes(l[l.length - 2]) ? -3 : -2).join(".");
}

let rawListsOpen = false;
let sitePrefill = "";

function siteRows() {
  const r = S.routes || { sites: [], sites_total: 0 };
  if (!r.sites.length) return `<div class="empty-row">${t("sites_empty")}</div>`;
  const rows = r.sites.map(x => `<div class="t-row site-row">
      <span class="site-host" title="${esc(x.site)}">${esc(x.site)}</span>
      <div class="route-cell"><select class="input route-select" data-site="${esc(x.site)}" data-cur="${esc(x.value)}" aria-label="${esc(t("col_route"))}: ${esc(x.site)}">
        ${routeOptions(x.value, t("route_default"))}</select>
        ${x.warn ? `<span class="route-warn" title="${esc(x.warn)}">${icon("alert", "inline-ico")}${esc(x.warn)}</span>` : ""}</div>
      <button class="icon-btn" data-act="site_remove" data-host="${esc(x.site)}" aria-label="${esc(t("site_remove"))}: ${esc(x.site)}" title="${esc(t("site_remove"))}">${icon("trash")}</button>
    </div>`).join("");
  const more = r.sites_total > r.sites.length ? `<div class="empty-row">${t("sites_more", { n: r.sites_total - r.sites.length })}</div>` : "";
  return rows + more;
}

function autoRows() {
  const a = S.auto || { enabled: false, items: [], total: 0, checked: 0, queue: 0 };
  if (!a.items.length) return `<div class="empty-row">${t(a.enabled ? "auto_empty" : "auto_off")}</div>`;
  const rows = a.items.slice(0, 60).map(x => `<div class="t-row auto-row">
      <span class="site-host" title="${esc(x.site)}">${esc(x.site)}</span>
      <span class="list-text auto-via"><b>${esc(x.via === "server" ? t("auto_via_server", { name: x.server || "?" }) : t("auto_via_vpn"))}</b>
        <span>${esc(x.why || "")}${x.why ? ". " : ""}${esc(cap(ago(x.at, "ago")))}</span></span>
      <div class="auto-actions">
        <button class="btn btn-small" data-act="auto_pin" data-site="${esc(x.site)}" title="${esc(t("auto_pin_hint"))}">${icon("check")}${t("auto_pin")}</button>
        <button class="icon-btn" data-act="auto_forget" data-site="${esc(x.site)}" aria-label="${esc(t("auto_forget"))}: ${esc(x.site)}" title="${esc(t("auto_forget_hint"))}">${icon("trash")}</button>
      </div></div>`).join("");
  const more = a.items.length > 60 ? `<div class="empty-row">${t("auto_more", { n: a.total - 60 })}</div>` : "";
  return rows + more;
}

function appRows() {
  const A = S.apps || { items: [] };
  if (!A.items.length) return `<div class="empty-row">${t("apps_empty")}</div>`;
  return A.items.map(x => `<div class="t-row app-row">
      <span class="site-host" title="${esc(x.name)}">${esc(x.title)}</span>
      <div class="route-cell"><select class="input route-select" data-app="${esc(x.name)}" data-cur="${esc(x.value)}" aria-label="${esc(t("col_route"))}: ${esc(x.title)}">
        ${routeOptions(x.value, null)}</select>
        ${x.warn ? `<span class="route-warn" title="${esc(x.warn)}">${icon("alert", "inline-ico")}${esc(x.warn)}</span>` : ""}</div>
      <div class="auto-actions">
        ${x.preset ? (busy("app_pick") ? stopBtn() : `<button class="btn btn-small" data-act="app_pick" data-name="${esc(x.name)}" title="${esc(t("apps_pick_hint"))}" ${S.busy ? "disabled" : ""}>${t("apps_pick")}</button>`) : ""}
        <button class="icon-btn" data-act="app_remove" data-name="${esc(x.name)}" aria-label="${esc(t("site_remove"))}: ${esc(x.title)}" title="${esc(t("site_remove"))}">${icon("trash")}</button>
      </div></div>`).join("");
}

function appOptions() {
  const A = S.apps || { running: [], presets: [] };
  const have = new Set((A.items || []).map(x => x.name));
  const seen = new Set();
  const opt = (v, label) => { if (have.has(v) || seen.has(v)) return ""; seen.add(v); return `<option value="${esc(v)}">${esc(label)}</option>`; };
  return (A.running || []).map(x => opt(x.name, x.title === x.name ? `${x.name} (${t("apps_now")})` : `${x.title} (${t("apps_now")})`)).join("")
    + (A.presets || []).map(x => opt(x.name, x.title)).join("");
}

const TORRENT = ["direct", "proxy", "block"];

const autoMeta = () => {
  const a = S.auto || {};
  const parts = [t("auto_meta", { n: a.total || 0, c: a.checked || 0 })];
  if (a.queue) parts.push(t("auto_queue", { n: a.queue }));
  return parts.join(". ");
};

function proxyCheck(p) {
  const c = p.check || {};
  if (busy("proxy") && proxyChecking === p.id) return `<span class="state skip">${t("s_checking")}</span>`;
  if (!c.at) return `<span class="hint">${t("px_unchecked")}</span>`;
  if (!c.ok) return `<span class="state blocked" title="${esc(c.error || "")}">${t("px_fail")}${c.error ? `: ${esc(c.error)}` : ""}</span>`;
  const tk = c.tiktok ? `<span class="state ${esc(c.tiktok)}">TikTok: ${t("s_" + c.tiktok)}</span>` : "";
  return `<span class="state ok">${t("px_ok")}</span>
    <span class="px-ip">${esc(c.ip)}</span><span>${cc(c.loc)} ${esc(countryName(c.loc))}</span>${tk}
    <button class="link-btn" data-act="proxy_report" data-id="${esc(p.id)}">${t("px_report")}</button>`;
}

function proxyRows() {
  const list = (S.routes && S.routes.proxies) || [];
  if (!list.length) return `<div class="empty-row">${t("px_empty")}</div>`;
  return list.map(p => `<div class="px-row">
      <div class="list-text"><b>${esc(p.name || p.label)}</b>
        <span>${[p.name ? esc(p.label) : "", p.auth ? t("px_auth") : "", p.used.length ? esc(t("px_used", { list: p.used.map(svcName).join(", ") })) : ""]
          .filter(Boolean).join(". ")}</span></div>
      <div class="px-check">${proxyCheck(p)}</div>
      <label class="px-chain"><span>${t("px_chain")}</span>${sw(p.chain, `data-act="proxy_chain" data-id="${esc(p.id)}" aria-label="${esc(t("px_chain"))}"`)}</label>
      <div class="px-actions">
        <button class="btn btn-small" data-act="proxy_check" data-id="${esc(p.id)}" ${S.busy ? "disabled" : ""}>${t("px_check")}</button>
        <button class="icon-btn" data-act="proxy_remove" data-id="${esc(p.id)}" aria-label="${esc(t("px_remove"))}" title="${esc(t("px_remove"))}">${icon("trash")}</button>
      </div></div>`).join("");
}

function renderRoutes(full) {
  const st = S.settings;
  if (!full && $("#routesPage")) {
    $("#geoText").textContent = geoText();
    for (const key of Object.keys(LIST_KEYS)) {
      const ta = $(`#${key}`);
      if (ta && !dirty.has(key) && document.activeElement !== ta) {
        ta.value = st[key] || "";
        $(`#${key}_n`).textContent = t("lines_n", { n: countLines(ta.value) });
      }
    }
    const focus = document.activeElement;
    if (!(focus && $("#siteRows").contains(focus) && focus.matches("select"))) $("#siteRows").innerHTML = siteRows();
    $("#proxyRows").innerHTML = proxyRows();
    if ($("#appRows")) {
      const f = document.activeElement;
      if (!(f && $("#appRows").contains(f) && f.matches("select"))) $("#appRows").innerHTML = appRows();
      if (f !== $("#appName")) $("#appList").innerHTML = appOptions();
      $("#torrentSeg").querySelectorAll("[data-v]").forEach(b => b.setAttribute("aria-checked", String((S.apps || {}).torrent === b.dataset.v)));
    }
    if ($("#autoRows")) {
      $("#autoRows").innerHTML = autoRows();
      $("#autoMeta").textContent = autoMeta();
      const a = S.auto || {};
      $("#autoSwitch").setAttribute("aria-checked", String(!!a.enabled));
      $("#autoClear").hidden = !a.total;
    }
    const via = $("#siteRouteVia");
    if (via && document.activeElement !== via) { const v = via.value; via.innerHTML = routeOptions(v, null); }
    return;
  }
  const list = key => `<div><h3>${t(LIST_KEYS[key])}<small><span id="${key}_n">${t("lines_n", { n: countLines(st[key] || "") })}</span>
        <button class="link-btn" data-act="reset_list" data-list="${key}">${t("clear")}</button></small></h3>
      <textarea class="input" id="${key}" rows="10" spellcheck="false">${esc(st[key] || "")}</textarea></div>`;
  $("#page").innerHTML = `<div id="routesPage" class="stack">
    ${details("head-routes", esc(t("routes_intro")), esc(t("routes_intro_more")))}
    <section class="card">
      <div class="card-head"><b>${t("sites_title")}</b><span class="hint">${t("sites_hint")}</span></div>
      <form class="route-add" id="siteRouteForm">
        <input class="input" id="siteRouteHost" placeholder="tiktok.com" autocomplete="off" spellcheck="false" aria-label="${t("sites_title")}" value="${esc(sitePrefill)}">
        <select class="input" id="siteRouteVia" aria-label="${t("col_route")}">${routeOptions("proxy", null)}</select>
        <button class="btn btn-primary" type="submit">${t("site_add")}</button>
      </form>
      <div class="table site-table" id="siteRows">${siteRows()}</div>
    </section>
    <section class="card" id="appsCard">
      <div class="card-head"><b>${t("apps_title")}</b><span class="hint">${t("apps_hint")}</span></div>
      <form class="route-add" id="appForm">
        <input class="input" id="appName" list="appList" placeholder="${esc(t("apps_ph"))}" autocomplete="off" spellcheck="false" aria-label="${esc(t("apps_title"))}">
        <datalist id="appList">${appOptions()}</datalist>
        <select class="input" id="appVia" aria-label="${t("col_route")}">${routeOptions("proxy", null)}</select>
        <button class="btn btn-primary" type="submit">${t("site_add")}</button>
      </form>
      <div class="table site-table" id="appRows">${appRows()}</div>
      <div class="feat-row">
        <span class="list-text"><b>${t("torrent_title")}</b><span>${t("torrent_hint")}</span></span>
        <span class="seg" role="radiogroup" aria-label="${esc(t("torrent_title"))}" id="torrentSeg">${TORRENT.map(v =>
          `<button type="button" role="radio" aria-checked="${(S.apps || {}).torrent === v}" data-act="torrent_set" data-v="${v}">${t("torrent_" + v)}</button>`).join("")}</span>
      </div>
    </section>
    <section class="card" id="autoCard">
      <div class="feat-row first">
        <span class="list-text"><b>${t("auto_title")}</b><span>${t("auto_hint")}</span><span class="hint" id="autoMeta">${esc(autoMeta())}</span></span>
        ${sw((S.auto || {}).enabled, `id="autoSwitch" data-act="auto_toggle" aria-label="${esc(t("auto_title"))}"`)}
      </div>
      <div class="table auto-table" id="autoRows">${autoRows()}</div>
      <div class="toolbar auto-toolbar"><span class="grow"></span>
        <button class="btn btn-ghost btn-small btn-danger" id="autoClear" data-act="auto_clear" ${(S.auto || {}).total ? "" : "hidden"}>${icon("trash")}${t("auto_clear")}</button></div>
    </section>
    <section class="card" id="proxyCard">
      <div class="card-head"><b>${t("px_title")}</b><span class="hint">${t("px_hint")}</span></div>
      <div id="proxyRows">${proxyRows()}</div>
      <form class="proxy-form" id="proxyForm">
        <input class="input" id="pxUrl" placeholder="socks5://login:password@1.2.3.4:1080" autocomplete="off" spellcheck="false" aria-label="${t("px_url")}">
        <input class="input" id="pxName" placeholder="${t("px_name_ph")}" autocomplete="off" aria-label="${t("px_name")}">
        <select class="input" id="pxType" aria-label="${t("px_type")}">
          <option value="auto">${t("px_type_auto")}</option><option value="socks">SOCKS5</option><option value="http">HTTP</option></select>
        <label class="check-row px-chain-new"><input type="checkbox" id="pxChain" checked><span><b>${t("px_chain")}</b><small>${t("px_chain_hint")}</small></span></label>
        <button class="btn btn-primary" type="submit">${t("px_add")}</button>
      </form>
    </section>
    <details class="card raw-lists" id="rawLists" ${rawListsOpen ? "open" : ""}>
      <summary><b>${t("raw_lists")}</b><span class="hint">${t("raw_lists_hint")}</span></summary>
      <div class="raw-body stack">
        ${details("head-routes-raw", esc(t("routes_short")), esc(t("own_rules_more")))}
        <div class="lists">${list("proxy_list")}${list("direct_list")}${list("block_list")}</div>
        <div class="toolbar">
          <button class="btn btn-ghost btn-danger" data-act="reset_rules">${icon("trash")}${t("reset_rules")}</button>
          <span class="grow"></span><button class="btn btn-primary" data-act="save_routing">${t("save_apply")}</button></div>
      </div>
    </details>
    <section class="card"><div class="upd-row"><span class="list-text geo-text"><b>${t("geo_title")}</b><span id="geoText">${esc(geoText())}</span></span>
      <button class="btn btn-small" data-act="update_geo">${icon("refresh")}${t("update_lists")}</button></div></section>
  </div>`;
  sitePrefill = "";
  for (const key of Object.keys(LIST_KEYS)) {
    $(`#${key}`).addEventListener("input", e => { dirty.add(key); $(`#${key}_n`).textContent = t("lines_n", { n: countLines(e.target.value) }); });
  }
  $("#rawLists").addEventListener("toggle", e => { rawListsOpen = e.target.open; });
  $("#siteRouteForm").addEventListener("submit", async e => {
    e.preventDefault();
    const host = $("#siteRouteHost").value.trim();
    const target = $("#siteRouteVia").value;
    if (!host) return toast(t("site_need"), "error", 3000);
    if (target === "custom:new") return focusProxyForm();
    const r = await act("route_site", { host, target, exact: true });
    if (r.ok) { $("#siteRouteHost").value = ""; toast(t("site_added", { host: r.result.join(", ") }), "ok", 3000); scheduleRefresh(50); }
  });
  $("#appForm").addEventListener("submit", async e => {
    e.preventDefault();
    const name = $("#appName").value.trim();
    const target = $("#appVia").value;
    if (!name) return toast(t("apps_need"), "error", 3000);
    if (target === "custom:new") return focusProxyForm();
    const r = await act("app_route", { name, target });
    if (r.ok) { $("#appName").value = ""; toast(t("apps_added", { name: r.result }), "ok", 3000); scheduleRefresh(50); }
  });
  act("apps_scan", {}, { quiet: true }).then(r => { if (r.ok) scheduleRefresh(30); });
  $("#proxyForm").addEventListener("submit", async e => {
    e.preventDefault();
    const url = $("#pxUrl").value.trim();
    if (!url) return toast(t("px_need"), "error", 3000);
    const r = await act("add_proxy", { url, name: $("#pxName").value.trim(), type: $("#pxType").value, chain: $("#pxChain").checked });
    if (r.ok) {
      $("#pxUrl").value = ""; $("#pxName").value = "";
      proxyChecking = r.result.id;
      toast(t("px_added"), "ok", 3000);
      scheduleRefresh(50);
    }
  });
  if ($("#siteRouteHost").value) $("#siteRouteHost").focus();
}

let proxyChecking = "";

function focusProxyForm() {
  const go2 = () => { const el = $("#pxUrl"); if (el) { el.scrollIntoView({ block: "center" }); el.focus(); } };
  if (page !== "routes") { go("routes"); setTimeout(go2, 30); } else go2();
}

async function saveRouting() {
  const args = { mode: S.mode, ru_direct: S.ru_direct };
  for (const key of Object.keys(LIST_KEYS)) args[key] = $(`#${key}`).value;
  const r = await act("save_routing", args);
  if (r.ok) {
    dirty.clear();
    if (r.result.bad && r.result.bad.length) toast(t("bad_lines") + "\n" + r.result.bad.slice(0, 10).join("\n"), "error");
    else toast(S.connected ? t("routes_saved") : t("routes_saved_off"), "ok");
  }
}

/* ---------- трафик ---------- */

async function loadConnections() {
  try { connections = await api("/api/connections"); } catch { return; }
  if (page === "traffic") renderTrafficRows();
}

function trafficTotalsHtml() {
  const tt = S.traffic_totals || { today: {}, month: {} };
  const cell = (label, x) => `<div class="tt-cell"><span class="hint">${label}</span>
    <b>${bytes((x.vpn || 0) + (x.direct || 0))}</b>
    <span class="hint">${esc(t("tt_split", { v: bytes(x.vpn || 0), d: bytes(x.direct || 0) }))}</span></div>`;
  return `<section class="card card-pad tt-card" id="ttCard">${cell(t("tt_today"), tt.today || {})}${cell(t("tt_month"), tt.month || {})}</section>`;
}

function renderTraffic() {
  $("#page").innerHTML = `
    ${trafficTotalsHtml()}
    ${details("head-traffic", esc(t("traffic_short")), esc(t("traffic_more")))}
    <div class="toolbar">
      <div class="chips" role="group">
        ${[["all", "f_all"], ["proxy", "f_proxy"], ["direct", "f_direct"], ["block", "f_block"]].map(([k, l]) =>
          `<button data-tf="${k}" aria-pressed="${trafficFilter === k}">${t(l)}</button>`).join("")}
      </div>
      <label class="search">${icon("search")}<input id="tq" type="search" placeholder="${t("search_site")}" value="${esc(trafficQuery)}" aria-label="${t("search_site")}"></label>
      <span class="grow"></span>
      <button class="btn btn-small btn-ghost" data-act="clear_traffic">${t("clear_list")}</button>
    </div>
    <div class="table"><div class="t-row conn-row t-head"><span>${t("col_site")}</span><span>${t("col_where")}</span><span>${t("col_conns")}</span><span>${t("col_last")}</span><span></span></div>
      <div id="trafficRows"></div></div>`;
  $("#tq").addEventListener("input", e => { trafficQuery = e.target.value; renderTrafficRows(); });
  renderTrafficRows();
}

function renderTrafficRows() {
  const box = $("#trafficRows");
  if (!box) return;
  const tc = $("#ttCard");
  if (tc) tc.outerHTML = trafficTotalsHtml();
  const q = trafficQuery.toLowerCase();
  const list = connections.filter(c => (trafficFilter === "all" || c.route === trafficFilter || (routeGroup(c.route) === "proxy" && trafficFilter === "proxy"))
    && (!q || c.host.toLowerCase().includes(q)));
  if (!list.length) {
    box.innerHTML = `<div class="empty-row">${S.connected ? t("traffic_empty") : t("traffic_off")}</div>`;
    return;
  }
  box.innerHTML = list.slice(0, 400).map(c => `<div class="t-row conn-row">
      <span class="conn-host" title="${esc(c.host)}:${c.port}">${esc(c.host)}</span>
      <span class="route ${esc(routeGroup(c.route))}" ${c.rule ? `title="${t("own_rule")}"` : ""}>${routeLabel(c.route)}${c.rule ? " ★" : ""}</span>
      <span class="conn-num">${c.count}</span><span class="conn-num">${esc(c.last)}</span>
      <button class="icon-btn conn-menu" data-act="conn_menu" data-host="${esc(c.host)}" data-route="${esc(routeGroup(c.route))}" data-rule="${c.rule ? 1 : ""}"
        aria-label="${esc(t("site_more"))}: ${esc(c.host)}" title="${esc(t("site_more"))}">${icon("more")}</button>
    </div>`).join("");
}

/* ---------- обновления ---------- */

const HOURS = {
  auto_update_hours: [0, 1, 3, 6, 12, 24],
  geo_update_hours: [0, 12, 24, 72, 168],
  core_update_hours: [0, 24, 168, 720],
  dpi_update_hours: [0, 12, 24, 72, 168],
};

function hoursSelect(key, disabled = false) {
  const cur = Number(S.settings[key] ?? 0);
  const opts = HOURS[key].includes(cur) ? HOURS[key] : HOURS[key].concat(cur).sort((a, b) => a - b);
  return `<select class="input select-auto" data-hours="${key}" aria-label="${t("how_often")}" style="height:32px" ${disabled ? "disabled" : ""}>
    ${opts.map(v => `<option value="${v}" ${cur === v ? "selected" : ""}>${t("h" + v) !== "h" + v ? t("h" + v) : t("h_n", { n: v })}</option>`).join("")}</select>`;
}

function dpiUpdText() {
  const d = S.dpi;
  if (!d || !d.supported) return t("dpi_st_win");
  const v = [d.zapret.version && `zapret ${d.zapret.version}`, d.byedpi.version && `ByeDPI ${d.byedpi.version}`].filter(Boolean);
  return v.length ? v.join(", ") : t("dpi_not_installed_both");
}

function appUpdateCard() {
  const a = S.app_update || {};
  const info = a.info || {};
  let state;
  if (!a.configured) state = t("au_not_configured");
  else if (info.staged) state = t("au_staged", { v: info.version });
  else if (info.version) state = t("au_available", { v: info.version });
  else state = a.checked ? t("au_latest", { when: ago(a.checked).replace(/^\S+\s/, "") }) : t("au_never");
  const btn = !a.configured ? "" : info.staged
    ? `<button class="btn btn-small btn-primary" data-act="restart_app">${icon("refresh")}${t("au_restart")}</button>`
    : busy("app_update") ? stopBtn() : `<button class="btn btn-small" data-act="app_update_check">${icon("refresh")}${t("au_check")}</button>`;
  return `<section class="card"><div class="upd-row">
      <span class="list-ico">${icon("download")}</span>
      <span class="list-text"><b>${t("au_title", { v: a.version || S.version })}</b><span style="display:block">${esc(state)}</span>
        ${a.just_updated ? `<span class="hint" style="display:block">${esc(t("au_just", { v: a.just_updated }))}</span>` : ""}
        ${info.notes ? `<span class="hint" style="display:block">${esc(info.notes)}</span>` : ""}</span>
      ${btn}</div></section>`;
}

function renderUpdates() {
  const u = S.updates;
  const subs = S.subs.filter(s => s.id !== "manual");
  const subState = !subs.length ? t("u_no_subs") : u.last_sub_update ? t("u_updated", { when: ago(u.last_sub_update).replace(/^\S+\s/, "") }) : t("u_not_yet");
  const core = u.xray ? t("u_core_v", { v: u.xray }) : u.xray_exists ? t("u_core_ok") : t("u_core_none");
  const row = (ic, name, state, key, actName, disabled = false, soon = false) => `<div class="upd-row">
      <span class="list-ico">${icon(ic)}</span>
      <span class="list-text"><b>${name}</b> ${soon ? soonBadge() : ""}<span style="display:block">${esc(state)}</span></span>
      ${hoursSelect(key, soon)}
      ${actName ? `<button class="btn btn-small" data-act="${actName}" ${disabled ? "disabled" : ""}>${icon("refresh")}${t("update_now")}</button>` : ""}</div>`;
  $("#page").innerHTML = `
    ${details("head-updates", esc(t("updates_short")), esc(t("updates_more")))}
    <section class="card">
      ${row("vpn", t("u_servers"), subState, "auto_update_hours", "update_sub", !subs.length)}
      ${row("routes", t("u_lists"), geoText(), "geo_update_hours", "update_geo")}
      ${row("bolt", t("u_core"), core, "core_update_hours", "update_xray")}
      ${row("key", t("u_dpi"), dpiUpdText(), "dpi_update_hours", "update_dpi", !S.dpi || !S.dpi.supported)}
    </section>
    ${appUpdateCard()}
    <div class="toolbar">
      ${busy("update") ? stopBtn() : `<button class="btn btn-primary" data-act="update_all">${icon("updates")}${t("u_update_all")}</button>`}
    </div>`;
}

/* ---------- настройки ---------- */

/* ---------- состояние: данные, способ, защита — простым языком и с подробностями ---------- */

/* Каждая проверка: {cls: good|warn|bad|idle, value: коротко, label} */
function healthItems() {
  const L = S.ladder || {};
  const on = S.connected;
  const awgOn = !!(S.awg && S.awg.active);
  const d = L.data;
  let data;
  if (awgOn) data = { cls: "idle", value: t("h_awg_data") };
  else if (!on) data = { cls: "idle", value: t("h_off") };
  else if (L.step || S.conn_busy) data = { cls: "warn", value: t("h_searching") };
  else if (!d || d.inconclusive) data = { cls: "idle", value: t("h_not_checked") };
  else data = d.ok ? { cls: "good", value: t("h_data_ok") } : { cls: "bad", value: t("h_data_bad") };
  const way = awgOn ? { cls: "good", value: "AmneziaWG" } : !on ? { cls: "idle", value: "—" } : { cls: "good", value: L.way || t("h_way_plain") };
  const c = S.certs;
  const certs = !c ? { cls: "idle", value: t("h_not_checked") } : c.errors ? { cls: "bad", value: t("h_certs_bad") }
    : c.warnings && !c.acked ? { cls: "warn", value: t("h_certs_warn") } : { cls: "good", value: t("h_certs_ok") };
  const l = S.leaks;
  const leaks = !l ? { cls: "idle", value: t("h_not_checked") } : l.errors ? { cls: "bad", value: t("h_leaks_bad") }
    : l.warnings ? { cls: "warn", value: t("h_leaks_warn") } : { cls: "good", value: t("h_leaks_ok") };
  return [Object.assign(data, { label: t("h_data") }), Object.assign(way, { label: t("h_way") }),
    Object.assign(certs, { label: t("h_certs") }), Object.assign(leaks, { label: t("h_leaks") })];
}

/* Общий вывод: хорошо, есть замечания, есть проблема или VPN выключен. */
function healthVerdict() {
  const items = healthItems();
  const errs = (S.problems || []).filter(p => p.level === "error");
  const bad = items.filter(i => i.cls === "bad").length + errs.length;
  const warn = items.filter(i => i.cls === "warn" && i !== items[0]).length
    + (S.problems || []).filter(p => p.level !== "error").length;
  if (bad) return { cls: "bad", title: t("v_bad"), sub: errs[0] ? errs[0].title : t("v_bad_sub"), short: t("v_bad_short") };
  if (warn) return { cls: "warn", title: t("v_warn", { n: warn }), sub: t("v_warn_sub"), short: t("v_warn_short", { n: warn }) };
  if (S.awg && S.awg.active && !S.connected) return { cls: "good", title: t("v_good"), sub: t("v_awg_sub"), short: t("v_good_short") };
  if (!S.connected) return { cls: "idle", title: t("v_off"), sub: t("v_off_sub"), short: t("v_off_short") };
  return { cls: "good", title: t("v_good"), sub: t("v_good_sub"), short: t("v_good_short") };
}

function healthStrip() {
  return `<button type="button" class="health" data-nav="status" aria-label="${esc(t("nav_status"))}">
    ${healthItems().map(i => `<span class="h-cell"><small>${esc(i.label)}</small><b><i class="dot ${i.cls}"></i>${esc(i.value)}</b></span>`).join("")}
  </button>`;
}

function kv(label, value, extra = "") {
  return `<div class="kv-row"><dt>${esc(label)}</dt><dd>${value}</dd>${extra ? `<div class="kv-act">${extra}</div>` : "<span></span>"}</div>`;
}

function renderStatus(full) {
  const L = S.ladder || {};
  const on = S.connected;
  const v = healthVerdict();
  const items = healthItems();
  const cur = S.current;
  const live = S.live || {};
  const dot = cls => `<i class="dot ${cls}"></i>`;
  const d = L.data;
  const dataText = !on ? esc(t("h_off")) : !d || d.inconclusive ? esc(t(d ? "st_data_na" : "h_not_checked"))
    : `${dot(d.ok ? "good" : "bad")}${esc(d.ok ? t("st_data_ok", { ms: d.ms }) : t("st_data_bad", { e: d.error || "" }))}<span class="hint"> · ${esc(ago(d.at, "ago"))}</span>`;
  const net = S.net || {};
  const netName = net.kind === "wifi" ? t("st_net_wifi", { ssid: net.ssid || "?" }) : net.kind === "wired" ? t("st_net_wired") : t("st_net_other");
  const netMem = S.settings.net_memory === false ? t("st_mem_off") : L.net_known ? t("st_mem_known") : t("st_mem_new");
  const last = L.last ? `${dot(L.last.ok ? "good" : "bad")}${esc(cap(L.last.text))}<span class="hint"> · ${esc(ago(L.last.at, "ago"))}</span>` : `<span class="hint">${esc(t("st_last_none"))}</span>`;
  const c = S.certs, l = S.leaks;
  const certSum = items[2], leakSum = items[3];
  const busyAny = !!S.busy || !!S.conn_busy;
  const page = $("#page");
  const openC = $("#stCerts") && $("#stCerts").open, openL = $("#stLeaks") && $("#stLeaks").open, openP = $("#stCheck") && $("#stCheck").open;
  const openJ = $("#stJournal") && $("#stJournal").open;
  page.innerHTML = `<div class="stack status-page" id="statusPage">
    <section class="verdict ${v.cls}">
      <span class="verdict-mark">${icon(v.cls === "good" ? "check" : v.cls === "idle" ? "power" : "alert")}</span>
      <div class="verdict-text"><h2>${esc(v.title)}</h2><p>${esc(v.sub)}</p></div>
      ${busy("health") ? stopBtn() : `<button class="btn btn-primary" data-act="health_check" ${busyAny ? "disabled" : ""}>${icon("refresh")}${t("st_check_all")}</button>`}
    </section>
    <section class="card status-card"><h3>${t("st_conn")}</h3><dl class="kv">
      ${kv(t("st_server"), on && cur ? `${cc(cur.cc)} <b>${esc(cur.name)}</b> <span class="hint">${esc(cur.protocol)}</span>` : `<span class="hint">${esc(t("h_off"))}</span>`)}
      ${kv(t("h_way"), on ? (L.way ? `${dot("good")}${esc(L.way)} <span class="hint">— ${esc(t("st_way_picked"))}</span>` : `${dot("good")}${esc(t("st_way_plain"))}`) : "—")}
      ${kv(t("h_data"), dataText, on ? (S.conn_busy ? "" : `<button class="btn btn-small" data-act="data_check">${t("st_data_check")}</button>`) : "")}
      ${kv(t("stat_ping"), on && live.ping != null ? `${live.ping} ${esc(t("ms"))}` : "—")}
      ${kv(t("st_backup"), S.backup && on ? esc(S.backup.name) : `<span class="hint">${esc(S.settings.autopilot ? t("st_backup_none") : t("off"))}</span>`)}
      ${kv(t("st_net"), `${esc(netName)} <span class="hint">· ${esc(netMem)}</span>`)}
      ${kv(t("st_last"), last)}
      ${kv(t("st_journal"), journalSummary())}
    </dl>
      <details class="st-more" id="stJournal" ${openJ ? "open" : ""}><summary>${t("journal_title")}</summary><div id="journalBox">${journalHtml()}</div></details>
    </section>
    <section class="card status-card"><h3>${t("st_protect")}</h3><dl class="kv">
      ${kv(t("h_certs"), `${dot(certSum.cls)}${esc(certSum.value)}${c && c.time ? `<span class="hint"> · ${esc(ago(c.time, "ago"))}</span>` : ""}`)}
      ${kv(t("h_leaks"), `${dot(leakSum.cls)}${esc(leakSum.value)}`)}
      ${kv(t("i_kill_switch_name"), S.settings.kill_switch ? `${dot("good")}${esc(t("on"))}` : `${dot("idle")}${esc(t("off"))}`)}
      ${kv(t("i_dns_name"), S.settings.dns_encrypted ? `${dot("good")}${esc(t("on"))}` : `${dot("idle")}${esc(t("off"))}`)}
    </dl>
      <details class="st-more" id="stCerts" ${openC ? "open" : ""}><summary>${t("certs_title")}</summary><div id="certBox"></div></details>
      <details class="st-more" id="stLeaks" ${openL ? "open" : ""}><summary>${t("leaks_title")}</summary><div id="leakBox"></div></details>
    </section>
    <section class="card status-card"><h3>${t("st_program")}</h3><dl class="kv">
      ${kv(t("nav_errors"), S.errors_count ? `${dot("warn")}${esc(t("errors_n", { n: S.errors_count }))}` : `${dot("good")}${esc(t("st_errors_none"))}`,
        `<button class="btn btn-small" data-nav="errors">${t("st_open")}</button>`)}
      ${kv(t("selfcheck"), checkReport ? esc(t("selfcheck_done", { e: checkReport.errors, w: checkReport.warnings })) : `<span class="hint">${esc(t("st_check_hint"))}</span>`)}
    </dl>
      <details class="st-more" id="stCheck" ${openP || busy("check") ? "open" : ""}><summary>${t("selfcheck")}</summary><div id="checkBox"></div></details>
    </section>
  </div>`;
  renderCheckBox();
}

/* Журнал подключения: кто (ты или автоматика) и почему подключал, переключал и отключал VPN. */
function journalSummary() {
  const J = S.journal || {};
  const n = (J.auto_hour || 0);
  return `${`<i class="dot ${n >= 3 ? "warn" : "good"}"></i>`}${esc(t("journal_auto", { h: J.auto_hour || 0, d: J.auto_day || 0 }))}`;
}

function journalHtml() {
  const items = (S.journal && S.journal.items) || [];
  if (!items.length) return `<p class="hint">${esc(t("journal_none"))}</p>`;
  const time = ts => new Date(ts * 1000).toLocaleString(LANG === "en" ? "en-GB" : "ru-RU",
    { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return `<p class="hint">${esc(t("journal_hint"))}</p><ul class="journal">${items.map(it => `<li class="j-${esc(it.kind)}">
    <time>${esc(time(it.t))}</time><b>${esc(it.kind_text)}</b>${it.server ? `<span>${esc(it.server)}</span>` : ""}
    <span class="hint">${esc(it.who === "user" ? t("journal_you") : it.who)}${it.why ? ` — ${esc(it.why)}` : ""}</span></li>`).join("")}</ul>`;
}

function renderSettings(full) {
  if (!full && $("#settingsPage")) return;
  const st = S.settings;
  const inp = (key, title, hint) => `<label class="field"><span>${title}</span><input class="input" data-set="${key}" value="${esc(st[key])}"><small class="hint">${hint}</small></label>`;
  $("#page").innerHTML = `<div id="settingsPage" class="stack">
    <section class="card">
      <div class="upd-row"><span class="list-text"><b>${t("language")}</b></span>
        <div class="seg" role="radiogroup" aria-label="${t("language")}"><button data-lang="ru" aria-checked="${LANG === "ru"}" role="radio">Русский</button><button data-lang="en" aria-checked="${LANG === "en"}" role="radio">English</button></div></div>
      <div class="upd-row"><span class="list-text"><b>${t("theme")}</b></span>
        <div class="seg" role="radiogroup" aria-label="${t("theme")}"><button data-theme-set="dark" aria-checked="${S.theme !== "light"}" role="radio">${t("theme_dark_short")}</button><button data-theme-set="light" aria-checked="${S.theme === "light"}" role="radio">${t("theme_light_short")}</button></div></div>
    </section>
    <h2 class="section-title">${t("privacy_title")}</h2>
    <section class="card card-pad stack" style="gap:10px" id="pinBox">${pinBoxHtml()}</section>
    <h2 class="section-title">${t("ping_check")}</h2>
    <section class="card"><div class="form-grid">${inp("ping_host", t("ping_host"), t("ping_host_hint"))}${inp("ping_path", t("ping_path"), "/generate_204")}
      ${inp("user_agent", t("ua"), t("ua_hint"))}</div></section>
    <div class="toolbar"><span class="grow"></span><button class="btn btn-primary" data-act="save_settings">${t("save")}</button></div>
    <h2 class="section-title">${t("happ_title")}</h2>
    <section class="card card-pad">${details("happ", esc(t("happ_short")), esc(t("happ_more")))}
      <div class="toolbar" style="margin-top:10px">
        <button class="btn btn-small" data-act="happ_open">${t("happ_send")}</button>
        <button class="btn btn-small" data-act="happ_copy">${icon("copy")}${t("happ_copy")}</button>
        <button class="btn btn-small" data-act="top_copy">${icon("copy")}${t("happ_top")}</button>
      </div></section>
    <h2 class="section-title">${t("program")}</h2>
    <section class="card card-pad"><div class="toolbar">
      <span class="hint grow">${esc(t("version_v", { v: S.version }))}. ${t("program_text")}</span>
      <button class="btn btn-small btn-ghost" data-act="open_folder">${icon("folder")}${t("open_folder")}</button>
      <button class="btn btn-small btn-danger" data-act="quit">${icon("exit")}${t("quit")}</button>
    </div></section>
  </div>`;
  bindPinBox();
}

function pinBoxHtml() {
  const p = S.pin || {};
  const sec = S.secure || {};
  const minutes = [0, 5, 15, 60];
  return `<div><b>${t("pin_title")}</b><p class="hint" style="margin:2px 0 0">${t(p.set ? "pin_on" : "pin_off")}</p></div>
    <form class="pin-form" id="pinForm">
      ${p.set ? `<input class="input" id="pinOld" type="password" inputmode="numeric" maxlength="12" placeholder="${esc(t("pin_old"))}" autocomplete="off">` : ""}
      <input class="input" id="pinNew" type="password" inputmode="numeric" maxlength="12" placeholder="${esc(t(p.set ? "pin_new2" : "pin_new"))}" autocomplete="off">
      <select class="input" id="pinMinutes" aria-label="${esc(t("pin_lock_after"))}">${minutes.map(m =>
        `<option value="${m}" ${m === (p.minutes || 0) ? "selected" : ""}>${esc(m ? t("pin_after_min", { n: m }) : t("pin_after_close"))}</option>`).join("")}</select>
      <button class="btn btn-primary btn-small" type="submit">${t(p.set ? "pin_change" : "pin_enable")}</button>
      ${p.set ? `<button class="btn btn-ghost btn-small btn-danger" type="button" id="pinRemove">${t("pin_remove")}</button>` : ""}
    </form>
    <div class="feat-row" style="padding:10px 0 0;border-top:1px solid var(--line)">
      <span class="list-text"><b>${t("secure_title")}</b><span>${t(sec.available ? "secure_text" : "secure_na")}</span></span>
      ${sw(sec.on && sec.available, `data-act="secure_toggle" aria-label="${esc(t("secure_title"))}"`, !sec.available)}
    </div>`;
}

function bindPinBox() {
  const f = $("#pinForm");
  if (!f) return;
  f.addEventListener("submit", async e => {
    e.preventDefault();
    const r = await act("pin_set", { pin: $("#pinNew").value, old: $("#pinOld") ? $("#pinOld").value : "", minutes: +$("#pinMinutes").value });
    if (r.ok) { toast(t("pin_saved"), "ok", 3000); scheduleRefresh(30); setTimeout(() => { $("#pinBox").innerHTML = pinBoxHtml(); bindPinBox(); }, 300); }
  });
  const rm = $("#pinRemove");
  if (rm) rm.addEventListener("click", async () => {
    const r = await act("pin_remove", { old: $("#pinOld").value });
    if (r.ok) { toast(t("pin_removed"), "ok", 3000); scheduleRefresh(30); setTimeout(() => { $("#pinBox").innerHTML = pinBoxHtml(); bindPinBox(); }, 300); }
  });
}

function renderLeakBox() {
  const box = $("#leakBox");
  if (!box) return;
  const r = S.leaks;
  const lvl = x => x.state === "ok" ? "ok" : x.state === "info" ? "info" : x.state === "warn" ? "warn" : "error";
  const res = r ? `<div class="check-summary">${esc(r.errors || r.warnings ? t("leaks_found", { e: r.errors, w: r.warnings }) : t("leaks_none"))}</div>
    <div class="check-list">${r.items.map(i => `<div class="check-item ${lvl(i)}">
      ${icon(i.state === "ok" ? "check" : i.state === "info" ? "layers" : "alert")}<span><b>${esc(i.title)}</b>${i.detail ? ` <span class="hint">${esc(i.detail)}</span>` : ""}${i.fix ? `<br><span class="hint">${esc(i.fix)}</span>` : ""}</span></div>`).join("")}</div>` : "";
  box.innerHTML = `<p class="hint" style="margin:0">${esc(t("leaks_short"))}</p>
    <div class="toolbar" style="margin-top:10px">
      ${busy("leaks") ? stopBtn(true) : `<button class="btn btn-small btn-primary" data-act="leak_test" ${S.connected ? "" : "disabled"}>${icon("lock")}${t("leaks_run")}</button>`}
      ${S.connected ? "" : `<span class="hint">${t("leaks_need_vpn")}</span>`}
    </div>${res}`;
}

function renderCertBox() {
  const box = $("#certBox");
  if (!box) return;
  const r = S.certs;
  const lvl = x => x.state === "ok" ? "ok" : x.state === "info" ? "info" : x.state === "warn" ? "warn" : "error";
  const res = r ? `<div class="check-summary">${esc(r.errors || r.warnings ? t("certs_found", { e: r.errors, w: r.warnings }) : t("certs_none"))}</div>
    <div class="check-list">${r.items.map(i => `<div class="check-item ${lvl(i)}">
      ${icon(i.state === "ok" ? "check" : i.state === "info" ? "layers" : "alert")}<span><b>${esc(i.title)}</b>${i.detail ? ` <span class="hint">${esc(i.detail)}</span>` : ""}${i.fix ? `<br><span class="hint">${esc(i.fix)}</span>` : ""}</span></div>`).join("")}</div>` : "";
  const ack = r && r.russian_root && r.russian_root.length && !r.acked
    ? `<button class="btn btn-small" data-act="cert_ack">${icon("check")}${t("certs_ack")}</button>` : "";
  box.innerHTML = `<p class="hint" style="margin:0">${esc(t("certs_short"))}</p>
    <div class="toolbar" style="margin-top:10px">
      ${busy("certs") ? stopBtn(true) : `<button class="btn btn-small btn-primary" data-act="cert_check">${icon("lock")}${t("certs_run")}</button>`}
      ${ack}
    </div>${res}`;
}

function renderCheckBox() {
  renderLeakBox();
  renderCertBox();
  const box = $("#checkBox");
  if (!box) return;
  let res = "";
  if (checkReport) {
    res = `<div class="check-summary">${esc(t("selfcheck_done", { e: checkReport.errors, w: checkReport.warnings }))}</div>
      ${checkReport.file ? `<p class="hint" style="margin:4px 0 8px">${esc(t("selfcheck_send"))}</p>` : ""}
      <div class="check-list">${checkReport.items.map(i => `<div class="check-item ${i.level}">
        ${icon(i.level === "ok" ? "check" : i.level === "info" ? "layers" : "alert")}<span><b>${esc(i.title)}</b>${i.detail ? ` <span class="hint">${esc(i.detail)}</span>` : ""}</span></div>`).join("")}</div>`;
  }
  box.innerHTML = `<p class="hint" style="margin:0">${esc(t("selfcheck_short"))}</p>
    <div class="toolbar" style="margin-top:10px">
      ${busy("check") ? stopBtn(true) : `<button class="btn btn-small btn-primary" data-act="run_check">${icon("check")}${t("selfcheck_run")}</button>`}
      ${checkReport && checkReport.file ? `<button class="btn btn-small" data-act="show_report">${icon("folder")}${t("selfcheck_show")}</button>` : ""}
      ${checkReport ? `<button class="btn btn-small" data-act="copy_check">${icon("copy")}${t("selfcheck_copy")}</button>` : ""}
    </div>${res}`;
}

async function saveSettings() {
  const args = {};
  $$("[data-set]").forEach(el => { args[el.dataset.set] = el.value; });
  const r = await act("save_settings", args);
  if (r.ok) { dirty.clear(); toast(t("settings_saved"), "ok", 3000); }
}

/* ---------- советы ---------- */

function renderTips() {
  const st0 = S.settings;
  const auth = st0.lan_auth && st0.lan_pass;
  const v = { socks: st0.socks_port, http: st0.http_port, ip: S.lan_ip || t("lan_ip_unknown"), lport: st0.lan_socks_port,
    cred: auth ? t("lan_cred", { user: st0.lan_user || "pult", pass: st0.lan_pass }) : t("lan_cred_none") };
  const tips = [1, 2, 3, 4, 5, 6, 7].map(n => `<div class="tip"><b>${esc(t(`tip${n}_t`))}</b><span>${esc(t(`tip${n}_x`))}</span></div>`).join("");
  const steps = (prefix, n) => `<ol class="steps">${Array.from({ length: n }, (_, i) => `<li>${esc(t(`${prefix}${i + 1}`, v))}</li>`).join("")}</ol>`;
  $("#page").innerHTML = `
    <section class="list-card"><h2>${t("tips_title")}</h2><div class="tips">${tips}</div></section>
    <section class="list-card"><h2>${t("tg_title")}</h2>
      <div class="card-pad stack" style="gap:14px">
        <div><b>${t("tg_way1")}</b> <span class="soon rec">${t("recommended")}</span>${steps("tg1_", 3)}</div>
        <div><b>${t("tg_way2")}</b>${steps("tg2_", 3)}
          <div class="toolbar" style="margin-top:8px">
            <button class="btn btn-small btn-primary" data-act="telegram_proxy">${t("tg_auto_btn")}</button>
            <button class="btn btn-small" data-copy="127.0.0.1:${v.socks}">${icon("copy")}${t("copy_addr")}</button>
          </div>
          <p class="hint" style="margin:8px 0 0">${esc(t("tg2_note"))}</p></div>
        <div><b>${t("tg_way3")}</b>${steps("tg3_", 3)}
          <div class="toolbar" style="margin-top:8px"><button class="btn btn-small" data-nav="share">${icon("qr")}${t("tg_qr_btn")}</button></div></div>
        <button class="link-btn" data-nav="manual" style="align-self:flex-start">${t("open_manual")}</button>
      </div>
    </section>`;
}

/* ---------- данные для подключения ---------- */

function renderManual(full) {
  const st = S.settings;
  if (!full && $("#manualPage") && dirty.size) return;
  const copyRow = (label, value, hint = "") => `<div class="upd-row">
      <span class="list-text"><b>${label}</b><span style="display:block">${esc(hint)}</span></span>
      <code class="addr">${esc(value)}</code>
      <button class="btn btn-small" data-copy="${esc(value)}">${icon("copy")}${t("copy")}</button></div>`;
  const lan = st.allow_lan && S.lan_ip;
  $("#page").innerHTML = `<div id="manualPage" class="stack">
    <p class="page-intro">${t("manual_intro")}</p>
    <section class="card">
      ${copyRow("SOCKS5", `127.0.0.1:${st.socks_port}`, t("socks_for"))}
      ${copyRow("HTTP", `127.0.0.1:${st.http_port}`, t("http_for"))}
      <div class="upd-row"><span class="list-text"><b>${t("login_pass")}</b><span style="display:block">${t("login_pass_none")}</span></span></div>
      <div class="upd-row"><span class="list-text"><b>${t("sysproxy_state")}</b><span style="display:block">${
        st.system_proxy ? esc(t("sysproxy_state_on", { port: st.http_port })) : t("sysproxy_state_off")}</span></span></div>
    </section>
    <h2 class="section-title">${t("lan_title")}</h2>
    <section class="card">
      <div class="upd-row"><span class="list-text"><b>${t("i_lan_name")}</b><span style="display:block">${t("i_lan_desc")}</span></span>
        ${sw(st.allow_lan, `data-fset="lan" aria-label="${esc(t("i_lan_name"))}"`)}</div>
      ${lan ? copyRow("SOCKS5", `${S.lan_ip}:${st.lan_socks_port}`, t("lan_for")) + copyRow("HTTP", `${S.lan_ip}:${st.lan_http_port}`, t("lan_for")) : ""}
      ${st.allow_lan ? `<div class="upd-row"><span class="list-text"><b>${t("lan_auth")}</b><span style="display:block">${t("lan_auth_hint")}</span></span>
        ${sw(st.lan_auth, `data-act="lan_auth" aria-label="${esc(t("lan_auth"))}"`)}</div>` : ""}
      ${st.allow_lan && st.lan_auth && st.lan_pass ? copyRow(t("lan_user"), st.lan_user || "pult") + `<div class="upd-row">
        <span class="list-text"><b>${t("lan_pass")}</b></span><code class="addr">${esc(st.lan_pass)}</code>
        <button class="btn btn-small" data-copy="${esc(st.lan_pass)}">${icon("copy")}${t("copy")}</button>
        <button class="btn btn-small" data-act="lan_new_pass">${icon("refresh")}${t("lan_new_pass")}</button></div>` : ""}
    </section>
    ${hotspotSection()}
    <h2 class="section-title">${t("ports_title")}</h2>
    <section class="card"><div class="form-grid">
      <label class="field"><span>${t("socks_port")}</span><input class="input" data-set="socks_port" value="${esc(st.socks_port)}"></label>
      <label class="field"><span>${t("http_port")}</span><input class="input" data-set="http_port" value="${esc(st.http_port)}"></label>
      <label class="field"><span>${t("lan_socks_port")}</span><input class="input" data-set="lan_socks_port" value="${esc(st.lan_socks_port)}"></label>
      <label class="field"><span>${t("lan_http_port")}</span><input class="input" data-set="lan_http_port" value="${esc(st.lan_http_port)}"></label>
    </div><div class="toolbar" style="padding:0 16px 14px"><span class="hint grow">${t("ports_hint")}</span>
      <button class="btn btn-small btn-primary" data-act="save_settings">${t("save")}</button></div></section>
    <button class="link-btn" data-nav="tips" style="align-self:flex-start">${t("tg_howto")}</button>
  </div>`;
  $$("#manualPage [data-set]").forEach(el => el.addEventListener("input", () => dirty.add(el.dataset.set)));
  loadWifiQr();
}

/* Раздача VPN по Wi-Fi: своя сеть компьютера, в режиме TUN устройства идут через VPN без настроек. */
function hotspotSection() {
  const h = S.hotspot;
  if (!h || !h.supported) return "";
  const busyNow = S.busy && S.busy_kind === "hotspot";
  const tunOn = S.tun && S.tun.active;
  let body;
  if (h.on) {
    body = `<div class="hs-grid">
        <div class="stack" style="gap:6px">
          <div class="hs-row"><span>${t("hs_network")}</span><code class="addr">${esc(h.ssid)}</code><button class="btn btn-small" data-copy="${esc(h.ssid)}">${icon("copy")}</button></div>
          <div class="hs-row"><span>${t("hs_password")}</span><code class="addr">${esc(h.password)}</code><button class="btn btn-small" data-copy="${esc(h.password)}">${icon("copy")}</button></div>
          <p class="hint">${t("hs_clients", { n: h.clients })}</p>
          <p class="hint">${h.via_tun ? t("hs_via_tun") : t("hs_no_tun", { port: S.settings.lan_socks_port })}</p>
          <div class="toolbar">${busyNow ? stopBtn() : `<button class="btn" data-act="hotspot_stop" ${S.busy ? "disabled" : ""}>${t("hs_stop")}</button>`}</div>
        </div>
        <div class="qr-img hs-qr" id="wifiQr"></div>
      </div>`;
  } else {
    body = `<p class="hint">${t("hs_text")}</p>
      ${!tunOn ? `<p class="hint">${icon("alert", "inline-ico")}${t("hs_tun_hint")}</p>` : ""}
      ${h.error ? `<p class="hint warn-text">${esc(h.error)}</p>` : ""}
      <div class="toolbar">${busyNow ? stopBtn() : `<button class="btn btn-primary" data-act="hotspot_start" ${S.busy ? "disabled" : ""}>${icon("wifi")}${t("hs_start")}</button>`}</div>`;
  }
  return `<h2 class="section-title">${t("hs_title")}</h2>
    <section class="card card-pad stack" style="gap:10px">${body}</section>`;
}

async function loadWifiQr() {
  const box = $("#wifiQr");
  if (!box || box.dataset.ssid === S.hotspot.ssid) return;
  const r = await act("share_qr", { id: "wifi" }, { quiet: true });
  if (r.ok && $("#wifiQr")) {
    $("#wifiQr").innerHTML = r.result.svg;
    $("#wifiQr").dataset.ssid = S.hotspot.ssid;
  }
}

/* ---------- журнал ---------- */

/* ---------- журнал ошибок ---------- */

let errorsData = null;
async function loadErrors() {
  const r = await act("errors_list");
  if (r.ok) { errorsData = r.result; if (page === "errors") renderErrors(); }
}

function renderErrors() {
  const d = errorsData;
  const items = d ? d.items : [];
  const off = items.length ? "" : "disabled";
  const kind = k => k === "crash" ? "blocked" : k === "check" ? "slow" : "region";
  $("#page").innerHTML = `<div class="stack" id="errorsPage">
    <p class="page-intro">${t("err_intro")}</p>
    <div class="toolbar">
      <button class="btn btn-small btn-primary" data-act="err_report" ${off}>${icon(d && d.repo ? "globe" : "copy")}${t(d && d.repo ? "err_report" : "err_copy")}</button>
      ${d && d.repo ? `<button class="btn btn-small" data-act="err_copy" ${off}>${icon("copy")}${t("err_copy")}</button>` : ""}
      <button class="btn btn-small btn-ghost" data-act="err_file" ${off}>${icon("folder")}${t("err_file")}</button>
      <span class="grow"></span>
      <button class="btn btn-small btn-ghost" data-act="err_clear" ${off}>${icon("trash")}${t("err_clear")}</button>
    </div>
    ${d && !d.repo ? `<section class="card card-pad stack" style="gap:8px"><b>${t("err_repo")}</b><span class="hint">${t("err_repo_hint")}</span>
      <div class="toolbar"><input class="input grow" id="errRepo" placeholder="https://github.com/name/vedomyj-vpn" aria-label="${esc(t("err_repo"))}">
        <button class="btn btn-small" data-act="err_repo_save">${t("save")}</button></div></section>`
      : d ? `<p class="hint">${esc(t("err_repo_is", { r: d.repo }))} <button class="link-btn" data-act="err_repo_change">${t("err_repo_change")}</button></p>` : ""}
    ${!d ? `<p class="hint">${t("loading")}</p>` : !items.length
      ? `<section class="card card-pad"><p class="hint" style="margin:0">${t("err_empty")}</p></section>`
      : `<section class="table">${items.map(e => `<div class="t-row err-row">
          <div class="err-head"><span class="state ${kind(e.kind)}">${esc(t("err_kind_" + e.kind))}</span>
            <b>${esc(e.title)}</b>${e.count > 1 ? `<span class="hint">×${e.count}</span>` : ""}</div>
          <div class="hint">${esc(cap(ago(e.last, "ago")))} · ${esc(t("version_v", { v: e.version }))}${e.where ? " · " + esc(e.where) : ""}</div>
          ${e.detail ? `<div class="hint err-detail">${esc(e.detail)}</div>` : ""}
          ${e.trace ? `<details><summary class="hint">${t("err_trace")}</summary><pre class="log err-trace">${esc(e.trace)}</pre></details>` : ""}
        </div>`).join("")}</section>`}
  </div>`;
}

async function errReport(open) {
  const r = await act("errors_issue", { open });
  if (!r.ok) return;
  const x = r.result;
  if (open && x.url) toast(t("err_opened"), "ok", 4000);
  else copy(`${x.title}\n\n${x.body}`, t("err_copied"));
}

async function loadLogs() {
  try { logs = await api("/api/logs"); } catch { return; }
  if (page === "log") renderLog();
}

function renderLog() {
  if (!$("#logBox")) {
    $("#page").innerHTML = `<div class="toolbar"><button class="btn btn-small" data-act="copy_log">${icon("copy")}${t("copy_log")}</button>
      <button class="btn btn-small btn-ghost" data-act="open_folder">${icon("folder")}${t("open_folder")}</button></div>
      <pre class="log" id="logBox"></pre>`;
  }
  const box = $("#logBox");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.innerHTML = logs.slice(-500).map(l => `<b>${esc(l.slice(0, 8))}</b>${esc(l.slice(8))}`).join("\n");
  if (atBottom) box.scrollTop = box.scrollHeight;
}

/* ---------- общий рендер ---------- */

function renderBusy() {
  const bar = $("#busy");
  const text = S.busy || S.conn_busy || "";
  bar.hidden = !text;
  document.body.classList.toggle("is-busy", !!text);
  $("#busyText").textContent = text ? text + "…" : "";
  $("#busyStop").textContent = t("stop_short");
}

function renderLock() {
  renderTheme();
  $("#backBtn").hidden = true; $("#moreBtn").hidden = true; $("#problemsBtn").hidden = true;
  $("#brand").hidden = false; $("#topTitle").hidden = true;
  if ($("#lockForm")) return;
  $("#page").innerHTML = `<div class="lock-screen">
    <img class="lock-mark" src="/icons/monogram.svg" alt="" width="56" height="56">
    <h2>${t("lock_title")}</h2>
    <p class="hint">${t("lock_hint")}</p>
    <form id="lockForm" class="lock-form">
      <input class="input" id="lockPin" type="password" inputmode="numeric" autocomplete="off" maxlength="12" aria-label="${esc(t("lock_title"))}" autofocus>
      <button class="btn btn-primary" type="submit">${t("lock_open")}</button>
    </form>
    ${S && S.pin_wait ? `<p class="hint">${esc(t("lock_wait", { n: S.pin_wait }))}</p>` : ""}
  </div>`;
  $("#lockForm").addEventListener("submit", async e => {
    e.preventDefault();
    const r = await act("unlock", { pin: $("#lockPin").value });
    if (r.ok) { $("#page").innerHTML = ""; scheduleRefresh(0); }
    else { $("#lockPin").value = ""; $("#lockPin").focus(); }
  });
  setTimeout(() => $("#lockPin") && $("#lockPin").focus(), 50);
}

function renderPage(full = false) {
  if (!S) return;
  queueMicrotask(syncPopover);
  if (S.locked) return renderLock();
  renderTheme();
  renderTop();
  renderBusy();
  renderProblemsBadge();
  switch (page) {
    case "home": return renderHome(full);
    case "more": return renderMore();
    case "features": return full || !$(".feat-row") ? renderFeatures() : null;
    case "zapret": return renderZapret(full);
    case "byedpi": return renderByedpi(full);
    case "services":
      if (!full && document.activeElement && (document.activeElement.id === "siteUrl" || document.activeElement.matches("select"))) return null;
      return renderServices();
    case "routes": return renderRoutes(full);
    case "ads": return renderAds(full);
    case "traffic": return full ? renderTraffic() : renderTrafficRows();
    case "updates": return renderUpdates();
    case "settings": return renderSettings(full);
    case "log": return renderLog();
    case "tips": return full ? renderTips() : null;
    case "manual": return renderManual(full);
    case "share": return renderShare(full);
    case "errors": return full || !$("#errorsPage") ? renderErrors() : null;
    case "status": return renderStatus(full);
    default: page = "home"; return renderHome(true);
  }
}

let refreshTimer = null;
let refreshing = false;
async function refresh() {
  if (refreshing) { scheduleRefresh(); return; }
  refreshing = true;
  try {
    const wasLocked = S && S.locked;
    S = await api("/api/state");
    if (wasLocked && !S.locked) { renderPage(true); refreshing = false; return; }
    if (S.lang && S.lang !== LANG) {
      LANG = S.lang;
      localStorage.setItem("pult-lang", LANG);
      renderPage(true);
    } else {
      renderPage(false);
    }
  } catch { /* связь пропала — разберётся обработчик событий */ }
  refreshing = false;
}
function scheduleRefresh(delay = 150) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, delay);
}

/* ---------- добавление подписки и серверов ---------- */

function startAddSub(url, name, modal) {
  pendingAdd = { error: null, modal: !!modal };
  act("add_sub", { url, name }, { quiet: !!modal }).then(r => {
    if (!r.ok) {
      if (modal) showModalError(r.error);
      pendingAdd = null;
    } else if (modal) {
      $("#mOk").disabled = true;
      $("#mOk").textContent = t("loading");
    }
  });
}

function showModalError(text) {
  const err = $("#mErr");
  if (!err) return toast(text, "error");
  err.textContent = text;
  err.hidden = false;
  const ok = $("#mOk");
  if (ok) { ok.disabled = false; ok.textContent = t("add"); }
}

function modalAddSub() {
  openModal(`<h2>${t("add_sub_title")}</h2><p class="modal-text">${t("add_sub_text")}</p>
    <div class="stack">
      <label class="field"><span>${t("link")}</span>
        <span class="row-gap"><input class="input" id="mUrl" placeholder="https://…" autocomplete="off">
        <button class="btn" id="mPaste" type="button">${t("paste")}</button></span></label>
      <label class="field"><span>${t("sub_name_opt")}</span><input class="input" id="mName" placeholder="${t("sub_name_ph")}"></label>
      <div class="modal-error" id="mErr" hidden></div>
    </div>
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button><button class="btn btn-primary" id="mOk">${t("add")}</button></div>`, m => {
    const submit = () => {
      const url = $("#mUrl").value.trim();
      if (!url) return showModalError(t("need_link"));
      $("#mErr").hidden = true;
      startAddSub(url, $("#mName").value.trim(), true);
    };
    m.querySelector("#mOk").addEventListener("click", submit);
    m.querySelector("#mUrl").addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
    m.querySelector("#mPaste").addEventListener("click", async () => {
      try { $("#mUrl").value = (await navigator.clipboard.readText()).trim(); }
      catch { $("#mUrl").focus(); toast(t("press_ctrl_v"), "info", 3000); }
    });
  });
}

function modalAddServer() {
  openModal(`<h2>${t("add_server_title")}</h2><p class="modal-text">${t("add_server_text")}</p>
    <div class="stack"><textarea class="input" id="mLinks" rows="6" spellcheck="false" placeholder="vless://…"></textarea>
      <div class="modal-error" id="mErr" hidden></div></div>
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button><button class="btn btn-primary" id="mOk">${t("add")}</button></div>`, m => {
    m.querySelector("#mOk").addEventListener("click", async () => {
      const text = $("#mLinks").value.trim();
      if (!text) return showModalError(t("need_links"));
      const r = await act("add_servers", { text }, { quiet: true });
      if (!r.ok) return showModalError(r.error);
      closeModal();
      toast(r.result ? t("servers_added", { n: r.result }) : t("servers_exist"), "ok");
      if (r.result) act("test", { sub: "manual" }, { quiet: true });
    });
  });
}

function modalRename(sub) {
  openModal(`<h2>${t("rename_title")}</h2>
    <div class="stack"><input class="input" id="mName" value="${esc(sub.name)}"></div>
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button><button class="btn btn-primary" id="mOk">${t("save")}</button></div>`, m => {
    const save = () => act("rename_sub", { id: sub.id, name: $("#mName").value }).then(() => closeModal());
    m.querySelector("#mOk").addEventListener("click", save);
    m.querySelector("#mName").addEventListener("keydown", e => { if (e.key === "Enter") save(); });
  });
}

/* ---------- меню ---------- */

function subMenu(anchor, id) {
  const sub = S.subs.find(s => s.id === id);
  if (!sub) return;
  const items = [];
  if (id !== "manual") items.push({ icon: "refresh", label: t("m_update"), run: () => act("update_sub", { id }) });
  items.push({ icon: "signal", label: t("m_ping"), run: () => act("test", { sub: id }) });
  if (id === "manual") {
    items.push({ icon: "plus", label: t("add_server"), run: modalAddServer });
  } else {
    items.push({ icon: "edit", label: t("m_rename"), run: () => modalRename(sub) });
    items.push({ icon: "copy", label: t("m_copy_sub"), run: async () => {
      const r = await act("sub_link", { id });
      if (r.ok) copy(r.result, t("link_copied"));
    } });
    items.push({ icon: "qr", label: t("m_qr"), run: () => qrModal("sub:" + id, t("qr_sub", { name: sub.name }), "sub") });
    items.push({ icon: "trash", label: t("m_remove_sub"), danger: true, run: async () => {
      if (await confirmModal(t("remove_sub_q"), t("remove_sub_text", { name: sub.name }), t("delete")))
        act("remove_sub", { id }).then(r => r.ok && toast(t("sub_removed"), "ok"));
    } });
  }
  openMenu(anchor, items);
}

function serverMenu(anchor, key) {
  const s = S.servers.find(x => x.key === key);
  if (!s) return;
  const items = [];
  if (s.supported) items.push({ icon: "power", label: s.current ? t("m_reconnect") : t("m_connect"), run: () => act("connect", { key }) });
  if (s.supported && s.kind !== "awg") items.push({ icon: "signal", label: t("m_ping"), run: () => act("test", { key }) });
  if (s.kind === "awg") items.push({ icon: "copy", label: t("m_awg_conf"), run: async () => {
    const r = await act("awg_conf", { key });
    if (r.ok) copy(r.result, t("awg_conf_copied"));
  } });
  if (s.has_link) items.push({ icon: "copy", label: t("m_copy_link"), run: async () => {
    const r = await act("server_link", { key });
    if (r.ok) copy(r.result, t("link_copied"));
  } });
  if (s.has_link) items.push({ icon: "qr", label: t("m_qr"), run: () => qrModal("srv:" + key, t("qr_server", { name: s.name }), "server") });
  if (s.sub === "manual") items.push({ icon: "trash", label: t("m_remove_server"), danger: true, run: () => act("remove_server", { key }) });
  openMenu(anchor, items);
}

/* Меню сайта на странице «Трафик»: быстрые варианты и переход к полному выбору (сервер, свой прокси, обход). */
function connMenu(anchor) {
  const { host, route, rule } = anchor.dataset;
  const to = target => () => act("route_site", { host, target }).then(r => {
    if (r.ok) { toast(`${r.result.join(", ")}: ${routeLabel(target)}`, "ok", 3000); loadConnections(); }
  });
  const items = [];
  if (route !== "proxy") items.push({ icon: "lock", label: t("to_vpn"), run: to("proxy") });
  if (route !== "direct") items.push({ icon: "globe", label: t("to_direct"), run: to("direct") });
  if (route !== "block") items.push({ icon: "block", label: t("to_block"), danger: true, run: to("block") });
  items.push({ icon: "sliders", label: t("site_more"), run: () => { sitePrefill = mainDomain(host); go("routes"); } });
  if (rule) items.push({ icon: "refresh", label: t("reset"), run: () => ACTIONS.reset_site(anchor) });
  openMenu(anchor, items);
}

function sortMenu(anchor) {
  const set = v => () => { S.sort = v; act("set_ui", { sort: v }, { quiet: true }); renderSubs(); };
  const mark = v => (S.sort || "ping") === v ? "check" : "";
  openMenu(anchor, [
    { icon: mark("ping"), label: t("sort_ping"), run: set("ping") },
    { icon: mark("name"), label: t("sort_name"), run: set("name") },
    { icon: mark("source"), label: t("sort_source"), run: set("source") },
  ]);
}

function addMenu(anchor) {
  openMenu(anchor, [
    { icon: "plus", label: t("add_sub"), run: modalAddSub },
    { icon: "plus", label: t("add_server"), run: modalAddServer },
    { icon: "vpn", label: t("add_vps"), run: modalVps },
  ]);
}

/* Свой сервер (VPS): ссылка из панели сервера или поля для Shadowsocks / SOCKS5. */
function modalVps() {
  let kind = "setup";
  const fields = () => kind === "setup"
    ? `<p class="modal-text" style="margin:0">${t("vw_text")}</p>
      <div class="form-grid" style="padding:0">
        <label class="field"><span>${t("vw_host")}</span><input class="input" id="wHost" placeholder="203.0.113.10" autocomplete="off" spellcheck="false"></label>
        <label class="field"><span>${t("vw_port")}</span><input class="input" id="wPort" value="22" inputmode="numeric"></label>
        <label class="field"><span>${t("vw_user")}</span><input class="input" id="wUser" value="root" autocomplete="off" spellcheck="false"></label>
        <label class="field"><span>${t("vps_name")}</span><input class="input" id="wName" placeholder="${t("vps_default_name")}"></label>
      </div>
      <p class="hint" style="margin:0">${icon("lock", "inline-ico soft")}${t("vw_pass_note")}</p>
      <p class="hint" style="margin:0">${t("vw_replace_note")}</p>`
    : kind === "link"
    ? `<label class="field"><span>${t("link")}</span><textarea class="input" id="vLink" rows="3" spellcheck="false" placeholder="vless://… trojan://… ss://…"></textarea></label>`
    : `<div class="form-grid" style="padding:0">
        <label class="field"><span>${t("vps_host")}</span><input class="input" id="vHost" placeholder="203.0.113.10"></label>
        <label class="field"><span>${t("vps_port")}</span><input class="input" id="vPort" placeholder="${kind === "ss" ? "8388" : "1080"}" inputmode="numeric"></label>
        ${kind === "ss" ? `<label class="field"><span>${t("vps_method")}</span><select class="input" id="vMethod">
            ${["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"].map(m => `<option>${m}</option>`).join("")}</select></label>`
          : `<label class="field"><span>${t("vps_user")}</span><input class="input" id="vUser" autocomplete="off"></label>`}
        <label class="field"><span>${t("vps_pass")}</span><input class="input" id="vPass" autocomplete="off"></label>
        <label class="field" style="grid-column:1/-1"><span>${t("vps_name")}</span><input class="input" id="vName" placeholder="${t("vps_name_ph")}"></label>
      </div>`;
  const body = () => `<h2>${t("vps_title")}</h2>
    ${kind === "setup" ? "" : `<p class="modal-text">${t("vps_text")}</p>`}
    <div class="seg" role="radiogroup" aria-label="${t("vps_title")}">
      ${[["setup", t("vw_tab")], ["link", t("vps_tab_link")], ["ss", "Shadowsocks"], ["socks", "SOCKS5"]].map(([k, l]) =>
        `<button type="button" role="radio" data-vkind="${k}" aria-checked="${kind === k}">${l}</button>`).join("")}
    </div>
    <div class="stack">${fields()}<div class="modal-error" id="mErr" hidden></div></div>
    ${kind === "setup" ? details("vw-help", esc(t("vw_help_short")), esc(t("vw_help"))) : details("vps-help", esc(t("vps_help_short")), esc(t("vps_help")))}
    <div class="modal-actions"><button class="btn btn-ghost" data-close>${t("cancel")}</button><button class="btn btn-primary" id="mOk">${kind === "setup" ? t("vw_go") : t("add")}</button></div>`;
  const mount = m => {
    m.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", closeModal));
    m.querySelectorAll("[data-vkind]").forEach(b => b.addEventListener("click", () => {
      kind = b.dataset.vkind;
      m.innerHTML = body();
      mount(m);
    }));
    m.querySelector("#mOk").addEventListener("click", async () => {
      if (kind === "setup") {
        const host = $("#wHost").value.trim();
        if (!host) return showModalError(t("vw_need_host"));
        const r = await act("vps_setup", { host, port: $("#wPort").value.trim() || "22", user: $("#wUser").value.trim() || "root",
          name: $("#wName").value.trim() }, { quiet: true });
        if (!r.ok) return showModalError(r.error);
        closeModal();
        toast(t("vw_started"), "info", 12000);
        return;
      }
      let link = "";
      if (kind === "link") {
        link = $("#vLink").value.trim();
      } else {
        const host = $("#vHost").value.trim(), port = $("#vPort").value.trim();
        const name = encodeURIComponent($("#vName").value.trim() || t("vps_default_name"));
        if (!host || !/^\d{1,5}$/.test(port)) return showModalError(t("vps_need"));
        const hp = host.includes(":") && !host.startsWith("[") ? `[${host}]:${port}` : `${host}:${port}`;
        const pass = $("#vPass").value;
        if (kind === "ss") {
          if (!pass) return showModalError(t("vps_need_pass"));
          link = `ss://${encodeURIComponent($("#vMethod").value + ":" + pass)}@${hp}#${name}`;
        } else {
          const user = $("#vUser").value.trim();
          const cred = user ? `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@` : "";
          link = `socks://${cred}${hp}#${name}`;
        }
      }
      if (!link) return showModalError(t("need_links"));
      const r = await act("add_servers", { text: link }, { quiet: true });
      if (!r.ok) return showModalError(r.error);
      closeModal();
      toast(r.result ? t("vps_added") : t("servers_exist"), "ok");
      if (r.result) act("test", { sub: "manual" }, { quiet: true });
    });
  };
  const m = openModal(body(), null, "modal-wide");
  mount(m);
}

/* ---------- обработка нажатий ---------- */

const LIST_NAMES = () => ({ proxy_list: t("list_proxy"), direct_list: t("list_direct"), block_list: t("list_block") });

function setTheme(next) {
  if (S) S.theme = next;
  localStorage.setItem("pult-theme", next);
  renderTheme();
  act("set_ui", { theme: next }, { quiet: true });
  if (page === "more" || page === "settings") renderPage(true);
}

const ACTIONS = {
  auto: () => act("auto"),
  toggle: () => act("toggle"),
  stop: () => act("stop").then(() => toast(t("stopped_after"), "info", 2500)),
  test: el => act("test", { sub: el.dataset.sub || "", key: el.dataset.key || "" }),
  speed_top: () => act("speed_top"),
  update_sub: el => act("update_sub", { id: el.dataset.id || "" }),
  add_sub_modal: modalAddSub,
  add_server_modal: modalAddServer,
  vps_modal: () => modalVps(),
  tile_set: el => {
    const key = el.dataset.key;
    const v = !S.settings[key];
    S.settings[key] = v;
    renderHero();
    act("save_settings", { [key]: v }).then(r => r.ok && toast(t(`${key}_${v ? "on" : "off"}`), "ok", 3500));
  },
  tile_autopilot: () => {
    const v = !S.settings.autopilot;
    S.settings.autopilot = v;
    renderHero();
    act("save_settings", { autopilot: v }).then(r => r.ok && toast(v ? t("autopilot_on") : t("autopilot_off"), "ok", 3000));
  },
  dpi_toggle: el => {
    const which = el.dataset.which;
    const v = el.getAttribute("aria-checked") !== "true";
    el.setAttribute("aria-checked", String(v));
    const z = which === "zapret" ? v : dpiOn("zapret");
    const b = which === "byedpi" ? v : dpiOn("byedpi");
    const args = DPI_COMBOS[z && b ? (S.dpi.byedpi.role === "main" ? "bz" : "zb") : z ? "z" : b ? "b" : "off"];
    act("set_dpi", args).then(() => scheduleRefresh(50));
  },
  dpi_site: el => {
    const v = el.getAttribute("aria-checked") !== "true";
    el.setAttribute("aria-checked", String(v));
    act("set_dpi", { [el.dataset.key]: v }).then(() => scheduleRefresh(50));
  },
  dpi_custom_save: () => act("set_dpi", { dpi_custom: $("#dpiCustom").value }).then(r => {
    if (!r.ok) return;
    toast(t("saved"), "ok", 2500);
    $("#dpiCustom").blur();
    scheduleRefresh(50);
  }),
  dpi_rest: el => {
    const id = el.dataset.id;
    openDetails.has(id) ? openDetails.delete(id) : openDetails.add(id);
    renderPage(true);
  },
  export_settings: exportSettings,
  hotspot_start: () => act("hotspot_start"),
  hotspot_stop: () => act("hotspot_stop"),
  lan_auth: el => {
    const v = el.getAttribute("aria-checked") !== "true";
    el.setAttribute("aria-checked", String(v));
    act("save_settings", { lan_auth: v }).then(r => r.ok && scheduleRefresh(50));
  },
  lan_new_pass: () => act("lan_new_pass").then(r => r.ok && toast(t("lan_pass_changed"), "ok", 5000)),
  import_pick: () => { const f = $("#shFile"); f.value = ""; f.click(); },
  qr_copy: () => shareQr && copy(shareQr.text, t("link_copied")),
  vps_add: () => vpsAddModal(),
  pick_zapret: () => act("pick_zapret"),
  pick_byedpi: () => act("pick_byedpi"),
  check_dpi: () => act("check_dpi"),
  update_dpi: () => act("update_dpi"),
  select_zapret: el => act("select_zapret", { name: el.dataset.val }),
  select_byedpi: el => act("select_byedpi", { args: el.dataset.val }),
  byedpi_test: () => act("test_byedpi_custom", { args: $("#byedpiCustom").value }),
  byedpi_use: () => act("select_byedpi", { args: $("#byedpiCustom").value }),
  check_services: () => act("check_services"),
  autofix: () => act("autofix"),
  speed_current: () => act("speed_current"),
  update_geo: () => act("update_geo"),
  update_xray: () => act("update_xray"),
  update_all: () => act("update_all"),
  save_routing: saveRouting,
  save_settings: saveSettings,
  route_site: el => act("route_site", { host: el.dataset.host, target: el.dataset.target }).then(r => {
    if (r.ok) toast(`${r.result.join(", ")}: ${routeLabel(el.dataset.target)}`, "ok", 3000);
  }),
  site_remove: el => act("route_site", { host: el.dataset.host, target: "auto", exact: true }).then(r => {
    if (r.ok) { toast(t("rule_reset", { host: el.dataset.host }), "ok", 3000); scheduleRefresh(50); }
  }),
  site_more: el => { sitePrefill = mainDomain(el.dataset.host); go("routes"); },
  app_pick: el => act("app_pick", { name: el.dataset.name }),
  app_remove: el => act("app_route", { name: el.dataset.name, target: "auto" }).then(r => {
    if (r.ok) { toast(t("apps_removed", { name: el.dataset.name }), "ok", 3000); scheduleRefresh(50); }
  }),
  leak_test: () => act("leak_test"),
  app_update_check: () => act("app_update_check"),
  restart_app: () => act("restart_app").then(r => r.ok && toast(t("au_restarting"), "info", 6000)),
  secure_toggle: el => {
    const v = el.getAttribute("aria-checked") !== "true";
    act("secure_set", { on: v }).then(r => { if (r.ok) { toast(t(v ? "secure_on" : "secure_off"), "ok", 3500); scheduleRefresh(50); } });
  },
  net_mark: el => act("net_mark", { kind: el.dataset.kind }).then(r => { if (r.ok) { toast(t("net_marked", { ssid: r.result }), "ok", 3000); scheduleRefresh(50); } }),
  net_forget: el => act("net_forget", { ssid: el.dataset.ssid }).then(r => r.ok && scheduleRefresh(50)),
  torrent_set: el => act("torrent_set", { value: el.dataset.v }).then(r => r.ok && scheduleRefresh(50)),
  auto_toggle: el => {
    const v = el.getAttribute("aria-checked") !== "true";
    el.setAttribute("aria-checked", String(v));
    act("auto_set", { on: v }).then(r => {
      if (!r.ok) el.setAttribute("aria-checked", String(!v));
      else toast(t(v ? "auto_on_toast" : "auto_off_toast"), "ok", 3000);
      scheduleRefresh(50);
    });
  },
  auto_pin: el => act("auto_forget", { site: el.dataset.site, pin: true }).then(r => {
    if (r.ok) { toast(t("auto_pinned", { host: el.dataset.site }), "ok", 3000); scheduleRefresh(50); }
  }),
  auto_forget: el => act("auto_forget", { site: el.dataset.site }).then(r => {
    if (r.ok) { toast(t("auto_forgot", { host: el.dataset.site }), "ok", 3500); scheduleRefresh(50); }
  }),
  auto_clear: () => act("auto_clear").then(r => {
    if (r.ok) { toast(t("auto_cleared"), "ok", 3000); scheduleRefresh(50); }
  }),
  conn_menu: el => connMenu(el),
  tile_ads: () => adsSet({ enabled: !S.settings.block_ads }),
  ads_toggle: () => adsSet({ enabled: !S.ads.enabled }),
  ads_novpn: () => adsSet({ without_vpn: !S.ads.without_vpn }),
  ads_level: el => adsSet({ level: el.dataset.v }),
  ads_list: el => adsSet({ lists: { [el.dataset.id]: !S.ads.lists[el.dataset.id] } }),
  ads_update: () => act("ads_update"),
  vpn_site_direct: el => vpnSiteAnswer(el.dataset.site, true),
  vpn_site_keep: el => vpnSiteAnswer(el.dataset.site, false),
  ads_site_allow: el => adsSiteAnswer(el.dataset.site, true),
  ads_site_keep: el => adsSiteAnswer(el.dataset.site, false),
  ads_pause: el => act("ads_pause", { minutes: +el.dataset.m }).then(r => r.ok && scheduleRefresh(50)),
  ads_allow: el => act("ads_allow", { host: el.dataset.host }).then(r => {
    if (r.ok) { toast(t("ads_allowed", { host: r.result }), "ok", 3000); scheduleRefresh(50); }
    if (r.ok && adsLookupRes && adsLookupHost) runAdsLookup();
  }),
  ads_save_lists: () => adsSet({ custom: $("#adsCustom").value, allow: $("#adsAllow").value }).then(r => {
    if (r.ok) toast(t("saved"), "ok", 2500);
  }),
  proxy_check: el => { proxyChecking = el.dataset.id; act("check_proxy", { id: el.dataset.id }); },
  proxy_chain: el => {
    const v = el.getAttribute("aria-checked") !== "true";
    el.setAttribute("aria-checked", String(v));
    act("update_proxy", { id: el.dataset.id, chain: v }).then(r => { if (!r.ok) el.setAttribute("aria-checked", String(!v)); scheduleRefresh(50); });
  },
  proxy_remove: async el => {
    const p = ((S.routes && S.routes.proxies) || []).find(x => x.id === el.dataset.id);
    if (!p) return;
    const text = p.used.length ? t("px_remove_used", { list: p.used.map(svcName).join(", ") }) : t("px_remove_text");
    if (!await confirmModal(t("px_remove_q", { name: p.name || p.label }), text, t("px_remove"))) return;
    const r = await act("remove_proxy", { id: p.id });
    if (r.ok) { toast(t("px_removed"), "ok", 3000); scheduleRefresh(50); }
  },
  proxy_report: el => act("proxy_report", { id: el.dataset.id }),
  reset_site: el => act("reset_site", { host: el.dataset.host }).then(r => {
    if (!r.ok) return;
    toast(r.result.length ? t("rule_reset", { host: el.dataset.host }) : t("no_rule"), "ok", 3500);
    loadConnections();
  }),
  reset_list: async el => {
    const key = el.dataset.list;
    if (!await confirmModal(t("clear_list_q"), t("clear_list_text", { name: LIST_NAMES()[key] }), t("clear_list"))) return;
    dirty.delete(key);
    const r = await act("reset_rules", { list: key });
    if (r.ok) { $(`#${key}`).value = ""; $(`#${key}_n`).textContent = t("lines_n", { n: 0 }); toast(t("list_cleared"), "ok", 3000); }
  },
  reset_rules: async () => {
    if (!await confirmModal(t("reset_rules_q"), t("reset_rules_text"), t("reset"))) return;
    const r = await act("reset_rules");
    if (r.ok) {
      Object.keys(LIST_KEYS).forEach(k => { dirty.delete(k); $(`#${k}`).value = ""; $(`#${k}_n`).textContent = t("lines_n", { n: 0 }); });
      toast(t("rules_reset"), "ok", 3500);
    }
  },
  clear_traffic: () => act("clear_traffic").then(() => { connections = []; renderTrafficRows(); }),
  telegram_proxy: async () => {
    const r = await act("telegram_proxy");
    if (!r.ok) return;
    if (r.result.opened) toast(t("tg_opened"), "ok", 12000);
    copy(r.result.link, r.result.opened ? "" : t("tg_copied"));
  },
  happ_open: () => act("happ_open").then(r => r.ok && toast(t("happ_sent"), "ok")),
  happ_copy: async () => { const r = await act("happ_link"); if (r.ok) copy(r.result, t("happ_copied")); },
  top_copy: async () => { const r = await act("top_links", { count: 5 }); if (r.ok) copy(r.result, t("top_copied")); },
  copy_log: () => copy(logs.join("\n"), t("log_copied")),
  err_report: () => errReport(!!(errorsData && errorsData.repo)),
  err_copy: () => errReport(false),
  err_file: () => act("errors_file"),
  err_clear: () => act("errors_clear").then(r => r.ok && loadErrors()),
  err_repo_change: () => { errorsData = Object.assign({}, errorsData, { repo: "" }); renderErrors(); },
  err_repo_save: () => act("errors_repo", { repo: ($("#errRepo") || {}).value || "" }).then(r => {
    if (r.ok) { toast(t("err_repo_saved"), "ok", 2500); loadErrors(); }
  }),
  cert_check: () => act("cert_check"),
  data_check: () => act("data_check"),
  health_check: () => act("health_check"),
  ladder_retry: () => act("ladder_retry").then(r => r.ok && toast(t("ww_trying"), "info", 3000)),
  net_memory_clear: () => act("net_memory_clear").then(r => r.ok && (toast(t("netmem_cleared"), "ok", 2500), scheduleRefresh(50))),
  cert_ack: () => act("cert_ack").then(r => r.ok && scheduleRefresh(50)),
  open_folder: () => act("open_folder"),
  awg_download: () => act("awg_download").then(r => r.ok && toast(t("awg_after_install"), "info", 8000)),
  run_check: () => { checkReport = null; act("run_check").then(() => renderCheckBox()); },
  copy_check: () => checkReport && copy(checkReport.text, t("report_copied")),
  show_report: () => checkReport && checkReport.file && act("show_report", { name: checkReport.file }),
  theme: () => setTheme(S.theme === "light" ? "dark" : "light"),
  lang_toggle: () => setLang(LANG === "ru" ? "en" : "ru"),
  quit: async () => {
    if (await confirmModal(t("quit_q"), t("quit_text"), t("quit"), false)) {
      await act("quit");
      document.body.innerHTML = `<div class="lost"><div><h2>${t("closed_title")}</h2><p>${t("closed_text")}</p></div></div>`;
    }
  },
};

document.addEventListener("click", e => {
  const pop = $("#popover");
  if (!pop.hidden && !e.target.closest("#popover") && !e.target.closest("[data-menu], [data-dd]")) closeMenu();

  const more = e.target.closest("[data-more]");
  if (more) {
    const id = more.dataset.more;
    const body = more.closest(".details").querySelector(".more-body");
    const open = body.hidden;
    body.hidden = !open;
    open ? openDetails.add(id) : openDetails.delete(id);
    more.textContent = open ? t("less") : t("more");
    more.setAttribute("aria-expanded", String(open));
    e.preventDefault();
    return;
  }

  const feat = e.target.closest("[data-feat]");
  if (feat) {
    const id = feat.dataset.feat;
    openFeats.has(id) ? openFeats.delete(id) : openFeats.add(id);
    return renderFeatures();
  }

  const fset = e.target.closest("[data-fset]");
  if (fset && !fset.disabled) {
    const f = FEATURES.flatMap(g => g.items).find(x => x.id === fset.dataset.fset);
    if (!f || !f.set) return;
    const v = fset.getAttribute("aria-checked") !== "true";
    fset.setAttribute("aria-checked", String(v));
    Promise.resolve(f.set(v)).then(r => { if (r && !r.ok) fset.setAttribute("aria-checked", String(!v)); scheduleRefresh(50); });
    return;
  }

  const info = e.target.closest("[data-info]");
  if (info && !e.target.closest("#popover")) return detailModal(info.dataset.info);

  const dd = e.target.closest("[data-dd]");
  if (dd) {
    e.stopPropagation();
    if (!pop.hidden && pop._anchor === dd) return closeMenu();
    if (dd.dataset.dd === "dpi") return dpiDropdown(dd);
    if (dd.dataset.dd === "engine") return engineDropdown(dd);
    return dd.dataset.dd === "route" ? routeDropdown(dd) : connDropdown(dd);
  }

  const qrb = e.target.closest("[data-qr]");
  if (qrb && !qrb.disabled) {
    shareSel = qrb.dataset.qr;
    shareQr = null;
    renderQrBox();
    return loadQr(shareSel);
  }

  const nav = e.target.closest("[data-nav]");
  if (nav) return go(nav.dataset.nav);

  const menu = e.target.closest("[data-menu]");
  if (menu) {
    e.stopPropagation();
    if (!pop.hidden && pop._anchor === menu) return closeMenu();
    const kind = menu.dataset.menu;
    if (kind === "sub") return subMenu(menu, menu.dataset.id);
    if (kind === "srv") return serverMenu(menu, menu.dataset.key);
    if (kind === "sort") return sortMenu(menu);
    if (kind === "add") return addMenu(menu);
    return;
  }

  const a = e.target.closest("[data-act]");
  if (a && ACTIONS[a.dataset.act]) return ACTIONS[a.dataset.act](a);

  const lang = e.target.closest("[data-lang]");
  if (lang) return setLang(lang.dataset.lang);

  const th = e.target.closest("[data-theme-set]");
  if (th) return setTheme(th.dataset.themeSet);

  const cp = e.target.closest("[data-copy]");
  if (cp) return copy(cp.dataset.copy, t("copied"));

  const tf = e.target.closest("[data-tf]");
  if (tf) {
    trafficFilter = tf.dataset.tf;
    $$("[data-tf]").forEach(b => b.setAttribute("aria-pressed", String(b === tf)));
    return renderTrafficRows();
  }

  const toggle = e.target.closest("[data-toggle]");
  if (toggle) {
    const id = toggle.dataset.toggle;
    const set = new Set(S.collapsed || []);
    set.has(id) ? set.delete(id) : set.add(id);
    S.collapsed = Array.from(set);
    act("set_ui", { collapsed: S.collapsed }, { quiet: true });
    return renderSubs();
  }

  const row = e.target.closest(".srv[data-key]");
  if (row && !row.classList.contains("is-off")) {
    const s = S.servers.find(x => x.key === row.dataset.key);
    if (s && !s.current) act("connect", { key: s.key });
  }
});

document.addEventListener("change", e => {
  if (e.target.id === "shFile") return importFile(e.target.files[0]);
  const hs = e.target.closest("[data-hours]");
  if (hs) return act("save_settings", { [hs.dataset.hours]: Number(hs.value) }).then(r => r.ok && toast(t("saved"), "ok", 2500));
  if (e.target.id === "siteRouteVia" && e.target.value === "custom:new") { e.target.value = "proxy"; return focusProxyForm(); }
  const sel = e.target.closest(".route-select");
  if (sel) {
    const target = sel.value;
    sel.blur();  // иначе обновление страницы ждёт, пока список в фокусе
    if (target === "custom:new") { sel.value = sel.dataset.cur || "auto"; return focusProxyForm(); }
    sel.dataset.cur = target;
    if (sel.dataset.site && siteResult && siteResult.site === sel.dataset.site) siteResult.route = target;
    const req = sel.dataset.svc ? act("service_route", { name: sel.dataset.svc, target })
      : sel.dataset.app ? act("app_route", { name: sel.dataset.app, target })
      : act("route_site", { host: sel.dataset.site, target, exact: true });
    req.then(() => scheduleRefresh(50));
  }
});

document.addEventListener("keydown", e => {
  if (e.key === "Escape") { closeMenu(); if (!$("#overlay").hidden) closeModal(); }
  if (e.key === "Enter" && e.target.matches(".srv[data-key], [data-pick]")) e.target.click();
});

function setLang(lang) {
  if (lang === LANG) return;
  LANG = lang;
  localStorage.setItem("pult-lang", lang);
  if (S) S.lang = lang;
  renderPage(true);
  act("set_ui", { lang }, { quiet: true }).then(() => scheduleRefresh(50));
}

$("#backBtn").addEventListener("click", () => go((PAGES[page] || {}).back || "home"));
$("#moreBtn").addEventListener("click", () => go("more"));
$("#langBtn").addEventListener("click", () => setLang(LANG === "ru" ? "en" : "ru"));
$("#problemsBtn").addEventListener("click", problemsModal);
$("#busyStop").addEventListener("click", () => ACTIONS.stop());

/* ---------- поток событий ---------- */

// свёрнутое окно ничего не перерисовывает; развернули — показать свежие цифры
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && S && page === "home") renderHero();
});

let failures = 0;
let lostTimer = null;

function connectEvents() {
  const es = new EventSource(`/api/events?t=${encodeURIComponent(TOKEN)}`);
  es.onopen = () => {
    failures = 0;
    clearTimeout(lostTimer);
    lostTimer = null;
    const lost = $(".lost");
    if (lost) lost.remove();
    scheduleRefresh(0);
  };
  es.onmessage = e => {
    let m;
    try { m = JSON.parse(e.data); } catch { return; }
    const d = m.data || {};
    switch (m.event) {
      case "log":
        logs.push(d.text);
        if (logs.length > 1000) logs = logs.slice(-500);
        if (page === "log") renderLog();
        break;
      case "busy":
        if (S) { S.busy = d.active ? d.text : ""; renderBusy(); }
        if (!d.active && pendingAdd) {
          const p = pendingAdd;
          pendingAdd = null;
          if (p.error) showModalError(p.error);
          else if (p.modal) { closeModal(); toast(t("sub_added"), "ok"); }
        }
        scheduleRefresh();
        break;
      case "conn":
        if (S) { S.conn_busy = d.active ? d.text : ""; renderBusy(); if (page === "home") renderHero(); }
        scheduleRefresh();
        break;
      case "live":
        if (S) {
          const was = S.connected;
          S.live = d.live; S.connected = d.connected;
          // обычно меняются только цифры; подключился или отключился — пересобрать экран
          if (page === "home" && !document.hidden) { if (was !== d.connected) renderHero(); else updateHeroLive(); }
        }
        break;
      case "connections":
        if (page === "traffic") throttledConnections();
        break;
      case "journal":
        if (page === "status") scheduleRefresh(400);
        break;
      case "check":
        checkReport = d.report;
        if (page === "status") renderCheckBox();
        toast(t("selfcheck_done", { e: d.report.errors, w: d.report.warnings }), d.report.errors ? "error" : "ok");
        break;
      case "lock":
        if (S) S.locked = true;
        closeModal && closeModal();
        renderLock();
        break;
      case "unlocked":
        scheduleRefresh(0);
        break;
      case "certs":
        if (S) S.certs = d.result;
        renderCertBox();
        if (page === "status") renderStatus();
        if (d.result && (d.result.errors || d.result.warnings) && page !== "status")
          toast(t("certs_found", { e: d.result.errors, w: d.result.warnings }), d.result.errors ? "error" : "ok", 6000);
        break;
      case "leaks":
        if (S) S.leaks = d.result;
        if (page === "status") renderStatus();
        else toast(d.result.errors || d.result.warnings ? t("leaks_found", { e: d.result.errors, w: d.result.warnings }) : t("leaks_none"),
          d.result.errors ? "error" : "ok", 6000);
        break;
      case "vps":
        if (page === "share") { loadVps(); loadShareItems(); }
        if (d.friend) qrModal(d.friend, t("qr_friend", { name: d.name || "" }), "friend");
        break;
      case "repair":
        repairResult = d.result;
        if (page === "services") renderSiteBox();
        else toast(d.result.verdict, d.result.fixed ? "ok" : "info", 9000);
        break;
      case "site":
        siteResult = d.result;
        if (page === "services") renderSiteBox();
        else toast(d.result.verdict, "ok", 8000);
        break;
      case "summary":
        toast(d.text, "ok", 10000);
        break;
      case "vpn_site": {
        const it = d.item || {};
        askToast(t("vpn_site_ask", { h: it.site }), [
          { label: t("vpn_site_direct"), primary: true, run: () => vpnSiteAnswer(it.site, true) },
          { label: t("vpn_site_keep"), run: () => vpnSiteAnswer(it.site, false) }]);
        scheduleRefresh();
        break;
      }
      case "ads_site": {
        const it = d.item || {};
        askToast(t(it.threat ? "ads_site_ask_threat" : "ads_site_ask", { h: it.site, list: (it.lists || []).join(", ") }), [
          { label: t("ads_site_allow"), primary: !it.threat, run: () => adsSiteAnswer(it.site, true) },
          { label: t("ads_site_keep"), run: () => adsSiteAnswer(it.site, false) }]);
        scheduleRefresh();
        break;
      }
      case "info":
        toast(d.text, "info", 3500);
        break;
      case "error":
        if (pendingAdd && pendingAdd.modal) pendingAdd.error = d.text;
        else toast(d.text, "error", 10000);
        break;
      default:
        scheduleRefresh();
    }
  };
  es.onerror = () => {
    failures++;
    if (failures >= 3 && !lostTimer) {
      lostTimer = setTimeout(() => {
        lostTimer = null;
        if (failures >= 3 && !$(".lost")) {
          const el = document.createElement("div");
          el.className = "lost";
          el.innerHTML = `<div><h2>${t("lost_title")}</h2><p>${t("lost_text")}</p></div>`;
          document.body.append(el);
        }
      }, 4000);
    }
  };
}

let connTimer = null;
function throttledConnections() {
  if (connTimer) return;
  connTimer = setTimeout(() => { connTimer = null; loadConnections(); }, 1000);
}

/* ---------- запуск ---------- */

renderTheme();
refresh().then(() => renderPage(true));
connectEvents();
