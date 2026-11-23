// Проверка отступов: текст не прилипает к краям кнопок и карточек, кнопки не налезают друг на друга,
// ничего не вылезает за экран. Подключают build/ui_check.js (компьютер) и android/coretest/ui_walk.js (телефон):
//   await page.evaluate(fs.readFileSync(".../layout_audit.js", "utf8")); const bad = await page.evaluate("__audit()");
// Текст, обрезанный нарочно (многоточие, «…» в длинных названиях), не считается.
// Ищет на странице тесные места: текст у края кнопок/карточек, кнопки вплотную друг к другу, обрезанный текст, вылезание за экран.
window.__audit = function () {
  const out = [];
  const W = innerWidth;
  // окно уменьшено целиком (html.fit, zoom): все размеры на экране меньше во столько же раз — и пороги тоже
  const Z = parseFloat(getComputedStyle(document.documentElement).zoom) || 1;
  const vis = (el) => {
    // всплывающие подсказки (тосты) и плашка «идёт задача… Стоп» висят поверх страницы на время — их не считаем
    if (el.closest && el.closest(".toasts, #toast, #busy")) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    if (el.checkVisibility && !el.checkVisibility({ contentVisibilityAuto: true, opacityProperty: true, visibilityProperty: true })) return false;
    for (let e = el; e && e !== document.body; e = e.parentElement) {
      const cs = getComputedStyle(e);
      if (cs.display === "none" || cs.visibility === "hidden" || +cs.opacity === 0) return false;
    }
    return r.bottom > 0 && r.top < innerHeight * 3;
  };
  const desc = (el) => {
    const t = (el.innerText || el.value || el.getAttribute("aria-label") || "").trim().replace(/\s+/g, " ").slice(0, 40);
    return `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}${el.className && typeof el.className === "string" ? "." + el.className.trim().split(/\s+/).slice(0, 3).join(".") : ""} «${t}»`;
  };
  const boxed = (el) => {
    const cs = getComputedStyle(el);
    const bg = cs.backgroundColor;
    const hasBg = bg && !/rgba\(0, 0, 0, 0\)|transparent/.test(bg);
    const hasBorder = ["Top", "Right", "Bottom", "Left"].some((s) => parseFloat(cs["border" + s + "Width"]) > 0 && !/rgba\(0, 0, 0, 0\)/.test(cs["border" + s + "Color"]));
    return hasBg || hasBorder;
  };
  const cut = (el) => { for (let q = el; q && q !== document.body; q = q.parentElement) {
      const cs = getComputedStyle(q);
      if (cs.textOverflow === "ellipsis" || (cs.webkitLineClamp && cs.webkitLineClamp !== "none")) return true; }
    return false; };
  const textRects = (el) => {
    const rects = [];
    const tw = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n; (n = tw.nextNode());) {
      if (!n.textContent.trim()) continue;
      const p = n.parentElement;
      if (!p || !vis(p) || cut(p)) continue;
      const rg = document.createRange();
      rg.selectNodeContents(n);
      for (const r of rg.getClientRects()) if (r.width > 1) rects.push(r);
    }
    return rects;
  };
  if (document.documentElement.scrollWidth > W + 1) out.push(["page-overflow", `ширина ${document.documentElement.scrollWidth} > ${W}`]);
  // 1) кнопки, поля, чипы, карточки: текст у края
  const modal = document.querySelector(".modal:not([hidden]), .sheet:not([hidden])");
  const scope = modal && modal.getBoundingClientRect().width > 0 ? modal : document;
  const boxes = scope.querySelectorAll("button, .btn, input, select, textarea, .chip, .card, .modal, section, .row, .m-opt, .tg-row, .problem, .hint, .toast, .badge, .pill, label");
  for (const el of boxes) {
    if (!vis(el) || !boxed(el)) continue;
    const r = el.getBoundingClientRect();
    if (r.right > W + 0.5 || r.left < -0.5) out.push(["offscreen", desc(el)]);
    if (["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName)) {
      const cs = getComputedStyle(el);
      if (parseFloat(cs.paddingLeft) < 8) out.push(["input-pad", desc(el) + ` padL=${cs.paddingLeft}`]);
      continue;
    }
    if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflowX !== "auto" && el.tagName === "BUTTON") out.push(["clipped", desc(el)]);
    const tr = textRects(el);
    if (!tr.length) continue;
    const minX = Math.min(...tr.map((x) => Math.min(x.left - r.left, r.right - x.right)));
    const minY = Math.min(...tr.map((x) => Math.min(x.top - r.top, r.bottom - x.bottom)));
    const small = r.height < 34 * Z;
    const needX = (small ? 6 : el.matches(".card, .modal, section") ? 12 : 9) * Z;
    if (minX < needX) out.push(["text-edge-x", desc(el) + ` ${minX.toFixed(1)}px`]);
    if (minY < (small ? 2 : 4) * Z) out.push(["text-edge-y", desc(el) + ` ${minY.toFixed(1)}px`]);
  }
  // 2) управляющие элементы вплотную или внахлёст
  const ctl = [...scope.querySelectorAll("button, .btn, input, select, textarea, a[href], .chip, [data-act]")].filter(vis)
    .filter((el) => !ctlParent(el));
  const grouped = (a, b) => a.parentElement === b.parentElement && a.parentElement.matches(".seg, .segmented, .chips, [role=radiogroup], [role=tablist], .seg-group, .tabs")
    || (a.matches(".list-row, .row, .srv-row") && b.matches(".list-row, .row, .srv-row"));
  function ctlParent(el) { for (let p = el.parentElement; p; p = p.parentElement) if (p.matches && p.matches("button, .btn, a[href]")) return true; return false; }
  for (let i = 0; i < ctl.length; i++) {
    const a = ctl[i].getBoundingClientRect();
    for (let j = i + 1; j < ctl.length; j++) {
      if (ctl[i].contains(ctl[j]) || ctl[j].contains(ctl[i]) || grouped(ctl[i], ctl[j])) continue;
      const b = ctl[j].getBoundingClientRect();
      const gapX = Math.max(b.left - a.right, a.left - b.right);
      const gapY = Math.max(b.top - a.bottom, a.top - b.bottom);
      if (gapX < 0 && gapY < 0) { out.push(["overlap", desc(ctl[i]) + " ⟷ " + desc(ctl[j])]); continue; }
      const sameRow = gapY < 0, sameCol = gapX < 0;
      if ((sameRow && gapX < 6 * Z - 0.05) || (sameCol && gapY < 6 * Z - 0.05)) out.push(["tight-gap", desc(ctl[i]) + " ⟷ " + desc(ctl[j]) + ` ${(sameRow ? gapX : gapY).toFixed(1)}px`]);
    }
  }
  return [...new Map(out.map((x) => [x.join("|"), x])).values()];
};
