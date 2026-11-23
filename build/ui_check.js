// Проверка окна программы в настоящем браузере (Chromium): то, что ловит только живой интерфейс.
// Запуск: python3 build/ui_server.py & node build/ui_check.js <порт>
//   • главный экран не пересобирается каждые 2 секунды (меняются только цифры), нажатие не «проваливается»;
//   • выпадающее меню едет за кнопкой при прокрутке или закрывается — не висит в стороне;
//   • «подключён» горит ровно у одного сервера;
//   • журнал подключения есть на экране «Состояние»;
//   • тема: тёмная, светлая и «как в Windows» переключаются в настройках;
//   • на всех экранах и в окнах текст не прилипает к краям, кнопки не налезают друг на друга (ширина 1180, 900 и 720);
//   • в консоли нет ошибок.
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const port = process.argv[2];
const fails = [];
const ok = (cond, name, detail = "") => { console.log(`${cond ? "[OK]  " : "[FAIL]"} ${name}${detail ? " — " + detail : ""}`); if (!cond) fails.push(name); };

(async () => {
  const browser = await chromium.launch(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {});
  const page = await browser.newPage({ viewport: { width: 1180, height: 760 } });
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`http://127.0.0.1:${port}/?t=tok`);
  await page.waitForSelector("#hero .power");
  await page.waitForTimeout(2000);

  // 1. главный экран стоит на месте, пока идут обновления цифр
  const r = await page.evaluate(async () => {
    const hero = document.querySelector("#hero");
    const power0 = hero.querySelector(".power");
    let rebuilt = 0, live = 0;
    new MutationObserver((ms) => ms.forEach((m) => { if (m.target === hero) rebuilt++; })).observe(hero, { childList: true });
    const es = new EventSource(`/api/events?t=tok`);
    es.onmessage = (e) => { try { if (JSON.parse(e.data).event === "live") live++; } catch {} };
    await new Promise((res) => setTimeout(res, 8000));
    es.close();
    return { rebuilt, live, same: hero.querySelector(".power") === power0 };
  });
  ok(r.live >= 2, "Обновления цифр приходят", `событий: ${r.live}`);
  ok(r.rebuilt === 0 && r.same, "Главный экран не пересобирается при обновлении цифр", `пересборок: ${r.rebuilt}`);

  // 2. нажатие, растянутое на обновление цифр, срабатывает
  const box = await page.locator("#hero .power").boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.waitForTimeout(2600);
  const sent = page.waitForRequest((rq) => rq.url().includes("/api/action"), { timeout: 3000 }).then(() => true).catch(() => false);
  await page.mouse.up();
  ok(await sent, "Нажатие на большую кнопку не теряется между обновлениями");
  await page.waitForTimeout(1500);
  // снова подключить (кнопка выключила VPN)
  await page.locator("#hero .power").click();
  await page.waitForTimeout(2500);

  // 3. «подключён» — у одного сервера
  const cur = await page.locator(".srv.is-current").count();
  ok(cur === 1, "«Подключён» горит у одного сервера", `таких: ${cur}`);

  // 4. меню при прокрутке: едет за кнопкой или закрывается
  await page.locator('[data-menu="sort"]').click();
  await page.waitForTimeout(300);
  const before = await page.evaluate(() => {
    const p = document.querySelector("#popover"), a = document.querySelector('[data-menu="sort"]');
    return p && !p.hidden ? { dy: p.getBoundingClientRect().top - a.getBoundingClientRect().bottom } : null;
  });
  ok(!!before, "Меню открывается");
  await page.evaluate(() => { const m = document.querySelector(".main"); m.scrollTop += 120; m.dispatchEvent(new Event("scroll")); });
  await page.waitForTimeout(300);
  const after = await page.evaluate(() => {
    const p = document.querySelector("#popover"), a = document.querySelector('[data-menu="sort"]');
    if (!p || p.hidden) return { closed: true };
    const pr = p.getBoundingClientRect(), ar = a.getBoundingClientRect();
    // меню у своей кнопки — снизу или сверху (если внизу не помещается)
    return { closed: false, below: Math.round(pr.top - ar.bottom), above: Math.round(ar.top - pr.bottom) };
  });
  const attached = after.closed || (after.below >= 0 && after.below < 14) || (after.above >= 0 && after.above < 14);
  ok(attached, "Меню не «съезжает» при прокрутке", JSON.stringify(after));
  await page.keyboard.press("Escape");
  await page.evaluate(() => { document.querySelector(".main").scrollTop = 0; });

  // 4а. способ: «VPN-сервер» и обратно «Авто» — переключается и запоминается
  await page.locator('[data-act="method"][data-method="server"]').click();
  await page.waitForTimeout(1200);
  const m1 = await page.locator('[data-act="method"][data-method="server"]').getAttribute("aria-checked");
  await page.locator('[data-act="method"][data-method="auto"]').click();
  await page.waitForTimeout(1200);
  const m2 = await page.locator('[data-act="method"][data-method="auto"]').getAttribute("aria-checked");
  ok(m1 === "true" && m2 === "true", "Способ переключается (VPN-сервер, потом Авто)", `${m1} ${m2}`);
  // 4б. AmneziaWG без конфига: не ошибка, а окно «создать бесплатный WARP или вставить свой»
  await page.locator('[data-act="method"][data-method="awg"]').click();
  await page.waitForSelector(".modal");
  const warpBtn = await page.locator('.modal [data-act="warp_create"]').count();
  const ownBtn = await page.locator(".modal #mOwn").count();
  const awgSel = await page.locator('[data-act="method"][data-method="awg"]').getAttribute("aria-checked");
  ok(warpBtn === 1 && ownBtn === 1 && awgSel !== "true", "AmneziaWG без конфига: окно с «Создать бесплатный WARP»",
    `${warpBtn} ${ownBtn} ${awgSel}`);
  await page.locator(".modal [data-close]").first().click();
  const routeOk = await page.locator(".route .rt-node").count();
  ok(routeOk >= 2, "Путь трафика на главном экране", `звеньев: ${routeOk}`);

  // 1.26.1: маршрутизация, подключение и движок — снова на главном (и в «Дополнительно»); Мультисервер и Автопереход
  const homeSel = await page.evaluate(() => ["route", "conn", "engine"].map(d => document.querySelectorAll(`#hero [data-dd="${d}"]`).length).join(""));
  const homeSw = await page.evaluate(() => [
    document.querySelectorAll('#hero [data-act="tile_set"][data-key="multi_enabled"]').length,
    document.querySelectorAll('#hero [data-act="home_autopilot"]').length].join(""));
  const multiBefore = await page.evaluate(() => S.settings.multi_enabled);
  await page.click('#hero [data-act="tile_set"][data-key="multi_enabled"]');
  await page.waitForTimeout(500);
  const multiAfter = await page.evaluate(() => S.settings.multi_enabled);
  await page.click('#hero [data-act="tile_set"][data-key="multi_enabled"]');
  await page.waitForTimeout(400);
  await page.click('#hero [data-act="home_autopilot"]');
  await page.waitForTimeout(700);
  const apMethod = await page.evaluate(() => S.method);
  await page.click('#hero [data-act="home_autopilot"]');
  await page.waitForTimeout(700);
  const apBack = await page.evaluate(() => S.method);
  ok(homeSel === "111" && homeSw === "11" && multiBefore !== multiAfter && apMethod === "server" && apBack === "auto",
    "Главный экран: Маршрутизация, Подключение, Движок, Мультисервер и Автопереход", `${homeSel} ${homeSw} ${multiBefore}→${multiAfter} ${apMethod}→${apBack}`);
  await page.locator("#moreBtn").click();
  await page.waitForSelector('[data-dd="route"]');
  ok(await page.locator('[data-dd="conn"]').count() === 1 && await page.locator('[data-dd="engine"]').count() === 1,
    "Маршрутизация, подключение и движок — и в «Дополнительно»");

  // 4в. «Семья»: кнопка на главном, приглашение с QR, настройка устройства → посылка
  await page.locator("#backBtn").click();
  await page.locator("#familyBtn").click();
  await page.waitForSelector("#famPage");
  await page.locator('[data-act="fam_invite"]').click();
  await page.fill("#mFamMe", "Сын");
  await page.fill("#mFamDev", "Мама — телефон");
  await page.locator("#mOk").click();
  await page.waitForSelector("#mFamText");
  const inv = await page.inputValue("#mFamText");
  const qrOk = await page.locator(".modal .qr-img svg").count();
  ok(inv.startsWith("vedomyj-family://i/") && qrOk === 1, "Семья: приглашение текстом и QR-кодом", inv.slice(0, 24));
  await page.locator(".modal [data-close]").first().click();
  await page.waitForSelector('[data-act="fam_device"]');
  await page.locator('[data-act="fam_device"]').first().click();
  await page.fill("#mFamSubUrl", "https://example.com/sub/abc");
  await page.locator("#mOk").click();
  await page.waitForSelector("#mFamText");
  const pkt = await page.inputValue("#mFamText");
  ok(pkt.startsWith("vedomyj-family://p/") && !pkt.includes("example.com"), "Семья: посылка зашифрована", pkt.slice(0, 24));
  await page.locator(".modal [data-close]").first().click();
  await page.locator("#backBtn").click();

  // 5. журнал подключения на экране «Состояние»
  await page.locator('[data-nav="status"]').first().click();
  await page.waitForSelector("#stJournal");
  await page.locator("#stJournal summary").click();
  const jl = await page.locator("#journalBox li").count();
  ok(jl >= 1, "Журнал подключения на экране «Состояние»", `записей: ${jl}`);

  // 5а. тема: тёмная, светлая и «как в Windows» (следует за темой системы на лету)
  await page.evaluate(() => go("settings"));
  await page.waitForSelector('[data-theme-set="auto"]');
  const themeOf = () => page.evaluate(() => document.documentElement.dataset.theme);
  await page.click('[data-theme-set="light"]');
  const thLight = await themeOf();
  await page.emulateMedia({ colorScheme: "light" });
  await page.click('[data-theme-set="auto"]');
  const thAutoL = await themeOf();
  await page.emulateMedia({ colorScheme: "dark" });
  await page.waitForTimeout(200);
  const thAutoD = await themeOf();
  const autoChecked = await page.getAttribute('[data-theme-set="auto"]', "aria-checked");
  await page.click('[data-theme-set="dark"]');
  const thDark = await themeOf();
  ok(thLight === "light" && thAutoL === "light" && thAutoD === "dark" && autoChecked === "true" && thDark === "dark",
    "Тема: тёмная, светлая и «как в Windows» переключаются в настройках", `${thLight} ${thAutoL} ${thAutoD} ${autoChecked} ${thDark}`);
  await page.evaluate(() => go("home"));

  // 5б. «Способ»: стрелки-списки у плиток (движок, конфиги AmneziaWG и ускорение, чем ускорять без VPN)
  await page.waitForSelector('[data-dd="m_server"]');
  const ddItems = async (sel) => {
    await page.click(sel);
    await page.waitForSelector("#popover:not([hidden]) .dd");
    const items = await page.$$eval("#popover .dd-item, #popover .dd-head", (els) => els.map((e) => e.textContent.replace(/\s+/g, " ").trim()));
    await page.keyboard.press("Escape");
    await page.mouse.click(5, 5);
    await page.waitForTimeout(150);
    return items.join(" | ");
  };
  const ddSrv = await ddItems('[data-dd="m_server"]');
  const ddAwg = await ddItems('[data-dd="m_awg"]');
  const ddDpi = await page.locator('.tg-dd[data-dd="dpi"]').count();  // на Linux ускорения нет — стрелка неактивна
  // «Способ» — ровный список: пять строк одной высоты, стрелки только у «VPN-сервер» и «AmneziaWG»
  const rows = await page.$$eval(".methods.m-list .m-wrap", (els) => els.map((e) => [e.querySelector(".m-text b").textContent.trim(),
    Math.round(e.getBoundingClientRect().height), Math.round(e.getBoundingClientRect().left)]));
  const names = rows.map((r) => r[0]).join(",");
  const sameH = new Set(rows.map((r) => r[1])).size === 1 && new Set(rows.map((r) => r[2])).size === 1;
  const ddCount = await page.locator(".methods .m-dd").count();
  ok(/Xray/.test(ddSrv) && /Hysteria2/.test(ddSrv) && /sing-box/.test(ddSrv) && !/zapret/i.test(ddAwg)
    && ddDpi === 1 && names === "Авто,VPN-сервер,AmneziaWG,Zapret,ByeDPI" && sameH && ddCount === 2,
    "«Способ»: ровный список Авто / VPN-сервер / AmneziaWG / Zapret / ByeDPI, стрелки у сервера и AmneziaWG",
    `${names} ${rows.map((r) => r[1]).join("/")} dd=${ddCount} | ${ddSrv.slice(0, 40)} / ${ddAwg.slice(0, 40)} / ${ddDpi}`);
  await page.click('[data-dd="m_server"]');
  await page.click('#popover [data-pick="eng:xray"]');
  await page.waitForTimeout(600);
  const engPick = await page.evaluate(() => S.engine && S.engine.pick);
  await page.click('[data-dd="m_server"]');
  await page.click('#popover [data-pick="eng:auto"]');
  await page.waitForTimeout(400);
  ok(engPick === "xray", "Движок выбирается прямо в плитке «VPN-сервер»", engPick);

  // 5в. «Не работает» и «Белые списки» — ряд из двух одинаковых кнопок
  const nwBox = await page.locator(".nw-row .nw-cell").evaluateAll((els) => els.map((e) => Math.round(e.getBoundingClientRect().width)));
  await page.click('[data-act="wl_toggle"]');
  await page.waitForTimeout(900);
  const wlOn = await page.getAttribute('[data-act="wl_toggle"]', "aria-checked");
  const wlSet = await page.evaluate(() => S.settings && S.settings.wl_priority !== undefined ? S.wl.manual : null);
  await page.click('[data-act="wl_toggle"]');
  await page.waitForTimeout(900);
  const wlOff = await page.getAttribute('[data-act="wl_toggle"]', "aria-checked");
  ok(nwBox.length === 2 && Math.abs(nwBox[0] - nwBox[1]) <= 1 && wlOn === "true" && wlOff === "false" && wlSet !== false,
    "«Не работает» и «Белые списки» в один ряд, галочка переключается", `${nwBox} ${wlOn} ${wlOff}`);
  await page.click('[data-act="nw_open"]');
  await page.waitForSelector("#nwBox [data-nwsel]");
  await page.click('#nwBox [data-nwsel="Telegram"]');
  await page.click("#nwGo");
  await page.waitForSelector("#nwRes .nw-res:not(.busy)", { timeout: 60000 });
  const nwText = await page.textContent("#nwRes");
  await page.click('#nwBox [data-nwtab="site"]');
  const nwSite = await page.locator("#nwSite").count();
  await page.locator("#nwBox [data-close]").first().click();
  ok(/Telegram/.test(nwText) && nwSite === 1, "«Не работает»: сервис проверяется всеми путями, есть вкладка «Сайт»", nwText.slice(0, 90));

  // 5г. реклама: «Проверить блокировку» с «Исправить», списки «Монстра», окно «Монстр»
  await page.evaluate(() => go("ads"));
  await page.waitForSelector('[data-act="ads_check_run"]');
  await page.waitForSelector('[data-act="ads_check_run"]:not([disabled])', { timeout: 60000 });
  await page.click('[data-act="ads_check_run"]');
  await page.waitForSelector("#adsCheck .chk-row", { timeout: 60000 });
  const chk = await page.$$eval("#adsCheck .chk-row", (els) => els.map((e) => e.textContent.replace(/\s+/g, " ").trim()));
  const monsterRows = await page.locator('[data-act="ads_list"][data-id^="m_"]').count();
  await page.click('.monster-card [data-act="monster"]');
  await page.waitForSelector(".modal h2");
  const monsterTitle = await page.textContent(".modal h2");
  await page.locator(".modal [data-close]").first().click();
  ok(chk.length >= 1 && monsterRows === 3 && /Монстр/.test(monsterTitle),
    "Реклама: «Проверить блокировку», списки «Монстра», как установить «Монстра»", `${chk.length} ${monsterRows} ${chk[0] ? chk[0].slice(0, 50) : ""}`);
  await page.evaluate(() => go("home"));

  // 5д. WARP во встроенном ядре: «Через VPN и WARP» в выборе маршрута, «Запасной WARP» в профессиональных
  await page.evaluate(() => go("routes"));
  await page.waitForTimeout(400);
  const warpOpt = await page.$$eval('#siteRouteVia option[value="warp"]', (els) => els.length);
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  const warpSw = await page.$('[data-pset="warp_fallback"]');
  ok(warpOpt >= 1 && !!warpSw, "WARP: «Через VPN и WARP» в маршрутах, «Запасной WARP» в профессиональных", `${warpOpt} ${!!warpSw}`);
  await page.evaluate(() => go("home"));
  // 5е. «Семья»: посылки доставляются сами — переключатель на месте
  await page.evaluate(() => go("family"));
  await page.waitForTimeout(400);
  const famSw = await page.$eval('#famMail [data-act="fam_dht"]', (el) => el.getAttribute("aria-checked")).catch(() => "");
  ok(famSw === "true", "Семья: «Посылки доставляются сами» включено по умолчанию", famSw);
  await page.evaluate(() => go("home"));

  // 5ж. DNS-туннель (эксперимент): выключен по умолчанию; включили — у своего сервера кнопка, окно с записями домена
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  const xSw0 = await page.$eval('[data-pset="exp_xdns"]', (el) => el.getAttribute("aria-checked")).catch(() => "");
  await page.evaluate(() => go("share"));
  await page.waitForTimeout(600);
  const xBtn0 = await page.locator("[data-vxdns]").count();
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  await page.click('[data-pset="exp_xdns"]');
  await page.waitForTimeout(800);
  await page.evaluate(() => go("share"));
  await page.waitForSelector("[data-vxdns]", { timeout: 10000 }).catch(() => null);
  const xBtn1 = await page.locator("[data-vxdns]").count();
  let recs = "";
  if (xBtn1) {
    await page.click("[data-vxdns]");
    await page.waitForSelector("#xDom");
    await page.fill("#xDom", "Example.RU");
    await page.waitForTimeout(200);
    recs = (await page.textContent("#xRecs")).replace(/\s+/g, " ");
    await page.locator(".modal [data-close]").first().click();
  }
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  await page.click('[data-pset="exp_xdns"]');
  await page.waitForTimeout(500);
  await page.evaluate(() => go("home"));
  ok(xSw0 === "false" && xBtn0 === 0 && xBtn1 >= 1 && /tns\.example\.ru/.test(recs) && /t\.example\.ru/.test(recs) && /203\.0\.113\.10/.test(recs),
    "DNS-туннель: выключен по умолчанию; включён — кнопка у своего сервера, записи для регистратора с адресом сервера",
    `${xSw0} ${xBtn0} ${xBtn1} ${recs.slice(0, 90)}`);

  // 5з. свой протокол (эксперимент): выключен по умолчанию; включили — кнопка у своего сервера
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  const pSw0 = await page.$eval('[data-pset="exp_proto"]', (el) => el.getAttribute("aria-checked")).catch(() => "");
  await page.click('[data-pset="exp_proto"]');
  await page.waitForTimeout(800);
  await page.evaluate(() => go("share"));
  await page.waitForSelector("[data-vproto]", { timeout: 10000 }).catch(() => null);
  const pBtn = await page.locator("[data-vproto]").count();
  const pTxt = pBtn ? (await page.textContent("[data-vproto]")).trim() : "";
  await page.evaluate(() => go("pro"));
  await page.waitForTimeout(300);
  await page.click('[data-pset="exp_proto"]');
  await page.waitForTimeout(500);
  await page.evaluate(() => go("home"));
  ok(pSw0 === "false" && pBtn >= 1 && /Свой протокол/.test(pTxt),
    "Свой протокол: выключен по умолчанию; включён — кнопка у своего сервера", `${pSw0} ${pBtn} ${pTxt}`);

  // 6. отступы: все экраны и главные окна на трёх ширинах окна
  const audit = fs.readFileSync(path.join(__dirname, "layout_audit.js"), "utf8");
  const PAGES = ["home", "status", "more", "features", "zapret", "byedpi", "services", "routes", "traffic", "updates", "settings",
    "log", "tips", "manual", "share", "ads", "errors", "family", "pro"];
  const MODALS = ["modalAddSub()", "modalAddServer()", "modalAwgStart()", "modalFamInvite()", "modalVps()", "modalNotWorking()"];
  const tight = [];
  for (const [w, h] of [[1180, 760], [900, 700], [720, 640]]) {
    await page.setViewportSize({ width: w, height: h });
    await page.evaluate(audit);
    for (const name of PAGES) {
      await page.evaluate((n) => go(n), name);
      await page.waitForTimeout(350);
      for (const [kind, d] of await page.evaluate("__audit()")) tight.push(`${w}/${name}: ${kind} ${d}`);
    }
    await page.evaluate(() => go("home"));
    for (const m of MODALS) {
      await page.evaluate(m);
      await page.waitForTimeout(350);
      for (const [kind, d] of await page.evaluate("__audit()")) tight.push(`${w}/${m}: ${kind} ${d}`);
      await page.evaluate(() => closeModal());
      await page.waitForTimeout(150);
    }
  }
  ok(tight.length === 0, "Отступы: текст и кнопки не прилипают к краям и друг к другу", tight.slice(0, 6).join(" | "));

  ok(errors.length === 0, "В консоли нет ошибок", errors.slice(0, 3).join(" | "));
  await browser.close();
  process.exit(fails.length ? 1 : 0);
})().catch((e) => { console.log("[FAIL] " + e); process.exit(1); });
