// Проверка окна программы в настоящем браузере (Chromium): то, что ловит только живой интерфейс.
// Запуск: python3 build/ui_server.py & node build/ui_check.js <порт>
//   • главный экран не пересобирается каждые 2 секунды (меняются только цифры), нажатие не «проваливается»;
//   • выпадающее меню едет за кнопкой при прокрутке или закрывается — не висит в стороне;
//   • «подключён» горит ровно у одного сервера;
//   • журнал подключения есть на экране «Состояние»;
//   • в консоли нет ошибок.
const { chromium } = require("playwright");
const port = process.argv[2];
const fails = [];
const ok = (cond, name, detail = "") => { console.log(`${cond ? "[OK]  " : "[FAIL]"} ${name}${detail ? " — " + detail : ""}`); if (!cond) fails.push(name); };

(async () => {
  const browser = await chromium.launch();
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

  // маршрутизация, вход и движок теперь в «Дополнительно»
  await page.locator("#moreBtn").click();
  await page.waitForSelector('[data-dd="route"]');
  ok(await page.locator('[data-dd="conn"]').count() === 1 && await page.locator('[data-dd="engine"]').count() === 1,
    "Маршрутизация, подключение и движок — в «Дополнительно»");

  // 5. журнал подключения на экране «Состояние»
  await page.locator('[data-nav="status"]').first().click();
  await page.waitForSelector("#stJournal");
  await page.locator("#stJournal summary").click();
  const jl = await page.locator("#journalBox li").count();
  ok(jl >= 1, "Журнал подключения на экране «Состояние»", `записей: ${jl}`);

  ok(errors.length === 0, "В консоли нет ошибок", errors.slice(0, 3).join(" | "));
  await browser.close();
  process.exit(fails.length ? 1 : 0);
})().catch((e) => { console.log("[FAIL] " + e); process.exit(1); });
