// Проверка интерфейса Android-версии: проход по экранам на ширине телефона, без ошибок в консоли.
// Запуск: node ui_walk.js <порт> <папка для снимков>
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const port = process.argv[2];
const out = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "dark" });
  const page = await ctx.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const base = `http://127.0.0.1:${port}`;
  const shot = async (name, full) => { await page.waitForTimeout(250); await page.screenshot({ path: `${out}/${name}.png`, fullPage: !!full }); };
  const waitIdle = async () => {
    for (let i = 0; i < 120; i++) {
      const st = await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result);
      if (!st.busy.title && st.status !== "connecting") return st;
      await page.waitForTimeout(250);
    }
    throw new Error("busy too long");
  };
  await page.goto(`${base}/ui/index.html`);
  await page.waitForSelector(".power");
  await shot("01-empty");
  // добавить подписку
  const subUrl = await (await page.request.get(`${base}/test/suburl`)).text();
  await page.click(".empty .btn.primary");
  await page.fill("#addText", subUrl);
  await page.waitForTimeout(200);
  const det = await page.textContent("#addDetect");
  if (!det.includes("подписка")) throw new Error("detect: " + det);
  await shot("02-add");
  await page.click("#addGo");
  await waitIdle();
  await page.waitForTimeout(1200);
  await shot("03-servers", true);
  // подключиться
  await page.click(".power");
  const st = await waitIdle();
  if (st.status !== "on") throw new Error("not connected: " + st.status);
  await page.waitForTimeout(1200);
  await shot("04-connected");
  const hs = await page.$eval(".health", (e) => e.textContent.replace(/\s+/g, " "));
  if (!hs.includes("Данные") || !hs.includes("Способ")) throw new Error("health strip: " + hs);
  await page.click('[data-act="speed-test"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1200);
  if (!(await page.textContent("#speed")).includes("Мбит/с")) throw new Error("speed test result missing: " + await page.textContent("#speed"));
  // меню сервера
  await page.click('.row[data-act="server"]:not(.current) [data-act="server-menu"]');
  await shot("05-server-menu");
  await page.click("#sheetBack");
  // способ и переключатели на главной
  await page.click('[data-act="method"][data-v="server"]');
  await page.waitForTimeout(300);
  if ((await page.getAttribute('[data-act="method"][data-v="server"]', "aria-checked")) !== "true") throw new Error("method server not selected");
  await page.click('[data-act="method"][data-v="auto"]');
  await page.waitForTimeout(300);
  // AmneziaWG без конфига: не ошибка, а лист «создать бесплатный WARP или вставить свой»
  await page.click('[data-act="method"][data-v="awg"]');
  await page.waitForTimeout(400);
  const warpTxt = await page.$eval("#sheet", (e) => e.textContent.replace(/\s+/g, " "));
  if (!(await page.$('#sheet [data-act="warp-create"]')) || !warpTxt.includes("WARP")) throw new Error("warp sheet: " + warpTxt);
  await shot("05b-warp");
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(300);
  if ((await page.getAttribute('[data-act="method"][data-v="auto"]', "aria-checked")) !== "true") throw new Error("awg without config changed the mode");
  // стрелки у плиток «Способ»: движок, AmneziaWG и ускорение, ускорение без VPN
  await page.click('[data-act="m-dd"][data-v="server"]');
  await page.waitForTimeout(300);
  if (!(await page.$('#sheet [data-act="engine-set"][data-v="hy2"]'))) throw new Error("server arrow: no engine sheet");
  await page.evaluate(() => window.pultBack());
  await page.click('[data-act="m-dd"][data-v="awg"]');
  await page.waitForTimeout(300);
  const awgList = await page.$eval("#sheet", (e) => e.textContent.replace(/\s+/g, " "));
  if (!awgList.includes("WARP") || !(await page.$('#sheet [data-nav="dpi"]'))) throw new Error("awg arrow: " + awgList);
  await shot("05e-awg-list");
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(200);
  // «Не работает» и «Белые списки» — ряд под «Способом»
  const cells = await page.$$eval(".nw-row .nw-cell", (els) => els.map((e) => Math.round(e.getBoundingClientRect().width)));
  if (cells.length !== 2 || Math.abs(cells[0] - cells[1]) > 1) throw new Error("nw row: " + cells);
  await page.click('[data-act="wl-flip"]');
  await page.waitForTimeout(1300);
  await waitIdle();
  if ((await page.getAttribute('[data-act="wl-flip"]', "aria-checked")) !== "true") throw new Error("whitelists box did not turn on");
  await page.click('[data-act="wl-flip"]');
  await page.waitForTimeout(1300);
  await waitIdle();
  if ((await page.getAttribute('[data-act="wl-flip"]', "aria-checked")) !== "false") throw new Error("whitelists box did not turn off");
  await page.click('[data-act="nw-open"]');
  await page.waitForTimeout(300);
  await page.click('#sheet [data-act="nw-sel"][data-v="YouTube"]');
  await page.click('#sheet [data-act="nw-go"]');
  for (let i = 0; i < 60 && !(await page.$("#nwRes .nw-res:not(.busy)")); i++) await page.waitForTimeout(500);
  const nwTxt = await page.$eval("#nwRes", (e) => e.textContent.replace(/\s+/g, " "));
  if (!nwTxt.includes("YouTube")) throw new Error("not working: " + nwTxt);
  await shot("05f-not-working");
  await page.click('#sheet [data-act="nw-tab"][data-v="app"]');
  await page.waitForTimeout(500);
  if (!(await page.$("#nwQ"))) throw new Error("not working: no app search");
  await page.click('#sheet [data-act="nw-tab"][data-v="site"]');
  if (!(await page.$("#nwSite"))) throw new Error("not working: no site field");
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(300);
  // «Семья»: кнопка на главном → приглашение → посылка для устройства
  await page.click("#familyBtn");
  await page.waitForTimeout(400);
  await shot("05c-family");
  await page.click('[data-act="fam-invite"]');
  await page.waitForTimeout(300);
  await page.fill("#famMe", "Сын");
  await page.fill("#famDev", "Мама — телефон");
  await page.click('[data-act="fam-invite-go"]');
  await page.waitForTimeout(500);
  const famTxt = await page.$eval("#sheet", (e) => e.textContent.replace(/\s+/g, " "));
  if (!famTxt.includes("Отправить в мессенджер") || !(await page.$("#sheet img.fam-qr"))) throw new Error("family invite sheet: " + famTxt);
  await shot("05d-family-invite");
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(300);
  await page.click('[data-act="fam-device"]');
  await page.waitForTimeout(400);
  await page.fill("#famSubUrl", "https://example.com/sub/abc");
  await shot("05e-family-device");
  await page.click('[data-act="fam-send"]');
  await page.waitForTimeout(500);
  if (!(await page.$eval("#sheet", (e) => e.textContent)).includes("Посылка для")) throw new Error("family send sheet missing");
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(300);
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(400);
  if (!(await page.$(".route .rt-node"))) throw new Error("route missing on home");
  await page.click('[data-act="flip"][data-k="dns_encrypted"]');
  await waitIdle();
  await page.waitForTimeout(1100);
  // раздача (теперь в «Настройках → Подключение»)
  await page.evaluate(() => window.pultGo("share"));
  await page.waitForTimeout(1100);
  await shot("06-share-off");
  await page.click('[data-act="hotspot-local"]');
  await waitIdle();
  await page.waitForTimeout(1300);
  await shot("07-share-on", true);
  await page.click('[data-act="share-tab"][data-v="telegram"]');
  await shot("08-share-telegram", true);
  const tabsOk = await page.$$eval('.tabs [role="tab"]', (els) => els.every((e) => e.getBoundingClientRect().right <= window.innerWidth - 8));
  if (!tabsOk) throw new Error("share tabs overflow the screen");
  await page.click('[data-act="hotspot-stop"]');
  await waitIdle();
  await page.click("#back");
  // настройки
  await page.click("#settingsBtn");
  await page.waitForTimeout(1100);
  await shot("09-settings", true);
  await page.click('[data-nav="apps"]');
  await page.waitForTimeout(400);
  await page.click('[data-pkg="ru.sberbankmobile"]');
  await shot("10-apps");
  await page.click('[data-act="apps-save"]');
  await waitIdle();
  await page.click('[data-nav="transfer"]');
  await page.waitForTimeout(300);
  await page.click('[data-act="tf-subs"]');
  await shot("11-transfer", true);
  await page.click("#back");
  await page.click('[data-nav="routes"]');
  await page.waitForTimeout(300);
  await page.click('[data-nav="rules"]');
  await page.fill("#r_proxy_list", "example.org\n1.2.3.4");
  await page.click('[data-act="rules-save"]');
  await waitIdle();
  await page.click("#back");
  await page.waitForTimeout(300);
  await page.click('[data-nav="log"]');
  await shot("12-log");
  await page.click("#back");
  await page.click('[data-act="set"][data-k="lang"][data-v="en"]');
  await page.waitForTimeout(1200);
  await shot("13-settings-en");
  await page.click('[data-act="set"][data-k="lang"][data-v="ru"]');
  await page.click('[data-act="set"][data-k="theme"][data-v="light"]');
  await page.waitForTimeout(1200);
  await page.click("#back");
  await page.waitForTimeout(1200);
  await shot("14-home-light", true);
  // блокировка рекламы
  await page.evaluate(() => window.pultGo("ads"));
  await page.waitForTimeout(300);
  await page.click('[data-act="ads-flip"]');
  await page.waitForTimeout(400);
  await waitIdle();
  await page.waitForTimeout(1300);
  const adsText = await page.textContent("#view");
  if (!/В списке \d+ адресов/.test(adsText)) throw new Error("ads: lists not built: " + adsText.slice(0, 300));
  await page.click('[data-act="ads-level"][data-v="pro"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.fill("#adsHost", "main5.ads.example");
  await page.click('[data-act="ads-lookup"]');
  await page.waitForTimeout(200);
  if (!(await page.textContent("#adsLookup")).includes("блокируется: Основной список")) throw new Error("lookup: " + await page.textContent("#adsLookup"));
  await shot("17-ads", true);
  await page.click("#back");
  await page.waitForTimeout(400);
  // обход замедлений
  await page.evaluate(() => window.pultGo("dpi"));
  await page.waitForTimeout(300);
  await page.click('[data-act="dpi-pick"]');
  await page.waitForTimeout(400);
  await waitIdle();
  await page.waitForTimeout(1300);
  const dpiText = await page.textContent("#view");
  if (!dpiText.includes("Работает:")) throw new Error("dpi: no working method: " + dpiText.slice(0, 300));
  await shot("18-dpi", true);
  await page.click("#back");
  await page.waitForTimeout(400);
  // свои маршруты: прокси и сервис через него
  await page.evaluate(() => window.pultGo("routes"));
  await page.waitForTimeout(300);
  await page.fill("#pxRaw", "socks5://user:pass@198.51.100.7:1080");
  await page.fill("#pxName", "TikTok США");
  await page.click('[data-act="px-add"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1300);
  const pxText = await page.textContent("#rtProxies");
  if (!pxText.includes("работает, страна US")) throw new Error("proxy not checked: " + pxText);
  const pid = await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result.routes.proxies[0].id);
  await page.selectOption('select[data-name="TikTok"]', "custom:" + pid);
  await page.waitForTimeout(300);
  await waitIdle();
  await page.fill("#siteHost", "music.example.org");
  await page.selectOption("#siteTarget", "dpi");
  await page.click('[data-act="site-add"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1300);
  const tt = await page.$eval('select[data-name="TikTok"]', (el) => el.value);
  if (tt !== "custom:" + pid) throw new Error("TikTok route not kept: " + tt);
  if (!(await page.textContent("#rtSites")).includes("music.example.org")) throw new Error("site route missing");
  await shot("19-routes", true);
  await page.click("#back");
  await page.waitForTimeout(1200);
  await shot("20-home-tiles");
  // свой сервер
  await page.evaluate(() => window.pultGo("vps"));
  await page.fill("#vpsHost", "vps.example.net");
  await page.fill("#vpsPass", "secret");
  await page.fill("#vpsName", "Мой VPS");
  await page.click('[data-act="vps-go"]');
  await waitIdle();
  await page.waitForTimeout(1300);
  await shot("15-vps-done");
  // свой сервер: состояние и ключ для друга (пароль — только в шторке, для одного действия)
  await page.click('[data-act="vps-check"]');
  await page.fill("#vpPass", "secret");
  await page.click("#vpGo");
  await waitIdle();
  await page.waitForTimeout(1300);
  if (!(await page.textContent("#vpsMine")).includes("Xray")) throw new Error("vps status missing: " + JSON.stringify(await page.textContent("#vpsMine")) + " / " + (await page.textContent("#toast")) + " / " + (await page.evaluate(() => JSON.stringify(JSON.parse(window.Pult.call("state", "{}")).result.message))));
  await page.click('[data-act="vps-friend"]');
  await page.fill("#vfName", "Саша");
  await page.fill("#vpPass", "secret");
  await page.click("#vpGo");
  await waitIdle();
  await page.waitForTimeout(1500);
  if (!(await page.$("#sheet .qr img"))) throw new Error("friend QR did not open");
  await shot("15b-vps-friend-qr");
  await page.click("#sheetBack", { position: { x: 8, y: 8 } });
  await page.waitForTimeout(300);
  await page.$eval("#vpsMine", (el) => el.scrollIntoView());
  await shot("15c-vps-mine");
  const vpsSt = await page.evaluate(() => JSON.stringify(JSON.parse(window.Pult.call("state", "{}")).result.vps));
  if (vpsSt.includes("secret") || !vpsSt.includes("Саша")) throw new Error("vps state: " + vpsSt);
  await page.click("#back");
  await page.waitForTimeout(1200);
  const names = await page.$$eval('.row[data-act="server"] .title > span:first-child', (els) => els.map((e) => e.textContent));
  if (!names.some((n) => n.includes("Мой VPS"))) throw new Error("vps server missing: " + names.join(", "));
  // проверка программы (VPN включён)
  await page.click("#settingsBtn");
  await page.click('[data-nav="check"]');
  await page.click('[data-act="check-run"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1200);
  const items = await page.$$eval(".check-item", (els) => els.map((e) => e.className + " " + e.textContent.replace(/\s+/g, " ")));
  if (items.length < 6) throw new Error("check: too few items: " + items.join(" | "));
  if (!items.some((i) => i.includes("VPN работает"))) throw new Error("check: VPN not checked: " + items.join(" | "));
  await shot("16-check", true);
  await page.click('[data-act="check-send"]');
  const report = await page.evaluate(() => JSON.parse(window.Pult.call("check_text", "{}")).result);
  if (/127\.0\.0\.1|nl1\.example\.com|11111111-2222/.test(report)) throw new Error("check: report leaks addresses");
  if (!(await page.$('.check-item [data-act="check-fix"][data-v="battery"]'))) throw new Error("check: no battery fix button");
  if (items.some((i) => i.includes("Через VPN не открываются"))) throw new Error("check: sites via VPN fail: " + items.join(" | "));
  if (!items.some((i) => i.includes("сертификат Минцифры"))) throw new Error("check: no certificate step: " + items.join(" | "));
  // экран «Состояние»: вывод, данные, способ; проверка сертификатов — сертификат Минцифры, кнопка «Понятно»
  await page.click("#back");
  await page.waitForTimeout(400);
  await page.click('[data-nav="status"]');
  await page.waitForTimeout(500);
  await page.click('[data-act="data-run"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1200);
  const stTxt = await page.$eval("#statusBox", (e) => e.textContent.replace(/\s+/g, " "));
  if (!stTxt.includes("Подключение") || !stTxt.includes("Способ") || !/Данные\s*(идут|не идут)/.test(stTxt))
    throw new Error("status: " + stTxt.slice(0, 500));
  await shot("16a-status", true);
  await page.click('[data-act="cert-run"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1200);
  const certTxt = await page.$eval("#certsCard", (e) => e.textContent.replace(/\s+/g, " "));
  if (!certTxt.includes("сертификат Минцифры") || !certTxt.includes("Подмены сертификатов напрямую нет")
      || !certTxt.includes("Через VPN сертификаты настоящие")) throw new Error("certs: " + certTxt);
  await page.$eval("#certsCard", (e) => e.scrollIntoView());
  await shot("16b-certs");
  await page.click('[data-act="cert-ack"]');
  await page.waitForTimeout(1200);
  if (await page.$('[data-act="cert-ack"]')) throw new Error("certs: ack button still shown");
  const probs = await page.evaluate(() => JSON.stringify(JSON.parse(window.Pult.call("state", "{}")).result.problems));
  if (probs.includes("cert_root")) throw new Error("certs: root problem not resolved: " + probs);
  await page.click('[data-act="health-run"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1200);
  const st2 = await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result);
  if (!st2.leaks || !st2.certs) throw new Error("health check: leaks/certs missing");
  await page.click("#back");
  await page.waitForTimeout(400);
  // «Назад» возвращает список настроек туда же, где он был
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await page.waitForTimeout(200);
  const y0 = await page.evaluate(() => window.scrollY);
  await page.click('[data-nav="log"]');
  await page.waitForTimeout(300);
  await page.click("#back");
  await page.waitForTimeout(400);
  const y1 = await page.evaluate(() => window.scrollY);
  if (y0 < 100 || Math.abs(y1 - y0) > 4) throw new Error(`settings scroll not restored: ${y0} -> ${y1}`);
  // лестница: переключатели в настройках и карточка «ничего не работает» на главной
  const setTxt = await page.$eval("#setBox", (e) => e.textContent.replace(/\s+/g, " "));
  if (!setTxt.includes("Профессиональные")) throw new Error("settings: no advanced row: " + setTxt.slice(0, 400));
  // профессиональные: переключатели защиты и лестницы, сбор ошибок, «вернуть как было»
  await page.click('[data-nav="pro"]');
  await page.waitForTimeout(500);
  const proTxt = await page.$eval("#proBox", (e) => e.textContent.replace(/\s+/g, " "));
  for (const w of ["Предохранители", "Автооткат", "Безопасный запуск", "Подбор отпечатка TLS", "Сторож данных", "Память сетей", "Сбор ошибок"])
    if (!proTxt.includes(w)) throw new Error("pro: no " + w + ": " + proTxt.slice(0, 500));
  await page.click('[data-act="flip"][data-k="guard_rollback"]');
  await page.waitForTimeout(1300);
  if (await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result.settings.guard_rollback) !== false)
    throw new Error("pro: guard switch did nothing: " + (await page.textContent("#toast")) + " / " + (await page.$eval('[data-k="guard_rollback"]', (e) => e.outerHTML)));
  await page.click('[data-act="collect-start"][data-h="1"]');
  await page.waitForTimeout(1300);
  const colTxt = await page.$eval("#proBox", (e) => e.textContent.replace(/\s+/g, " "));
  if (!colTxt.includes("Идёт сбор")) throw new Error("pro: collect not running: " + colTxt.slice(-400));
  await shot("23-pro-collect");
  await page.click('[data-act="collect-stop"]');
  await page.waitForTimeout(400);
  await waitIdle();
  await page.waitForTimeout(1300);
  if (!(await page.$('[data-act="collect-send"]'))) throw new Error("pro: no report after stop: " + (await page.textContent("#toast")));
  const rep = await page.evaluate(() => JSON.parse(window.Pult.call("collect_text", "{}")).result);
  if (!rep.includes("VEDOMYJ") || /11111111-2222|vless:\/\//.test(rep)) throw new Error("pro: bad report: " + rep.slice(0, 300));
  await page.click('[data-act="collect-copy"]');
  await page.click('[data-act="pro-reset"]');
  await page.waitForTimeout(300);
  await page.click("#prYes");
  await page.waitForTimeout(1300);
  if (await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result.settings.guard_rollback) !== true)
    throw new Error("pro: reset did not restore guard");
  await shot("24-pro", true);
  await page.click("#back");
  await page.waitForTimeout(400);
  await page.evaluate(() => window.Pult.call("test_nothing", "{}"));
  await page.click("#back");
  await page.waitForTimeout(1300);
  const ww = await page.$eval("#ww", (e) => (e.hidden ? "HIDDEN" : e.textContent.replace(/\s+/g, " ")));
  if (!ww.includes("Сейчас не работает ни один сервер") || !ww.includes("Яндекс")) throw new Error("what works: " + ww);
  await shot("22-what-works");
  await page.click('[data-act="ladder-retry"]');
  await page.waitForTimeout(300);
  await waitIdle();
  await page.waitForTimeout(1300);
  await page.click("#settingsBtn");
  await page.waitForTimeout(400);
  // журнал ошибок: записи без секретов, репозиторий, заявка
  await page.click('[data-nav="errors"]');
  await page.waitForTimeout(400);
  const errTxt = await page.$eval("#errBox", (e) => e.textContent.replace(/\s+/g, " "));
  if (!errTxt.includes("На телефоне стоит сертификат Минцифры")) throw new Error("errors: no problem entry: " + errTxt);
  if (/127\.0\.0\.1|example\.com|11111111-2222/.test(errTxt)) throw new Error("errors: leaks addresses: " + errTxt);
  await page.fill("#errRepo", "https://github.com/me/vedomyj-vpn");
  await page.click('[data-act="err-repo"]');
  await page.waitForTimeout(400);
  const errTxt2 = await page.$eval("#errBox", (e) => e.textContent.replace(/\s+/g, " "));
  if (!errTxt2.includes("me/vedomyj-vpn") || !(await page.$('[data-act="err-report"]'))) throw new Error("errors: repo not saved: " + errTxt2);
  await page.click('[data-act="err-report"]');
  await page.waitForTimeout(300);
  await shot("21-errors", true);
  await page.click("#back");
  await page.waitForTimeout(400);
  await page.click("#back");
  await page.waitForTimeout(1200);
  // кнопка «назад» телефона
  const handled = await page.evaluate(() => window.pultBack());
  if (handled) throw new Error("back on home should return false");
  // движки: конфиг AmneziaWG вставкой, выбор движка, передача в приложение AmneziaWG
  await page.click('[data-act="add"]');
  await page.fill("#addText", "# Дом\n[Interface]\nPrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=\nAddress = 10.8.1.7/32\nJc = 4\n\n"
    + "[Peer]\nPublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMTI=\nEndpoint = awg.example.com:51820\n");
  await page.waitForTimeout(250);
  const detA = await page.textContent("#addDetect");
  if (!detA.includes("1")) throw new Error("awg detect: " + detA);
  await page.click("#addGo");
  await waitIdle();
  await page.waitForTimeout(1200);
  const rowA = await page.$('.row[data-act="awg"]');
  if (!rowA) throw new Error("awg row missing");
  await page.evaluate(() => window.pultGo("settings")); // способ и движок — в «Настройках → Подключение»
  await page.waitForTimeout(300);
  await page.click('[data-act="engine"]');
  await page.waitForTimeout(300);
  const engTxt = await page.$eval("#sheet", (e) => e.textContent.replace(/\s+/g, " "));
  if (!engTxt.includes("Hysteria2") || !engTxt.includes("AmneziaWG")) throw new Error("engine sheet: " + engTxt);
  await shot("23-engine");
  await page.click('[data-act="engine-set"][data-v="awg"]');
  await page.waitForTimeout(500);
  const awgTxt = await page.$eval("#sheet", (e) => e.textContent.replace(/\s+/g, " "));
  if (!awgTxt.includes("Импорт из файла") || !awgTxt.includes("Сохранить файл .conf") || awgTxt.includes("PrivateKey"))
    throw new Error("awg sheet: " + awgTxt);
  await shot("24-awg");
  await page.click('[data-act="awg-save"]');
  await page.click('[data-act="awg-open"]');
  await page.waitForTimeout(300);
  await page.evaluate(() => window.pultBack()); // кнопка «назад» телефона закрывает лист
  await page.waitForTimeout(300);
  await page.click('[data-act="engine"]');
  await page.waitForTimeout(300);
  await page.click('[data-act="engine-set"][data-v="auto"]');
  await page.waitForTimeout(1200);
  await page.evaluate(() => window.pultBack());
  await page.waitForTimeout(600);
  // выключить
  await page.click(".power");
  await page.waitForTimeout(1200);
  const off = await page.evaluate(() => JSON.parse(window.Pult.call("state", "{}")).result.status);
  if (off !== "off") throw new Error("still on");
  // отступы на всех экранах при ширине 360 и 412: текст не у края, кнопки не вплотную (build/layout_audit.js)
  const audit = fs.readFileSync(path.join(__dirname, "..", "..", "build", "layout_audit.js"), "utf8");
  const tight = [];
  for (const w of [360, 412]) {
    await page.setViewportSize({ width: w, height: 800 });
    await page.evaluate(audit);
    for (const v of ["home", "status", "share", "transfer", "vps", "family", "settings", "apps", "rules", "routes", "ads", "dpi", "check", "errors", "log", "pro"]) {
      if (v !== "home") await page.evaluate((x) => window.pultGo(x), v);
      await page.evaluate(() => window.scrollTo(0, 0)); // шапка закреплена: при прокрутке она «налезает» на экран
      await page.waitForTimeout(400);
      for (const [kind, d] of await page.evaluate("__audit()")) tight.push(`${w}/${v}: ${kind} ${d}`);
      if (v !== "home") { await page.evaluate(() => window.pultBack()); await page.waitForTimeout(250); }
    }
    // листы «Не работает» (все вкладки) и «AmneziaWG ▾»
    await page.click('[data-act="nw-open"]');
    for (const tab of ["service", "app", "site"]) {
      await page.click(`#sheet [data-act="nw-tab"][data-v="${tab}"]`);
      await page.waitForTimeout(400);
      for (const [kind, d] of await page.evaluate("__audit()")) tight.push(`${w}/nw-${tab}: ${kind} ${d}`);
    }
    await page.evaluate(() => window.pultBack());
    await page.click('[data-act="m-dd"][data-v="awg"]');
    await page.waitForTimeout(300);
    for (const [kind, d] of await page.evaluate("__audit()")) tight.push(`${w}/awg-list: ${kind} ${d}`);
    await page.evaluate(() => window.pultBack());
    await page.waitForTimeout(250);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  if (tight.length) throw new Error("tight layout:\n" + tight.join("\n"));
  // горизонтальная прокрутка
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  if (overflow) throw new Error("horizontal overflow");
  await browser.close();
  if (errors.length) { console.log("CONSOLE ERRORS:\n" + errors.join("\n")); process.exit(1); }
  console.log("UI OK");
})().catch((e) => { console.error("FAIL", e); process.exit(1); });
