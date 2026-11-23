#!/bin/sh
# Самопроверка ядра Android-версии на обычной Java (без Android): ./coretest/run.sh
# Нужны JDK 8+ и Python 3 (сверка с программой для Windows).
set -e
cd "$(dirname "$0")"
OUT="${TMPDIR:-/tmp}/pult-coretest-classes"
rm -rf "$OUT" && mkdir -p "$OUT"
javac --release 8 -encoding UTF-8 -Xlint:-options -nowarn -d "$OUT" ../app/src/main/java/com/pultvpn/app/core/*.java
javac --release 8 -encoding UTF-8 -Xlint:-options -nowarn -cp "$OUT" -d "$OUT" CoreTest.java Dump.java
J="java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp $OUT"
fail=0
for m in links routing; do
  $J Dump $m < $m.txt > "$OUT/j_$m.txt"
  python3 dump.py $m < $m.txt > "$OUT/p_$m.txt"
  if cmp -s "$OUT/j_$m.txt" "$OUT/p_$m.txt"; then echo "[OK]   Сверка с Windows: $m"; else echo "[FAIL] Сверка с Windows: $m"; diff "$OUT/p_$m.txt" "$OUT/j_$m.txt" | head -20; fail=1; fi
done
for m in proxies siteentry adsline adsite adsabp; do
  $J Dump $m < $m.txt > "$OUT/j_$m.txt"
  python3 dump.py $m < $m.txt > "$OUT/p_$m.txt"
  if cmp -s "$OUT/j_$m.txt" "$OUT/p_$m.txt"; then echo "[OK]   Сверка с Windows: $m"; else echo "[FAIL] Сверка с Windows: $m"; diff "$OUT/p_$m.txt" "$OUT/j_$m.txt" | head -20; fail=1; fi
done
a=$($J Dump services < /dev/null); b=$(python3 dump.py services < /dev/null)
if [ "$a" = "$b" ]; then echo "[OK]   Сверка с Windows: сервисы и адреса обхода"; else echo "[FAIL] Сверка с Windows: сервисы"; fail=1; fi
for f in sub_b64 sub_json sub_html; do
  a=$($J Dump sub < $f.txt); b=$(python3 dump.py sub < $f.txt)
  if [ "$a" = "$b" ]; then echo "[OK]   Сверка с Windows: $f"; else echo "[FAIL] Сверка с Windows: $f"; fail=1; fi
done
python3 dump.py updatevector < /dev/null > "$OUT/vec.json"
a=$($J Dump updateverify < "$OUT/vec.json")
if [ "$a" = "ok 99.0.0 Тест <b>&</b> «кавычки» | forged rejected" ]; then echo "[OK]   Сверка с Windows: подпись выпуска"; else echo "[FAIL] подпись выпуска: $a"; fail=1; fi
$J Dump vpsawg < /dev/null > "$OUT/j_vpsa.sh"; python3 dump.py vpsawg < /dev/null > "$OUT/p_vpsa.sh"
if cmp -s "$OUT/j_vpsa.sh" "$OUT/p_vpsa.sh"; then echo "[OK]   Сверка с Windows: AmneziaWG 2.0 на своём сервере"; else echo "[FAIL] AmneziaWG 2.0 на своём сервере"; diff "$OUT/p_vpsa.sh" "$OUT/j_vpsa.sh" | head; fail=1; fi
$J Dump vproto < /dev/null > "$OUT/j_vpro.sh"; python3 dump.py vproto < /dev/null > "$OUT/p_vpro.sh"
if cmp -s "$OUT/j_vpro.sh" "$OUT/p_vpro.sh"; then echo "[OK]   Сверка с Windows: свой протокол (диалект, скрипт, ссылка, старое ядро)"; else echo "[FAIL] свой протокол"; diff "$OUT/p_vpro.sh" "$OUT/j_vpro.sh" | head; fail=1; fi
$J Dump vpsxdns < /dev/null > "$OUT/j_vpsd.sh"; python3 dump.py vpsxdns < /dev/null > "$OUT/p_vpsd.sh"
if cmp -s "$OUT/j_vpsd.sh" "$OUT/p_vpsd.sh"; then echo "[OK]   Сверка с Windows: DNS-туннель (домен, скрипт, ссылка, старое ядро)"; else echo "[FAIL] DNS-туннель"; diff "$OUT/p_vpsd.sh" "$OUT/j_vpsd.sh" | head; fail=1; fi
$J Dump vpsbridge < /dev/null > "$OUT/j_vpsb.sh"; python3 dump.py vpsbridge < /dev/null > "$OUT/p_vpsb.sh"
if cmp -s "$OUT/j_vpsb.sh" "$OUT/p_vpsb.sh"; then echo "[OK]   Сверка с Windows: мост через российский сервер"; else echo "[FAIL] мост через российский сервер"; diff "$OUT/p_vpsb.sh" "$OUT/j_vpsb.sh" | head; fail=1; fi
$J Dump vps < /dev/null > "$OUT/j_vps.sh"; python3 dump.py vps < /dev/null > "$OUT/p_vps.sh"
if cmp -s "$OUT/j_vps.sh" "$OUT/p_vps.sh"; then echo "[OK]   Сверка с Windows: скрипт своего сервера"; else echo "[FAIL] скрипт своего сервера"; fail=1; fi
$J Dump dns < /dev/null > "$OUT/j_dns.txt"; python3 dump.py dns < /dev/null > "$OUT/p_dns.txt"
if cmp -s "$OUT/j_dns.txt" "$OUT/p_dns.txt"; then echo "[OK]   Сверка с Windows: запросы и ответы защищённого DNS"; else echo "[FAIL] защищённый DNS"; diff "$OUT/p_dns.txt" "$OUT/j_dns.txt" | head; fail=1; fi
$J Dump vpsextra < /dev/null > "$OUT/j_vpsx.sh"; python3 dump.py vpsextra < /dev/null > "$OUT/p_vpsx.sh"
if cmp -s "$OUT/j_vpsx.sh" "$OUT/p_vpsx.sh"; then echo "[OK]   Сверка с Windows: состояние сервера и ключи друзей"; else echo "[FAIL] состояние сервера и ключи друзей"; diff "$OUT/p_vpsx.sh" "$OUT/j_vpsx.sh" | head; fail=1; fi
a=$($J Dump vpslinks < /dev/null); b=$(python3 dump.py vpslinks < /dev/null)
if [ "$a" = "$b" ]; then echo "[OK]   Сверка с Windows: ссылки своего сервера"; else echo "[FAIL] ссылки своего сервера"; fail=1; fi
$J Dump warp < /dev/null > "$OUT/j_warp.txt"; python3 dump.py warp < /dev/null > "$OUT/p_warp.txt"
if cmp -s "$OUT/j_warp.txt" "$OUT/p_warp.txt"; then echo "[OK]   Сверка с Windows: WARP (ключи, обманки, конфиг)"; else echo "[FAIL] WARP"; diff "$OUT/p_warp.txt" "$OUT/j_warp.txt" | head; fail=1; fi
$J Dump dht < /dev/null > "$OUT/j_dht.txt"; python3 dump.py dht < /dev/null > "$OUT/p_dht.txt"
if cmp -s "$OUT/j_dht.txt" "$OUT/p_dht.txt"; then echo "[OK]   Сверка с Windows: сеть торрентов (bencode, ed25519, ящики «Семьи»)"; else echo "[FAIL] сеть торрентов"; diff "$OUT/p_dht.txt" "$OUT/j_dht.txt" | head; fail=1; fi
$J Dump familyseal < /dev/null > "$OUT/j_fs.txt"; python3 dump.py familyseal < /dev/null > "$OUT/p_fs.txt"
cat "$OUT/j_fs.txt" "$OUT/p_fs.txt" | $J Dump familyopen > "$OUT/j_fo.txt"; cat "$OUT/j_fs.txt" "$OUT/p_fs.txt" | python3 dump.py familyopen > "$OUT/p_fo.txt"
if cmp -s "$OUT/j_fo.txt" "$OUT/p_fo.txt" && [ "$(head -2 "$OUT/j_fs.txt")" = "$(head -2 "$OUT/p_fs.txt")" ]; then echo "[OK]   Сверка с Windows: Семья (приглашения и посылки)"; else echo "[FAIL] Семья"; diff "$OUT/p_fo.txt" "$OUT/j_fo.txt" | head; diff "$OUT/p_fs.txt" "$OUT/j_fs.txt" | head -4; fail=1; fi
$J CoreTest || fail=1
# код для Android компилируется? (с заглушками Android SDK — сам Android SDK для этого не нужен)
rm -rf "$OUT/stubs" "$OUT/stubcls" && mkdir -p "$OUT/stubcls"
python3 make_stubs.py "$OUT/stubs" > /dev/null
find "$OUT/stubs" -name "*.java" > "$OUT/stubs.txt"
javac -encoding UTF-8 -nowarn -d "$OUT/stubcls" @"$OUT/stubs.txt"
if javac --release 8 -encoding UTF-8 -Xlint:-options -nowarn -cp "$OUT/stubcls" -d "$OUT/stubcls" \
    ../app/src/main/java/com/pultvpn/app/core/*.java ../app/src/main/java/com/pultvpn/app/phone/*.java; then
  echo "[OK]   Код для Android компилируется (Java 8, заглушки SDK)"
else
  echo "[FAIL] Код для Android не компилируется"; fail=1
fi
# интерфейс в браузере с настоящим движком (если есть Node.js и Playwright)
if command -v node >/dev/null 2>&1 && node -e "require('playwright')" >/dev/null 2>&1; then
  javac --release 8 -encoding UTF-8 -Xlint:-options -nowarn -cp "$OUT" -d "$OUT" UiServer.java
  PORT=$(( 20000 + $$ % 20000 ))
  $J UiServer ../app/src/main/assets/ui $PORT > "$OUT/ui.log" 2>&1 &
  UIPID=$!
  sleep 2
  mkdir -p "$OUT/shots"
  if node ui_walk.js $PORT "$OUT/shots"; then echo "[OK]   Интерфейс: проход по всем экранам"; else echo "[FAIL] Интерфейс"; fail=1; fi
  kill $UIPID 2>/dev/null
else
  echo "[--]   Интерфейс не проверялся: нет Node.js с Playwright"
fi
exit $fail
