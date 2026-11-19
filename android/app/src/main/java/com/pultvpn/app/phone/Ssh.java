package com.pultvpn.app.phone;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.pultvpn.app.core.Engine;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/** SSH для мастера своего сервера. Пароль используется только для входа и нигде не сохраняется. */
final class Ssh {
    private Ssh() {
    }

    static final long TIMEOUT_MS = 15 * 60 * 1000L;

    static void run(String host, int port, String user, String password, String script, Engine.LineSink out,
                    final Engine.Stop stop) throws Exception {
        JSch jsch = new JSch();
        final Session session = jsch.getSession(user, host, port);
        session.setPassword(password);
        Properties cfg = new Properties();
        cfg.put("StrictHostKeyChecking", "no"); // новый сервер: ключа ещё нет в списке известных
        cfg.put("PreferredAuthentications", "password,keyboard-interactive");
        session.setConfig(cfg);
        session.setServerAliveInterval(15000);
        session.connect(20000);
        ChannelExec ch = null;
        final long started = System.currentTimeMillis();
        Thread watchdog = new Thread(new Runnable() {
            @Override
            public void run() {
                // «Стоп» и слишком долгая установка обрывают соединение — чтение тогда сразу закончится
                while (session.isConnected()) {
                    if (stop.stopped() || System.currentTimeMillis() - started > TIMEOUT_MS) {
                        session.disconnect();
                        return;
                    }
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "ssh-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        try {
            ch = (ChannelExec) session.openChannel("exec");
            ch.setCommand("bash -s");
            OutputStream stdin = ch.getOutputStream();
            InputStream stdout = ch.getInputStream();
            ch.connect(20000);
            stdin.write(script.getBytes(StandardCharsets.UTF_8));
            stdin.flush();
            stdin.close();
            BufferedReader r = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8));
            String line;
            while ((line = r.readLine()) != null) {
                out.line(line);
            }
        } finally {
            if (ch != null) {
                ch.disconnect();
            }
            session.disconnect();
            watchdog.interrupt();
        }
    }
}
