package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Популярные сервисы и их адреса — для своих маршрутов («YouTube — через обход замедления» и т.п.). Как services.py. */
public final class Services {
    private Services() {
    }

    public static final class Service {
        public final String name;
        public final List<String> domains;
        public final boolean russian;

        Service(String name, boolean russian, String... domains) {
            this.name = name;
            this.russian = russian;
            this.domains = Collections.unmodifiableList(Arrays.asList(domains));
        }
    }

    public static final List<Service> ALL = Collections.unmodifiableList(Arrays.asList(
            new Service("Telegram", false, "telegram.org", "t.me", "telesco.pe", "telegram-cdn.org"),
            new Service("WhatsApp", false, "whatsapp.com", "whatsapp.net"),
            new Service("Discord", false, "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"),
            new Service("YouTube", false, "youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtu.be"),
            new Service("Instagram", false, "instagram.com", "cdninstagram.com"),
            new Service("TikTok", false, "tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com",
                    "tiktokv.us", "tiktokv.eu", "tiktokw.us", "tiktokw.eu", "ttwstatic.com", "byteoversea.com", "ibytedtos.com",
                    "ibyteimg.com", "musical.ly", "tiktok-row.net", "byteintlapi.com"),
            new Service("Facebook", false, "facebook.com", "fbcdn.net"),
            new Service("X (Twitter)", false, "x.com", "twitter.com", "twimg.com"),
            new Service("ChatGPT", false, "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"),
            new Service("Claude", false, "claude.ai", "anthropic.com", "claude.com"),
            new Service("Twitch", false, "twitch.tv", "ttvnw.net", "jtvnw.net"),
            new Service("Spotify", false, "spotify.com", "scdn.co"),
            new Service("Steam", false, "steampowered.com", "steamcommunity.com", "steamstatic.com"),
            new Service("Google", false, "google.com"),
            new Service("Госуслуги", true, "gosuslugi.ru"),
            new Service("Сбербанк", true, "sberbank.ru", "sberbank.com"),
            new Service("Т-Банк", true, "tbank.ru", "tinkoff.ru"),
            new Service("Яндекс", true, "ya.ru", "yandex.ru", "yandex.net"),
            new Service("VK", true, "vk.com", "userapi.com"),
            new Service("Ozon", true, "ozon.ru"),
            new Service("Wildberries", true, "wildberries.ru", "wb.ru")));

    /** Адреса YouTube и Discord для обхода замедления (как dpi.py). */
    public static final List<String> YOUTUBE_DOMAINS = Collections.unmodifiableList(Arrays.asList("youtube.com", "youtu.be",
            "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt.be"));
    public static final List<String> DISCORD_DOMAINS = Collections.unmodifiableList(Arrays.asList("discord.com", "discord.gg",
            "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.dev", "discord.new", "discord.gift",
            "discordstatus.com", "dis.gd"));

    public static Service find(String name) {
        for (Service s : ALL) {
            if (s.name.equals(name)) {
                return s;
            }
        }
        return null;
    }

    public static List<String> names() {
        List<String> out = new ArrayList<String>();
        for (Service s : ALL) {
            out.add(s.name);
        }
        return out;
    }
}
