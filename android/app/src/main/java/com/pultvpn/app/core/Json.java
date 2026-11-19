package com.pultvpn.app.core;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Маленький JSON без библиотек: объекты — LinkedHashMap, массивы — ArrayList, числа — Long или Double.
 * Один и тот же код работает и на Android, и в проверке на обычной Java.
 */
public final class Json {
    private Json() {
    }

    // ---------- разбор ----------

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != p.s.length()) {
            throw p.err("лишние символы после JSON");
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new IllegalArgumentException("ожидался JSON-объект");
        }
        return (Map<String, Object>) v;
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) {
            this.s = s == null ? "" : s;
        }

        IllegalArgumentException err(String msg) {
            return new IllegalArgumentException("JSON: " + msg + " (позиция " + i + ")");
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '﻿') {
                    i++;
                } else {
                    break;
                }
            }
        }

        Object value(int depth) {
            if (depth > 200) {
                throw err("слишком глубокая вложенность");
            }
            if (i >= s.length()) {
                throw err("неожиданный конец");
            }
            char c = s.charAt(i);
            if (c == '{') {
                return object(depth);
            }
            if (c == '[') {
                return array(depth);
            }
            if (c == '"') {
                return string();
            }
            if (c == 't' && s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (c == 'f' && s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            if (c == 'n' && s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return number();
            }
            throw err("непонятный символ «" + c + "»");
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') {
                    throw err("ожидалось имя поля");
                }
                String k = string();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') {
                    throw err("ожидалось двоеточие");
                }
                i++;
                ws();
                m.put(k, value(depth + 1));
                ws();
                if (i >= s.length()) {
                    throw err("неожиданный конец");
                }
                char c = s.charAt(i++);
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    throw err("ожидалась запятая");
                }
            }
        }

        List<Object> array(int depth) {
            List<Object> a = new ArrayList<Object>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == ']') {
                i++;
                return a;
            }
            while (true) {
                ws();
                a.add(value(depth + 1));
                ws();
                if (i >= s.length()) {
                    throw err("неожиданный конец");
                }
                char c = s.charAt(i++);
                if (c == ']') {
                    return a;
                }
                if (c != ',') {
                    throw err("ожидалась запятая");
                }
            }
        }

        String string() {
            StringBuilder b = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) {
                    throw err("незакрытая строка");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return b.toString();
                }
                if (c != '\\') {
                    b.append(c);
                    continue;
                }
                if (i >= s.length()) {
                    throw err("незакрытая строка");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw err("неверный \\u");
                        }
                        try {
                            b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw err("неверный \\u");
                        }
                        i += 4;
                        break;
                    default:
                        throw err("неверная escape-последовательность");
                }
            }
        }

        Object number() {
            int start = i;
            if (s.charAt(i) == '-') {
                i++;
            }
            boolean frac = false;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c >= '0' && c <= '9') {
                    i++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    frac = true;
                    i++;
                } else {
                    break;
                }
            }
            String t = s.substring(start, i);
            try {
                if (!frac) {
                    return Long.parseLong(t);
                }
                return Double.parseDouble(t);
            } catch (NumberFormatException ex) {
                try {
                    return Double.parseDouble(t);
                } catch (NumberFormatException ex2) {
                    throw err("неверное число");
                }
            }
        }
    }

    // ---------- запись ----------

    public static String write(Object v) {
        StringBuilder b = new StringBuilder();
        write(b, v);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof String) {
            quote(b, (String) v);
        } else if (v instanceof Boolean) {
            b.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                b.append("null");
            } else if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                b.append((long) d);
            } else {
                b.append(d);
            }
        } else if (v instanceof Number) {
            b.append(((Number) v).longValue());
        } else if (v instanceof Map) {
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                quote(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof Iterable) {
            b.append('[');
            Iterator<Object> it = ((Iterable<Object>) v).iterator();
            boolean first = true;
            while (it.hasNext()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                write(b, it.next());
            }
            b.append(']');
        } else if (v instanceof Object[]) {
            b.append('[');
            Object[] arr = (Object[]) v;
            for (int k = 0; k < arr.length; k++) {
                if (k > 0) {
                    b.append(',');
                }
                write(b, arr[k]);
            }
            b.append(']');
        } else {
            quote(b, String.valueOf(v));
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    // < и > экранируются: JSON уходит в страницу интерфейса
                    if (c < 0x20 || c == '<' || c == '>' || c == ' ' || c == ' ') {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
    }

    // ---------- удобства ----------

    /** Объект из пар ключ-значение: Json.obj("a", 1, "b", "x"). */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        for (int k = 0; k + 1 < kv.length; k += 2) {
            m.put(String.valueOf(kv[k]), kv[k + 1]);
        }
        return m;
    }

    public static List<Object> arr(Object... items) {
        List<Object> a = new ArrayList<Object>();
        for (Object o : items) {
            a.add(o);
        }
        return a;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    public static Map<String, Object> map(Map<String, Object> m, String key) {
        return m == null ? null : map(m.get(key));
    }

    public static List<Object> list(Map<String, Object> m, String key) {
        return m == null ? null : list(m.get(key));
    }

    /** Вложенный объект; создаётся, если его нет. */
    public static Map<String, Object> child(Map<String, Object> m, String key) {
        Map<String, Object> c = map(m.get(key));
        if (c == null) {
            c = new LinkedHashMap<String, Object>();
            m.put(key, c);
        }
        return c;
    }

    public static String str(Map<String, Object> m, String key, String def) {
        if (m == null) {
            return def;
        }
        Object v = m.get(key);
        if (v == null) {
            return def;
        }
        if (v instanceof Double) {
            double d = (Double) v;
            if (d == Math.rint(d)) {
                return String.valueOf((long) d);
            }
        }
        return String.valueOf(v);
    }

    public static String str(Map<String, Object> m, String key) {
        return str(m, key, "");
    }

    public static long num(Map<String, Object> m, String key, long def) {
        if (m == null) {
            return def;
        }
        Object v = m.get(key);
        if (v instanceof Number) {
            return ((Number) v).longValue();
        }
        if (v instanceof String) {
            try {
                return (long) Double.parseDouble(((String) v).trim());
            } catch (NumberFormatException e) {
                return def;
            }
        }
        return def;
    }

    public static double dbl(Map<String, Object> m, String key, double def) {
        if (m == null) {
            return def;
        }
        Object v = m.get(key);
        if (v instanceof Number) {
            return ((Number) v).doubleValue();
        }
        return def;
    }

    public static boolean bool(Map<String, Object> m, String key, boolean def) {
        if (m == null) {
            return def;
        }
        Object v = m.get(key);
        return v instanceof Boolean ? (Boolean) v : def;
    }

    /** Глубокая копия JSON-значения. */
    @SuppressWarnings("unchecked")
    public static <T> T copy(T v) {
        if (v instanceof Map) {
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                m.put(e.getKey(), copy(e.getValue()));
            }
            return (T) m;
        }
        if (v instanceof List) {
            List<Object> a = new ArrayList<Object>();
            for (Object o : (List<Object>) v) {
                a.add(copy(o));
            }
            return (T) a;
        }
        return v;
    }

    /** JSON с ключами по алфавиту — для устойчивых идентификаторов серверов. */
    @SuppressWarnings("unchecked")
    public static String canonical(Object v) {
        if (v instanceof Map) {
            java.util.TreeMap<String, Object> t = new java.util.TreeMap<String, Object>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                t.put(e.getKey(), e.getValue());
            }
            StringBuilder b = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> e : t.entrySet()) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                b.append(write(e.getKey())).append(':').append(canonical(e.getValue()));
            }
            return b.append('}').toString();
        }
        if (v instanceof List) {
            StringBuilder b = new StringBuilder("[");
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) {
                    b.append(',');
                }
                first = false;
                b.append(canonical(o));
            }
            return b.append(']').toString();
        }
        return write(v);
    }
}
