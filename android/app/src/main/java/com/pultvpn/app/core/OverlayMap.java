package com.pultvpn.app.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Настройки с наложением на один запуск: get() сначала смотрит в overlay (безопасный запуск выключает
 * необязательную автоматику), а сохранение в файл идёт по настоящим значениям (entrySet).
 */
public final class OverlayMap extends LinkedHashMap<String, Object> {
    private static final long serialVersionUID = 1L;
    public final Map<String, Object> overlay = new LinkedHashMap<String, Object>();

    public OverlayMap(Map<String, Object> base) {
        super(base);
    }

    @Override
    public Object get(Object key) {
        if (!overlay.isEmpty() && overlay.containsKey(key)) {
            return overlay.get(key);
        }
        return super.get(key);
    }
}
