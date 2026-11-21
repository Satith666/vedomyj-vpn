package com.pultvpn.app.core;

import java.util.Map;

/**
 * Действия интерфейса, которые выполняет только движок (без экрана Android): свои маршруты и прокси,
 * блокировка рекламы, обход замедлений. Общие для приложения и для проверки интерфейса в браузере.
 */
public final class Api {
    private Api() {
    }

    /** Нет такого действия. */
    public static final Object UNKNOWN = new Object();

    public static Object call(Engine e, String action, Map<String, Object> a) {
        switch (action) {
            case "routes":
                return e.routesState();
            case "route_service":
                e.setServiceRoute(Json.str(a, "name"), Json.str(a, "target", "auto"));
                return true;
            case "route_site":
                return e.routeSite(Json.str(a, "host"), Json.str(a, "target", "auto"), Json.bool(a, "main", false));
            case "add_proxy": {
                Map<String, Object> px = e.addProxy(Json.str(a, "raw"), Json.str(a, "name"), Json.str(a, "kind", "auto"),
                        Json.bool(a, "chain", true));
                e.checkProxy(Json.str(px, "id")); // сразу проверить: работает ли и какая страна
                return px;
            }
            case "update_proxy":
                e.updateProxy(Json.str(a, "id"), a.get("name") instanceof String ? (String) a.get("name") : null,
                        a.get("chain") instanceof Boolean ? (Boolean) a.get("chain") : null);
                return true;
            case "remove_proxy":
                e.removeProxy(Json.str(a, "id"));
                return true;
            case "check_proxy":
                return e.checkProxy(Json.str(a, "id"));
            case "ads_set": {
                Map<String, Object> v = Json.map(a, "values");
                return e.setAds(v == null ? Json.obj() : v);
            }
            case "ads_update":
                return e.updateAdblock(false);
            case "ads_allow":
                e.adsAllow(Json.str(a, "host"));
                return true;
            case "ads_site":
                return e.adsSiteAnswer(Json.str(a, "site"), Json.bool(a, "allow", false));
            case "ads_lookup":
                return e.adsLookup(Json.str(a, "host"));
            case "ads_pause":
                e.adsPause(Json.num(a, "minutes", 0));
                return true;
            case "dpi_set": {
                Map<String, Object> v = Json.map(a, "values");
                e.setDpi(v == null ? Json.obj() : v);
                return true;
            }
            case "method":
                e.setMethod(Json.str(a, "method"));
                return e.method();
            case "dpi_pick":
                return e.dpiPick();
            case "repair_site":
                return e.repairSite(Json.str(a, "host"));
            case "app_update_check":
                return e.appUpdateCheck();
            case "leak_test":
                return e.leakTest();
            case "speed_test":
                return e.speedTest();
            case "cert_check":
                return e.certCheck();
            case "ladder_retry":
                return e.ladderRetry();
            case "data_check":
                return e.dataCheckTask();
            case "health_check":
                return e.healthCheck();
            case "net_memory_clear":
                e.netMemoryClear();
                return true;
            case "cert_ack":
                e.certAck();
                return true;
            case "errors_list":
                return e.errorsState();
            case "errors_issue":
                return e.errorsIssue();
            case "errors_clear":
                e.errorsClear();
                return true;
            case "errors_repo":
                return e.setErrorsRepo(Json.str(a, "repo"));
            case "engine_pick":
                e.setEnginePick(Json.str(a, "pick"));
                return true;
            case "awg_info":
                return e.awgInfo(Json.str(a, "key"));
            default:
                return UNKNOWN;
        }
    }
}
