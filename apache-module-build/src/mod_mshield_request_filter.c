#include "mod_mshield.h"

/*
 * Request header filter called via apr_table_do() on all "Cookie" headers.
 *
 * We copy all cookies we want to keep into r->notes (mod_mshield session and free cookies).
 * Cookies are sent in a single line from the browser Cookie: jsessionid=1234; foo=3322;
 *
 * Returns TRUE to continue iteration, FALSE to stop iteration.
 * Also sets ((cookie_res*)result)->status in case of errors.
 */
int
mod_mshield_filter_request_cookies_cb(void *result, const char *key, const char *value) {
    cookie_res *cr = (cookie_res *) result;
    request_rec *r = cr->r;

    char *qa, *cookiestr, *last;

    mod_mshield_server_t *config = ap_get_module_config(r->server->module_config, &mshield_module);

    if (!config) {
        ERRLOG_REQ_CRIT("Cannot load configuration!");
        cr->status = STATUS_ERROR;
        return FALSE; /* abort iteration */
    }

    qa = apr_pstrdup(r->pool, value);
    if (!qa) {
        ERRLOG_REQ_CRIT("Out of memory");
        cr->status = STATUS_ERROR;
        return FALSE; /* abort iteration */
    }

    /* iterate over all cookies in this Cookie: header */
    for (cookiestr = apr_strtok(qa, "; ", &last); cookiestr != NULL; cookiestr = apr_strtok(NULL, "; ", &last)) {
        char *sc = strstr(cookiestr, config->cookie_name);
        if (sc) {
            /* session cookie */
            ERRLOG_REQ_DEBUG("Found a mod_mshield session cookie: [%s]", sc);
            sc += strlen(config->cookie_name);
            if (*sc == '=') {
                cr->sessionid = apr_pstrdup(r->pool, sc + 1);
                continue;
            }
        }

        /* not a session cookie */
        if (config->session_store_free_cookies) {
            switch (mod_mshield_regexp_match(r, config->session_store_free_cookies, cookiestr)) {
                case STATUS_MATCH:
                    ERRLOG_REQ_INFO("Found a free cookie: [%s]", cookiestr);
                    apr_table_add(cr->headers, "Cookie", cookiestr);
                    break;
                case STATUS_NOMATCH:
                    ERRLOG_REQ_CRIT("Ignored unexpected cookie from client [%s]", cookiestr);
                    break;
                case STATUS_ERROR:
                default:
                    ERRLOG_REQ_CRIT("Error matching free cookie regexp (value=[%s])", value);
                    cr->status = STATUS_ERROR;
                    return FALSE; /* abort iteration */
            }
        } else {
            ERRLOG_REQ_INFO("No free cookie URL configured");
        }
    }

    return TRUE;
}

