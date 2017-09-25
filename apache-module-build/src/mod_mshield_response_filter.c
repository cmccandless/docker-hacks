#include "mod_mshield.h"

/*
 * Parse Set-Cookie string into cookie name and value.
 * cookiestr does not include the Set-Cookie: header name, only the content.
 */
static void
parse_cookie(request_rec *r, const char *cookiestr, char **pname, char **pvalue) {
    char *substr, *end;

    substr = strchr(cookiestr, '=');
    *pname = apr_pstrndup(r->pool, cookiestr, (strlen(cookiestr) - strlen(substr)));
    substr++;    /* now substr points to the value */
    end = strchr(substr, ';');
    if (end) {
        *pvalue = apr_pstrndup(r->pool, substr, (strlen(substr) - strlen(end)));
    } else {
        *pvalue = apr_pstrndup(r->pool, substr, strlen(substr));
    }
}


/*
 * Parse Set-Cookie string containing MOD_MSHIELD_BACKEND_SESSION command.
 * cookiestr does not include the Set-Cookie: header name, only the content.
 * We need the raw cookie data because the command cookie syntax contains
 * semicolons (in violation of cookie specs).
 */
static void
parse_cookie_backend_session(request_rec *r, const char *cookiestr,
                             char **pbname, char **pbvalue, char **pbclearance) {
    char *last;
    char *tok = NULL;
    char *p = NULL;

    *pbname = NULL;
    *pbvalue = NULL;
    *pbclearance = NULL;

    for (tok = apr_strtok(apr_pstrdup(r->pool, cookiestr), "; ", &last);
         tok != NULL; tok = (char *) apr_strtok(NULL, "; ", &last)) {
        if ((p = strstr(tok, "bname"))) {
            p += strlen("bname");
            if (*p == '=') {
                *pbname = apr_pstrdup(r->pool, p + 1);
            }
        }
        if ((p = strstr(tok, "bvalue"))) {
            p += strlen("bvalue");
            if (*p == '=') {
                *pbvalue = apr_pstrdup(r->pool, p + 1);
            }
        }
        if ((p = strstr(tok, "bclearance"))) {
            p += strlen("bclearance");
            if (*p == '=') {
                *pbclearance = apr_pstrdup(r->pool, p + 1);
            }
        }
    }
}


/*
 * Filter cookies from all URLs.
 */
static int
filter_response_cookie(request_rec *r, cookie_res *cr,
                       mod_mshield_server_t *config, mod_mshield_dir_t *dconfig,
                       char *cookie_name, char *cookie_value, const char *cookiestr) {
    apr_status_t status;

    /* Add free cookies back into to final response. */
    if (config->session_store_free_cookies) {
        switch (mod_mshield_regexp_match(r, config->session_store_free_cookies,
                                         apr_pstrcat(r->pool, cookie_name, "=", cookie_value,
                                                     NULL))) { /* XXX do we really want to match the cookie value as well? */
            case STATUS_MATCH:
                ERRLOG_REQ_DEBUG("Found free cookie [%s] [%s]", cookie_name, cookie_value);
                apr_table_add(cr->headers, "Set-Cookie", cookiestr);
                return TRUE;
            case STATUS_NOMATCH:
                break;
            case STATUS_ERROR:
            default:
                ERRLOG_REQ_CRIT("Error while matching free cookie regexp");
                cr->status = STATUS_ERROR;
                return FALSE; /* abort iteration */
        }
    }

    /* Store all other cookies to the cookie store. */
/*SET*/    status = mshield_session_set_cookie(cr->session, cookie_name, cookie_value,
                                               dconfig->mod_mshield_location_id);
    if (status != STATUS_OK) {
        ERRLOG_REQ_CRIT("Error while storing cookie!");
        cr->status = status;
        return FALSE; /* abort iteration */
    }

    return TRUE;
}


/*
 * Special handling for cookies from a logon URL.
 * Called for cookies from logon URLs.
 */
int
filter_response_cookie_from_logon_url(request_rec *r, cookie_res *cr,
                                      mod_mshield_server_t *config, mod_mshield_dir_t *dconfig,
                                      char *cookie_name, char *cookie_value, const char *cookiestr) {
    /* LOGON=ok */
    if (!apr_strnatcmp(cookie_name, config->global_logon_auth_cookie_name)) {
        ERRLOG_REQ_DEBUG("LOGON cookie was found in HTTP response message");

        /* check cookie value */
        if (!apr_strnatcmp(cookie_value, config->global_logon_auth_cookie_value)) {
            ERRLOG_REQ_INFO("LOGON OK received");
            ERRLOG_REQ_DEBUG("Setting cr->session->data->logon_state=1 and cr->must_renew=1");
            /*SET*/
            cr->session->data->logon_state = 1;
            cr->must_renew = 1;
        } else {
            ERRLOG_REQ_CRIT("Ignoring LOGON cookie with value [%s], expected [%s]", cookie_value,
                        config->global_logon_auth_cookie_value);
        }
        return TRUE;
    }

    /* If we've seen a valid LOGOK=ok in this request, handle special command cookies. */
    if (cr->must_renew) {
        ERRLOG_REQ_DEBUG("Handle Special Cookie (AUTH_STRENGTH) because LOGON=ok found");
        /* Authentication strength */
        if (!apr_strnatcmp(cookie_name, "MOD_MSHIELD_AUTH_STRENGTH")) { /* XXX make cookie name configurable */
            int auth_strength = atoi(cookie_value);
            ERRLOG_REQ_INFO("Received auth_strength from login server: %d", auth_strength);
            if ((auth_strength >= 0) && (auth_strength <= 2)) {
                /*SET*/
                cr->session->data->auth_strength = auth_strength;
            } else {
                /*SET*/
                cr->session->data->auth_strength = 0;
            }
            return TRUE;
        }

        /* Service list cookie */
        ERRLOG_REQ_DEBUG("Handle Special Cookie (Service List Cookie) because LOGON=ok found");
        if (!apr_strnatcmp(cookie_name, config->service_list_cookie_name)) {
            ERRLOG_REQ_INFO("Found Service List Cookie [%s]", cookie_value);
            /*SET*/
            apr_cpystrn(cr->session->data->service_list, cookie_value, sizeof(cr->session->data->service_list));
            return TRUE;
        }

        /* Redirect URL cookie */
        ERRLOG_REQ_DEBUG("Handle Special Cookie (MOD_MSHIELD_REDIRECT) because LOGON=ok found");
        if (!apr_strnatcmp(cookie_name, "MOD_MSHIELD_REDIRECT")) { /* XXX make cookie name configurable */
            /*SET*/
            apr_cpystrn(cr->session->data->redirect_url_after_login, cookie_value,
                        sizeof(cr->session->data->redirect_url_after_login));
            ERRLOG_REQ_INFO("xxx-xxx Found MOD_MSHIELD_REDIRECT [%s]", cookie_value);
            return TRUE;
        }



        /* DLS support: allow login servers to set cookies for other location IDs.
         * We use cookiestr for parsing because of the semicolon separator used in
         * the login service command cookie protocol specification. */
        ERRLOG_REQ_DEBUG("Handle Special Cookie (MOD_MSHIELD_BACKEND_SESSION) because LOGON=ok found");
        if (!apr_strnatcmp(cookie_name, "MOD_MSHIELD_BACKEND_SESSION")) { /* XXX make cookie name configurable */
            char *bname, *bvalue, *bclearance;
            char *last;

            ERRLOG_REQ_INFO("Found MOD_MSHIELD_BACKEND_SESSION [%s]", cookiestr);
            parse_cookie_backend_session(r, cookiestr, &bname, &bvalue, &bclearance);
            ERRLOG_REQ_INFO("Parsed bname [%s] bvalue [%s] bclearance [%s]", bname, bvalue, bclearance);

            /* loop over location IDs in bclearance locid list */
            for (bclearance = apr_strtok(bclearance, ",", &last);
                 bclearance != NULL; bclearance = apr_strtok(NULL, ",", &last)) {
                /*SET*/
                apr_status_t status = mshield_session_set_cookie(cr->session, bname, bvalue, atoi(bclearance));
                if (status != STATUS_OK) {
                    ERRLOG_REQ_CRIT("Error while storing cookie!");
                    cr->status = status;
                    return FALSE; /* abort iteration */
                }
            }

            return TRUE;
        }
        /* end of LOGON=ok command cookies */
    }

    return filter_response_cookie(r, cr, config, dconfig, cookie_name, cookie_value, cookiestr);
}


/*
 * This function is called for all Set-Cookie HTTP RESPONSE HEADERs
 *
 * HTTP/1.1 302 Found
 * Date: Mon, 22 Aug 2005 21:10:45 GMT
 * Set-Cookie: E2=jLllj33EsXhInvgW5KDkMtzB4YcqLy2Eawv1EAbY0K3NGUHczLF1oIrJ7bURyw1; domain=mshield.ch; path=/;
 * Set-Cookie: TEST=ABC;
 * Set-Cookie: FREECOOKIE=123;
 * Location: /cgi/cgi-bin/printenv?__cookie_try=1
 * Content-Length: 281
 * Content-Type: text/html; charset=iso-8859-1
 *
 * It checks the Set-Cookie headers.
 *
 * Returns:
 *   TRUE  - continue iteration
 *   FALSE - abort iteration
 *
 * Sets ((cookie_res*)result)->status to signal error conditions.
 */
int
mod_mshield_filter_response_cookies_cb(void *result, const char *key, const char *value) {
    cookie_res *cr = (cookie_res *) result;
    request_rec *r = cr->r;
    mod_mshield_server_t *config;
    mod_mshield_dir_t *dconfig;
    char *cookie_name, *cookie_value;

    config = ap_get_module_config(r->server->module_config, &mshield_module);
    if (!config) {
        ERRLOG_REQ_CRIT("Illegal server configuration");
        cr->status = STATUS_ERROR;
        return FALSE;
    }
    dconfig = ap_get_module_config(r->per_dir_config, &mshield_module);
    if (!dconfig) {
        ERRLOG_REQ_CRIT("Illegal directory configuration");
        cr->status = STATUS_ERROR;
        return FALSE;
    }

    parse_cookie(r, value, &cookie_name, &cookie_value);

    /*
     * Set the username for the session.
     * Source for the username is the MOD_MSHIELD_USERNAME_VALUE value from the LS logon ok cookie.
     */
    if (!apr_strnatcmp(cookie_name, config->username_value) && cr->session->data->logon_state == 1) {
        apr_cpystrn(cr->session->data->username, cookie_value, sizeof(cr->session->data->username));
        ERRLOG_REQ_INFO("FRAUD-ENGINE: Received USERNAME [%s] for UUID [%s]", cr->session->data->username,
                    cr->session->data->uuid);

        cJSON *user_mapping_json;
        user_mapping_json = cJSON_CreateObject();
        cJSON_AddItemToObject(user_mapping_json, "userName", cJSON_CreateString(cr->session->data->username));
        cJSON_AddItemToObject(user_mapping_json, "sessionUUID", cJSON_CreateString(cr->session->data->uuid));

        ERRLOG_REQ_DEBUG("FRAUD-ENGINE: Sent JSON user mapping object is: [%s]", cJSON_Print(user_mapping_json));

        if (config->fraud_detection_enabled) {
            kafka_produce(config->pool, &config->kafka, config->kafka.topic_usermapping, &config->kafka.rk_topic_usermapping,
                          RD_KAFKA_PARTITION_UA, cJSON_Print(user_mapping_json), cr->session->data->uuid);
        }

        cJSON_Delete(user_mapping_json);
    }


    if (!apr_strnatcmp(cookie_name, "") && !apr_strnatcmp(cookie_value, "")) {
        ERRLOG_REQ_INFO("Skipped Set-Cookie with empty name [%s] or empty value [%s]", cookie_name, cookie_value);
        return TRUE;
    }

    switch (mod_mshield_regexp_match(r, config->authorized_logon_url, r->uri)) {
        case STATUS_MATCH:
            ERRLOG_REQ_DEBUG("xxx-xxx Trusted Cookie from Authorized LOGON URL");
            ERRLOG_REQ_DEBUG("xxx-xxx Cookie Name [%s] and Value [%s]", cookie_name, cookie_value);
            /*SET*/
            return filter_response_cookie_from_logon_url(r, cr, config, dconfig, cookie_name, cookie_value, value);
        case STATUS_NOMATCH:
            ERRLOG_REQ_DEBUG("xxx-xxx Found Cookie mshield not from Authorized LOGON URL");
            /*SET*/
            return filter_response_cookie(r, cr, config, dconfig, cookie_name, cookie_value, value);
        case STATUS_ERROR:
        default:
            ERRLOG_REQ_CRIT("xxx-xxx DEFAULT mod_mshield_filter_response_cookies_cb");
            cr->status = STATUS_ERROR;
            return FALSE;
    }
}
