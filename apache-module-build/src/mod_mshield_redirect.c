#include "mod_mshield.h"

/*
 * Redirect to a relative URI.  Adds a Location header to the request and
 * returns the appropriate HTTP response code.
 *
 * This function directly returns HTTP error codes, so the correct way to
 * call it is:
 *    return mod_mshield_redirect_to_relurl(r, uri);
 */
int
mod_mshield_redirect_to_relurl(request_rec *r, const char *relurl) {
    const char *url, *host;
    apr_port_t port;

    if (!relurl) {
        ERRLOG_REQ_CRIT("Redirection to NULL attempted!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Check for CR/LF injection; if we still have unencoded newlines or
     * carriage returns in relurl here, deny the redirection.
     * This is a last resort against HTTP Response Splitting attacks.
     * If we still have CR/LF characters here, then that would be a bug
     * in the calling code which must be fixed.
     */
    switch (mod_mshield_regexp_match(r, "[\r\n]", relurl)) {
        case STATUS_MATCH:
            ERRLOG_REQ_CRIT("ATTACK: Target URL contains raw CR/LF characters [%s]", relurl);
            ERRLOG_REQ_CRIT("This is a bug in mod_mshield - CR/LF chars should be encoded!");
            return HTTP_INTERNAL_SERVER_ERROR;
        case STATUS_NOMATCH:
            ERRLOG_REQ_DEBUG("Target URL does not contain CR/LF [%s]", relurl);
            break;
        case STATUS_ERROR:
        default:
            ERRLOG_REQ_CRIT("Error while matching CRLF");
            return HTTP_INTERNAL_SERVER_ERROR;
    }

    port = ap_get_server_port(r);
    if ((port != DEFAULT_HTTP_PORT) && (port != DEFAULT_HTTPS_PORT)) {
        /* because of multiple passes through don't use r->hostname() */
        host = apr_psprintf(r->pool, "%s:%d", ap_get_server_name(r), port);
    } else {
        host = apr_psprintf(r->pool, "%s", ap_get_server_name(r));
    }
    //url = apr_psprintf(r->pool, "%s", relurl);
    url = apr_psprintf(r->pool, "%s://%s%s", ap_http_scheme(r), host, relurl);

    apr_table_unset(r->err_headers_out, "Location");
    apr_table_unset(r->headers_out, "Location");
    apr_table_set(r->err_headers_out, "Location", url);
    r->content_type = NULL;

    ERRLOG_REQ_DEBUG("Redirect: 302 Moved Temporarily; Location: %s", url);

    return HTTP_MOVED_TEMPORARILY;
}


/*
 * Redirect to cookie_try next stage, or cookie refused URL.
 *
 * This function directly returns HTTP error codes, so the correct way
 * to call it is:
 *    return mod_mshield_handle_shm_error(r);
 */
int
mod_mshield_redirect_to_cookie_try(request_rec *r, mod_mshield_server_t *config) {
    int cookie_try, i;
    char *target_uri;

    /*
     * Get cookie try argument and redirect to next cookie_try stage.
     * If cookie_try >= 3, redirect to the cookie refused error page.
     */
    cookie_try = mod_mshield_find_cookie_try(r);
    ERRLOG_REQ_DEBUG("Parsed cookie_try=[%d]", cookie_try);
    if (cookie_try < 0) {
        ERRLOG_REQ_CRIT("Cookie Test Error [%d]", cookie_try);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (cookie_try >= 3) {
        return mod_mshield_redirect_to_relurl(r, config->client_refuses_cookies_url);
    }

    cookie_try++;
    ERRLOG_REQ_DEBUG("Redirecting to cookie test stage %s=%d", MOD_MSHIELD_COOKIE_TRY, cookie_try);

    /*
     * Strip all GET parameters from r->unparsed_uri,
     * append the cookie_try parameter, and redirect.
     */
    target_uri = apr_pstrdup(r->pool, r->unparsed_uri);
    if (target_uri == NULL) {
        ERRLOG_REQ_CRIT("Out of memory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    for (i = strlen(target_uri); i > 0; i--) {
        if (target_uri[i] == '?') {
            target_uri[i] = '\0';
        }
    }
    ERRLOG_REQ_DEBUG("r->uri=[%s] r->unparsed_uri=[%s] target_uri=[%s]", r->uri, r->unparsed_uri, target_uri);
    return mod_mshield_redirect_to_relurl(r, apr_psprintf(r->pool, "%s?%s=%d", target_uri, MOD_MSHIELD_COOKIE_TRY,
                                                          cookie_try));
}


/*
 * Handle an out of SHM memory condition by redirecting the user to the
 * error page, if available, or generating an internal server error.
 *
 * This function directly returns HTTP error codes, so the correct way
 * to call it is:
 *    return mod_mshield_handle_shm_error(r);
 */
int
mod_mshield_redirect_to_shm_error(request_rec *r, mod_mshield_server_t *config) {
    ERRLOG_REQ_CRIT("All SHM space used!");

    apr_table_unset(r->headers_out, "Set-Cookie");
    apr_table_unset(r->err_headers_out, "Set-Cookie");

    if (config->all_shm_space_used_url == NULL) {
        ERRLOG_REQ_INFO("MOD_MSHIELD_ALL_SHM_SPACE_USED_URL not configured in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return mod_mshield_redirect_to_relurl(r, config->all_shm_space_used_url);
}


/*
 * Parse the first (!) __cookie_try parameter from the request arguments.
 *
 * Returns value of parameter __cookie_try or 0 if it was not found.
 */
int
mod_mshield_find_cookie_try(request_rec *r) {
    char *p;
    static const char *param_name = MOD_MSHIELD_COOKIE_TRY;
    ERRLOG_REQ_DEBUG("r->args: [%s]", r->args);

    if (!r->args) {
        return 0;
    }

    p = strstr(r->args, param_name);
    if (p) {
        p += strlen(param_name);
        if (*p == '=') {
            char *cid = (char *) apr_pstrdup(r->pool, p + 1);
            if (cid) {
                p = strchr(cid, '&');
                if (p)
                    *p = '\0';
                return atoi(cid);
            }
        }
    }
    return 0;
}


/*
 * Strip __cookie_try parameter from the relative URL.
 * We just cut in front of the __cookie_try; arguments following it
 * are silently discarded.  This is not a problem since the
 * __cookie_try is always appended without additional parameters,
 * mshield an improved version of this function could just strip out
 * the __cookie_try=n and fix up the resulting URL.
 *
 * Note that this function will modify the original string.
 */
char *
mod_mshield_strip_cookie_try(char *relurl) {
    char *p;
    static const char *param_str = MOD_MSHIELD_COOKIE_TRY "=";

    if (relurl && (p = strstr(relurl, param_str))) {
        p--;
        if (*p == '?' || *p == '&') {
            *p = '\0';
        }
    }
    return relurl;
}
