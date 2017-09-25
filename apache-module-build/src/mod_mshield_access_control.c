#include "mod_mshield.h"

/*
 * Check request authorization.
 *
 * Returns:
 * STATUS_ELOGIN	client not logged in yet
 * STATUS_OK		client is properly authorized or no authorization required
 * STATUS_EDENIED	client is properly authenticated, mshield not authorized
 * STATUS_ESTEPUP1	client is properly authenticated, mshield with too low auth_strength (1)
 * STATUS_ESTEPUP2	client is properly authenticated, mshield with too low auth_strength (2)
 * STATUS_ERROR		internal error
 */
apr_status_t
mshield_access_control(request_rec *r, session_t *session, mod_mshield_server_t *config, mod_mshield_dir_t *dconfig) {
    if (!dconfig->logon_required) {
        return STATUS_OK;
    }

    ERRLOG_REQ_DEBUG("MOD_MSHIELD_LOGON_REQUIRED enabled, checking authentication and authorization");
    ERRLOG_REQ_DEBUG("MOD_MSHIELD_LOGON_REQUIRED dconfig [%d]", dconfig->logon_required);
    ERRLOG_REQ_DEBUG("MYLOGIN [%s]", r->uri);


    /* check if login url here (fix for / problem by MSHIELD) */
    /*GET*/
    switch (mod_mshield_regexp_match(r, "(^/mylogin/login.html)|(^/webapp/mblogin/do_login)", r->uri)) {
        case STATUS_MATCH:
            ERRLOG_REQ_DEBUG("MYLOGIN FOUND");
            return STATUS_OK;
        case STATUS_NOMATCH:
            ERRLOG_REQ_DEBUG("MYLOGIN NOMATCH");
            break;
        case STATUS_ERROR:
        default:
            ERRLOG_REQ_CRIT("ERROR while /mylogin/login.html");
            return STATUS_ERROR;
    }



    /*GET*/
    if (session->data->logon_state == 0) {
        ERRLOG_REQ_DEBUG("Client not logged in yet (session->data->logon_state == 0)");
        return STATUS_ELOGIN;
    }
    /*GET*/
    if (session->data->logon_state == 1) {
        ERRLOG_REQ_INFO("Client is logged in successfully (session->data->logon_state == 1)");
        if (config->service_list_enabled_on) {
            ERRLOG_REQ_DEBUG("service list check is on, list is [%s]", session->data->service_list);
            /*GET*/
            if (!apr_strnatcmp(session->data->service_list, "empty")) {
                ERRLOG_REQ_CRIT("Service list check enabled mshield service list not set by login server");
                return STATUS_ERROR;
            }

            /* match URL against service list */
            /*GET*/
            switch (mod_mshield_regexp_match(r, session->data->service_list, r->uri)) {
                case STATUS_MATCH:
                    ERRLOG_REQ_DEBUG("service_list matched: pass through");
                    break;
                case STATUS_NOMATCH:
                    ERRLOG_REQ_CRIT("Access denied - service_list did not match");
                    return STATUS_EDENIED;
                case STATUS_ERROR:
                default:
                    ERRLOG_REQ_CRIT("Error while matching service_list");
                    return STATUS_ERROR;
            }
        } else {
            ERRLOG_REQ_DEBUG("service list check is off");
        }

        /*
        * User is authorized from the uri point of view: Need to check, if the user has the correct auth_level for the requesting uri
        */
        ERRLOG_REQ_INFO("Authentication strength required [%d] session [%d]", dconfig->mod_mshield_auth_strength,
                session->data->auth_strength);
        /*GET*/
        if (session->data->auth_strength >= dconfig->mod_mshield_auth_strength) {
            ERRLOG_REQ_DEBUG("session auth_strength >= required auth_strength");
            return STATUS_OK;
        } else {
            if (dconfig->mod_mshield_auth_strength == 1) {
                ERRLOG_REQ_INFO("redirect to login 1");
                return STATUS_ESTEPUP1;
            }
            if (dconfig->mod_mshield_auth_strength == 2) {
                ERRLOG_REQ_INFO("redirect to login 2");
                return STATUS_ESTEPUP2;
            }
            return STATUS_ERROR;
        }
        /* not reached */
    }

    ERRLOG_REQ_CRIT("Unexpected value of logon state [%d]", session->data->logon_state);
    return STATUS_ERROR;
}
