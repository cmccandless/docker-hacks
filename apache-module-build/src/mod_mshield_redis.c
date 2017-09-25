/**
 * @file mod_mshield_redis.c
 * @author Philip Schmid
 * @date 2. May 2017
 * @brief File containing mod_mshield Redis related code.
 */

#include "mod_mshield.h"

/**
 * @brief Helper function which calculates the time diff between two timespec structs in nanoseconds.
 *
 * @param timeA_p The first and bigger (newer) timespec.
 * @param timeB_p The second and smaller (older) timespec.
 *
 * @return nanoseconds difference between \p timeA_p and \p timeB_p
 */
int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p) {
    return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}

/**
 * @brief Function to handle redis replies.
 *
 * @param reply The Redis reply which was created from redisCommand().
 * @param request The apache request which we possibly need to redirect.
 * @param session Current session of the request.
 *
 * @return STATUS_ERROR If reply was NULL or Redis didn't provide 3 elements inside the reply.
 * @return STATUS_REDIRERR If the request redirection failed.
 * @return STATUS_OK If MOD_MSHIELD_RESULT_OK was received from Redis and the request redirection was successful.
 * @return HTTP_MOVED_TEMPORARILY If MOD_MSHIELD_RESULT_FRAUD or MOD_MSHIELD_RESULT_SUSPICIOUS was received from redis
 *         and the redirection was successful.
 */
apr_status_t handle_mshield_result(void *reply, void *request, session_t *session) {

    redisReply *redis_reply = reply;
    request_rec *r = (request_rec *) request;

    apr_status_t status;
    mod_mshield_server_t *config;

    config = ap_get_module_config(r->server->module_config, &mshield_module);

    if (reply == NULL) {
        return STATUS_ERROR;
    }

    if (redis_reply->type == REDIS_REPLY_ARRAY && redis_reply->elements == 3) {
        ap_log_error(PC_LOG_DEBUG, NULL, "FRAUD-ENGINE: Waiting for redis result for request [%s]...",
                     apr_table_get(r->subprocess_env, "UNIQUE_ID"));
        for (int j = 0; j < redis_reply->elements; j++) {
            if (redis_reply->element[j]->str) {
                ap_log_error(PC_LOG_DEBUG, NULL, "FRAUD-ENGINE: Redis psubscribe [%u] %s", j, redis_reply->element[j]->str);
                /* MOD_MSHIELD_RESULT_OK will be the case in most of the time. Therefore check this first. */
                if (strcmp(redis_reply->element[j]->str, MOD_MSHIELD_RESULT_OK) == 0) {
                    ap_log_error(PC_LOG_INFO, NULL, "FRAUD-ENGINE: Engine result for request [%s] is [%s]",
                                 apr_table_get(r->subprocess_env, "UNIQUE_ID"), MOD_MSHIELD_RESULT_OK);
                    return STATUS_OK;
                }
                if (strcmp(redis_reply->element[j]->str, MOD_MSHIELD_RESULT_SUSPICIOUS) == 0) {
                    ap_log_error(PC_LOG_INFO, NULL, "FRAUD-ENGINE: Engine result for request [%s] is [%s]",
                                 apr_table_get(r->subprocess_env, "UNIQUE_ID"), MOD_MSHIELD_RESULT_SUSPICIOUS);
                    ap_log_error(PC_LOG_INFO, NULL, "Current auth_strength of session is [%d]",
                                 session->data->auth_strength);
                    if (session->data->auth_strength < 2) {
                        status = mod_mshield_redirect_to_relurl(r, config->global_logon_server_url_2);
                        if (status == HTTP_MOVED_TEMPORARILY) {
                            ap_log_error(PC_LOG_DEBUG, NULL,
                                         "FRAUD-ENGINE: Redirection to global_logon_server_url_2 was successful");
                            return status;
                        } else {
                            ap_log_error(PC_LOG_CRIT, NULL,
                                         "FRAUD-ENGINE: Redirection to global_logon_server_url_2 failed");
                            return STATUS_REDIRERR;
                        }
                    }
                    return STATUS_OK;
                }
                if (strcmp(redis_reply->element[j]->str, MOD_MSHIELD_RESULT_FRAUD) == 0) {
                    ap_log_error(PC_LOG_INFO, NULL, "FRAUD-ENGINE: Engine result for request [%s] is [%s]",
                                 apr_table_get(r->subprocess_env, "UNIQUE_ID"), MOD_MSHIELD_RESULT_FRAUD);
                    status = mod_mshield_redirect_to_relurl(r, config->fraud_detected_url);
                    /* Drop the fraudly session! */
                    mshield_session_unlink(session);
                    if (status == HTTP_MOVED_TEMPORARILY) {
                        ap_log_error(PC_LOG_DEBUG, NULL,
                                     "FRAUD-ENGINE: Redirection to fraud_detected_url was successful");
                        return status;
                    } else {
                        ap_log_error(PC_LOG_CRIT, NULL, "FRAUD-ENGINE: Redirection to fraud_detected_url failed");
                        return STATUS_REDIRERR;
                    }
                }
            }

        }
    }
    return STATUS_ERROR;
}
