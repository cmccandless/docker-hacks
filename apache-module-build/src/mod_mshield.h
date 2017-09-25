/**
 * @file mod_mshield.h
 * @author Philip Schmid
 * @date 2. May 2017
 * @brief mod_mshield main header file
 */

#ifndef MOD_MSHIELD_H
#define MOD_MSHIELD_H

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_hash.h"
#include "apr_want.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"
#include "util_script.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_core.h"
#include "util_md5.h"
#include "pcre.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "ap_config.h"
#include "apr_optional.h"
#include "apr_base64.h"
#include "apr_anylock.h"
#include "ap_mpm.h"
#include "stdbool.h"

#include "mod_mshield_debug.h"
#include "mod_mshield_errno.h"
#include "mod_mshield_compat.h"

#include "cJSON.h"

#include "librdkafka/rdkafka.h"

#include "hiredis/hiredis.h"


/********************************************************************
 * <!-- Configuration default values -->
 */
#define MOD_MSHIELD_COOKIE_NAME                     "MOD_MSHIELD"                                   /**< The name of the session cookie */
#define MOD_MSHIELD_COOKIE_DOMAIN                   ""                                              /**< Cookie Domain Specifier */
#define MOD_MSHIELD_COOKIE_PATH                     "/"                                             /**< The path of the cookie */
#define MOD_MSHIELD_COOKIE_REFUSE_URL               "/refused_cookies.html"                         /**< URL, if client refuses the set-cookie header and if not configured in httpd.conf */
#define MOD_MSHIELD_SESSION_FREE_URL                "^/refused_cookies.html$"                       /**< FREE URL's (session not required for theses regexp URL's) */
#define MOD_MSHIELD_COOKIE_EXPIRATION               ""                                              /**< The expiration date of the cookie */
#define MOD_MSHIELD_COOKIE_SECURE                   1                                               /**< Cookie secure flag (0, 1) */
#define MOD_MSHIELD_COOKIE_HTTPONLY                 1                                               /**< Cookie HTTPonly flag (0, 1) */
#define MOD_MSHIELD_DEFAULT_SHM_SIZE                "32768"                                         /**< Default Shared Memory Segment */
#define MOD_MSHIELD_SESSION_HARD_TIMEOUT            3600                                            /**< Session hard timeout in seconds */
#define MOD_MSHIELD_SESSION_INACTIVITY_TIMEOUT      900                                             /**< Session inactivity timeout in seconds */
#define MOD_MSHIELD_SESSION_INACTIVITY_TIMEOUT_URL  "/mod_mshield/error/session_inactivity.html"    /**< Session inactivity timeout URL */
#define MOD_MSHIELD_SESSION_TIMEOUT_URL             "/mod_mshield/error/session_expired.html"       /**< Session timeout URL */
#define MOD_MSHIELD_SESSION_RENEW_URL               "^/renew/"                                      /**< Regexp when a session shall be renewed */
#define MOD_MSHIELD_SESSION_DESTROY                 "^/logout/"                                     /**< Session destroy regexp */
#define MOD_MSHIELD_SESSION_DESTROY_URL             ""                                              /**< Session destroy url */
#define MOD_MSHIELD_GLOBAL_LOGON_SERVER_URL         ""                                              /**< URL for global logon server (default) */
#define MOD_MSHIELD_GLOBAL_LOGON_SERVER_URL_1       ""                                              /**< URL for global logon server (username & password) */
#define MOD_MSHIELD_GLOBAL_LOGON_SERVER_URL_2       ""                                              /**< URL for global logon server (strong authentication) */
#define MOD_MSHIELD_GLOBAL_LOGON_AUTH_COOKIE_NAME   "LOGON"                                         /**< Cookiename for authentication */
#define MOD_MSHIELD_GLOBAL_LOGON_AUTH_COOKIE_VALUE  "ok"                                            /**< Cookievalue for successful authentication */
#define MOD_MSHIELD_SHM_USED_URL                    "/mod_mshield/error/session_shm_used.html"      /**< URL if a shm problem occours */
#define MOD_MSHIELD_FREE_COOKIES                    "^language=|^trustme="                          /**< Cookies not stored in cookie store */
#define MOD_MSHIELD_SERVICE_LIST_COOKIE_NAME        "MOD_MSHIELD_SERVICE_LIST"                      /**< The name of the  cookie */
#define MOD_MSHIELD_SERVICE_LIST_COOKIE_VALUE       "^/.*$"                                         /**< Default service list */
#define MOD_MSHIELD_SERVICE_LIST_ERROR_URL          ""                                              /**< Authorization error page url */
#define MOD_MSHIELD_AUTHORIZED_LOGON_URL            "^/.*$"                                         /**< From what r->uri LOGON=ok cookies are accepted */
#define MOD_MSHIELD_AUTHORIZATION_ENABLED           0                                               /**< Enable session authentication */
#define MOD_MSHIELD_URL_AFTER_RENEW                 "/"                                             /**< Set url after renew here */
#define MOD_MSHIELD_ENABLED_RETURN_TO_ORIG_URL      0                                               /**< MOD_MSHIELD_ENABLED_RETURN_TO_ORIG_URL */
#define MOD_MSHIELD_ALL_SHM_SPACE_USED_URL          ""                                              /**< URL of error page if a shm is full */
#define MOD_MSHIELD_USERNAME_VALUE                  "MOD_MSHIELD_USERNAME"                          /**< Login server LOGON cookie username value name (needs to be the same as in login.php) */

#define MOD_MSHIELD_FRAUD_DETECTION_ENABLED         0                                               /**< By default the fraud detection functionality is off */
#define MOD_MSHIELD_FRAUD_LEARNING_MODE             0                                               /**< By default the fraud detection learning mode is off */
#define MOD_MSHIELD_FRAUD_VALIDATION_THRESHOLD      3                                               /**< If a risk level surpass or equals this threshold, a session ration result from the engine is required. */
#define MOD_MSHIELD_FRAUD_DETECTED_URL              "/error/fraud_detected.html"                    /**< Set the URL to redirect to if a fraud is found */
#define MOD_MSHIELD_FRAUD_ERROR_URL                 "/error/fraud_error.html"                       /**< Set the URL to redirect to if the analyse fails */
#define MOD_MSHIELD_KAFKA_BROKER                    ""                                              /**< Set the kafka broker IP and port */
#define MOD_MSHIELD_KAFKA_TOPIC_ANALYSE             "MarkovClicks"                                  /**< Set Kafka topic on which clicks are sent to the engine */
#define MOD_MSHIELD_KAFKA_TOPIC_USERMAPPING         "MarkovLogins"                                  /**< Set Kafka topic on which the username <-> UUID mapping is sent to the engine */
#define MOD_MSHIELD_KAFKA_TOPIC_URL_CONFIG          "MarkovUrlConfigs"                              /**< Set Kafka topic on which the url <-> risk_level configuration is sent to the engine */
#define MOD_MSHIELD_KAFKA_MSG_DELIVERY_TIMEOUT      3                                               /**< Timeout for the Kafka message delivery check (in seconds!) */
#define MOD_MSHIELD_KAFKA_DELIVERY_CHECK_INTERVAL   100000                                          /**< Time to sleep between kafka produce delivery report polls (in ns!) */
#define MOD_MSHIELD_REDIS_SERVER                    ""                                              /**< Set the redis server */
#define MOD_MSHIELD_REDIS_PORT                      0                                               /**< Set the redis server's port */
#define MOD_MSHIELD_REDIS_RESPONSE_TIMEOUT          3                                               /**< Set how long to wait for request analyse result (in seconds!) */
#define MOD_MSHIELD_REDIS_CONNECTION_TIMEOUT        3                                               /**< Set Redis connection timeout (in seconds!) */


/********************************************************************
 * <!-- Compile time configuration -->
 */

/**
 * @brief Session ID bytes
 *
 * 192 bits of entropy is 2^64 times better security than "standard" 128 bits
 * Note that under Linux, starving entropy from /dev/random can lead to Apache blocking until
 * sufficient amounts of entropy is available.  This is an APR issue, not a mod_mshield issue.
 */
#define MOD_MSHIELD_SIDBYTES        24

/**
 * @brief Cookie test suffix
 *
 * Appended to URLs like:
 * @code
 *      host/foo/bar?__cookie_try=1
 * @endcode
 */
#define MOD_MSHIELD_COOKIE_TRY        "__cookie_try"

#ifndef MOD_MSHIELD_SESSION_COUNT
/**
 * @brief Default number of mod_mshield sessions (SHM)
 * @note 120000 sessions require about 30 seconds to start (init) and allocate 6 MB
 *       10000 sessions require about 10 seconds to start (init) and allocate 3 MB
 *       (on a Sun E4500 Solaris 10 system with 8 400 MHz Sparc CPUs)
 *
 * @warning These are meant to be overridden using the -D compiler/preprocessor option.
 */
#define MOD_MSHIELD_SESSION_COUNT        100
#endif
#ifndef MOD_MSHIELD_COOKIESTORE_COUNT
#define MOD_MSHIELD_COOKIESTORE_COUNT    200        /**< Default cookiestore size (SHM) */
#endif

/**
 * Minimum URL criticality level
 */
#define MOD_MSHIELD_URL_CRITICALITY_LEVEL_MIN    0

/**
 * Maximum URL criticality level
 */
#define MOD_MSHIELD_URL_CRITICALITY_LEVEL_MAX    1000

/**
 * Session "FRAUD" return value from the engine rating
 */
#define MOD_MSHIELD_RESULT_FRAUD        "FRAUD"

/**
 * Session "SUSPICIOUS" return value from the engine rating
 */
#define MOD_MSHIELD_RESULT_SUSPICIOUS   "SUSPICIOUS"

/**
 * Session "OK" return value from the engine rating
 */
#define MOD_MSHIELD_RESULT_OK           "OK"

/**
 * Kafka log level. Has to be between 0 (LOG_EMERG) and 7 (LOG_DEBUG).
 */
#define MOD_MSHIELD_KAFKA_LOG_LEVEL          LOG_WARNING

extern module AP_MODULE_DECLARE_DATA mshield_module;        /**< mod_mshield apache module name */
extern apr_global_mutex_t *mshield_mutex;                   /**< mod_mshield mutex to secure shared memory access */

/**
 * @brief mod_mshield Kafka struct which stores the Kafka configuration.
 */
typedef struct {
    struct {
        apr_hash_t *global;                         /**< Kafka global configuration options */
        apr_hash_t *topic;                          /**< Kafka topic configuration options */
    } conf_producer;                                /**< Kafka configuration options struct */
    const char *topic_analyse;                      /**< Set the kafka topic on which clicks are sent to the engine */
    const char *rk_topic_analyse;                   /**< topic_analyse handle */
    const char *topic_usermapping;                  /**< Set the kafka topic on which the username <-> UUID mapping is sent */
    const char *rk_topic_usermapping;               /**< topic_usermapping handle */
    const char *topic_url_config;                   /**< Set the kafka topic on which the url <-> risk_level configuration is sent */
    const char *rk_topic_url_config;                /**< topic_url_config handle */
    const char *broker;                             /**< Set the IP of the Kafka broker */
    int delivery_check_interval;                    /**< The interval in ms to check for the message delivery report */
    int msg_delivery_timeout;                       /**< Timeout for the Kafka message delivery check (in seconds!) */
    rd_kafka_t *rk_producer;                        /**< Kafka producer handle */
    rd_kafka_topic_partition_list_t *topics;        /**< Kafka topics for high-level consumer */
} mod_mshield_kafka_t;

/**
 * @brief mod_mshield Redis struct which stores the Redis configuration.
 */
typedef struct {
    const char *server;                             /**< Set the Redis server */
    int port;                                       /**< Set the Redis port on which the host listens */
    int connection_timeout;                         /**< Set Redis connection timeout (in seconds!) */
    int response_query_interval;                    /**< The interval in ms to query request result */
    int response_timeout;                           /**< How long to wait at most for request analyse result (in seconds!) */
} mod_mshield_redis_t;

/**
 * @brief mod_mshield struct which contains all global configurations
 */
typedef struct {
    int enabled;                                    /**< [On, Off] switch for enable/disable mod_mshield */
    const char *client_refuses_cookies_url;         /**< Error URL, if the client refuses our mod_mshield cookie */
    const char *cookie_name;                        /**< The cookie name value of the mod_mshield cookie */
    const char *cookie_domain;                      /**< The cookie domain value */
    const char *cookie_path;                        /**< The cookie path value */
    const char *cookie_expiration;                  /**< The cookie expiration flag value */
    int cookie_secure;                              /**< The cookie secure flag value */
    int cookie_httponly;                            /**< The HTTPonly flag (for MS IE only) */
    const char *session_free_url;                   /**< Regexp statement, for which mod_mshield is not enforced */

    apr_int64_t session_hard_timeout;               /**< How long a mod_mshield session is accepted, before a new must be given */
    apr_int64_t session_inactivity_timeout;         /**< How long the client can do *nothing*, before it's session expires */
    const char *session_expired_url;                /**< Error URL, once a session times out (expires); defaults to renew URL XXX */
    const char *session_renew_url;                  /**< URL for which MOD_MSHIELD sets new MOD_MSHIELD session */

    const char *all_shm_space_used_url;             /**< Error URL, if all sessions are taken by mod_mshield and NO shm available */

    const char *session_destroy;                    /**< Session destroy URI */
    const char *session_destroy_url;                /**< Error URL, once we have destroyed the session */

    int authorization_enabled;                      /**< Authorization enabled or not */

    const char *global_logon_server_url;            /**< Logon Server URI */
    const char *global_logon_server_url_1;          /**< Logon Server URI 1 (used for step up 1) */
    const char *global_logon_server_url_2;          /**< Logon Server URI 2 (used for step up 2) */
    const char *global_logon_auth_cookie_name;      /**< Cookie Name, which is used as authenticator */
    const char *global_logon_auth_cookie_value;     /**< Cookie Value, which is used as authenticator */

    const char *session_store_free_cookies;         /**< The cookies configured here are not handled by the session store */

    const char *service_list_cookie_name;           /**< Service list cookie name */
    const char *service_list_cookie_value;          /**< Service list */
    const char *service_list_error_url;             /**< Error, if user is not authorized */
    int service_list_enabled_on;                    /**< Boolean to enable/disable the server list */
    const char *authorized_logon_url;               /**< Regexp from what r->uri LOGON=ok are accepted */
    const char *url_after_renew;                    /**< Redirect URL after renew session */

    int mshield_config_enabled_return_to_orig_url;  /**< IF RETURN TO ORIG URL SHALL BE ENABLED/DISABLED */
    const char *username_value;                     /**< The username_value value */

    apr_pool_t *pool;                               /**< mod_mshield global memory pool */
    int fraud_detection_enabled;                    /**< Enable or disable fraud detection functionality */
    int fraud_detection_learning_mode;              /**< Enable or disable learning mode */
    int fraud_detection_validation_threshold;       /**< Threshold which fixes if the session with risk level X should be rated by the engine */
    const char *fraud_detected_url;                 /**< URL to redirect to if a fraud is found */
    const char *fraud_error_url;                    /**< URL to redirect to if the analyse fails */
    apr_hash_t *url_store;                          /**< Url store for web application urls and its criticality */
    mod_mshield_kafka_t kafka;                      /**< The mod_mshield server Kafka configuration */
    mod_mshield_redis_t redis;                      /**< The mod_mshield server Redis configuration*/
} mod_mshield_server_t;

/**
 * @brief mod_mshield directory level configuration
 */
typedef struct {
    const char *logon_server_url;                   /**< Logon Server URI */
    const int logon_required;                       /**< Logon required flag */
    const int mod_mshield_location_id;              /**< To group the backend sessions */
    const int mod_mshield_auth_strength;            /**< Required authentication strength per directory */
} mod_mshield_dir_t;

/**
 * @brief mod_mshield shared memory structures
 */
typedef struct {
    int slot_used;                                  /**< Bool if the session is used of not*/
    char session_name[32];                          /**< Name of session cookie */
    char session_id[
            MOD_MSHIELD_SIDBYTES / 3 * 4 +
        1];                                         /**< Value of session cookie, MOD_MSHIELD_SIDBYTES random bytes, Base64 */
    char url[255];                                  /**< Used to store URLs for client redirection */
    int ctime;                                      /**< Cookie time */
    int atime;                                      /**< Activity time */
    int cookiestore_index;                          /**< Index of first cookie in cookie store; -1 if none */
    int logon_state;                                /**< 0 = not logged in, 1 = logged in */
    int redirect_on_auth_flag;                      /**< Redirect client to orig_url on first authenticated request to protected URL */
    char service_list[100];                         /**< mod_mshield service list */
    int auth_strength;                              /**< Auth strength of the session */
    char redirect_url_after_login[255];             /**< Redirect to URL from which the session came from */
    char uuid[MOD_MSHIELD_SIDBYTES / 3 * 4 +
              1];                                   /**< mod_mshield unique identifier (for logical user session level) */
    char username[64];                              /**< Username of Backend Web App */
} session_data_t;


/**
 * @brief The mod_mshield cookie data
 */
typedef struct {
    int slot_used;                                  /**< Bool if the cookie is used of not */
    char name[100];                                 /**< Name of the cookie  */
    char value[100];                                /**< Cookie value */
    int next;                                       /**< "Pointer" to the next cookie */
    int prev;                                       /**< "Pointer" to the previous cookie*/
    int location_id;                                /**< ID from the mod_mshield directory level configuration location */
} cookie_t;


/**
 * @brief Opaque session handle type, portable across processes.
 */
typedef int session_handle_t;

/**
 * Define value of invalid session handle
 */
#define INVALID_SESSION_HANDLE (-1)

/**
 * @brief Session type for use by callers, only valid within a single process.
 */
typedef struct {
    session_handle_t handle;                        /**< Session handle */
    session_data_t *data;                           /**< Session data */
    request_rec *request;                           /**< The session request */
    mod_mshield_server_t *config;                   /**< The mod_mshield server configuration */
} session_t;

/**
 * @brief Iterator data structure (parameters and result)
 */
typedef struct {
    request_rec *r;                                /**< Request record. IN */
    session_t *session;                            /**< Session context. Only response cookie filter. */
    apr_status_t status;                           /**< Error status from callbacks. OUT */
    apr_table_t *headers;                          /**< Headers to add back into headers(_out|_in) */
    int must_renew;                                /**< Must renew session ID. Only response cookie filter. */
    const char *sessionid;                         /**< Session ID read from cookie. Only request cookie filter. */
} cookie_res;

/********************************************************************
 * <!-- mod_mshield_redirect.c -->
 */
int mod_mshield_redirect_to_relurl(request_rec *r, const char *relurl);

int mod_mshield_redirect_to_cookie_try(request_rec *r, mod_mshield_server_t *config);

int mod_mshield_redirect_to_shm_error(request_rec *r, mod_mshield_server_t *config);

int mod_mshield_find_cookie_try(request_rec *r);

char *mod_mshield_strip_cookie_try(char *relurl);

/********************************************************************
 * <!-- mod_mshield_regexp.c -->
 */
apr_status_t mod_mshield_regexp_match(request_rec *r, const char *pattern, const char *subject);

apr_status_t mod_mshield_regexp_imatch(request_rec *r, const char *pattern, const char *subject);

apr_status_t mod_mshield_regexp_match_ex(request_rec *r, const char *pattern, int opts, const char *subject);

/********************************************************************
 * <!-- mod_mshield_cookie.c -->
 */
apr_status_t mshield_add_session_cookie_to_headers(request_rec *r, mod_mshield_server_t *config, apr_table_t *headers,
                                                   session_t *session);

int mshield_add_to_headers_out_cb(void *data, const char *key, const char *value);

int mshield_add_to_headers_in_cb(void *data, const char *key, const char *value);

/********************************************************************
 * <!-- mod_mshield_access_control.c -->
 */
apr_status_t
mshield_access_control(request_rec *r, session_t *session, mod_mshield_server_t *config, mod_mshield_dir_t *dconfig);

/********************************************************************
 * <!-- mod_mshield_response_filter.c -->
 */
int mod_mshield_filter_response_cookies_cb(void *result, const char *key, const char *value);

/********************************************************************
 * <!-- mod_mshield_request_filter.c -->
 */
int mod_mshield_filter_request_cookies_cb(void *result, const char *key, const char *value);

/********************************************************************
 * <!-- mod_mshield_session.c -->
 */
void mshield_session_init(session_t *session, request_rec *r, mod_mshield_server_t *config);

int mshield_session_isnull(session_t *session);

apr_status_t mshield_session_find(session_t *session, const char *session_name, const char *session_id);

apr_status_t mshield_session_open(session_t *session, request_rec *r, session_handle_t handle);

apr_status_t mshield_session_create(session_t *session, bool is_new_session);

char *generate_uuid(session_t *session);

char *generate_click_id(session_t *session);

void mshield_session_unlink(session_t *session);

apr_status_t mshield_session_validate(session_t *session, int hard_timeout, int inactivity_timeout);

apr_status_t mshield_session_renew(session_t *session);

const char *mshield_session_get_cookies(session_t *session);

apr_status_t mshield_session_set_cookie(session_t *session, const char *key, const char *value, int locid);

/********************************************************************
 * <!-- mod_mshield_shm.c -->
 */
apr_status_t mshield_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);

apr_status_t shm_cleanup(void *not_used);

apr_status_t mshield_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);

apr_status_t shm_cleanup_cookiestore(void *not_used);

/* the following SHM functions are for session internal use only */
session_data_t *get_session_by_index(int index);

void mshield_shm_free(session_data_t *session_data);

int mshield_shm_timeout(session_data_t *session_data, int hard_timeout, int inactivity_timeout);

apr_status_t create_new_shm_session(request_rec *r, const char *sid, const char *uuid, int *session_index);

const char *collect_cookies_from_cookiestore(request_rec *r, int anchor);

void mshield_cookiestore_free(int anchor);

apr_status_t
store_cookie_into_session(request_rec *r, session_data_t *session_data, const char *key, const char *value, int locid);

/********************************************************************
 * <!-- mod_mshield_config.c -->
 */
extern const command_rec mshield_cmds[]; /**< mod_mshield apache configuration directive handler */

/********************************************************************
 * <!-- mod_mshield_kafka.c -->
 */
apr_status_t kafka_cleanup(void *s);
apr_status_t extract_click_to_kafka(request_rec *r, char *uuid, session_t *session);
void extract_url_to_kafka(server_rec *s);
apr_status_t kafka_produce(apr_pool_t *p, mod_mshield_kafka_t *kafka, const char *topic, const char **rk_topic,
                   int32_t partition, char *msg, const char *key);

/********************************************************************
 * <!-- mod_mshield_redis.c -->
 */
apr_status_t handle_mshield_result(void *reply, void *request, session_t *session);
int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p);

#endif /* MOD_MSHIELD_H */
