/**
 * @file mod_mshield_debug.h
 * @author I. Buetler
 * @date 2. May 2017
 * @brief Various debugging/logging helpers.
 *
 *  * Convenience logging shortcuts - they assume request_rec *r or server_rec *s
 * are available, depending on variant.
 *
 * *_INFO and DEBUG_GENERAL are used for printf debugging
 * *_CRIT are used for error messages
 *
 * Example:
 * @code
 *    char *foo = "foo";
 *    char *bar = "bar";
 *    ERRLOG_CRIT("Failed to copy %s to %s", foo, bar);
 * @endcode
 * Error log will look like:
 * @code
 *    [Thu May 29 11:26:18 2008] [crit] [client 127.0.0.1] mod_mshield_example.c:21: Failed to copy foo to bar
 * @endcode
 *
 */

#ifndef MOD_MSHIELD_DEBUG_H
#define MOD_MSHIELD_DEBUG_H

/**
 * <!-- Log level shortcuts -->
 */
#define PC_LOG_DEBUG        APLOG_MARK,APLOG_DEBUG,0    /**< Set log level to debug */
#define PC_LOG_INFO         APLOG_MARK,APLOG_INFO,0     /**< Set log level to info */
#define PC_LOG_CRIT         APLOG_MARK,APLOG_CRIT,0     /**< Set log level to crit */

/**
 * <!-- Logging helpers -->
 */
#define ERRLOG_REQ(level, format, ...)      ap_log_rerror(level, r, "[MSHIELD] [%s] [%s:%d]: " format, apr_table_get(r->subprocess_env, "UNIQUE_ID"), __FILE__, __LINE__, ##__VA_ARGS__)    /**< Log helper for request related stuff */
#define ERRLOG_REQ_DEBUG(format, ...)       ERRLOG_REQ(PC_LOG_DEBUG, format, ##__VA_ARGS__)    /**< Log request stuff at debug level */
#define ERRLOG_REQ_INFO(format, ...)        ERRLOG_REQ(PC_LOG_INFO, format, ##__VA_ARGS__)     /**< Log request stuff at info level */
#define ERRLOG_REQ_CRIT(format, ...)        ERRLOG_REQ(PC_LOG_CRIT, format, ##__VA_ARGS__)     /**< Log request stuff at crit level */

#define ERRLOG_SRV(level, format, ...)      ap_log_error(level, s, "[MSHIELD] [%s:%d]: " format, __FILE__, __LINE__, ##__VA_ARGS__)     /**< Log helper for server related stuff */
#define ERRLOG_SRV_DEBUG(format, ...)       ERRLOG_SRV(PC_LOG_DEBUG, format, ##__VA_ARGS__)    /**< Log server stuff at debug level */
#define ERRLOG_SRV_INFO(format, ...)        ERRLOG_SRV(PC_LOG_INFO, format, ##__VA_ARGS__)     /**< Log server stuff at info level */
#define ERRLOG_SRV_CRIT(format, ...)        ERRLOG_SRV(PC_LOG_CRIT, format, ##__VA_ARGS__)     /**< Log server stuff at crit level */

#define MSHIELD_LOG_DEBUG(p, format, args...)   ap_log_perror(PC_LOG_DEBUG, p, "[MSHIELD] [%s:%d]: " format, __FILE__, __LINE__, ##args)     /**< Log general server stuff at debug level */
#define MSHIELD_LOG_INFO(p, format, args...)    ap_log_perror(PC_LOG_INFO, p, "[MSHIELD] [%s:%d]: " format, __FILE__, __LINE__, ##args)      /**< Log general server stuff at info level */
#define ERROR(p, format, args...)               ap_log_perror(PC_LOG_CRIT, p, "[MSHIELD] [%s:%d]: " format, __FILE__, __LINE__, ##args)      /**< Log general server stuff at crit level */

#endif /* MOD_MSHIELD_DEBUG_H */
