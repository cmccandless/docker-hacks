/**
 * @file mod_mshield_errno.h
 * @author Philip Schmid
 * @date 2. May 2017
 * @brief Error number definitions
 *
 * We use apr_status_t from APR as status type and use the
 * error number range reserved for the application using APR.
 *
 * APR reserves the range APR_OS_START_USERERR ... +50000
 * for the application using APR.  It is therefore safe to
 * intermingle apr_status_t from APR functions with our
 * own STATUS_* status numbers.
 */

#ifndef MOD_MSHIELD_ERRNO_H
#define MOD_MSHIELD_ERRNO_H

/**
 * <!-- Make sure our errors are within the APR user error range -->
 */
#define MOD_MSHIELD_ERRNO_OFFSET    200                                                         /**< Custom status offset */
#define NEW_MOD_MSHIELD_STATUS(x)    (APR_OS_START_USERERR + MOD_MSHIELD_ERRNO_OFFSET + (x))    /**< Custom status creation helper */

/*
 * mod_mshield error definitions
 */
#define STATUS_OK           APR_SUCCESS                 /**< Success                    */
#define STATUS_ERROR        NEW_MOD_MSHIELD_STATUS(1)   /**< Unspecified error          */
#define STATUS_ENOEXIST     NEW_MOD_MSHIELD_STATUS(2)   /**< Does not exist, not found  */
#define STATUS_ESHMFULL     NEW_MOD_MSHIELD_STATUS(3)   /**< Shared memory full         */
#define STATUS_ETIMEOUT     NEW_MOD_MSHIELD_STATUS(4)   /**< Session timeout            */
#define STATUS_CONERROR     NEW_MOD_MSHIELD_STATUS(5)   /**< Connection error           */
#define STATUS_MISCONFIG    NEW_MOD_MSHIELD_STATUS(6)   /**< Configuration failed       */
#define STATUS_REDIRERR     NEW_MOD_MSHIELD_STATUS(7)   /**< Redirection failed         */

#define STATUS_ELOGIN       NEW_MOD_MSHIELD_STATUS(5)   /**< Login required             */
#define STATUS_ESTEPUP1     NEW_MOD_MSHIELD_STATUS(6)   /**< Stepup 1 required          */
#define STATUS_ESTEPUP2     NEW_MOD_MSHIELD_STATUS(7)   /**< Stepup 2 required          */
#define STATUS_EDENIED      NEW_MOD_MSHIELD_STATUS(8)   /**< Access denied              */

#define STATUS_MATCH        STATUS_OK                   /**< Regexp did match           */
#define STATUS_NOMATCH      STATUS_ENOEXIST             /**< Regexp did not match       */

#endif /* MOD_MSHIELD_ERRNO_H */
