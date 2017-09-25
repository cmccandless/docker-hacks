#include "mod_mshield.h"

/*
 * Match a string against a regular expression without doing any captures.
 *
 * Returns:
 *	STATUS_MATCH	regexp matched subject
 *	STATUS_NOMATCH	regexp did not match subject
 *	STATUS_ERROR	internal error when compiling or matching
 */
apr_status_t
mod_mshield_regexp_match(request_rec *r, const char *pattern, const char *subject) {
    return mod_mshield_regexp_match_ex(r, pattern, 0, subject);
}

/*
 * Match a string case-less against a regular expression,
 * without doing any captures.
 *
 * Returns:
 *	STATUS_MATCH	regexp matched subject
 *	STATUS_NOMATCH	regexp did not match subject
 *	STATUS_ERROR	internal error when compiling or matching
 */
apr_status_t
mod_mshield_regexp_imatch(request_rec *r, const char *pattern, const char *subject) {
    return mod_mshield_regexp_match_ex(r, pattern, PCRE_CASELESS, subject);
}

/*
 * Match a string against a regular expression with PCRE Options,
 * without doing any captures.  This function is used internally
 * by the other matching functions.
 *
 * Returns:
 *	STATUS_MATCH	regexp matched subject
 *	STATUS_NOMATCH	regexp did not match subject
 *	STATUS_ERROR	internal error when compiling or matching
 */
apr_status_t
mod_mshield_regexp_match_ex(request_rec *r, const char *pattern, int opts, const char *subject) {
    pcre *re;
    const char *error;
    int offset, rc;

    if (pattern == NULL || subject == NULL) {
        ap_log_error(PC_LOG_CRIT, NULL, "Internal error: pattern or subject is NULL.");
        return STATUS_ERROR;
    }

    re = pcre_compile(pattern, opts, &error, &offset, NULL);
    if (re == NULL) {
        ap_log_error(PC_LOG_CRIT, NULL, "Cannot compile regexp /%s/ at offset %d: %s", pattern, offset, error);
        return STATUS_ERROR;
    }

    rc = pcre_exec(re, NULL, subject, strlen(subject), 0, 0, NULL, 0);
    if (rc >= 0) {
        return STATUS_MATCH;
    } else if (rc == PCRE_ERROR_NOMATCH) {
        return STATUS_NOMATCH;
    } else {
        ap_log_error(PC_LOG_CRIT, NULL, "Cannot match regexp /%s/ against '%s' (%d)", pattern, subject, rc);
        return STATUS_ERROR;
    }
}


