/* Copyright 2014 Apcera Inc. All rights reserved. */

/*
 * I suspect portability problems with the date parsing routines.
 * When we find them, we should turn this guard into a conditional upon the
 * standardization macros necessary to have the features we want.
 * os/.../ngx_time.h has nowhere near what we need.
 */
#define NGX_OPENSSL_WANT_DATEHANDLING 1

#include <ngx_config.h>
#include <ngx_core.h>

#include <ctype.h>
#ifdef NGX_OPENSSL_WANT_DATEHANDLING
# include <time.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

/*
 * If a version number component is more than this, then it's likely someone
 * trying to attack us with an overflow.
 */
#define MAX_OSSLVER_COMPONENT 256

/*
 * Tuning for parsing builddates
 */
#ifdef NGX_OPENSSL_WANT_DATEHANDLING
# define PARSE_BUILDDATE_STRIPPREFIX  (1 << 0)
#endif /* NGX_OPENSSL_WANT_DATEHANDLING */

/* Configuration initialisation */

struct ngx_openssl_version_conf_s {
    ngx_str_t version_min;
#ifdef NGX_OPENSSL_WANT_DATEHANDLING
    ngx_str_t builddate_min;
#endif /* NGX_OPENSSL_WANT_DATEHANDLING */
};
typedef struct ngx_openssl_version_conf_s ngx_openssl_version_conf_t;

static void *ngx_openssl_version_create_conf(ngx_cycle_t *cycle);
static char *ngx_openssl_version_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_openssl_version_module_init(ngx_cycle_t *cycle);

static ngx_command_t ngx_openssl_version_commands[] = {
    { ngx_string("openssl_version_minimum"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_openssl_version_conf_t, version_min),
      NULL },

#ifdef NGX_OPENSSL_WANT_DATEHANDLING
    { ngx_string("openssl_builddate_minimum"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_openssl_version_conf_t, builddate_min),
      NULL },
#endif /* NGX_OPENSSL_WANT_DATEHANDLING */

    ngx_null_command
};

static ngx_core_module_t ngx_openssl_version_module_ctx = {
    ngx_string("openssl_version_module"),
    ngx_openssl_version_create_conf,
    ngx_openssl_version_init_conf
};

ngx_module_t ngx_openssl_version_module = {
    NGX_MODULE_V1,
    &ngx_openssl_version_module_ctx,    /* module context */
    ngx_openssl_version_commands,       /* module directives */
    NGX_CORE_MODULE,                    /* module type */
    NULL,                               /* init master */
    ngx_openssl_version_module_init,    /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_openssl_version_module_init(ngx_cycle_t *cycle)
{
    /*
     * nginx arranges to init openssl before modules are processed.
     */
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "OpenSSL: Built with [%s] runtime is [%s]",
                  OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION));
    return NGX_OK;
}

static void *
ngx_openssl_version_create_conf(ngx_cycle_t *cycle)
{
    ngx_openssl_version_conf_t *ovcf;

    ovcf = ngx_pcalloc(cycle->pool, sizeof(ngx_openssl_version_conf_t));
    if (ovcf == NULL) {
        return NULL;
    }

    // calloc 0s are fine for these members:
    // ovcf->version_min
    // ovcf->builddate_min

    return ovcf;
}

static long
parse_openssl_version(ngx_str_t *minimum_str, const char **error)
{
    long want_version;
    unsigned int want_major = 0;
    unsigned int want_minor = 0;
    unsigned int want_fix = 0;
    unsigned int want_patch = 0;
    const unsigned int want_status = 0x0F; /* release */
    int in_section = 0;
    unsigned int *current_int;
    u_char *p, *endp;

    /* If error itself is NULL, is invocation error and we want to trigger
     * a segfault anyway, so this is either "correct" or "forcing a failure
     * early, in a way we want".
     */
    *error = NULL;

    /* We skip parsing ancient versions which are just broken.
     * Thus we have the version information documented in SSLeay(3):
     *  MMNNFFPPS: major minor fix patch status
     */
    p = minimum_str->data;
    endp = p + minimum_str->len;
    current_int = &want_major;
    for (/**/; *p && isprint(*p) && p < endp; ++p) {
        if (isdigit(*p)) {
            *current_int *= 10;
            *current_int += (unsigned int)(*p - '0');
            if (*current_int > MAX_OSSLVER_COMPONENT) {
                *error = "OpenSSL version component too high";
                return 0L;
            }
            continue;
        }
        if (*p == '.') {
            if (in_section < 2) {
                switch (in_section) {
                case 0:
                    in_section = 1;
                    current_int = &want_minor;
                    break;
                case 1:
                    in_section = 2;
                    current_int = &want_fix;
                    break;
                }
                continue;
            }
            *error = "OpenSSL version has too many dot sections";
            return 0L;
        }
        if (in_section < 2) {
            *error = "OpenSSL version missing a section";
            return 0L;
        }
        if (in_section == 3) {
            *error = "OpenSSL version has bad patch section";
            return 0L;
        }
        in_section++;
        if (!isalpha(*p)) {
            *error = "OpenSSL version has unparseable patch level";
            return 0L;
        }
        want_patch = (*p | 0x20) - 'a' + 1;
    }

    /* We allow empty fix, and empty minor, so can say "1.1". */
    if (in_section < 2) {
        *error = "OpenSSL version string is too short";
        return 0L;
    }

    if ((want_major > 255) || (want_minor > 255) || (want_fix > 255) || (want_patch > 255)) {
        *error = "OpenSSL version string has too large a component";
        return 0L;
    }

    want_version = 0L;
    /*  Note: 9 hex digits:
     *  MMNNFFPPS: major minor fix patch status
     */
    want_version |= (want_major & 0xFF) << 28;
    want_version |= (want_minor & 0xFF) << 20;
    want_version |= (want_fix   & 0xFF) << 12;
    want_version |= (want_patch & 0xFF) <<  4;
    want_version |= (want_status & 0x0F);

    return want_version;
}

#ifdef NGX_OPENSSL_WANT_DATEHANDLING
static time_t
parse_openssl_builddate(ngx_pool_t *pool, ngx_str_t *orig_minimum_str, int flags, const char **error)
{
    /*
     * "built on: Mon Apr  7 15:08:30 PDT 2014"
     * The "built on: " prefix is included in the OpenSSL version return string
     * but we don't want it in the nginx config file, so we only handle it if
     * (flags&PARSE_BUILDDATE_STRIPPREFIX).
     */
    struct tm tm;
    const char *prefix = "built on: ";
    u_char *input;
    char *rest;
    ngx_str_t min;
    size_t len;
    time_t result;

    /* If error itself is NULL, is invocation error and we want to trigger
     * a segfault anyway, so this is either "correct" or "forcing a failure
     * early, in a way we want".
     */
    *error = NULL;

    /* Leave data structure of original string alone */
    min.data = orig_minimum_str->data;
    min.len = orig_minimum_str->len;
    orig_minimum_str = NULL;

    if (flags & PARSE_BUILDDATE_STRIPPREFIX) {
        len = ngx_strlen(prefix);
        if (min.len <= len) {
            *error = "build date string too short even for prefix";
            return (time_t)0;
        }
        if (ngx_strncmp(min.data, prefix, len) != 0) {
            *error = "build date string does not start with expected prefix";
            return (time_t)0;
        }
        min.data += len;
        min.len -= len;
    }

    /*
     *  0         1         2
     *  01234567890123456789012345678
     * "Mon Apr  7 15:08:30 PDT 2014" -- handled
     * "Mon Apr  7 15:19:04 EDT 2014" -- rejected by strptime because of "EDT"
     * You may cry now.
     */

    if (min.len != 28) {
        *error = "build date wrong length for OpenSSL timestamp layout";
        return (time_t)0;
    }

    /* ensure NUL termination before parsing to libc, and mangle private copy */
    input = ngx_pstrdup(pool, &min);

    /* get rid of timezone information which libc won't reliably parse */
    if (isdigit(input[18]) && isdigit(input[24]) && isspace(input[19]) && isspace(input[23])) {
        input[20] = input[21] = input[22] = '-';
    } else {
        /* be slightly different from strptime error, to tell apart */
        *error = "build date string unparseable layout";
        return (time_t)0;
    }

    rest = strptime((const char *)input, "%a %b %e %H:%M:%S --- %Y", &tm);
    if (rest == NULL) {
        *error = "build date string unparseable";
        return (time_t)0;
    }
    if (*rest != '\0') {
        *error = "unparsed remnants in date string";
        return (time_t)0;
    }

    /* timegm() is non-standard, mktime() is; mktime has timezones, but as long
     * as we have the same timezones in all compared items, we should be good.
     */
    result = timegm(&tm);
    if (result == -1) {
        *error = "timegm() failed to parse our time struct";
        return (time_t)0;
    }
    return result;
}
#endif /* NGX_OPENSSL_WANT_DATEHANDLING */

static char *
ngx_openssl_version_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_openssl_version_conf_t *ovcf = conf;
    const char *error, *have_builddate;
    long runtime_version, want_version;
    time_t runtime_builddate, want_builddate;
    ngx_str_t have_builddate_ngx;

    if (ovcf->version_min.len > 0) {
        want_version = parse_openssl_version(&ovcf->version_min, &error);
        if (error != NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "%s (parsing '%V')", error, &ovcf->version_min);
            return NGX_CONF_ERROR;
        }

        runtime_version = SSLeay();

        if (want_version > runtime_version) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL runtime too old; asked for %V, got: %s",
                          &ovcf->version_min, SSLeay_version(SSLEAY_VERSION));
            return NGX_CONF_ERROR;
        }
    }

#ifdef NGX_OPENSSL_WANT_DATEHANDLING
    if (ovcf->builddate_min.len > 0) {
        want_builddate = parse_openssl_builddate(cycle->pool, &ovcf->builddate_min, 0, &error);
        if (error != NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "%s (parsing configured minimum build-date '%V')", error, &ovcf->builddate_min);
            return NGX_CONF_ERROR;
        }

        have_builddate = SSLeay_version(SSLEAY_BUILT_ON);
        have_builddate_ngx.data = (u_char *)have_builddate;
        have_builddate_ngx.len = ngx_strlen(have_builddate);
        runtime_builddate = parse_openssl_builddate(cycle->pool, &have_builddate_ngx, PARSE_BUILDDATE_STRIPPREFIX, &error);
        if (error != NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "%s (parsing OpenSSL's runtime reported build-date '%V')", error, &have_builddate_ngx);
            return NGX_CONF_ERROR;
        }

        if (runtime_builddate < want_builddate) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL runtime built too long ago; wanted %T, got %T",
                          want_builddate, runtime_builddate);
            return NGX_CONF_ERROR;
        }
    }
#endif /* NGX_OPENSSL_WANT_DATEHANDLING */

    return NGX_CONF_OK;
}
