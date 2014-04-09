/* Copyright 2014 Apcera Inc. All rights reserved. */

#include <ngx_config.h>
#include <ngx_core.h>

#include <ctype.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

/*
 * If a version number component is more than this, then it's likely someone
 * trying to attack us with an overflow.
 */
#define MAX_OSSLVER_COMPONENT 256

/* Configuration initialisation */

struct ngx_openssl_version_conf_s {
    ngx_str_t minimum_string;
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
      offsetof(ngx_openssl_version_conf_t, minimum_string),
      NULL },

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

    // ovcf->minimum_string  -- calloc 0s are fine

    return ovcf;
}

static char *
ngx_openssl_version_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_openssl_version_conf_t *ovcf = conf;
    long runtime_version, want_version;
    unsigned int want_major = 0;
    unsigned int want_minor = 0;
    unsigned int want_fix = 0;
    unsigned int want_patch = 0;
    const unsigned int want_status = 0x0F; /* release */
    int in_section = 0;
    unsigned int *current_int;
    u_char *p, *endp;

    if (ovcf->minimum_string.len == 0) {
        return NGX_CONF_OK;
    }

    /* We skip parsing ancient versions which are just broken.
     * Thus we have the version information documented in SSLeay(3):
     *  MMNNFFPPS: major minor fix patch status
     */
    p = ovcf->minimum_string.data;
    endp = p + ovcf->minimum_string.len;
    current_int = &want_major;
    for (/**/; *p && isprint(*p) && p < endp; ++p) {
        if (isdigit(*p)) {
            *current_int *= 10;
            *current_int += (unsigned int)(*p - '0');
            if (*current_int > MAX_OSSLVER_COMPONENT) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "OpenSSL version component too high (parsing: %V)", &ovcf->minimum_string);
                return NGX_CONF_ERROR;
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
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL version has too many dot sections (%V)", &ovcf->minimum_string);
            return NGX_CONF_ERROR;
        }
        if (in_section < 2) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL version missing a section (%V)", &ovcf->minimum_string);
            return NGX_CONF_ERROR;
        }
        if (in_section == 3) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL version has bad patch section (%V)", &ovcf->minimum_string);
            return NGX_CONF_ERROR;
        }
        in_section++;
        if (!isalpha(*p)) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "OpenSSL version has unparseable patch level (%V)", &ovcf->minimum_string);
            return NGX_CONF_ERROR;
        }
        want_patch = (*p | 0x20) - 'a' + 1;
    }

    /* We allow empty fix, and empty minor, so can say "1.1". */
    if (in_section < 2) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "OpenSSL version string is too short (%V)", &ovcf->minimum_string);
        return NGX_CONF_ERROR;
    }

    if ((want_major > 255) || (want_minor > 255) || (want_fix > 255) || (want_patch > 255)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "OpenSSL version string has too large a component (%V)", &ovcf->minimum_string);
        return NGX_CONF_ERROR;
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

    runtime_version = SSLeay();

    if (want_version > runtime_version) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "OpenSSL runtime too old; asked for %V, got: %s",
                      &ovcf->minimum_string, SSLeay_version(SSLEAY_VERSION));
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
