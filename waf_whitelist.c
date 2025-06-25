/*
 * waf_ip_list.c - WAF IP 黑白名单模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 实现基于 IP 地址字符串精确匹配的黑白名单功能。
 *
 *  [函数说明]
 *    - waf_set_whitelist:   [回调] 解析 `waf_whitelist` 指令, 将 IP 字符串存入数组。
 *    - waf_check_whitelist: [核心] 检查客户端 IP 是否精确匹配白名单中的某一项。
 *    - waf_set_blacklist:   [回调] 解析 `waf_blacklist` 指令, 将 IP 字符串存入数组。
 *    - waf_check_blacklist: [核心] 检查客户端 IP 是否精确匹配黑名单中的某一项。
 * =====================================================================================
 */
#include "waf_common.h"

// --- 白名单实现 ---

char *waf_set_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_str_t *new_ip;

    if (lcf->whitelist == NULL) {
        lcf->whitelist = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (lcf->whitelist == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    new_ip = ngx_array_push(lcf->whitelist);
    if (new_ip == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *new_ip = value[1];

    return NGX_CONF_OK;
}

ngx_int_t waf_check_whitelist(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    ngx_str_t *whitelisted_ip;
    ngx_uint_t i;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf->whitelist == NULL) {
        return NGX_DECLINED;
    }

    whitelisted_ip = lcf->whitelist->elts;
    for (i = 0; i < lcf->whitelist->nelts; i++) {
        if (r->connection->addr_text.len == whitelisted_ip[i].len &&
            ngx_memcmp(r->connection->addr_text.data, whitelisted_ip[i].data, r->connection->addr_text.len) == 0)
        {
            return NGX_OK; // 匹配成功
        }
    }

    return NGX_DECLINED; // 未匹配
}


// --- 黑名单实现 ---

char *waf_set_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_loc_conf_t *lcf = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_str_t *new_ip;

    if (lcf->blacklist == NULL) {
        lcf->blacklist = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (lcf->blacklist == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    new_ip = ngx_array_push(lcf->blacklist);
    if (new_ip == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *new_ip = value[1];

    return NGX_CONF_OK;
}

ngx_int_t waf_check_blacklist(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    ngx_str_t *blacklisted_ip;
    ngx_uint_t i;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf->blacklist == NULL) {
        return NGX_DECLINED;
    }

    blacklisted_ip = lcf->blacklist->elts;
    for (i = 0; i < lcf->blacklist->nelts; i++) {
        if (r->connection->addr_text.len == blacklisted_ip[i].len &&
            ngx_memcmp(r->connection->addr_text.data, blacklisted_ip[i].data, r->connection->addr_text.len) == 0)
        {
            return NGX_OK; // 匹配成功
        }
    }

    return NGX_DECLINED; // 未匹配
} 