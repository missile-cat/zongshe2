#ifndef WAF_WHITELIST_H
#define WAF_WHITELIST_H

#include "waf_common.h"

/**
 * @file waf_whitelist.c
 * @brief "waf_whitelist" 指令的回调函数。
 *        解析 nginx.conf 中的 IP/CIDR 并存入配置。
 */
char *waf_set_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/**
 * @file waf_whitelist.c
 * @brief 检查客户端 IP 是否在白名单中。
 * @return 如果匹配白名单返回 NGX_OK，否则返回 NGX_DECLINED。
 */
ngx_int_t waf_check_whitelist(ngx_http_request_t *r);

char *waf_set_blacklist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t waf_check_blacklist(ngx_http_request_t *r);

#endif /* WAF_WHITELIST_H */ 