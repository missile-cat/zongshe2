#ifndef WAF_URL_WHITELIST_H
#define WAF_URL_WHITELIST_H

#include "waf_common.h"

/**
 * @file waf_url_whitelist.c
 * @brief "waf_url_whitelist" 指令的回调函数。
 *        解析 nginx.conf 中的 URL 路径并存入配置。
 */
char *waf_set_url_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/**
 * @file waf_url_whitelist.c
 * @brief 检查当前请求的 URL 是否在白名单中。
 * @return 如果匹配白名单返回 NGX_OK，否则返回 NGX_DECLINED。
 */
ngx_int_t waf_check_url_whitelist(ngx_http_request_t *r);

#endif /* WAF_URL_WHITELIST_H */ 