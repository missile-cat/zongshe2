#ifndef WAF_LOG_H
#define WAF_LOG_H

#include "waf_common.h"

/**
 * @brief 将 WAF 拦截事件写入 Nginx 的错误日志。
 *
 * @param r Nginx 请求对象，用于获取连接和日志上下文。
 * @param rule 触发的 WAF 规则。
 *
 * @note 此函数通过 Nginx 的 ngx_log_error() API 记录日志，
 *       遵循 Nginx 的标准日志格式，并自动包含时间戳、进程ID等信息。
 *       日志级别固定为 NGX_LOG_NOTICE。
 */
void waf_log_rule_match(ngx_http_request_t *r, waf_rule_t *rule);

ngx_int_t waf_log_init(ngx_conf_t* cf, waf_main_conf_t* mcf);

#endif 