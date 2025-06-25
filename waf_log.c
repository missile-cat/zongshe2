/*
 * waf_log.c - WAF 日志记录模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 提供一个统一的接口 (`waf_log_attack`)，用于将检测到的攻击事件
 *      记录到 Nginx 的错误日志中。
 *    - 日志记录是异步的、高性能的，并且遵循 Nginx 的标准实践。
 *
 *  [函数说明]
 *    - waf_log_attack: [核心] 当有规则匹配时，此函数被调用以生成一条
 *                      详细的攻击日志。
 *
 *  [调用关系]
 *    - waf_action.c::waf_exec_actions() -> waf_log_attack()
 * =====================================================================================
 */
#include "waf_common.h"

/**
 * @brief [核心] 将攻击事件记录到 Nginx 的 error_log。
 *
 * @param r     Nginx 请求对象。
 * @param rule  触发日志记录的规则。
 *
 * @note 此函数会检查配置中的 waf_log 开关。如果日志被禁用，则不执行任何操作。
 *       日志级别为 NGX_LOG_WARN，以便管理员可以轻松地从常规日志中过滤出 WAF 事件。
 *       日志格式: [waf] Attack intercepted. client: [IP], server: [host], 
 *                 request: "[request line]", ruleid: [ID], action: [action]
 */
void waf_log_attack(ngx_http_request_t *r, waf_rule_t *rule) {
    waf_loc_conf_t *lcf;

    // 获取 location 配置
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf == NULL) {
        return;
    }

    // 检查日志是否启用
    if (!lcf->log_enable) {
        return;
    }

    // 使用 Nginx 核心的日志功能来记录，这是最高效的方式
    // 增加对 host header 的空指针检查，防止异常请求导致崩溃
    if (r->headers_in.host != NULL && r->headers_in.host->value.len > 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "[waf] Attack Detected. client_ip=%V, server_name=%V, request_url=\"%V\", rule_id=%s, action=%s",
                  &r->connection->addr_text,
                  &r->headers_in.host->value,
                  &r->request_line,
                  rule->id,
                  rule->action_str);
    } else {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "[waf] Attack Detected. client_ip=%V, server_name=unknown, request_url=\"%V\", rule_id=%s, action=%s",
                  &r->connection->addr_text,
                  &r->request_line,
                  rule->id,
                  rule->action_str);
    }
}

void waf_log(const char *level, const char *msg, ...) {
    // ... existing code ...
} 