/*
 * waf_action.c - WAF 动作执行模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 当一个 WAF 规则被触发时，此模块负责执行该规则所指定的防御动作。
 *    - 它是 WAF 决策的最终执行者，负责拦截请求、记录日志、计分或重定向等。
 *
 *  [函数说明]
 *    - waf_exec_actions:     [核心] 根据匹配到的规则，执行相应的动作组合。
 *    - waf_action_redirect:  执行"重定向"动作，构造并发送302响应。
 *
 *  [调用关系]
 *    - waf_rule_engine.c::waf_exec_rules() -> waf_exec_actions()
 *    - waf_exec_actions() -> waf_log.c::waf_log_rule_match()
 *    - waf_exec_actions() -> waf_blacklist.c::waf_blacklist_add_score()
 * =====================================================================================
 */
#include "waf_common.h"
#include "waf_log.h"

// 内部函数，用于处理重定向动作
static ngx_int_t waf_action_redirect(ngx_http_request_t *r, waf_rule_t *rule);

/**
 * @brief [核心] 执行 WAF 规则匹配后的防御动作。
 *
 * @param r             Nginx 请求对象。
 * @param matched_rule  已匹配到的规则。
 *
 * @return ngx_int_t    根据动作返回不同的 Nginx 状态码。
 *                      - NGX_HTTP_FORBIDDEN (403) for "deny"
 *                      - NGX_HTTP_TOO_MANY_REQUESTS (429) for "ratelimit"
 *                      - NGX_HTTP_MOVED_TEMPORARILY (302) for "redirect"
 *                      - NGX_DECLINED for "log", "pass", "score" to continue request processing.
 *
 * @note 此函数是 WAF 响应的核心，它会先记录日志，然后根据动作类型执行拦截、计分等操作。
 */
ngx_int_t waf_exec_actions(ngx_http_request_t *r, waf_rule_t *matched_rule) {
    waf_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    if (lcf == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
        "[WAF] Executing actions for matched rule id: %d", matched_rule->id);

    // 步骤1: 无论什么动作，首先记录日志。
    // 日志模块会根据配置判断是否真的需要写入。
    if (matched_rule->action_type & ACTION_LOG) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: LOG");
        waf_log_attack(r, matched_rule);
    }
    
    // 步骤2: 根据动作类型(action_type)的位掩码，执行相应的操作。
    // 这种设计允许一个规则包含多个动作。
    
    // "deny" 动作: 立即中断请求，返回 403 Forbidden。
    // 这是最高优先级的拦截动作。
    if (matched_rule->action_type & ACTION_DENY) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: DENY. Returning 403.");
        return NGX_HTTP_FORBIDDEN;
    }

    // "redirect" 动作: 将客户端重定向到指定的 URL。
    if (matched_rule->action_type & ACTION_REDIRECT) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: REDIRECT.");
        return waf_action_redirect(r, matched_rule);
    }

    // "score" 动作: 为当前客户端 IP 增加分数。
    if (matched_rule->action_type & ACTION_SCORE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: SCORE. Adding %d.", matched_rule->action_score);
        waf_blacklist_add_score(r, matched_rule->action_score);
    }
    
    // "ratelimit" 动作: 返回 429 Too Many Requests。
    // 通常用于表示速率限制，但这里作为一种独立的拦截方式。
    if (matched_rule->action_type & ACTION_RATELIMIT) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: RATELIMIT. Returning 429.");
        return NGX_HTTP_TOO_MANY_REQUESTS;
    }

    // 对于 "log", "pass", "score" 等不立即中断请求的动作，
    // 在完成日志记录和/或计分后，返回 NGX_DECLINED，
    // 允许 Nginx 继续处理该请求。
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Action: PASS/SCORE/LOG. Declining to next module.");
    return NGX_DECLINED;
}


/**
 * @brief 执行 "redirect" 动作，将客户端重定向到指定 URL。
 * 
 * @param r     Nginx 请求对象。
 * @param rule  包含重定向 URL 的规则。
 * 
 * @return ngx_int_t Nginx 状态码 (e.g., NGX_HTTP_MOVED_TEMPORARILY)。
 * 
 * @note 此函数会构造一个 HTTP 302 重定向响应。
 */
static ngx_int_t waf_action_redirect(ngx_http_request_t *r, waf_rule_t *rule) {
    ngx_table_elt_t *location_header;

    // 检查规则中是否包含合法的重定向 URL
    if (rule->action_redirect_url.len == 0) {
        // 如果没有提供 URL，则退化为 deny 动作
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "waf: redirect action for rule %s is missing a URL, denying instead.", rule->id);
        return NGX_HTTP_FORBIDDEN;
    }

    // --- 构造重定向响应 ---
    
    // 1. 设置响应状态码为 302 (临时重定向)
    r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;

    // 2. 创建并设置 Location 响应头
    location_header = ngx_list_push(&r->headers_out.headers);
    if (location_header == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    location_header->hash = 1;
    ngx_str_set(&location_header->key, "Location");
    location_header->value = rule->action_redirect_url;

    // 3. 发送响应头并结束请求
    ngx_http_send_header(r);
    
    return NGX_HTTP_MOVED_TEMPORARILY;
}
