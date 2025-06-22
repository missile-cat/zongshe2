#include "waf_common.h"
#include <stdio.h>
#include <time.h>

/*
 * waf_log.c - WAF 日志记录模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 将 WAF 的拦截事件格式化并输出到 Nginx 的标准错误日志中。
 *    - 本模块不直接进行文件 I/O 操作，而是通过调用 Nginx 核心的 `ngx_log_error` API，
 *      从而可以利用 Nginx 强大而高效的日志系统（如日志级别、缓冲、轮转等）。
 *
 *  [函数说明]
 *    - waf_log_rule_match: [核心] 当一个规则匹配成功时被调用，负责生成一条详细的、
 *                          包含了攻击时间、IP、URL、规则ID和执行动作的日志信息。
 *
 *  [调用关系]
 *    - waf_action.c::waf_exec_actions() -> waf_log_rule_match() -> Nginx Core Logging
 * =====================================================================================
 */

// 定义一个足够大的缓冲区来安全地格式化日志消息
#define WAF_LOG_BUFFER_SIZE 2048

/**
 * @brief 将 WAF 规则匹配事件写入 Nginx 的错误日志。
 *
 * @param r     Nginx 请求对象，用于获取连接、日志上下文和请求URI等信息。
 * @param rule  触发的 WAF 规则，用于获取规则ID和动作字符串。
 *
 * @note 此函数是 WAF 可观测性的核心。
 *       1. 它首先检查当前位置的配置是否启用了日志 (`log_enable`)。
 *       2. 然后，它使用 `ngx_snprintf` 将所有关键信息（规则ID、客户端IP、URL、动作）
 *          安全地格式化到一个缓冲区中。
 *       3. 最后，它以 `NGX_LOG_NOTICE` 级别调用 `ngx_log_error`，将格式化后的
 *          字符串写入 Nginx 的错误日志。选择 NOTICE 级别是为了确保在默认的
 *          `error_log` 配置下这些重要的安全事件能被记录下来。
 */
void waf_log_rule_match(ngx_http_request_t *r, waf_rule_t *rule) {
    waf_loc_conf_t *lcf;
    u_char log_buffer[WAF_LOG_BUFFER_SIZE];
    
    // 获取 location 配置
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf == NULL || !lcf->log_enable) {
        return; // 如果日志未启用，则直接返回
    }
    
    // 使用 ngx_snprintf 安全地格式化日志消息
    // %V 是 Nginx 特有的格式化符号，用于打印 ngx_str_t 类型的字符串
    (void) ngx_snprintf(log_buffer, WAF_LOG_BUFFER_SIZE,
                       "[WAF] Matched Rule(ID: %s) | Client: %V | URL: %V | Action: %s",
                       rule->id,
                       &r->connection->addr_text,
                       &r->unparsed_uri,
                       rule->action_str);
    
    // 调用 Nginx 核心日志函数来记录日志
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "%s", log_buffer);
}

/**
 * @brief 将一次攻击事件记录到日志文件中。
 * @param r      当前的 Nginx 请求对象。
 * @param lcf    当前 location 的 WAF 配置，主要为了获取日志文件句柄 log_fd。
 * @param rule   已匹配成功的规则，用于获取日志内容。
 *
 * @note 日志格式示例:
 *   [WAF] Attack from 127.0.0.1, rule: 101, msg: 'SQL Injection', uri: /search?q=1'or'1'='1
 */
void waf_log_attack(ngx_http_request_t *r, waf_rule_t *rule) {
    waf_loc_conf_t *lcf;

    // 获取 location 配置并检查是否启用日志
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf == NULL || !lcf->log_enable) {
        return;
    }

    // 统一使用 ngx_log_error 记录攻击事件，消除对文件 I/O 的依赖
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "[WAF][Attack] client:%V rule:%s action:%s uri:%V",
        &r->connection->addr_text,
        rule->id,
        rule->action_str,
        &r->unparsed_uri);
}


