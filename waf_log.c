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
void waf_log_attack(ngx_http_request_t *r, waf_loc_conf_t *lcf, waf_rule_t *rule) {
    // 检查日志文件是否已经配置并成功打开。
    // lcf->log_fd 在 ngx_http_waf_init 阶段通过 log_path 打开。
    // 如果 waf_log_path 未配置或打开失败，则不记录日志。
    if (lcf->log_path.len == 0 || lcf->log_fd == NGX_INVALID_FILE) {
        return;
    }

    // 在栈上分配一个足够大的缓冲区来格式化日志消息。
    u_char log_buf[WAF_MAX_LOG_LEN];
    u_char *p;
    
    // 使用 ngx_snprintf 进行安全的格式化，防止缓冲区溢出。
    // 这是一个非阻塞的写操作，性能较高。
    p = ngx_snprintf(log_buf, WAF_MAX_LOG_LEN,
                     "[WAF] Attack from %V, rule: %V, msg: '%V', uri: %V%Z",
                     &r->connection->addr_text, // 客户端 IP 地址
                     &rule->actions.id,         // 规则 ID
                     &rule->actions.msg,        // 规则消息
                     &r->unparsed_uri);         // 完整的原始 URI
    
    // 使用 ngx_write_fd 将格式化好的日志内容写入文件。
    // 这是一个非阻塞的写操作。
    ngx_write_fd(lcf->log_fd, log_buf, p - log_buf);
}

/**
 * @brief 记录一条 WAF 安全事件日志。
 * @param conf 当前 location 的 WAF 配置，用于获取日志文件句柄。
 * @param r 当前的 Nginx 请求对象，用于获取 IP、URI 等信息。
 * @param rule 命中的规则，用于获取规则 ID、消息等信息。
 * @return 成功返回 NGX_OK，失败返回 NGX_ERROR。
 */
ngx_int_t waf_log_event(waf_loc_conf_t *conf, ngx_http_request_t *r, waf_rule_t *rule) {
    // 检查日志文件句柄是否有效
    if (conf->log_fd == NGX_INVALID_FILE) {
        // 在实际生产中，可能需要尝试重新打开日志文件
        return NGX_ERROR;
    }

    u_char buf[1024];
    u_char *p = buf;
    u_char *last = buf + sizeof(buf); // 缓冲区的末尾，防止溢出
    
    // 获取当前时间
    time_t now = time(NULL);
    struct tm tm;
    ngx_localtime(now, &tm);

    // 获取客户端 IP
    ngx_str_t ip = r->connection->addr_text;

    // 使用 ngx_snprintf 构建 JSON 格式的日志行
    // %V 是 Nginx 特有的格式化符号，用于打印 ngx_str_t 类型的字符串
    p = ngx_snprintf(p, last - p,
        "{\"timestamp\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\", "
        "\"client_ip\":\"%V\", "
        "\"request_uri\":\"%V\", "
        "\"rule_id\":\"%V\", "
        "\"message\":\"%V\", "
        "\"action\":\"%s\"}\n",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        &ip,
        &r->uri,
        &rule->actions.id,
        &rule->actions.msg,
        rule->actions.deny ? "deny" : "log" // 根据 deny 标志位决定动作是 deny 还是仅 log
    );

    // 将格式化好的字符串写入日志文件
    if (p > buf) {
        // ngx_write_fd 是一个非阻塞的写操作
        (void)ngx_write_fd(conf->log_fd, buf, p - buf);
    }
    
    return NGX_OK;
} 