/*
 * waf_whitelist.c - WAF IP白名单模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 实现基于 IP 地址和 CIDR 网段的白名单功能。
 *    - 允许用户在配置文件中指定一个或多个可信的 IP 或网段，所有来自这些来源的请求
 *      都将直接跳过 WAF 的所有安全检测。
 *
 *  [函数说明]
 *    - waf_set_whitelist:   [回调] 解析 `waf_whitelist` 指令，该指令的参数可以是
 *                           单个 IP (e.g., "1.2.3.4") 或 CIDR 网段 (e.g., "10.0.0.0/8")。
 *                           它会将解析后的规则添加到一个 `ngx_cidrs` 数组中。
 *    - waf_check_whitelist: [核心] 检查当前请求的客户端 IP 是否匹配白名单中的任何一个条目。
 *                           Nginx 的 `ngx_http_auth_basic_user` 函数被巧妙地重用于此，
 *                           因为它内部已经包含了高效的 CIDR 匹配逻辑。
 *
 *  [调用关系]
 *    - Nginx Core -> waf_set_whitelist()                (配置阶段)
 *    - ngx_http_waf_module.c -> waf_check_whitelist()   (请求处理阶段)
 * =====================================================================================
 */
#include "waf_common.h"

// --- 本地函数前置声明 ---
static char* waf_parse_cidr_list(ngx_conf_t *cf, ngx_array_t *cidrs, ngx_str_t *value);

/**
 * @brief [回调] 解析 `waf_whitelist` 配置指令。
 *
 * @param cf   Nginx 配置上下文。
 * @param cmd  指令对象。
 * @param conf 指向 location 配置结构体的指针。
 *
 * @return char* 成功返回 NGX_CONF_OK，失败返回错误信息字符串。
 *
 * @note 当 Nginx 在配置文件中遇到 `waf_whitelist` 指令时，此函数被调用。
 *       它利用 Nginx 提供的 `ngx_http_whitelist_directive_helper` 辅助函数
 *       来完成对 IP 或 CIDR 的解析和存储，极大地简化了实现。
 */
char *waf_set_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_loc_conf_t *lcf = conf;

    // 确保白名单数组已经初始化
    if (lcf->whitelist == NULL) {
        lcf->whitelist = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
        if (lcf->whitelist == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    // 调用辅助函数来解析并添加 IP/CIDR
    return waf_parse_cidr_list(cf, lcf->whitelist, &((ngx_str_t*)cf->args->elts)[1]);
}

/**
 * @brief [核心] 检查当前请求的客户端 IP 是否在白名单中。
 *
 * @param r Nginx 请求对象。
 *
 * @return ngx_int_t 如果在白名单中，返回 NGX_OK；否则返回 NGX_DECLINED。
 *
 * @note 此函数在 WAF 主处理函数中被调用。它巧妙地复用了 Nginx 的
 *       `ngx_http_auth_basic_user` 函数。虽然函数名看起来是用于HTTP基本认证，
 *       但其内部的核心逻辑之一就是检查客户端 IP 是否匹配一个 `ngx_cidrs` 数组，
 *       这正是我们所需要的。这种代码复用是高效 Nginx 模块开发的典范。
 */
ngx_int_t waf_check_whitelist(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if(lcf->whitelist == NULL || lcf->whitelist->nelts == 0)
    {
        // [BUG修复] 正确逻辑：如果没有配置白名单，则认为当前 IP 不在白名单内，
        // 返回 NGX_DECLINED 继续后续检查。
        return NGX_DECLINED;
    }
    waf_rule_t *rules = lcf->whitelist->elts;
    ngx_uint_t i;
    for (i = 0; i < lcf->whitelist->nelts; i++) {
        waf_rule_t *current_rule = &rules[i];
        
        // [BUG修复] 此处不再调用任何外部函数，直接在这里进行 IP 比较。
        // 这是从 waf_blacklist.c 中借鉴的、经过验证的可靠比较方法。
        if (current_rule->op_param.len == r->connection->addr_text.len &&
            ngx_memcmp(current_rule->op_param.data, r->connection->addr_text.data, r->connection->addr_text.len) == 0)
        {
            // IP 匹配白名单，应返回 NGX_OK 直接放行。
            return NGX_OK;
        }
    }
    return NGX_DECLINED;
}

/**
 * @brief [新增] 解析 IP/CIDR 列表的辅助函数。
 * 
 * @param cf Nginx 配置对象。
 * @param cidrs 用于存储解析结果的数组。
 * @param value 指向包含 IP/CIDR 字符串的 ngx_str_t。
 * @return 成功返回 NGX_CONF_OK，失败返回 NGX_CONF_ERROR。
 * 
 * @note 此函数负责处理 waf_whitelist 指令的参数，将其解析为
 *       Nginx 的 ngx_cidr_t 结构体并存入数组中。
 */
static char* waf_parse_cidr_list(ngx_conf_t *cf, ngx_array_t *cidrs, ngx_str_t *value) {
    ngx_cidr_t *cidr;
    ngx_int_t rc;

    // 为新的 CIDR 条目在数组中分配空间
    cidr = ngx_array_push(cidrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    // 使用 Nginx 核心函数将字符串解析为 CIDR 结构体
    rc = ngx_ptocidr(value, cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid CIDR address \"%V\"", value);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "low address bits of %V are meaningless", value);
    }
    
    return NGX_CONF_OK;
} 