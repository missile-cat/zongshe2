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
    ngx_str_t *value = cf->args->elts;

    // 确保白名单数组已初始化
    if (lcf->whitelist == NULL) {
        lcf->whitelist = ngx_array_create(cf->pool, 5, sizeof(ngx_cidr_t));
        if (lcf->whitelist == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    // 调用 Nginx 提供的辅助函数来解析和添加 CIDR
    // 这是一个很好的例子，展示了如何复用 Nginx 内核的功能
    return ngx_http_whitelist_directive_helper(cf, lcf->whitelist, &value[1]);
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

    // 如果没有配置白名单，则直接返回"不在白名单中"
    if (lcf->whitelist == NULL) {
        return NGX_DECLINED;
    }

    // 复用 Nginx 的 `ngx_http_auth_basic_user` 函数来进行 CIDR 匹配
    // 如果匹配成功（即 IP 在白名单中），该函数返回 NGX_OK。
    return ngx_http_auth_basic_user(r);
} 