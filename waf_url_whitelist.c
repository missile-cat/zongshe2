/*
 * waf_url_whitelist.c - WAF URL白名单模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 实现基于 URL 的白名单功能。
 *    - 允许用户在配置文件中指定一个或多个 URL 路径，凡是匹配这些路径的请求，
 *      都将直接跳过 WAF 的所有安全检测，从而可以避免对特定接口（如文件上传）的误判。
 *
 *  [函数说明]
 *    - waf_set_url_whitelist:   [回调] 解析 `waf_url_whitelist` 指令，将配置的
 *                               URL 添加到一个 ngx_array_t 数组中。
 *    - waf_check_url_whitelist: [核心] 检查当前请求的 URI 是否匹配白名单中的任何一个条目。
 *
 *  [调用关系]
 *    - Nginx Core -> waf_set_url_whitelist()                (配置阶段)
 *    - ngx_http_waf_module.c -> waf_check_url_whitelist()   (请求处理阶段)
 * =====================================================================================
 */
#include "waf_common.h"

/**
 * @brief [回调] 解析 `waf_url_whitelist` 配置指令。
 *
 * @param cf   Nginx 配置上下文。
 * @param cmd  指令对象。
 * @param conf 指向 location 配置结构体的指针。
 *
 * @return char* 成功返回 NGX_CONF_OK，失败返回错误信息字符串。
 *
 * @note 当 Nginx 在配置文件中遇到 `waf_url_whitelist` 指令时，此函数被调用。
 *       它负责将指令的参数（即 URL 路径）添加到一个动态数组 `lcf->url_whitelist` 中，
 *       以供请求处理阶段使用。
 */
char *waf_set_url_whitelist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_loc_conf_t *lcf = conf;
    ngx_str_t *value;
    ngx_str_t *new_url;

    // 确保 url_whitelist 数组已初始化
    if (lcf->url_whitelist == NULL) {
        lcf->url_whitelist = ngx_array_create(cf->pool, 5, sizeof(ngx_str_t));
        if (lcf->url_whitelist == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    
    // 向数组中添加一个新的 URL 条目
    new_url = ngx_array_push(lcf->url_whitelist);
    if (new_url == NULL) {
        return NGX_CONF_ERROR;
    }
    *new_url = value[1];

    return NGX_CONF_OK;
}

/**
 * @brief [核心] 检查当前请求的 URI 是否在白名单中。
 *
 * @param r Nginx 请求对象。
 *
 * @return ngx_int_t 如果在白名单中，返回 NGX_OK；否则返回 NGX_DECLINED。
 *
 * @note 此函数在 WAF 主处理函数中被调用。它会遍历 `lcf->url_whitelist` 数组，
 *       将数组中的每个白名单 URL 与当前请求的 URI (`r->uri`) 进行前缀匹配。
 *       只要有一个匹配成功，就立即返回 NGX_OK，表示请求应被放行。
 */
ngx_int_t waf_check_url_whitelist(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    ngx_str_t *whitelist_urls;
    ngx_uint_t i;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);

    // 如果没有配置白名单，则直接返回"不在白名单中"
    if (lcf->url_whitelist == NULL) {
        return NGX_DECLINED;
    }

    whitelist_urls = lcf->url_whitelist->elts;
    for (i = 0; i < lcf->url_whitelist->nelts; i++) {
        // 使用 ngx_strncmp 进行前缀匹配，例如白名单是 "/api/"，
        // 那么 "/api/user" 和 "/api/post" 都会匹配成功。
        if (r->uri.len >= whitelist_urls[i].len &&
            ngx_strncmp(r->uri.data, whitelist_urls[i].data, whitelist_urls[i].len) == 0) {
            return NGX_OK; // 匹配成功
        }
    }

    return NGX_DECLINED; // 遍历完毕，未匹配
} 