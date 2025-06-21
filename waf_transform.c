/*
 * waf_transform.c - WAF 数据转换模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 对从请求中提取的原始数据，应用一个或多个转换函数。
 *    - 这是绕过 WAF 常见技术（如编码、大小写变换）的核心防御手段。
 *    - 所有转换函数都应该是幂等的，即对同一个输出重复应用同一个转换函数，结果不变。
 *
 *  [函数说明]
 *    - waf_exec_transformations: [核心] 根据规则中指定的转换函数组合（一个位掩码），
 *                                依次调用具体的转换函数来处理输入数据。
 *    - lowercase:                将输入字符串转换为全小写。
 *    - url_decode:               对 URL 编码的字符串进行解码 (e.g., "%20" -> " ")。
 *
 *  [调用关系]
 *    - waf_rule_engine.c::waf_exec_rules() -> waf_exec_transformations()
 * =====================================================================================
 */
#include "waf_common.h"

// --- 本地函数前置声明 ---
static void lowercase(ngx_pool_t *pool, ngx_str_t *str);
static void url_decode(ngx_pool_t *pool, ngx_str_t *str);

/**
 * @brief [核心] 对输入字符串应用一系列转换函数。
 *
 * @param pool      Nginx 内存池，用于在需要时（如URL解码后字符串变长）分配新内存。
 * @param input     [输入] 指向原始数据的 ngx_str_t。
 * @param trans_mask 一个位掩码，每一位代表一种转换函数 (e.g., T_LOWERCASE, T_URLDECODE)。
 * @param output    [输出] 指向 ngx_str_t 的指针，用于存放转换后的结果。
 *
 * @return ngx_int_t 始终返回 NGX_OK。
 *
 * @note 此函数会检查 `trans_mask` 中的每一个标志位，如果该位置位，
 *       则调用对应的转换函数。转换操作是"就地"的，直接修改 `output` 指向的
 *       字符串内容。为了效率，它首先将 `input` 直接赋给 `output`，
 *       只有当转换确实改变了数据时，才可能分配新内存。
 */
ngx_int_t waf_exec_transformations(ngx_pool_t *pool, const ngx_str_t *input, 
                                   ngx_uint_t trans_mask, ngx_str_t *output) {
    // 初始时，输出等于输入。
    // 如果没有任何转换，函数将直接返回，避免不必要的数据拷贝。
    *output = *input;

    // 检查是否需要进行 lowercase 转换
    if (trans_mask & T_LOWERCASE) {
        lowercase(pool, output);
    }

    // 检查是否需要进行 URL decode 转换
    if (trans_mask & T_URLDECODE) {
        url_decode(pool, output);
    }

    // 扩展点: 在此添加其他转换函数，如 base64_decode, hex_decode 等
    // if (trans_mask & T_BASE64_DECODE) { ... }

    return NGX_OK;
}

/**
 * @brief 将字符串转换为全小写（in-place）。
 */
static void lowercase(ngx_pool_t *pool, ngx_str_t *str) {
    if (str == NULL || str->data == NULL) return;
    u_char *p = str->data;
    for (size_t i = 0; i < str->len; i++) {
        p[i] = ngx_tolower(p[i]);
    }
}

/**
 * @brief 对 URL 编码的字符串进行解码（in-place）。
 * @note 这是一个简化的实现。一个完整的实现需要处理各种边缘情况，
 *       例如不完整的 %xx 序列、非法的编码字符等。
 *       Nginx 提供了 `ngx_unescape_uri` 这样的核心函数，
 *       在生产级的实现中应该优先使用它们。
 */
static void url_decode(ngx_pool_t *pool, ngx_str_t *str) {
    if (str == NULL || str->data == NULL) return;
    
    u_char *dst = str->data;
    u_char *src = str->data;
    
    // 使用 Nginx 核心函数进行 URL 解码，它会处理所有细节
    ngx_unescape_uri(&dst, &src, str->len, 0);
    
    // 更新解码后字符串的长度
    str->len = dst - str->data;
} 