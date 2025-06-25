/*
 * waf_common.h - WAF 模块公共头文件
 *
 * =====================================================================================
 *  [模块职责]
 *    - 定义整个 WAF 模块共享的核心数据结构，如 `waf_rule_t` (规则)、
 *      `waf_loc_conf_t` (配置) 等。
 *    - 提供所有 WAF 子模块 (`waf_*.c`) 的函数原型 (public API) 声明，充当
 *      模块间的 "接口定义语言"。
 *    - 包含所有必要的 Nginx 和标准库头文件，简化各模块的 `include` 声明。
 *
 *  [结构体说明]
 *    - waf_transformations_t: [转换] 用标志位记录一条规则需要执行哪些转换函数。
 *    - waf_variable_t:        [变量] 存储一个要检查的变量名 (如 "ARGS:id")。
 *    - waf_actions_t:         [动作] 存储解析后的动作，包括标志位和参数。
 *    - waf_rule_t:            [规则] WAF 的核心，一条 `SecRule` 的完整 C 语言表示。
 *                             它聚合了转换、变量、操作符和动作。
 *    - waf_loc_conf_t:        [配置] Nginx location 级别的配置存储。WAF 的所有
 *                             规则、开关、日志设置都存放在这里。
 *
 *  [函数接口总览]
 *    - ngx_http_waf_module.c:
 *      - (static) ngx_http_waf_handler:      HTTP 请求处理主入口。
 *      - (static) ngx_http_waf_set_rule:     `SecRule` 指令的回调函数。
 *
 *    - waf_parser.c:
 *      - waf_parse_rule:                      解析单条 SecRule 规则。
 *
 *    - waf_request.c:
 *      - waf_get_var:                         从请求中提取变量值。
 *
 *    - waf_transform.c:
 *      - waf_exec_transformations:            对提取出的值应用转换函数。
 *
 *    - waf_rule_engine.c:
 *      - waf_exec_rules:                      执行所有规则。
 *
 *    - waf_action.c:
 *      - waf_exec_actions:                    执行匹配后的动作。
 *
 *    - waf_log.c:
 *      - waf_log_attack:                      记录攻击日志。
 * =====================================================================================
 */

#ifndef WAF_COMMON_H
#define WAF_COMMON_H

// --- 核心 Nginx 头文件 ---
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_regex.h> // 需要包含这个头文件以使用 ngx_regex_t

// --- 正则表达式库 (PCRE) 头文件 ---
// PCRE 是 Nginx 的标准依赖，用于高效的正则表达式匹配。
#include <pcre.h> 

// =====================================================================================
//  核心数据结构定义
// =====================================================================================

// --- 枚举和宏定义 ---

// 动作类型 (位掩码)
#define ACTION_PASS      0x0001
#define ACTION_LOG       0x0002
#define ACTION_DENY      0x0004
#define ACTION_REDIRECT  0x0008
#define ACTION_SCORE     0x0010
#define ACTION_RATELIMIT 0x0020

// 变量类型
typedef enum {
    VAR_ARGS,
    VAR_ARGS_POST,
    VAR_REQUEST_BODY,
    VAR_REQUEST_URI,
    VAR_REQUEST_HEADERS,
    VAR_REQUEST_METHOD,
    VAR_COOKIES
} waf_variable_type_t;

// 转换函数类型 (位掩码)
#define T_LOWERCASE 0x01
#define T_URLDECODE 0x02

// 操作符类型
typedef enum {
    OP_RX,      // 正则匹配
    OP_STREQ    // 字符串相等
} waf_operator_type_t;


/**
 * @brief 转换函数集合
 * @details 使用标志位 (bit-fields) 来表示一条规则需要应用哪些转换函数。
 *          这种方式比使用字符串数组更高效。
 */
typedef struct {
    ngx_uint_t lowercase:1;      // t:lowercase
    ngx_uint_t url_decode:1;     // t:urlDecode
    // 扩展点: 在此添加更多转换函数的标志位
    // ngx_uint_t remove_nulls:1;
    // ngx_uint_t html_entity_decode:1;
} waf_transformations_t;


/**
 * @brief 单条 WAF 规则的内存表示。
 *        由 waf_parser.c 在 Nginx 配置加载阶段进行填充。
 */
typedef struct {
    ngx_pool_t *pool;                   // 内存池
    u_char *id;                         // 规则 ID
    
    // 转换部分
    ngx_uint_t transform_type;          // 转换函数的位掩码 (T_*)

    // 变量部分
    waf_variable_type_t variable_type;  // 变量类型 (VAR_*)
    ngx_str_t variable_arg;             // 变量的参数 (例如，请求头的名称)

    // 操作符部分
    ngx_uint_t op_type;         // 操作符类型 (OP_RX, OP_STREQ, ...)
    ngx_str_t op_param;         // 操作符参数 (如 "@streq" 中的字符串)
    pcre_jit_stack *op_jit_stack; // PCRE JIT 堆栈 (用于性能优化)
    ngx_regex_t *op_regex;      // 编译后的 PCRE 正则表达式

    // 动作部分
    u_char* action_str;                 // 原始的 action 字符串
    ngx_uint_t action_type;             // 动作的位掩码 (ACTION_*)
    ngx_int_t action_score;             // "score" 动作的分值
    ngx_str_t action_redirect_url;      // "redirect" 动作的 URL
    
    ngx_array_t *actions;       // 动作数组 (waf_action_t)
} waf_rule_t;


/**
 * @brief 用于在请求处理过程中传递从请求中提取出的变量。
 */
typedef struct {
    waf_variable_type_t type;
    ngx_str_t arg;
    ngx_str_t value;
} waf_variable_t;


/**
 * @brief Nginx location 级别的配置块
 * @details 用于存储在 nginx.conf 的 `location` 块内定义的 WAF 相关配置。
 *          Nginx 会为每个配置了 WAF 指令的 location 创建一个这样的结构体实例。
 */
typedef struct {
    ngx_flag_t enable;          // WAF 总开关 (waf on/off)
    ngx_flag_t log_enable;      // WAF 日志开关 (waf_log on/off)
    ngx_array_t *rules;         // [核心] 存储该 location 所有 SecRule 规则的数组
    ngx_array_t *whitelist;     // IP白名单 (ngx_str_t)
    ngx_array_t *blacklist;     // IP黑名单 (ngx_str_t)
    ngx_array_t *url_whitelist; // URL白名单 (ngx_str_t)
} waf_loc_conf_t;


/**
 * @brief [新增] WAF 请求上下文
 * @details 用于存储单个请求的处理状态，每个请求都有自己独立的实例。
 */
typedef struct {
    ngx_flag_t has_read_body;   // 用于防止 body 读取死循环的标志
} waf_ctx_t;


/**
 * @brief [新增] Nginx main 级别的配置块
 * @details 用于存储 WAF 的全局配置，这些配置在所有 server 和 location 之间共享。
 */
typedef struct {
    ngx_array_t *rules;             /* waf_rule_t 数组 */
    ngx_int_t block_threshold;
    ngx_int_t block_timeout;
    ngx_shm_zone_t *shm_zone;
    ngx_uint_t shm_size;
} waf_main_conf_t;


// =====================================================================================
//  各子模块函数原型声明 (Public APIs)
// =====================================================================================

/**
 * @file waf_parser.c
 * @brief 解析 nginx.conf 中的 SecRule 字符串为 waf_rule_t 结构体。
 */
ngx_int_t waf_parse_rule(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *trans_str,
                         ngx_str_t *var_str, ngx_str_t *op_str, ngx_str_t *act_str);

/**
 * @file waf_request.c
 * @brief 从 ngx_http_request_t 中提取规则所需的变量值。
 * @param r      Nginx 请求对象。
 * @param var    需要提取的变量定义。
 * @return 成功找到返回 NGX_OK，未找到返回 NGX_DECLINED, 需要等待返回 NGX_AGAIN。
 */
ngx_int_t waf_get_var(ngx_http_request_t *r, waf_variable_t *var);

/**
 * @file waf_transform.c
 * @brief 对提取出的变量值应用转换函数。
 * @param pool       内存池，用于可能的新内存分配。
 * @param input      输入字符串。
 * @param trans_mask 需要应用的转换函数位掩码。
 * @param output     [输出参数] 存放转换结果的字符串。
 * @return 始终返回 NGX_OK。
 */
ngx_int_t waf_exec_transformations(ngx_pool_t *pool, const ngx_str_t *input, 
                                   ngx_uint_t trans_mask, ngx_str_t *output);

/**
 * @file waf_rule_engine.c
 * @brief 遍历并执行所有规则，返回第一条匹配的规则。
 * @param r Nginx 请求对象。
 * @return 如果有规则匹配，返回指向该 waf_rule_t 的指针；
 *         如果需要等待 request body，返回 (waf_rule_t *)NGX_AGAIN；
 *         否则返回 NULL。
 */
waf_rule_t* waf_exec_rules(ngx_http_request_t *r);

/**
 * @file waf_action.c
 * @brief 根据匹配到的规则，执行相应的动作 (如 deny, log)。
 * @param r             Nginx 请求对象。
 * @param matched_rule  已匹配的规则。
 * @return 如果执行了中断性动作，返回 HTTP 错误码 (如 403)；否则返回 NGX_DECLINED。
 */
ngx_int_t waf_exec_actions(ngx_http_request_t *r, waf_rule_t *matched_rule);


/**
 * @file waf_log.c
 * @brief 将攻击事件记录到 Nginx 的 error_log。
 * @param r     Nginx 请求对象。
 * @param rule  触发日志记录的规则。
 */
void waf_log_attack(ngx_http_request_t *r, waf_rule_t *rule);

// --- 包含其他子模块的公共头文件 ---
#include "waf_whitelist.h"
#include "waf_blacklist.h"
#include "waf_url_whitelist.h"

extern ngx_module_t ngx_http_waf_module;

#endif /* WAF_COMMON_H */ 