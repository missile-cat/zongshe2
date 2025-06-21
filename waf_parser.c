/*
 * waf_parser.c - WAF 规则解析器模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 解析用户在 nginx.conf 中定义的 `SecRule` 指令。
 *    - 将字符串形式的规则（变量、操作符、动作）转换为高效的内部数据结构 (`waf_rule_t`)。
 *    - 对规则的语法进行合法性校验，例如检查参数数量、操作符格式等。
 *    - 预编译正则表达式，将性能开销大的操作尽可能地提前到配置加载阶段。
 *
 *  [函数说明]
 *    - waf_parse_rule:           [核心] SecRule 指令解析的主入口。
 *    - waf_parse_variable:       解析规则的"变量"部分 (e.g., "ARGS", "REQUEST_HEADERS")。
 *    - waf_parse_operator:       解析规则的"操作符"部分 (e.g., "@rx", "@streq")，并预编译正则。
 *    - waf_parse_action:         解析规则的"动作"部分 (e.g., "deny", "score:10")。
 *    - waf_parse_transformation: 解析规则的"转换函数"部分 (e.g., "t:lowercase")。
 *
 *  [调用关系]
 *    - ngx_http_waf_module.c::ngx_http_waf_set_rule() -> waf_parse_rule()
 * =====================================================================================
 */
#include "waf_common.h"

// --- 本地函数前置声明 ---
static ngx_int_t waf_parse_variable(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *var_str);
static ngx_int_t waf_parse_operator(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *op_str);
static ngx_int_t waf_parse_action(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *act_str);
static ngx_int_t waf_parse_transformation(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *trans_str);

/**
 * @brief [核心] 解析单条 SecRule 规则。
 *
 * @param cf         Nginx 配置上下文，用于内存分配和日志记录。
 * @param rule       一个指向 waf_rule_t 结构体的指针，解析结果将填充到这里。
 * @param trans_str  包含转换函数定义的字符串 (可能为 NULL)。
 * @param var_str    包含变量定义的字符串。
 * @param op_str     包含操作符定义的字符串。
 * @param act_str    包含动作定义的字符串。
 *
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 *
 * @note 此函数是规则解析的总调度器。它按照"转换 -> 变量 -> 操作符 -> 动作"的顺序，
 *       依次调用相应的子解析函数来完成对整条规则的解析和填充。
 */
ngx_int_t waf_parse_rule(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *trans_str,
                         ngx_str_t *var_str, ngx_str_t *op_str, ngx_str_t *act_str) {

    ngx_memzero(rule, sizeof(waf_rule_t));
    rule->pool = cf->pool;

    if (trans_str != NULL && waf_parse_transformation(cf, rule, trans_str) != NGX_OK) return NGX_ERROR;
    if (waf_parse_variable(cf, rule, var_str) != NGX_OK) return NGX_ERROR;
    if (waf_parse_operator(cf, rule, op_str) != NGX_OK) return NGX_ERROR;
    if (waf_parse_action(cf, rule, act_str) != NGX_OK) return NGX_ERROR;

    return NGX_OK;
}

/**
 * @brief 解析规则的"转换函数"部分。
 *
 * @param cf       Nginx 配置上下文。
 * @param rule     待填充的规则结构体。
 * @param trans_str 包含转换函数的字符串，例如 "t:lowercase,t:urlDecode"。
 *
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 *
 * @note 此函数会解析逗号分隔的转换函数列表，并将对应的转换函数ID
 *       (如 T_LOWERCASE, T_URLDECODE) 通过位或操作存入 rule->transform_type。
 */
static ngx_int_t waf_parse_transformation(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *trans_str) {
    if (trans_str == NULL || trans_str->data == NULL) return NGX_OK;

    // 示例: "t:lowercase,t:urlDecode"
    if (ngx_strstr(trans_str->data, "t:lowercase")) rule->transform_type |= T_LOWERCASE;
    if (ngx_strstr(trans_str->data, "t:urlDecode")) rule->transform_type |= T_URLDECODE;
    
    return NGX_OK;
}

/**
 * @brief 解析规则的"变量"部分。
 *
 * @param cf       Nginx 配置上下文。
 * @param rule     待填充的规则结构体。
 * @param var_str  包含变量定义的字符串，例如 "ARGS" 或 "REQUEST_HEADERS:User-Agent"。
 *
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 *
 * @note 函数会识别变量类型（如 VAR_ARGS, VAR_REQUEST_HEADERS），并将其存入
 *       `rule->variable_type`。如果变量带有参数（如 `User-Agent`），
 *       参数会被存入 `rule->variable_arg`。
 */
static ngx_int_t waf_parse_variable(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *var_str) {
    u_char *p = (u_char*) ngx_strchr(var_str->data, ':');
    ngx_str_t collection, arg;

    if (p != NULL) {
        collection.data = var_str->data;
        collection.len = p - var_str->data;
        arg.data = p + 1;
        arg.len = var_str->data + var_str->len - (p + 1);
        rule->variable_arg = arg;
    } else {
        collection = *var_str;
    }
    
    // 宏用于简化字符串比较
    #define COMPARE_VAR(name, type) \
        if (collection.len == sizeof(name) - 1 && ngx_strncasecmp(collection.data, (u_char*)name, collection.len) == 0) \
            { rule->variable_type = type; return NGX_OK; }

    COMPARE_VAR("ARGS", VAR_ARGS);
    COMPARE_VAR("ARGS_POST", VAR_ARGS_POST);
    COMPARE_VAR("REQUEST_BODY", VAR_REQUEST_BODY);
    COMPARE_VAR("REQUEST_URI", VAR_REQUEST_URI);
    COMPARE_VAR("REQUEST_HEADERS", VAR_REQUEST_HEADERS);
    COMPARE_VAR("REQUEST_METHOD", VAR_REQUEST_METHOD);
    COMPARE_VAR("COOKIES", VAR_COOKIES);

    #undef COMPARE_VAR

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown variable: \"%V\"", &collection);
    return NGX_ERROR;
}

/**
 * @brief 解析规则的"操作符"部分。
 *
 * @param cf      Nginx 配置上下文。
 * @param rule    待填充的规则结构体。
 * @param op_str  包含操作符和参数的字符串，例如 "@rx evil_pattern" 或 "@streq bad_string"。
 *
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 *
 * @note 这是解析逻辑中最关键和复杂的部分。
 *       - 识别操作符类型（如 OP_RX, OP_STREQ），存入 `rule->op_type`。
 *       - 提取操作符参数（正则表达式或字符串），存入 `rule->op_param`。
 *       - 如果是正则表达式 (`@rx`)，则调用 PCRE JIT 进行预编译，将编译结果
 *         存入 `rule->op_regex`，这极大地提升了运行时性能。
 */
static ngx_int_t waf_parse_operator(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *op_str) {
    u_char *p = (u_char*) ngx_strchr(op_str->data, ' ');
    ngx_str_t op_name, op_param;

    if (p != NULL) {
        op_name.data = op_str->data;
        op_name.len = p - op_str->data;
        op_param.data = p + 1;
        op_param.len = op_str->data + op_str->len - (p + 1);
    } else {
        op_name = *op_str;
        ngx_str_null(&op_param);
    }
    
    // 去除参数两边的引号
    if (op_param.len >= 2 && op_param.data[0] == '"' && op_param.data[op_param.len - 1] == '"') {
        op_param.data++;
        op_param.len -= 2;
    }
    rule->op_param = op_param;
    
    // 解析操作符类型
    if (op_name.len == (sizeof("@rx")-1) && ngx_strncmp(op_name.data, (u_char*)"@rx", op_name.len) == 0) {
        rule->op_type = OP_RX;
        // [核心] 预编译正则表达式
        ngx_regex_compile_t rc;
        u_char errstr[NGX_MAX_CONF_ERRSTR];
        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));
        rc.pattern = op_param;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;
        if (ngx_regex_compile(&rc) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "regex compile failed: %V in \"%V\"", &rc.err, &op_param);
            return NGX_ERROR;
        }
        rule->op_regex = rc.regex;
    } else if (op_name.len == (sizeof("@streq")-1) && ngx_strncmp(op_name.data, (u_char*)"@streq", op_name.len) == 0) {
        rule->op_type = OP_STREQ;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown operator: \"%V\"", &op_name);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * @brief 解析规则的"动作"部分。
 *
 * @param cf      Nginx 配置上下文。
 * @param rule    待填充的规则结构体。
 * @param act_str 包含一个或多个动作的字符串，例如 "id:'1001',action:'deny,log'"。
 *
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 *
 * @note 函数负责解析逗号分隔的动作列表。
 *       - 提取规则ID，存入 `rule->id`。
 *       - 识别每个动作（如 deny, log, score, redirect），并设置 `rule->action_type`
 *         中的对应位。
 *       - 如果动作带参数（如 `score:10`），则解析参数值并存入相应的字段
 *         (`rule->action_score`)。
 *       - 将完整的动作字符串存入 `rule->action_str`，供日志记录使用。
 */
static ngx_int_t waf_parse_action(ngx_conf_t *cf, waf_rule_t *rule, ngx_str_t *act_str) {
    rule->action_str = (u_char*) ngx_pstrdup(cf->pool, act_str);
    
    // 提取 ID
    u_char* id_start = (u_char*) ngx_strstr(act_str->data, "id:'");
    if (id_start) {
        id_start += sizeof("id:'") - 1;
        u_char* id_end = (u_char*) ngx_strchr(id_start, '\'');
        if (id_end) {
            rule->id = ngx_palloc(cf->pool, id_end - id_start + 1);
            ngx_memcpy(rule->id, id_start, id_end - id_start);
            rule->id[id_end - id_start] = '\0';
        }
    }
    
    // 解析动作类型
    if (ngx_strstr(act_str->data, "deny")) rule->action_type |= ACTION_DENY;
    if (ngx_strstr(act_str->data, "log")) rule->action_type |= ACTION_LOG;
    if (ngx_strstr(act_str->data, "pass")) rule->action_type |= ACTION_PASS;
    if (ngx_strstr(act_str->data, "ratelimit")) rule->action_type |= ACTION_RATELIMIT;
    
    // 解析带参数的动作
    u_char* score_start = (u_char*) ngx_strstr(act_str->data, "score:");
    if (score_start) {
        rule->action_type |= ACTION_SCORE;
        score_start += sizeof("score:") - 1;
        rule->action_score = ngx_atoi(score_start, act_str->data + act_str->len - score_start);
    }
    
    u_char* redirect_start = (u_char*) ngx_strstr(act_str->data, "redirect:'");
    if (redirect_start) {
        rule->action_type |= ACTION_REDIRECT;
        redirect_start += sizeof("redirect:'") - 1;
        u_char* redirect_end = (u_char*) ngx_strchr(redirect_start, '\'');
        if (redirect_end) {
            rule->action_redirect_url.data = redirect_start;
            rule->action_redirect_url.len = redirect_end - redirect_start;
        }
    }

    return NGX_OK;
}
