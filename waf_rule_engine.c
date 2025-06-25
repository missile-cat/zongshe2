#include "waf_common.h"

/*
 * waf_rule_engine.c - WAF 规则执行引擎
 *
 * =====================================================================================
 *  [模块职责]
 *    - 作为 WAF 的核心检测逻辑单元。
 *    - 遍历当前 location 配置的所有规则 (`waf_rule_t`)。
 *    - 对每一条规则，它会：
 *      1. 调用 `waf_request.c` 来获取规则所需的请求变量数据。
 *      2. 调用 `waf_transform.c` 对获取到的数据进行转换 (如小写、URL解码)。
 *      3. 执行规则中定义的操作符 (如正则表达式匹配)。
 *    - 如果发现匹配的规则，立即停止执行并返回该规则。
 *
 *  [函数说明]
 *    - waf_exec_rules:      [核心] 规则引擎的主函数，负责整个检测流程的调度。
 *    - waf_exec_operator:   执行单个操作符的逻辑，如 `@rx` (正则匹配) 或 `@streq` (字符串相等)。
 *
 *  [调用关系]
 *    - ngx_http_waf_module.c::ngx_http_waf_handler() -> waf_exec_rules()
 *    - waf_exec_rules() -> waf_request.c::waf_get_var()
 *    - waf_exec_rules() -> waf_transform.c::waf_exec_transformations()
 *    - waf_exec_rules() -> waf_exec_operator()
 * =====================================================================================
 */

// --- 本地函数前置声明 ---
static ngx_int_t waf_exec_operator(ngx_log_t *log, waf_rule_t *rule, const ngx_str_t *input);

/**
 * @brief [核心] 执行当前 location 的所有 WAF 规则。
 *
 * @param r  Nginx 请求对象。
 *
 * @return waf_rule_t* 如果有规则匹配成功，则返回指向该规则的指针；
 *                     如果所有规则都未匹配，则返回 NULL。
 *
 * @note 这是 WAF 检测逻辑的入口点。它会按顺序遍历规则列表，一旦发现
 *       第一个匹配的规则，就会立即"短路"(short-circuit)并返回，
 *       不再继续检查后续规则。
 */
waf_rule_t *waf_exec_rules(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    waf_rule_t *rules;
    ngx_uint_t i;
    
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    if (lcf == NULL || lcf->rules == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG] Rule engine exiting: No location config or rules array found.");
        return NULL; // 没有配置或没有规则
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG] Rule engine entered with %ud rule(s).", lcf->rules->nelts);

    rules = lcf->rules->elts;
    for (i = 0; i < lcf->rules->nelts; i++) {
        waf_rule_t *current_rule = &rules[i];
        waf_variable_t var_to_check;
        ngx_str_t transformed_value;
        
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG] >> Checking Rule ID: %s", current_rule->id ? (char*)current_rule->id : "N/A");

        // --- 步骤 1: 获取变量数据 ---
        var_to_check.type = current_rule->variable_type;
        var_to_check.arg = current_rule->variable_arg;
        ngx_int_t rc = waf_get_var(r, &var_to_check);

        if (rc == NGX_DECLINED || rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]     - Result: Failed to get variable, skipping rule.");
            continue; 
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "[WAF-DEBUG]   - Step 1: waf_get_var() returned value '%.*s'", 
            (int)var_to_check.value.len, var_to_check.value.data);

        if (rc == NGX_AGAIN) {
            return (waf_rule_t *)NGX_AGAIN;
        }
        
        // --- 步骤 2: 执行转换 ---
        if (waf_exec_transformations(r->pool, &var_to_check.value, 
                                     current_rule->transform_type, &transformed_value) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]   - Step 2: Failed to execute transformations, skipping.");
            continue;
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, 
            "[WAF-DEBUG]   - Step 2: After transformation, value is '%.*s'", 
            (int)transformed_value.len, transformed_value.data);

            // --- 步骤 3: 执行操作符匹配 ---
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]   - Step 3: Executing operator with param '%.*s'", 
            (int)current_rule->op_param.len, current_rule->op_param.data
        );
        
        // [BUGFIX] ARGS 是一个集合，需要迭代检查
        if (current_rule->variable_type == VAR_ARGS && current_rule->variable_arg.len == 0) {
            u_char *args_data = transformed_value.data;
            u_char *args_end = args_data + transformed_value.len;
            u_char *current_pos = args_data;

            while (current_pos < args_end) {
                u_char *delimiter = (u_char*)ngx_strlchr(current_pos, args_end, '&');
                ngx_str_t single_arg;
                
                if (delimiter == NULL) { // 最后一个参数
                    single_arg.data = current_pos;
                    single_arg.len = args_end - current_pos;
                    current_pos = args_end;
                } else {
                    single_arg.data = current_pos;
                    single_arg.len = delimiter - current_pos;
                    current_pos = delimiter + 1;
                }

                if (waf_exec_operator(r->connection->log, current_rule, &single_arg) == NGX_OK) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]     - Result: MATCHED! Rule triggered on arg '%.*s'.", (int)single_arg.len, single_arg.data);
                    return current_rule; // 匹配成功，立刻返回
                }
            }
            // 如果循环结束都没有匹配，则继续下一条规则
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]     - Result: No args matched for this rule.");

        } else {
            // 对于非 ARGS 集合的变量，或指定了参数的 ARGS (如 ARGS:id)，执行原始逻辑
            if (waf_exec_operator(r->connection->log, current_rule, &transformed_value) == NGX_OK) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF-DEBUG]     - Result: MATCHED! Rule triggered.");
                return current_rule; 
            }
        }
    }

    return NULL;
}

/**
 * @brief 执行单个操作符的匹配逻辑。
 *
 * @param log  Nginx 日志对象。
 * @param rule  当前正在执行的规则。
 * @param input 经过转换函数处理后的、待检测的输入字符串。
 *
 * @return ngx_int_t 匹配成功返回 NGX_OK，失败返回 NGX_DECLINED。
 *
 * @note 此函数是规则匹配的核心判断点。
 *       - 对于 `@rx`，它使用预编译好的 PCRE 正则表达式 (`rule->op_regex`)
 *         对输入字符串进行匹配。
 *       - 对于 `@streq`，它执行简单的字符串完全相等比较。
 */
static ngx_int_t waf_exec_operator(ngx_log_t *log, waf_rule_t *rule, const ngx_str_t *input) {
    if (input == NULL || input->data == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: Input data is NULL, declining.", rule->id);
        return NGX_DECLINED;
    }

    switch (rule->op_type) {
        case OP_RX: {
            if (rule->op_regex == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: Regex is NULL, declining.", rule->id);
                return NGX_DECLINED;
            }
            ngx_int_t rc = ngx_regex_exec(rule->op_regex, (ngx_str_t *)input, NULL, 0);
            if (rc > 0) {
                 ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: RX match success.", rule->id);
                return NGX_OK;
            }
            return NGX_DECLINED;
        }

        case OP_STREQ: {
            if (rule->op_param.data == NULL) {
                ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: STREQ param is NULL, declining.", rule->id);
                return NGX_DECLINED;
            }

            // [BUGFIX] 当应用于 ARGS 时，只比较 '=' 后面的 value 部分
            ngx_str_t value_to_check = *input;
            if (rule->variable_type == VAR_ARGS) {
                u_char *eq_pos = (u_char*)ngx_strlchr(input->data, input->data + input->len, '=');
                if (eq_pos != NULL) {
                    value_to_check.data = eq_pos + 1;
                    value_to_check.len = (input->data + input->len) - (eq_pos + 1);
                }
            }

            if (value_to_check.len == rule->op_param.len &&
                ngx_strncmp(value_to_check.data, rule->op_param.data, value_to_check.len) == 0) {
                ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: STREQ match success.", rule->id);
                return NGX_OK;
            }
            return NGX_DECLINED;
    }
    
        // 扩展点: 在此添加对其他操作符的支持
        // case OP_CONTAINS: { ... }
        // case OP_PM: { ... }

        default:
            ngx_log_error(NGX_LOG_WARN, log, 0, "[WAF] Operator for rule %d: Unknown operator type %d, declining.", rule->id, rule->op_type);
            return NGX_DECLINED;
    }
    
    return NGX_DECLINED;
}

// 规则加载、编译等可在配置解析时实现，这里略。 