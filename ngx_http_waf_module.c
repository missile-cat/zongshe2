/*
 * ngx_http_waf_module.c - Nginx WAF 模块主文件
 *
 * =====================================================================================
 *  [模块职责]
 *    - 作为 WAF 功能与 Nginx 内核之间的"粘合剂"。
 *    - 定义 WAF 的配置文件指令 (如 `waf on/off`, `SecRule`, `waf_log_path`)，并提供
 *      解析这些指令的回调函数。
 *    - 将 WAF 的核心处理逻辑 (`ngx_http_waf_handler`) 挂接到 Nginx 的请求处理流程中，
 *      使得 WAF 能够在适当的时机对请求进行检查。
 *    - 管理模块的配置结构体的创建和合并。
 *
 *  [函数说明]
 *    - ngx_http_waf_handler:       [核心] 请求处理函数，在 Nginx 的 REWRITE 阶段被调用，
 *                                  是 WAF 检测逻辑的起点。
 *    - ngx_http_waf_set_rule:      [回调] `SecRule` 指令的解析函数，负责启动规则解析流程。
 *    - ngx_http_waf_create_loc_conf: [回调] 创建 location 级别的配置结构体，并设置默认值。
 *    - ngx_http_waf_merge_loc_conf:  [回调] 合并父级和子级的 location 配置。
 *    - ngx_http_waf_init:          [回调] Nginx 完成配置解析后的初始化函数，用于挂接 handler。
 *
 *  [调用关系]
 *    - [配置阶段]:
 *        - Nginx Core -> ngx_http_waf_set_rule() -> waf_parser.c::waf_parse_rule()
 *    - [请求处理阶段]:
 *        - Nginx Core -> ngx_http_waf_handler() -> waf_rule_engine.c::waf_exec_rules()
 *        - ngx_http_waf_handler() -> waf_action.c::waf_exec_actions()
 * =====================================================================================
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "waf_common.h"
#include "waf_blacklist.h"
#include "waf_whitelist.h"
#include "waf_url_whitelist.h"

// 配置相关函数
static char *ngx_http_waf_set_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r);
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_waf_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_waf_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_waf_pre_init(ngx_conf_t *cf);

/**
 * @brief 定义本模块的配置文件指令。
 *
 * 这个数组是模块与 Nginx 配置系统交互的核心。
 */
static ngx_command_t ngx_http_waf_commands[] = {
    {
        ngx_string("waf"), // 指令名称
        // 指令作用域: main, srv, loc; 指令类型: on/off 开关
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot, // Nginx 提供的标准回调，用于处理 on/off
        NGX_HTTP_LOC_CONF_OFFSET, // 配置存储在 location 配置结构体中
        offsetof(waf_loc_conf_t, enable), // 具体存储到 enable 字段
        NULL
    },
    {
        ngx_string("waf_log"),
        // 作用域: main, srv, loc; 类型: 带1个参数
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot, // Nginx 提供的标准回调，用于处理字符串参数
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(waf_loc_conf_t, log_enable), // 存储到 log_enable 字段
        NULL
    },
    {
        ngx_string("waf_shm_size"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_http_waf_shm_size,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("waf_block_threshold"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(waf_main_conf_t, block_threshold),
        NULL
    },
    {
        ngx_string("waf_block_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(waf_main_conf_t, block_timeout),
        NULL
    },
    {
        ngx_string("waf_url_whitelist"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        waf_set_url_whitelist,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("SecRule"),
        // [BUG修复] 原来的 NGX_CONF_TAKE1 是错误的，它限制指令只能带一个参数。
        // 而处理函数实际需要3或4个参数。改为 NGX_CONF_1MORE，允许指令携带多个参数，
        // 具体的参数数量检查交由指令的回调函数 ngx_http_waf_set_rule 进行。
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_waf_set_rule, // 使用我们自定义的回调函数来解析规则
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    { ngx_string("waf_whitelist"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      waf_set_whitelist,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command // 数组结束标志
};

/**
 * @brief 定义模块的上下文 (context)。
 *
 * 这个结构体将我们的回调函数"注册"到 Nginx 的不同阶段。
 */
static ngx_http_module_t ngx_http_waf_module_ctx = {
    ngx_http_waf_pre_init,         /* preconfiguration */
    ngx_http_waf_init,             /* postconfiguration */
    ngx_http_waf_create_main_conf, /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    ngx_http_waf_create_loc_conf,  /* create location configuration */
    ngx_http_waf_merge_loc_conf    /* merge location configuration */
};

/**
 * @brief 定义 WAF 模块本身。
 *
 * 这是 Nginx 识别一个模块的入口点。
 */
ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,      /* module context */
    ngx_http_waf_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          // ... (其他 master/worker/process 的回调)
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

/**
 * @brief [核心] WAF 请求处理函数。
 *
 * Nginx 在 REWRITE 阶段会调用此函数。
 */
static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r) {
    waf_loc_conf_t *lcf;
    waf_rule_t *matched_rule;

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] === WAF Handler Started ===");

    // --- 0. 黑名单检查 ---
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 1: Checking IP Blacklist.");
    if (waf_blacklist_check_ip(r) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Result: IP Blacklisted. Denying access.");
        return NGX_HTTP_FORBIDDEN;
    }
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Pass: IP not in Blacklist.");

    // 获取当前 location 的配置
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_waf_module);
    
    // --- 1. WAF 总开关检查 & 白名单检查 ---
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 2: Checking if WAF is enabled (lcf->enable: %d).", lcf->enable);
    if (lcf->enable == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Result: WAF is disabled. Skipping.");
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 3: Checking IP Whitelist.");
    if (waf_check_whitelist(r) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Result: IP Whitelisted. Access granted.");
        return NGX_DECLINED;
    }
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Pass: IP not in Whitelist.");

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 4: Checking URL Whitelist.");
    if (waf_check_url_whitelist(r) == NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Result: URL Whitelisted. Access granted.");
        return NGX_DECLINED;
    }
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Pass: URL not in Whitelist.");

    // --- 2. 规则引擎处理 ---
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 5: Executing Rule Engine.");
    matched_rule = waf_exec_rules(r);
    if (matched_rule == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Result: No rules matched. Access granted.");
        return NGX_DECLINED;
    }

    // --- 3. 执行动作 ---
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[WAF] Step 6: Rule matched (id: %d). Executing action.", matched_rule->id);
    return waf_exec_actions(r, matched_rule);
}

/**
 * @brief [回调] "SecRule" 指令的解析函数。
 *
 * 当 Nginx 在配置文件中遇到 "SecRule" 时，会调用此函数。
 */
static char *ngx_http_waf_set_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_loc_conf_t *lcf = conf;
    waf_rule_t *new_rule;
    ngx_str_t *value;

    // [修改] 规则可以有3个或4个参数
    if (cf->args->nelts != 4 && cf->args->nelts != 5) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
            "invalid number of arguments in SecRule directive (expected 3 or 4)");
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    if (lcf->rules == NULL) {
        lcf->rules = ngx_array_create(cf->pool, 10, sizeof(waf_rule_t));
        if (lcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    new_rule = ngx_array_push(lcf->rules);
    if (new_rule == NULL) {
        return NGX_CONF_ERROR;
    }

    // [修改] 根据参数数量调用不同的解析逻辑
    if (cf->args->nelts == 5) {
        // 带转换函数的4段式: SecRule "T" "V" "O" "A"
        if (waf_parse_rule(cf, new_rule, &value[1], &value[2], &value[3], &value[4]) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid SecRule (with transformations)");
            return NGX_CONF_ERROR;
        }
    } else {
        // 不带转换函数的3段式: SecRule "V" "O" "A"
        if (waf_parse_rule(cf, new_rule, NULL, &value[1], &value[2], &value[3]) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid SecRule (without transformations)");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

/**
 * @brief [回调] 创建 location 级别的配置结构体。
 */
static void *ngx_http_waf_create_loc_conf(ngx_conf_t *cf) {
    waf_loc_conf_t *lcf;
    
    // 从内存池分配空间
    lcf = ngx_pcalloc(cf->pool, sizeof(waf_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }
    
    // 设置配置项的默认值。使用 NGX_CONF_UNSET 来表示"未设置"，
    // 这样在 merge conf 阶段可以知道是否需要从上层继承。
    lcf->enable = NGX_CONF_UNSET;
    lcf->log_enable = NGX_CONF_UNSET;
    lcf->rules = NULL;
    lcf->whitelist = NULL;
    lcf->url_whitelist = NULL;
    // lcf->log_fd 将在 ngx_http_waf_init 中被初始化

    return lcf;
}

/**
 * @brief [回调] 合并 location 级别的配置。
 *
 * 当内层 location (如 location /path) 没有定义自己的 WAF 配置时，
 * 此函数负责将外层 (如 server) 的配置继承下来。
 */
static char *ngx_http_waf_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    waf_loc_conf_t *prev = parent;
    waf_loc_conf_t *conf = child;

    // 如果子配置未设置，则使用父配置的值。
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->log_enable, prev->log_enable, 0);

    // 规则数组不直接合并，每个 location 维护自己的规则集。
    // 更高级的实现可以考虑合并规则。
    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }
    if (conf->whitelist == NULL) {
        conf->whitelist = prev->whitelist;
    }
    if (conf->url_whitelist == NULL) {
        conf->url_whitelist = prev->url_whitelist;
    }

    return NGX_CONF_OK;
}

/**
 * @brief [回调] Nginx 完成配置解析后的初始化函数。
 *
 * 在此函数中，我们将 WAF 的处理函数 (`ngx_http_waf_handler`) 挂接到 Nginx
 * 的请求处理流程 (REWRITE 阶段)。这是模块能够工作的关键。
 */
static ngx_int_t ngx_http_waf_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_log_error(NGX_LOG_WARN, cf->log, 0, "[WAF INIT] Post-configuration hook started.");

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_waf_handler;
    ngx_log_error(NGX_LOG_WARN, cf->log, 0, "[WAF INIT] Success: WAF handler installed in REWRITE phase.");

    return NGX_OK;
}

/**
 * @brief [新增] 创建 main 级别的配置结构体。
 */
static void *ngx_http_waf_create_main_conf(ngx_conf_t *cf) {
    waf_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(waf_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->rules = NGX_CONF_UNSET_PTR;
    mcf->shm_size = 0;

    return mcf;
}

/**
 * @brief "waf_shm_size" 指令的回调函数。
 * @details 负责向 Nginx 注册一块共享内存区域。
 */
static char *ngx_http_waf_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    waf_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_waf_module);
    ngx_str_t *value = cf->args->elts;
    ngx_str_t shm_name;
    ngx_uint_t shm_size;

    if (mcf->shm_size != 0) {
        return "is duplicate";
    }

    shm_size = ngx_parse_size(&value[1]);
    if (shm_size == (ngx_uint_t)NGX_ERROR || shm_size == 0) {
        return "invalid value";
    }

    mcf->shm_size = shm_size;
    
    ngx_str_set(&shm_name, "waf_shm");

    mcf->shm_zone = ngx_shared_memory_add(cf, &shm_name, mcf->shm_size, &ngx_http_waf_module);
    if (mcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
    mcf->shm_zone->init = ngx_http_waf_init_shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_waf_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
    // The 'data' parameter is the shm_zone->data from the old cycle.
    // Our waf_blacklist_init_shm function can handle this directly.
    return waf_blacklist_init_shm(shm_zone, data);
}

/**
 * @brief [回调] Nginx 加载配置前的预初始化。
 *
 * 这个函数目前是空的，但它的存在有时可以解决一些模块初始化的时序问题。
 */
static ngx_int_t ngx_http_waf_pre_init(ngx_conf_t *cf) {
    ngx_log_error(NGX_LOG_WARN, cf->log, 0, "[WAF PRE_INIT] Pre-configuration hook called.");
    return NGX_OK;
}