#include "waf_common.h"

// --- 本地函数前置声明 ---
static ngx_int_t waf_get_var_request_uri(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_args(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_args_post(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_request_body(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_request_headers(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_cookie(ngx_http_request_t *r, waf_variable_t *var);
static ngx_int_t waf_get_var_request_method(ngx_http_request_t *r, waf_variable_t *var);
static void waf_post_read_handler(ngx_http_request_t *r);
static ngx_int_t waf_get_var_request_body_common(ngx_http_request_t *r, waf_variable_t *var, ngx_uint_t type);


/**
 * @brief [核心] 获取规则变量所对应的数据。
 */
ngx_int_t waf_get_var(ngx_http_request_t *r, waf_variable_t *var) {
    switch (var->type) {
        case VAR_REQUEST_URI:
            return waf_get_var_request_uri(r, var);
        case VAR_ARGS:
            return waf_get_var_args(r, var);
        case VAR_ARGS_POST:
            return waf_get_var_args_post(r, var);
        case VAR_REQUEST_BODY:
            return waf_get_var_request_body(r, var);
        case VAR_REQUEST_HEADERS:
            return waf_get_var_request_headers(r, var);
        case VAR_COOKIES:
            return waf_get_var_cookie(r, var);
        case VAR_REQUEST_METHOD:
            return waf_get_var_request_method(r, var);
        default:
            return NGX_ERROR;
    }
    return NGX_ERROR;
}

static ngx_int_t waf_get_var_request_uri(ngx_http_request_t *r, waf_variable_t *var) {
    var->value = r->unparsed_uri;
    return NGX_OK;
}

static ngx_int_t waf_get_var_args(ngx_http_request_t *r, waf_variable_t *var) {
    if (var->arg.len > 0) { // 获取单个参数值
        return ngx_http_arg(r, var->arg.data, var->arg.len, &var->value);
    }
    var->value = r->args; // 获取所有参数
    return NGX_OK;
}

static ngx_int_t waf_get_var_request_body_common(ngx_http_request_t *r, waf_variable_t *var, ngx_uint_t type) {
    ngx_int_t rc = ngx_http_read_client_request_body(r, waf_post_read_handler);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    ngx_chain_t *cl = r->request_body->bufs;
    size_t len = 0;
    for (; cl; cl = cl->next) {
        len += ngx_buf_size(cl->buf);
    }
    if (len == 0) return NGX_DECLINED;

    u_char *p = ngx_palloc(r->pool, len + 1);
    if (p == NULL) return NGX_ERROR;
    var->value.data = p;

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
    }
    var->value.len = len;
    var->value.data[len] = '\0';
    
    if (type == VAR_ARGS_POST) {
        if (var->arg.len > 0) {
            u_char *body = var->value.data;
            u_char *end = body + var->value.len;
            u_char *cur = body;
            ngx_str_null(&var->value);

            while(cur < end) {
                u_char* pair_end = ngx_strlchr(cur, end, '&');
                if (pair_end == NULL) pair_end = end;
                
                u_char* eq = ngx_strlchr(cur, pair_end, '=');
                if (eq != NULL && (size_t)(eq-cur) == var->arg.len && ngx_strncmp(cur, var->arg.data, var->arg.len) == 0) {
                    var->value.data = eq + 1;
                    var->value.len = pair_end - (eq + 1);
                    break;
                }
                cur = pair_end + 1;
            }
        }
    }
    
    return NGX_OK;
}

static ngx_int_t waf_get_var_args_post(ngx_http_request_t *r, waf_variable_t *var) {
    return waf_get_var_request_body_common(r, var, VAR_ARGS_POST);
}

static ngx_int_t waf_get_var_request_body(ngx_http_request_t *r, waf_variable_t *var) {
    return waf_get_var_request_body_common(r, var, VAR_REQUEST_BODY);
}

static ngx_int_t waf_get_var_request_headers(ngx_http_request_t *r, waf_variable_t *var) {
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i;
    
    if (var->arg.len > 0) { 
        for (i = 0; ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) break;
                part = part->next;
                h = part->elts;
                i = 0;
            }
            if (h[i].key.len == var->arg.len && ngx_strncasecmp(h[i].key.data, var->arg.data, var->arg.len) == 0) {
                var->value = h[i].value;
                return NGX_OK;
            }
        }
        return NGX_DECLINED;
    }
    
    size_t len = 0;
    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        len += h[i].key.len + 2 + h[i].value.len + 1;
    }
    
    u_char *p = ngx_palloc(r->pool, len + 1);
    if (p == NULL) return NGX_ERROR;
    var->value.data = p;

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        p = ngx_copy(p, h[i].key.data, h[i].key.len);
        *p++ = ':'; *p++ = ' ';
        p = ngx_copy(p, h[i].value.data, h[i].value.len);
        *p++ = '\n';
    }
    var->value.len = len;

    return NGX_OK;
}

static ngx_int_t waf_get_var_cookie(ngx_http_request_t *r, waf_variable_t *var) {
    if (r->headers_in.cookie == NULL) {
        return NGX_DECLINED;
    }

    if (var->arg.len == 0) {
        var->value = r->headers_in.cookie->value;
        return NGX_OK;
    }

    u_char *cookie_str = r->headers_in.cookie->value.data;
    u_char *end = cookie_str + r->headers_in.cookie->value.len;
    u_char *cur = cookie_str;

    while (cur < end) {
        while (cur < end && (*cur == ' ' || *cur == ';')) {
            cur++;
        }

        u_char *pair_end = ngx_strlchr(cur, end, ';');
        if (pair_end == NULL) {
            pair_end = end;
        }

        u_char *eq = ngx_strlchr(cur, pair_end, '=');
        if (eq != NULL) {
            if ((size_t)(eq - cur) == var->arg.len && ngx_strncmp(cur, var->arg.data, var->arg.len) == 0) {
                var->value.data = eq + 1;
                var->value.len = pair_end - (eq + 1);
                return NGX_OK;
            }
        }
        cur = pair_end;
    }

    return NGX_DECLINED;
}

static ngx_int_t waf_get_var_request_method(ngx_http_request_t *r, waf_variable_t *var) {
    var->value = r->method_name;
    return NGX_OK;
}

static void waf_post_read_handler(ngx_http_request_t *r) {
    ngx_http_core_run_phases(r);
} 