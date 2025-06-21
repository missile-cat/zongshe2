#ifndef WAF_BLACKLIST_H
#define WAF_BLACKLIST_H

#include "waf_common.h"

/**
 * @brief 在 Nginx post-configuration 阶段，初始化共享内存区域。
 * @param shm_zone 共享内存区域对象。
 * @param data 传递给初始化函数的数据，重载时使用。
 * @return 成功返回 NGX_OK，失败返回 NGX_ERROR。
 */
ngx_int_t waf_blacklist_init_shm(ngx_shm_zone_t *shm_zone, void *data);

/**
 * @brief 检查客户端 IP 是否在黑名单中。
 * @param r Nginx 请求对象。
 * @return 如果在黑名单中则返回 NGX_OK，否则返回 NGX_DECLINED。
 */
ngx_int_t waf_blacklist_check_ip(ngx_http_request_t *r);

/**
 * @brief 为客户端 IP 增加指定的分数。如果分数超过阈值，IP将被加入黑名单。
 * @param r Nginx 请求对象。
 * @param score 要增加的分数。
 * @return 始终返回 NGX_OK。
 */
ngx_int_t waf_blacklist_add_score(ngx_http_request_t *r, ngx_int_t score);

#endif /* WAF_BLACKLIST_H */ 