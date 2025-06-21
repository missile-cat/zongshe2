/*
 * waf_blacklist.c - WAF 动态IP封禁模块
 *
 * =====================================================================================
 *  [模块职责]
 *    - 实现基于IP的动态计分和自动封禁功能。
 *    - 使用 Nginx 的共享内存（shared memory）来在所有 worker 进程间同步IP计分板和黑名单。
 *    - 采用循环数组（Circular Array）作为底层数据结构，以固定大小的内存空间高效处理大量IP，
 *      并通过"牺牲者"覆盖机制自动淘汰老旧数据，避免内存耗尽。
 *
 *  [函数说明]
 *    - waf_blacklist_init_shm: [回调] 初始化共享内存区域，计算并设置IP槽位的总容量。
 *    - waf_blacklist_check_ip: [核心] 检查客户端IP是否存在于黑名单中且尚未过期。
 *    - waf_blacklist_add_score: [核心] 为客户端IP增加指定分数。如果分数达到阈值，则将其
 *                               加入黑名单并设置过期时间。
 *
 *  [调用关系]
 *    - ngx_http_waf_module.c -> waf_blacklist_init_shm()   (配置阶段)
 *    - ngx_http_waf_module.c -> waf_blacklist_check_ip()   (请求处理开始时)
 *    - waf_action.c -> waf_blacklist_add_score()         (规则匹配并执行score动作时)
 * =====================================================================================
 */
#include "waf_common.h"

// --- 数据结构定义 ---

// 数组中存储的IP条目
typedef struct {
    u_char len;         // 地址文本长度
    u_char addr[NGX_SOCKADDR_STRLEN]; // IP地址文本
    
    ngx_int_t score;    // 当前分数
    time_t last_seen;   // 最后一次出现的时间
    time_t block_expires; // 0 表示未被拉黑，否则是拉黑截止时间
} waf_blacklist_entry_t;

// 共享内存区的总体控制结构
typedef struct {
    ngx_atomic_t        access_lock; // 一个简单的自旋锁
    ngx_uint_t          next_victim; // [核心] 下一个要覆盖的元素索引 (循环数组)
    ngx_uint_t          capacity;    // 数组总容量
    waf_blacklist_entry_t entries[1];      // [核心] 灵活数组成员，实际大小由共享内存决定
} waf_shm_data_t;


// --- 全局变量 ---
// 指向共享内存控制结构的全局指针，方便快速访问
static waf_shm_data_t *g_shm_data = NULL;

// --- 模块接口实现 ---

/**
 * @brief [回调] 在 Nginx post-configuration 阶段，初始化共享内存区域。
 * 
 * @param shm_zone Nginx 提供的共享内存区域对象。
 * @param data     一个指针，在 nginx reload 场景下，它会指向旧的共享内存数据。
 *                 如果 data 不为 NULL，说明是重载，内存已初始化，直接复用即可。
 * 
 * @return ngx_int_t 成功返回 NGX_OK，失败返回 NGX_ERROR。
 * 
 * @note 这是共享内存机制的核心入口。它负责在首次启动时初始化控制结构，并精确计算出
 *       基于用户配置的 shm_size，共享内存到底能容纳多少个IP条目。
 */
ngx_int_t waf_blacklist_init_shm(ngx_shm_zone_t *shm_zone, void *data) {
    // `data` 是来自旧工作周期的 shm_zone->data。
    // 如果它不为 NULL，说明我们正在进行 reload，内存已经初始化完毕。
    if (data) {
        // 共享内存已存在，直接复用。
        g_shm_data = shm_zone->shm.addr;
        return NGX_OK;
    }

    // 首次初始化
    g_shm_data = shm_zone->shm.addr;
    
    // 确保共享内存大小至少能容纳控制结构本身
    if (shm_zone->shm.size < sizeof(waf_shm_data_t)) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "[WAF] shm_size is too small");
        return NGX_ERROR;
    }
    
    // [核心] 计算数组容量: (总大小 - 控制结构大小) / 单个元素大小
    g_shm_data->capacity = (shm_zone->shm.size - offsetof(waf_shm_data_t, entries)) 
                           / sizeof(waf_blacklist_entry_t);
                           
    if (g_shm_data->capacity == 0) {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "[WAF] shm_size is too small for even one entry");
        return NGX_ERROR;
    }
    
    // 初始化控制变量
    g_shm_data->next_victim = 0;
    g_shm_data->access_lock = 0;
    
    // ngx_shared_memory_add 已经将内存区域清零，此处无需再次操作

    return NGX_OK;
}

/**
 * @brief [核心] 检查客户端 IP 是否在黑名单中。
 * 
 * @param r Nginx 请求对象，用于获取客户端IP地址。
 * 
 * @return ngx_int_t 如果IP在黑名单中且未过期，返回 NGX_OK；否则返回 NGX_DECLINED。
 * 
 * @note 这是WAF的第一道防线。在处理任何规则之前，首先检查IP是否已被封禁。
 *       函数会遍历共享内存中的数组，查找匹配的IP并检查其 block_expires 时间。
 */
ngx_int_t waf_blacklist_check_ip(ngx_http_request_t *r) {
    if (g_shm_data == NULL) return NGX_DECLINED;

    time_t now = ngx_time();
    
    // 遍历整个IP数组
    for (ngx_uint_t i = 0; i < g_shm_data->capacity; ++i) {
        waf_blacklist_entry_t *entry = &g_shm_data->entries[i];

        // 跳过无效条目(长度为0)或长度不匹配的条目，这是一种快速剪枝
        if (entry->len == 0 || entry->len != r->connection->addr_text.len) {
            continue;
        }

        // 比较IP地址的二进制内容
        if (ngx_memcmp(entry->addr, r->connection->addr_text.data, entry->len) == 0) 
        {
            // 找到了IP，检查是否被拉黑且未过期
            if (entry->block_expires != 0 && entry->block_expires > now) {
                return NGX_OK; // 在黑名单中
            }
            // 找到了但未被拉黑，或已过期，视为不在黑名单中
            return NGX_DECLINED; 
        }
    }

    // 遍历完成未找到该IP
    return NGX_DECLINED;
}

/**
 * @brief [核心] 为客户端 IP 增加指定的分数。
 *
 * @param r Nginx 请求对象。
 * @param score 要为该IP增加的分数。
 *
 * @return ngx_int_t 始终返回 NGX_OK。
 * 
 * @note 这是动态封禁的计分逻辑。
 *       1. 首先在数组中查找该IP，如果找到，则直接更新分数。
 *       2. 如果未找到，则使用"循环覆盖"机制，从数组中找一个"牺牲者"位置，
 *          用新IP的信息覆盖它，并从0开始计分。
 *       3. 更新分数后，检查是否达到封禁阈值 (`block_threshold`)，如果达到且
 *          该IP尚未被封禁，则设置其封禁截止时间 (`block_expires`)。
 */
ngx_int_t waf_blacklist_add_score(ngx_http_request_t *r, ngx_int_t score) {
    if (g_shm_data == NULL) return NGX_OK;
    
    waf_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_waf_module);
    time_t now = ngx_time();
    waf_blacklist_entry_t *target_entry = NULL;
    
    // 操作共享内存前加锁
    ngx_spinlock(&g_shm_data->access_lock, 1, 2048);

    // 步骤 1: 查找现有条目
    for (ngx_uint_t i = 0; i < g_shm_data->capacity; ++i) {
        waf_blacklist_entry_t *entry = &g_shm_data->entries[i];
        if (entry->len == r->connection->addr_text.len &&
            ngx_memcmp(entry->addr, r->connection->addr_text.data, entry->len) == 0) 
        {
            target_entry = entry;
            break;
        }
    }
    
    // 步骤 2: 如果没找到，覆盖一个"牺牲者"
    if (target_entry == NULL) {
        target_entry = &g_shm_data->entries[g_shm_data->next_victim];
        // 循环数组指针向后移动
        g_shm_data->next_victim = (g_shm_data->next_victim + 1) % g_shm_data->capacity;

        // 用新IP信息覆盖旧条目
        target_entry->len = r->connection->addr_text.len;
        ngx_memcpy(target_entry->addr, r->connection->addr_text.data, target_entry->len);
        target_entry->score = 0; // 新条目分数从0开始
        target_entry->block_expires = 0;
    }
    
    // 步骤 3: 更新分数和最后出现时间
    target_entry->score += score;
    target_entry->last_seen = now;

    // 步骤 4: 检查是否达到阈值，并拉黑 (如果尚未被拉黑)
    if (target_entry->block_expires == 0 && target_entry->score >= mcf->block_threshold) {
        target_entry->block_expires = now + mcf->block_timeout;
    }

    // 操作完毕，解锁
    ngx_unlock(&g_shm_data->access_lock);

    return NGX_OK;
} 