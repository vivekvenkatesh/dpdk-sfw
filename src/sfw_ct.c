#include "sfw_ct.h"
#include "sfw_log.h"
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

static struct rte_mempool *sfw_ct_mp = NULL;
static struct rte_timer ct_gc_timer;
struct rte_rcu_qsbr *sfw_ct_qs = NULL;

sfw_ct_entry_t *
sfw_ct_lookup(const struct rte_hash *h, const sfw_ct_key_t *key)
{
    sfw_ct_entry_t *data;
    int ret = rte_hash_lookup_data(h, key, (void **)&data);
    if (ret < 0) {
        return NULL;
    }
    return data;
}

int
sfw_ct_insert(const struct rte_hash *h, const sfw_ct_entry_t *entry)
{
    sfw_ct_entry_t *existing_entry;
    int res;

    existing_entry = sfw_ct_lookup(h, &entry->out_key);
    if (existing_entry != NULL) {
        return -1;
    }

    res = rte_hash_add_key_data(h, &entry->out_key, (void *)entry);
    if (res < 0) {
        SFW_LOG("Failed to insert outbound CT entry\n");
        return -1;
    }

    res = rte_hash_add_key_data(h, &entry->in_key, (void *)entry);
    if (res < 0) {
        SFW_LOG("Failed to insert inbound CT entry\n");
        rte_hash_del_key(h, &entry->out_key);
        return -1;
    }
    return 0;
}

int
sfw_ct_delete(const struct rte_hash *h, const sfw_ct_key_t *out_key)
{
    int res;
    sfw_ct_entry_t *entry = sfw_ct_lookup(h, out_key);
    if (entry == NULL) {
        SFW_LOG("Failed to lookup outbound CT entry\n");
        return -1;
    }

    /*
     * With RW_CONCURRENCY_LF + RCU defer queue, rte_hash_del_key() does NOT
     * immediately free the hash slot. Instead it enqueues the slot for
     * reclamation once all readers have passed a quiescent state. The RCU
     * free callback (sfw_ct_rcu_free_cb) will then call sfw_ct_entry_free().
     * We must NOT call sfw_ct_entry_free() here.
     */
    res = rte_hash_del_key(h, out_key);
    if (res < 0) {
        SFW_LOG("Failed to delete outbound CT entry\n");
        return -1;
    }
    res = rte_hash_del_key(h, &entry->in_key);
    if (res < 0) {
        SFW_LOG("Failed to delete inbound CT entry\n");
        return -1;
    }
    return 0;
}

/**
 * RCU defer-queue callback invoked by the hash library once all readers have
 * passed a quiescent state. Safely returns the CT entry to the mempool.
 */
static void
sfw_ct_rcu_free_cb(__rte_unused void *p, void *data)
{
    sfw_ct_entry_free((sfw_ct_entry_t *)data);
}

static void
sfw_ct_timer_cb(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
    uint64_t now = rte_get_timer_cycles();
    struct rte_hash *h = (struct rte_hash *)arg;
    const void *key;
    void *data;

    uint32_t next = 0;
    while (rte_hash_iterate(h, &key, &data, &next) >= 0) {
        sfw_ct_entry_t *entry = (sfw_ct_entry_t *)data;
        if (entry->timeout <= now) {
            SFW_LOG("CT entry timeout reached, deleting entry\n");
            /*
             * sfw_ct_delete() calls rte_hash_del_key() which enqueues the
             * entry into the RCU defer queue. sfw_ct_entry_free() will be
             * called automatically by sfw_ct_rcu_free_cb() once all readers
             * report a quiescent state. No manual free needed here.
             */
            sfw_ct_delete(h, &entry->out_key);
        }
    }
}

static void
sfw_ct_timer_init(unsigned int lcore_id, struct rte_hash *h)
{
    uint64_t period = rte_get_timer_hz() * SFW_CT_TIMER_INTERVAL_IN_SECS;
    rte_timer_init(&ct_gc_timer);
    /*
     * The timer must be assigned to the same lcore that calls
     * rte_timer_manage() (the Virtual TAP port lcore). This is a DPDK timer
     * library requirement: the callback is only dispatched by the owning
     * lcore's call to rte_timer_manage(). Hash concurrency is not a
     * concern here — it is handled by RW_CONCURRENCY_LF and RCU.
     */
    rte_timer_reset(&ct_gc_timer, period, PERIODICAL, lcore_id,
                    sfw_ct_timer_cb, h);
}


struct rte_hash*
sfw_ct_init(unsigned int lcore_id)
{
    /* --- Allocate and initialise the RCU quiescent-state variable --- */
    size_t qs_sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
    sfw_ct_qs = rte_zmalloc("sfw_ct_qsbr", qs_sz, RTE_CACHE_LINE_SIZE);
    if (sfw_ct_qs == NULL) {
        SFW_LOG("Unable to allocate RCU QSBR variable\n");
        return NULL;
    }
    if (rte_rcu_qsbr_init(sfw_ct_qs, RTE_MAX_LCORE) != 0) {
        SFW_LOG("Unable to initialise RCU QSBR variable\n");
        rte_free(sfw_ct_qs);
        sfw_ct_qs = NULL;
        return NULL;
    }

    /* --- Create lock-free hash table --- */
    struct rte_hash_parameters params = {
        .name             = "sfw_ct_hash",
        .entries          = MAX_FLOWS,
        .key_len          = sizeof(sfw_ct_key_t),
        .hash_func_init_val = 0,
        .socket_id        = rte_socket_id(),
        /* LF flag: lock-free concurrent reads and writes.
         * rte_hash_del_key() will NOT immediately free the slot;
         * instead it defers reclamation via the attached RCU variable. */
        .extra_flag       = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
    };
    struct rte_hash *h = rte_hash_create(&params);
    if (h == NULL) {
        SFW_LOG("Unable to create connection tracking hash table with errno = %d\n", rte_errno);
        rte_free(sfw_ct_qs);
        sfw_ct_qs = NULL;
        return NULL;
    }

    /* --- Wire RCU into the hash table (defer-queue mode) --- */
    struct rte_hash_rcu_config rcu_cfg = {
        .v                  = sfw_ct_qs,
        .mode               = RTE_HASH_QSBR_MODE_DQ,
        .free_key_data_func = sfw_ct_rcu_free_cb,
        .key_data_ptr       = NULL,
        .dq_size            = 0,  /* use default: total hash entries */
        .trigger_reclaim_limit = 0,  /* use default */
        .max_reclaim_size   = 0,  /* use default */
    };
    if (rte_hash_rcu_qsbr_add(h, &rcu_cfg) != 0) {
        SFW_LOG("Unable to attach RCU QSBR to hash table\n");
        rte_hash_free(h);
        rte_free(sfw_ct_qs);
        sfw_ct_qs = NULL;
        return NULL;
    }

    /*
     * Calculate mempool size:
     * MAX_FLOWS + (CACHE_SIZE * lcore_count) + 512 (safety margin)
     * Then align to optimal power of 2 size - 1
     */
    unsigned int cache_size = 256;
    unsigned int count = MAX_FLOWS + (cache_size * rte_lcore_count()) + 512;
    count = rte_align32pow2(count) - 1;

    sfw_ct_mp = rte_mempool_create("sfw_ct_pool", count, sizeof(sfw_ct_entry_t), cache_size, 0,
                                   NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (sfw_ct_mp == NULL) {
        SFW_LOG("Unable to create connection tracking mempool with errno = %d\n", rte_errno);
        rte_hash_free(h);
        rte_free(sfw_ct_qs);
        sfw_ct_qs = NULL;
        return NULL;
    }

    sfw_ct_timer_init(lcore_id, h);

    return h;
}

void
sfw_ct_cleanup(struct rte_hash *h)
{
    if (h != NULL) {
        rte_hash_free(h);
    }
    if (sfw_ct_mp != NULL) {
        rte_mempool_free(sfw_ct_mp);
        sfw_ct_mp = NULL;
    }
    if (sfw_ct_qs != NULL) {
        rte_free(sfw_ct_qs);
        sfw_ct_qs = NULL;
    }
}

sfw_ct_entry_t *
sfw_ct_entry_alloc()
{
    sfw_ct_entry_t *entry = NULL;
    if (rte_mempool_get(sfw_ct_mp, (void **)&entry) < 0) {
        return NULL;
    }
    return entry;
}

void
sfw_ct_entry_free(sfw_ct_entry_t *entry)
{
    rte_mempool_put(sfw_ct_mp, entry);
}
