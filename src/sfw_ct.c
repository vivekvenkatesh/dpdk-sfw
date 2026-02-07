#include "sfw_ct.h"
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_timer.h>

static struct rte_mempool *sfw_ct_mp = NULL;
static struct rte_timer ct_gc_timer;

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
        printf("Failed to insert outbound CT entry\n");
        fflush(stdout);
        return -1;
    }

    res = rte_hash_add_key_data(h, &entry->in_key, (void *)entry);
    if (res < 0) {
        printf("Failed to insert inbound CT entry\n");
        fflush(stdout);
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
        printf("Failed to lookup outbound CT entry\n");
        fflush(stdout);
        return -1;
    }

    res = rte_hash_del_key(h, out_key);
    if (res < 0) {
        printf("Failed to delete outbound CT entry\n");
        fflush(stdout);
        return -1;
    }
    res = rte_hash_del_key(h, &entry->in_key);
    if (res < 0) {
        printf("Failed to delete inbound CT entry\n");
        fflush(stdout);
        return -1;
    }
    return 0;
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
            printf("CT entry timeout reached, deleting entry\n");
            fflush(stdout);
            sfw_ct_delete(h, &entry->out_key);
            sfw_ct_entry_free(entry);
        }
    }
}

static void
sfw_ct_timer_init(unsigned int lcore_id, struct rte_hash *h)
{
    uint64_t period = rte_get_timer_hz() * SFW_CT_TIMER_INTERVAL_IN_SECS;
    rte_timer_init(&ct_gc_timer);
    /*
     * Choose the lcore id used for handling Virtual TAP port, since that is the one that can insert into this hash table
     * If other lcore is used, we could run into concurrency issue.
     */
    rte_timer_reset(&ct_gc_timer, period, PERIODICAL, lcore_id, sfw_ct_timer_cb, h);
}


struct rte_hash*
sfw_ct_init(unsigned int lcore_id)
{
    struct rte_hash_parameters params = {
        .name = "sfw_ct_hash",
        .entries = MAX_FLOWS,
        .key_len = sizeof(sfw_ct_key_t),
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    struct rte_hash *h = rte_hash_create(&params);
    if (h == NULL) {
        printf("Unable to create connection tracking hash table with errno = %d\n", rte_errno);
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
        printf("Unable to create connection tracking mempool with errno = %d\n", rte_errno);
        rte_hash_free(h);
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
