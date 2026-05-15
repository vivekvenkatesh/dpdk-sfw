/**
 * @file
 *
 * SFW application's Connection Tracking related headers.
 */

#ifndef __SFW_CT_H__
#define __SFW_CT_H__

#include <stdint.h>
#include <rte_hash.h>
#include <rte_common.h>
#include <rte_rcu_qsbr.h>

#define MAX_FLOWS 1024
#define SFW_CT_TIMER_INTERVAL_IN_SECS 1

typedef struct sfw_ct_key_t {
    uint32_t src_ip;                  /**< Source IP address */
    uint32_t dst_ip;                  /**< Destination IP address */
    uint8_t  protocol;                /**< L4 Protocol */
    union {
        struct {
            uint16_t src_port;       /**< Source port (for TCP/UDP) */
            uint16_t dst_port;       /**< Destination port (for TCP/UDP) */
        };
        struct {
            uint8_t  icmp_type;      /**< ICMP type */
            uint8_t  icmp_code;      /**< ICMP code */
            uint16_t icmp_id;        /**< ICMP identifier */
            uint16_t icmp_seq;       /**< ICMP sequence number */
        };
    };
} sfw_ct_key_t;

typedef enum sfw_ct_state_t {
    SFW_CT_STATE_NEW,
    SFW_CT_STATE_ESTABLISHED,
    SFW_CT_STATE_CLOSED,
} sfw_ct_state_t;

typedef struct sfw_ct_entry_t {
    sfw_ct_key_t out_key;            /**< Outbound Flow tuple (5-tuple) */
    sfw_ct_key_t in_key;             /**< Inbound Flow tuple (5-tuple) */
    sfw_ct_state_t state;            /**< Connection state */
    uint64_t last_seen;              /**< Last seen timestamp in cycles */
    uint64_t timeout;                /**< Timeout timestamp in cycles */
    //rte_spinlock_t lock;           /**< Spinlock for concurrent access */
} sfw_ct_entry_t;

/** Global RCU quiescent state variable. All reader lcores must register with this. */
extern struct rte_rcu_qsbr *sfw_ct_qs;

struct rte_hash*
sfw_ct_init(unsigned int lcore_id);

sfw_ct_entry_t *
sfw_ct_lookup(const struct rte_hash *h, const sfw_ct_key_t *key);

int
sfw_ct_insert(const struct rte_hash *h, const sfw_ct_entry_t *entry);


sfw_ct_entry_t *
sfw_ct_entry_alloc();

void
sfw_ct_entry_free(sfw_ct_entry_t *entry);

int
sfw_ct_delete(const struct rte_hash *h, const sfw_ct_key_t *key);

#endif