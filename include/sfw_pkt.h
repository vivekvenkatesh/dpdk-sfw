#ifndef __SFW_PKT_H__
#define __SFW_PKT_H__

#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_icmp.h>

typedef enum sfw_pkt_dir_t {
    SFW_PKT_DIR_INBOUND,
    SFW_PKT_DIR_OUTBOUND,
} sfw_pkt_dir_t;

// Shorter timeout for ICMP packets
#define SFW_PKT_ICMP_TIMEOUT_IN_SECS 10

int
sfw_pkt_parse_ipv4(sfw_pkt_dir_t pkt_dir,
                   struct rte_ipv4_hdr *ipv4_hdr,
                   struct rte_hash *ct_table);

#endif