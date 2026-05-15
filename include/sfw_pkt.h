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
#define SFW_PKT_ICMP_TIMEOUT_IN_SECS              10

// TCP state-dependent timeouts
#define SFW_PKT_TCP_SYN_TIMEOUT_IN_SECS           30    /**< Max wait for SYN-ACK */
#define SFW_PKT_TCP_ESTABLISHED_TIMEOUT_IN_SECS   3600  /**< Idle established connection */
#define SFW_PKT_TCP_CLOSING_TIMEOUT_IN_SECS       10    /**< Drain window after FIN/RST */

int
sfw_pkt_parse_ipv4(sfw_pkt_dir_t pkt_dir,
                   struct rte_ipv4_hdr *ipv4_hdr,
                   struct rte_hash *ct_table);

#endif