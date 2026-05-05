#include "sfw_pkt.h"
#include "sfw_log.h"
#include "sfw_ct.h"
#include <rte_icmp.h>

static void sfw_pkt_entry_init_ipv4(sfw_ct_entry_t *entry,
                                    struct rte_ipv4_hdr *ipv4_hdr)
{
    /* Outbound Key */
    entry->out_key.src_ip = ipv4_hdr->src_addr;
    entry->out_key.dst_ip = ipv4_hdr->dst_addr;
    entry->out_key.protocol = ipv4_hdr->next_proto_id;

    /* Inbound Key (Reversed) */
    entry->in_key.src_ip = ipv4_hdr->dst_addr;
    entry->in_key.dst_ip = ipv4_hdr->src_addr;
    entry->in_key.protocol = ipv4_hdr->next_proto_id;

    entry->state = SFW_CT_STATE_NEW;
    entry->last_seen = rte_get_timer_cycles();
}

static void sfw_pkt_entry_init_icmp(sfw_ct_entry_t *entry,
                                    struct rte_icmp_hdr *icmp_hdr) {
    entry->timeout = entry->last_seen +
                     SFW_PKT_ICMP_TIMEOUT_IN_SECS * rte_get_timer_hz();

    /* Outbound Key */
    entry->out_key.icmp_type = icmp_hdr->icmp_type;
    entry->out_key.icmp_code = icmp_hdr->icmp_code;
    entry->out_key.icmp_id = icmp_hdr->icmp_ident;
    entry->out_key.icmp_seq = icmp_hdr->icmp_seq_nb;

    /* Inbound Key (Expect Echo Reply) */
    entry->in_key.icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
    entry->in_key.icmp_code = 0;
    entry->in_key.icmp_id = icmp_hdr->icmp_ident;
    entry->in_key.icmp_seq = icmp_hdr->icmp_seq_nb;
}

static int sfw_pkt_handle_icmp(sfw_pkt_dir_t pkt_dir,
                                struct rte_ipv4_hdr *ipv4_hdr,
                                struct rte_icmp_hdr *icmp_hdr,
                                struct rte_hash *ct_table)
{
    SFW_LOG("ICMP packet type=%u, code=%u, id=%u, seq=%u\n",
           icmp_hdr->icmp_type, icmp_hdr->icmp_code, icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
    switch (icmp_hdr->icmp_type) {
        case RTE_ICMP_TYPE_ECHO_REQUEST:
            if (pkt_dir == SFW_PKT_DIR_OUTBOUND) {
                sfw_ct_entry_t *ct_entry = sfw_ct_entry_alloc();
                int res;

                if (ct_entry == NULL) {
                    SFW_LOG("Failed to allocate CT entry\n");
                    return -1;
                }
                sfw_pkt_entry_init_ipv4(ct_entry, ipv4_hdr);
                sfw_pkt_entry_init_icmp(ct_entry, icmp_hdr);
                res = sfw_ct_insert(ct_table, ct_entry);
                if (res < 0) {
                    SFW_LOG("Failed to insert CT entry for ICMP request\n");
                    sfw_ct_entry_free(ct_entry);
                    return -1;
                }
                SFW_LOG("Successfully inserted CT entry for ICMP request (id=%u, seq=%u)\n",
                       icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
                } else {
                SFW_LOG("ICMP request from inbound direction not allowed\n");
                return -1;
            }
            break;
        case RTE_ICMP_TYPE_ECHO_REPLY:
            if (pkt_dir == SFW_PKT_DIR_INBOUND) {
                sfw_ct_key_t in_key = {
                    .src_ip = ipv4_hdr->src_addr,
                    .dst_ip = ipv4_hdr->dst_addr,
                    .protocol = ipv4_hdr->next_proto_id,
                    .icmp_type = icmp_hdr->icmp_type,
                    .icmp_code = icmp_hdr->icmp_code,
                    .icmp_id = icmp_hdr->icmp_ident,
                    .icmp_seq = icmp_hdr->icmp_seq_nb,
                };
                sfw_ct_entry_t *entry = sfw_ct_lookup(ct_table, &in_key);
                if (entry == NULL) {
                    SFW_LOG("Failed to lookup CT entry for ICMP reply (id=%u, seq=%u)\n",
                           icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
                    return -1;
                }
                SFW_LOG("Successfully looked up CT entry for ICMP reply (id=%u, seq=%u)\n",
                       icmp_hdr->icmp_ident, icmp_hdr->icmp_seq_nb);
                if (rte_get_timer_cycles() > entry->timeout) {
                    SFW_LOG("CT entry timeout\n");
                    return -1;
                }
                entry->state = SFW_CT_STATE_ESTABLISHED;
                entry->last_seen = rte_get_timer_cycles();
            } else {
                SFW_LOG("ICMP reply from outbound direction not allowed\n");
                return -1;
            }
            break;
        default:
            return -1;
    }
    return 0;
}

int sfw_pkt_parse_ipv4(sfw_pkt_dir_t pkt_dir,
                        struct rte_ipv4_hdr *ipv4_hdr,
                        struct rte_hash *ct_table)
{
    uint8_t *src_ip = (uint8_t *)&ipv4_hdr->src_addr;
    uint8_t *dst_ip = (uint8_t *)&ipv4_hdr->dst_addr;
    SFW_LOG("IPv4 packet src ip = %u.%u.%u.%u, dst ip = %u.%u.%u.%u, protocol = %u\n",
           src_ip[0], src_ip[1], src_ip[2], src_ip[3],
           dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
           ipv4_hdr->next_proto_id);
    switch (ipv4_hdr->next_proto_id) {
        case IPPROTO_ICMP:
            return sfw_pkt_handle_icmp(pkt_dir, ipv4_hdr, (struct rte_icmp_hdr *)(ipv4_hdr + 1), ct_table);
        default:
            return -1;
    }
}
