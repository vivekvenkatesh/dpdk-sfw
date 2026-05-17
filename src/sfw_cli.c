#include "sfw_cli.h"
#include "sfw_ct.h"
#include "sfw_log.h"
#include <rte_hash.h>
#include <rte_timer.h>
#include <rte_byteorder.h>
#include <cmdline_rdline.h>
#include <cmdline_socket.h>
#include <cmdline.h>
#include <stdio.h>

extern struct rte_hash *global_ct_table;

static const char*
state_to_str(sfw_ct_state_t state)
{
    switch(state) {
        case SFW_CT_STATE_NEW: return "NEW";
        case SFW_CT_STATE_ESTABLISHED: return "ESTABLISHED";
        case SFW_CT_STATE_CLOSING: return "CLOSING";
        case SFW_CT_STATE_CLOSED: return "CLOSED";
        default: return "UNKNOWN";
    }
}

static void
print_ip(uint32_t ip, char *buf, size_t size)
{
    uint8_t *p = (uint8_t *)&ip;
    snprintf(buf, size, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
}

void
cmd_hash_dump_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
    unsigned int lcore_id = rte_lcore_id();
    rte_rcu_qsbr_thread_online(sfw_ct_qs, lcore_id);

    if (global_ct_table == NULL) {
        cmdline_printf(cl, "Hash table not initialized\n");
        rte_rcu_qsbr_thread_offline(sfw_ct_qs, lcore_id);
        return;
    }

    uint32_t next = 0;
    const void *next_key;
    void *next_data;
    int i = 1;

    uint64_t now = rte_get_timer_cycles();
    uint64_t hz = rte_get_timer_hz();

    while (rte_hash_iterate(global_ct_table, &next_key, &next_data, &next) >= 0) {
        sfw_ct_entry_t *entry = (sfw_ct_entry_t *)next_data;

        char src_ip_str[16], dst_ip_str[16];
        char src_ip_in_str[16], dst_ip_in_str[16];

        print_ip(entry->out_key.src_ip, src_ip_str, sizeof(src_ip_str));
        print_ip(entry->out_key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
        print_ip(entry->in_key.src_ip, src_ip_in_str, sizeof(src_ip_in_str));
        print_ip(entry->in_key.dst_ip, dst_ip_in_str, sizeof(dst_ip_in_str));

        uint64_t last_seen_sec = (now > entry->last_seen) ? (now - entry->last_seen) / hz : 0;
        uint64_t timeout_sec = (entry->timeout > now) ? (entry->timeout - now) / hz : 0;

        cmdline_printf(cl, "Flow Entry #%d:\n", i++);

        if (entry->out_key.protocol == 6 || entry->out_key.protocol == 17) {
            cmdline_printf(cl, "    Out Key: src_ip=%s dst_ip=%s protocol=%u src_port=%u dst_port=%u\n",
                           src_ip_str, dst_ip_str, entry->out_key.protocol,
                           rte_be_to_cpu_16(entry->out_key.src_port),
                           rte_be_to_cpu_16(entry->out_key.dst_port));
            cmdline_printf(cl, "    In Key: src_ip=%s dst_ip=%s protocol=%u src_port=%u dst_port=%u\n",
                           src_ip_in_str, dst_ip_in_str, entry->in_key.protocol,
                           rte_be_to_cpu_16(entry->in_key.src_port),
                           rte_be_to_cpu_16(entry->in_key.dst_port));
        } else if (entry->out_key.protocol == 1) { // ICMP
            cmdline_printf(cl, "    Out Key: src_ip=%s dst_ip=%s protocol=%u icmp_type=%u icmp_code=%u icmp_id=%u icmp_seq=%u\n",
                           src_ip_str, dst_ip_str, entry->out_key.protocol,
                           entry->out_key.icmp_type, entry->out_key.icmp_code,
                           rte_be_to_cpu_16(entry->out_key.icmp_id),
                           rte_be_to_cpu_16(entry->out_key.icmp_seq));
            cmdline_printf(cl, "    In Key: src_ip=%s dst_ip=%s protocol=%u icmp_type=%u icmp_code=%u icmp_id=%u icmp_seq=%u\n",
                           src_ip_in_str, dst_ip_in_str, entry->in_key.protocol,
                           entry->in_key.icmp_type, entry->in_key.icmp_code,
                           rte_be_to_cpu_16(entry->in_key.icmp_id),
                           rte_be_to_cpu_16(entry->in_key.icmp_seq));
        }

        cmdline_printf(cl, "    State: %s\n", state_to_str(entry->state));
        cmdline_printf(cl, "    Last Seen: %lu seconds ago\n", last_seen_sec);
        cmdline_printf(cl, "    Timeout: %lu seconds left\n\n", timeout_sec);
    }

    rte_rcu_qsbr_thread_offline(sfw_ct_qs, lcore_id);
}

int
sfw_cli_lcore_loop(__rte_unused void *arg)
{
    unsigned int lcore_id = rte_lcore_id();
    rte_rcu_qsbr_thread_register(sfw_ct_qs, lcore_id);

    struct cmdline *cl = cmdline_stdin_new(ctx, "sfw> ");
    if (cl == NULL) {
        SFW_LOG("Failed to create cmdline\n");
        return -1;
    }
    cmdline_interact(cl);
    cmdline_stdin_exit(cl);
    return 0;
}
