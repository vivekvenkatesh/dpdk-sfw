#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include <rte_rcu_qsbr.h>
#include <stdlib.h>
#include <stdio.h>
#include "sfw_port.h"
#include "sfw_log.h"
#include "sfw_ct.h"

struct rte_hash *global_ct_table = NULL;
extern int sfw_cli_lcore_loop(void *arg);

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct lcore_params {
    uint16_t port_id;
    struct rte_hash *ct_table;
};

static int
lcore_rx_loop(void *arg)
{
    struct lcore_params *params = (struct lcore_params *)arg;
    uint16_t portid = params->port_id;
    unsigned int lcore_id = rte_lcore_id();

    /* Register this lcore as a reader with the RCU subsystem */
    rte_rcu_qsbr_thread_register(sfw_ct_qs, lcore_id);
    rte_rcu_qsbr_thread_online(sfw_ct_qs, lcore_id);

    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (nb_rx > 0) {
            sfw_port_rx_pkt_rcv(portid, params->ct_table, bufs, nb_rx);
        }
        /*
         * Report quiescent state: at this point we no longer hold any
         * sfw_ct_entry_t pointers from the previous burst. This allows
         * the RCU defer queue to safely free entries deleted by the GC timer.
         */
        rte_rcu_qsbr_quiescent(sfw_ct_qs, lcore_id);

        if (portid == virtual_port) {
            rte_timer_manage();
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    uint16_t nb_ports;
    struct rte_mempool *mbuf_pool;
    uint8_t portid;
    struct lcore_params params[RTE_MAX_LCORE];
    unsigned int lcore_id, ct_timer_lcore;

    // Initialize the Environment Abstraction Layer (EAL).
    int ret = rte_eal_init(argc, argv);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    rte_timer_subsystem_init();
    if (sfw_log_init("dpdk-sfw.log", 10 * 1024 * 1024) != 0) {
        rte_exit(EXIT_FAILURE, "Error initializing logger\n");
    }

    if (rte_lcore_count() < 3) {
        rte_exit(EXIT_FAILURE, "Error: This application needs at least 3 logical cores to run.\n");
    }

    // Get the number of available NICs in the system
    nb_ports = rte_eth_dev_count_avail();
    SFW_LOG("\n Number of NICs in the system = %u\n", nb_ports);

    if (nb_ports != 2) {
        rte_exit(EXIT_FAILURE, "Error: This application needs 1 NIC and 1 Virtual TAP port to run\n");
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    }

    SFW_LOG("Mempool created\n");

    for (portid=0; portid < nb_ports; portid++) {
        struct rte_eth_link link;
        int res;

        SFW_LOG("Initializing Port\n");

        if (sfw_port_init(portid, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        }

        SFW_LOG("Waiting for port %u to be ready...", portid);
        do {
            res = rte_eth_link_get_nowait(portid, &link);
            if (res < 0) {
                rte_exit(EXIT_FAILURE, "Error getting link status for port %" PRIu16 "\n", portid);
            }
        } while (link.link_status == RTE_ETH_LINK_DOWN);

        SFW_LOG(" Port UP!\n");
    }

    // Port ID 1 handled by worker lcore
    portid = 1;
    lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);

    if (portid ==  virtual_port) {
        ct_timer_lcore = lcore_id;
    } else {
        ct_timer_lcore = rte_lcore_id();
    }

    struct rte_hash *ct_table = sfw_ct_init(ct_timer_lcore);
    if (ct_table == NULL) {
        rte_exit(EXIT_FAILURE, "Error creating connection tracking hash table\n");
    }

    global_ct_table = ct_table;

    params[lcore_id].port_id = portid;
    params[lcore_id].ct_table = ct_table;
    rte_eal_remote_launch(lcore_rx_loop, (void *)&params[lcore_id], lcore_id);
    SFW_LOG("Launching port %u on lcore %u\n", portid, lcore_id);

    unsigned int cli_lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(sfw_cli_lcore_loop, NULL, cli_lcore_id);
    SFW_LOG("Launching CLI on lcore %u\n", cli_lcore_id);
    // Port ID 0 handled by main lcore
    portid = 0;
    SFW_LOG("Launching port %u on lcore %u\n", portid, rte_lcore_id());

    /* Register the main lcore as a reader with the RCU subsystem */
    rte_rcu_qsbr_thread_register(sfw_ct_qs, rte_lcore_id());
    rte_rcu_qsbr_thread_online(sfw_ct_qs, rte_lcore_id());

    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (nb_rx > 0) {
            sfw_port_rx_pkt_rcv(portid, ct_table, bufs, nb_rx);
        }
        /*
         * Report quiescent state: at this point we no longer hold any
         * sfw_ct_entry_t pointers from the previous burst.
         */
        rte_rcu_qsbr_quiescent(sfw_ct_qs, rte_lcore_id());

        if (portid == virtual_port) {
            rte_timer_manage();
        }
    }
    return 0;
}
