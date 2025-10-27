#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <stdlib.h>
#include <stdio.h>
#include "sfw_port.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

struct lcore_params {
    uint16_t port_id;
};

static int
lcore_rx_loop(void *arg)
{
    struct lcore_params *params = (struct lcore_params *)arg;
    uint16_t portid = params->port_id;

    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        sfw_port_rx_pkt_rcv(portid, bufs, nb_rx);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    uint16_t nb_ports;
    struct rte_mempool *mbuf_pool;
    uint8_t portid;
    struct lcore_params params[RTE_MAX_LCORE];
    unsigned int lcore_id;

    // Initialize the Environment Abstraction Layer (EAL).
    int ret = rte_eal_init(argc, argv);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    if (rte_lcore_count() < 2) {
        rte_exit(EXIT_FAILURE, "Error: This application needs at least 2 logical cores to run.\n");
    }

    // Get the number of available NICs in the system
    nb_ports = rte_eth_dev_count_avail();
    printf("\n Number of NICs in the system = %u\n", nb_ports);

    if (nb_ports != 2) {
        rte_exit(EXIT_FAILURE, "Error: This application needs 1 NIC and 1 Virtual TAP port to run\n");
    }

    // Create a new mempool for mbufs
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    printf("Mempool created\n");

    for (portid=0; portid < nb_ports; portid++) {
        struct rte_eth_link link;
        int res;

        printf("Initializing Port\n");

        if (sfw_port_init(portid, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        }

        printf("Waiting for port %u to be ready...", portid);
        fflush(stdout);

        do {
            res = rte_eth_link_get_nowait(portid, &link);
            if (res < 0) {
                rte_exit(EXIT_FAILURE, "Error getting link status for port %" PRIu16 "\n", portid);
            }
        } while (link.link_status == RTE_ETH_LINK_DOWN);

        printf(" Port UP!\n");
    }

    // Port ID 1 handled by main lcore
    portid = 1;
    lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    params[lcore_id].port_id = portid;
    rte_eal_remote_launch(lcore_rx_loop, (void *)&params[lcore_id], lcore_id);
    printf("Launching port %u on lcore %u\n", portid, lcore_id);
    fflush(stdout);

    // Port ID 0 handled by main lcore
    portid = 0;
    printf("Launching port %u on lcore %u\n", portid, rte_lcore_id());
    fflush(stdout);
    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        sfw_port_rx_pkt_rcv(portid, bufs, nb_rx);
    }
    return 0;
}
