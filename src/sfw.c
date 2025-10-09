#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <stdlib.h>
#include <stdio.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static inline int
nic_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {0};
    uint16_t rx_queues = 1;
    uint16_t tx_queues = 1;
    int retval;

    if (port >= rte_eth_dev_count_avail())
        return -1;

    printf("DEBUG: Initializing port %u...\n", port);
    fflush(stdout);
    // Configure the Ethernet device.
    printf("DEBUG: Calling rte_eth_dev_configure()...\n");
    fflush(stdout);
    retval = rte_eth_dev_configure(port, rx_queues, tx_queues, &port_conf);
    if (retval != 0) {
        return retval;
    }
    printf("DEBUG: rte_eth_dev_configure() Succeeded.\n");
    fflush(stdout);

    // Allocate and set up 1 RX queue per Ethernet port.
    printf("DEBUG: Calling rte_eth_rx_queue_setup()...\n");
    fflush(stdout);
    retval = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) {
        return retval;
    }
    printf("DEBUG: rte_eth_rx_queue_setup() Succeeded.\n");
    fflush(stdout);

    printf("DEBUG: Calling rte_eth_tx_queue_setup()...\n");
    fflush(stdout);
    // Allocate and set up 1 TX queue per Ethernet port.
    retval = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL);
    if (retval < 0) {
        return retval;
    }
    printf("DEBUG: rte_eth_tx_queue_setup() Succeeded.\n");
    fflush(stdout);

    printf("DEBUG: Calling rte_eth_dev_start()...\n");
    fflush(stdout);
    // Start the Ethernet port.
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }
    printf("DEBUG: rte_eth_dev_start() Succeeded.\n");
    fflush(stdout);

    printf("DEBUG: Enabling promiscuous mode...\n");
    fflush(stdout);
    // Enable RX in promiscuous mode for the Ethernet device.
    rte_eth_promiscuous_enable(port);
    printf("DEBUG: Port %u initialization finished.\n", port);
    fflush(stdout);
    return 0;
}

int main(int argc, char *argv[])
{
    uint16_t nb_nics;
    struct rte_mempool *mbuf_pool;
    uint8_t portid;

    // Initialize the Environment Abstraction Layer (EAL).
    int ret = rte_eal_init(argc, argv);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    // Get the number of available NICs in the system
    nb_nics = rte_eth_dev_count_avail();
    printf("\n Number of NICs in the system = %u\n", nb_nics);

    // Create a new mempool for mbufs
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_nics, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    printf("Mempool created\n");

    for (portid=0; portid < nb_nics; portid++) {
        struct rte_eth_link link;

        printf("Initializing NIC\n");

        if (nic_init(portid, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        }

        printf("Waiting for port %u to be ready...", portid);
        fflush(stdout);

        do {
            rte_eth_link_get_nowait(portid, &link);
        } while (link.link_status == RTE_ETH_LINK_DOWN);

        printf(" Port UP!\n");
    }

    portid = 0;

    // Main loop
    for (;;)
    {
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        // This is the core logic: free the packets immediately after receiving them.
        for (uint16_t i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *this_pkt;
            struct rte_ether_hdr *eth;

            this_pkt = bufs[i];
            eth = rte_pktmbuf_mtod(this_pkt, struct rte_ether_hdr *);
            printf("Processing incoming pkt src mac = " RTE_ETHER_ADDR_PRT_FMT ", dst mac = " RTE_ETHER_ADDR_PRT_FMT ", ethertype = %u\n",
                   RTE_ETHER_ADDR_BYTES(&eth->src_addr), RTE_ETHER_ADDR_BYTES(&eth->dst_addr), eth->ether_type);
            fflush(stdout);
            rte_pktmbuf_free(this_pkt);
        }
    }

    return 0;
}
