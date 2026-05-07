#include "sfw_port.h"
#include "sfw_log.h"
#include "sfw_pkt.h"

uint16_t nic_port;
uint16_t virtual_port;

int
sfw_port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf port_conf = {0};
    uint16_t rx_queues = 1;
    uint16_t tx_queues = 1;
    int retval;

    if (port >= rte_eth_dev_count_avail()) {
        return -1;
    }

    SFW_LOG("DEBUG: Initializing port %u...\n", port);
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        SFW_LOG("ERROR: rte_eth_dev_info_get() failed for port %u: %s\n",
               port, strerror(-retval));
        return retval;
    }
    if ((strcmp(dev_info.driver_name, "net_vmxnet3")) == 0 ){
        nic_port = port;
        SFW_LOG("DEBUG: Port %u is of type NIC\n", port);
    } else if ((strcmp(dev_info.driver_name, "net_tap")) == 0 ){
        if (port == 0) {
            nic_port = port;
            SFW_LOG("DEBUG: Port %u is of type Virtual TAP (mapped to NIC)\n", port);
        } else {
            virtual_port = port;
            SFW_LOG("DEBUG: Port %u is of type Virtual TAP\n", port);
        }
    } else if ((strcmp(dev_info.driver_name, "net_pcap")) == 0 ){
        if (port == 0) {
            nic_port = port;
            SFW_LOG("DEBUG: Port %u is of type PCAP (mapped to NIC)\n", port);
        } else {
            virtual_port = port;
            SFW_LOG("DEBUG: Port %u is of type PCAP (mapped to Virtual TAP)\n", port);
        }
    }

    // Configure the Ethernet device.
    SFW_LOG("DEBUG: Calling rte_eth_dev_configure()...\n");
    retval = rte_eth_dev_configure(port, rx_queues, tx_queues, &port_conf);
    if (retval != 0) {
        return retval;
    }
    SFW_LOG("DEBUG: rte_eth_dev_configure() Succeeded.\n");
    // Allocate and set up 1 RX queue per Ethernet port.
    SFW_LOG("DEBUG: Calling rte_eth_rx_queue_setup()...\n");
    retval = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) {
        return retval;
    }
    SFW_LOG("DEBUG: rte_eth_rx_queue_setup() Succeeded.\n");
    SFW_LOG("DEBUG: Calling rte_eth_tx_queue_setup()...\n");
    // Allocate and set up 1 TX queue per Ethernet port.
    retval = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                                    rte_eth_dev_socket_id(port), NULL);
    if (retval < 0) {
        return retval;
    }
    SFW_LOG("DEBUG: rte_eth_tx_queue_setup() Succeeded.\n");
    SFW_LOG("DEBUG: Calling rte_eth_dev_start()...\n");
    // Start the Ethernet port.
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }
    SFW_LOG("DEBUG: rte_eth_dev_start() Succeeded.\n");
    SFW_LOG("DEBUG: Enabling promiscuous mode...\n");
    // Enable RX in promiscuous mode for the Ethernet device.
    rte_eth_promiscuous_enable(port);
    SFW_LOG("DEBUG: Port %u initialization finished.\n", port);
    return 0;
}

void
sfw_port_rx_pkt_rcv(uint16_t port_id, struct rte_hash *ct_table, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    struct rte_mbuf *tx_bufs[nb_pkts];
    uint16_t tx_count = 0;

    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *this_pkt;
        struct rte_ether_hdr *eth;
        struct rte_ipv4_hdr *ip;
        sfw_pkt_dir_t pkt_dir;

        if (port_id == virtual_port) {
            pkt_dir = SFW_PKT_DIR_OUTBOUND;
        } else if (port_id == nic_port) {
            pkt_dir = SFW_PKT_DIR_INBOUND;
        }

        this_pkt = pkts[i];
        eth = rte_pktmbuf_mtod(this_pkt, struct rte_ether_hdr *);
        SFW_LOG("Processing incoming pkt from port %d src mac = " RTE_ETHER_ADDR_PRT_FMT ", dst mac = " RTE_ETHER_ADDR_PRT_FMT ", ethertype = %u\n",
               port_id, RTE_ETHER_ADDR_BYTES(&eth->src_addr), RTE_ETHER_ADDR_BYTES(&eth->dst_addr), eth->ether_type);
        if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
            int res;
            ip = rte_pktmbuf_mtod_offset(this_pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            res = sfw_pkt_parse_ipv4(pkt_dir, ip, ct_table);
            if (res < 0) {
                SFW_LOG("Drop pkt since disallowed by SFW\n");
                rte_pktmbuf_free(this_pkt);
                continue;
            }
        } else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
            SFW_LOG("Forwarding ARP packet transparently\n");
            } else {
            SFW_LOG("Drop pkt since not ipv4 or ARP\n");
            rte_pktmbuf_free(this_pkt);
            continue;
        }

        //rte_pktmbuf_free(this_pkt);
        tx_bufs[tx_count++] = this_pkt;
    }

    if (port_id == nic_port) {
        // Send packets out through the Virtual TAP port
        const uint16_t nb_tx = rte_eth_tx_burst(virtual_port, 0, tx_bufs, tx_count);
        if (nb_tx < tx_count) {
            for (uint16_t i = nb_tx; i < tx_count; i++) {
                rte_pktmbuf_free(tx_bufs[i]);
            }
        }
    } else if (port_id == virtual_port) {
        // Send packets out through the NIC port
        const uint16_t nb_tx = rte_eth_tx_burst(nic_port, 0, tx_bufs, tx_count);
        if (nb_tx < tx_count) {
            for (uint16_t i = nb_tx; i < tx_count; i++) {
                rte_pktmbuf_free(tx_bufs[i]);
            }
        }
    } else {
        // Unknown port, free the packets
        for (uint16_t i = 0; i < tx_count; i++) {
            rte_pktmbuf_free(tx_bufs[i]);
        }
    }
}