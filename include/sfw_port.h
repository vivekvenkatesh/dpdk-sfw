#ifndef _SFW_PORT_H_
#define _SFW_PORT_H_

#include <rte_ethdev.h>
#include <rte_mempool.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

int sfw_port_init(uint16_t port, struct rte_mempool *mbuf_pool);
void sfw_port_rx_pkt_rcv(uint16_t port_id, struct rte_mbuf **pkts, uint16_t nb_pkts);

#endif /* _SFW_PORT_H_ */