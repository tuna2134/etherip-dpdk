#include "wrapper.h"

int dpdk_errno(void) {
    return rte_errno;
}

uint16_t dpdk_rx_burst(uint16_t port, uint16_t queue,
                       struct rte_mbuf **packets, uint16_t count) {
    return rte_eth_rx_burst(port, queue, packets, count);
}

uint16_t dpdk_tx_burst(uint16_t port, uint16_t queue,
                       struct rte_mbuf **packets, uint16_t count) {
    return rte_eth_tx_burst(port, queue, packets, count);
}

struct rte_mbuf *dpdk_pktmbuf_alloc(struct rte_mempool *pool) {
    return rte_pktmbuf_alloc(pool);
}

void dpdk_pktmbuf_free(struct rte_mbuf *packet) {
    rte_pktmbuf_free(packet);
}

void *dpdk_pktmbuf_append(struct rte_mbuf *packet, uint16_t length) {
    return rte_pktmbuf_append(packet, length);
}

void *dpdk_pktmbuf_prepend(struct rte_mbuf *packet, uint16_t length) {
    return rte_pktmbuf_prepend(packet, length);
}

void *dpdk_pktmbuf_adj(struct rte_mbuf *packet, uint16_t length) {
    return rte_pktmbuf_adj(packet, length);
}

int dpdk_pktmbuf_trim(struct rte_mbuf *packet, uint16_t length) {
    return rte_pktmbuf_trim(packet, length);
}

int dpdk_mbuf_single_data(struct rte_mbuf *packet, void **data, uint16_t *length) {
    if (packet->nb_segs != 1) {
        return 0;
    }
    *data = rte_pktmbuf_mtod(packet, void *);
    *length = rte_pktmbuf_data_len(packet);
    return 1;
}

uint32_t dpdk_mbuf_packet_length(const struct rte_mbuf *packet) {
    return rte_pktmbuf_pkt_len(packet);
}
