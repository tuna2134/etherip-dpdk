#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

int dpdk_errno(void);
uint16_t dpdk_rx_burst(uint16_t port, uint16_t queue,
                       struct rte_mbuf **packets, uint16_t count);
uint16_t dpdk_tx_burst(uint16_t port, uint16_t queue,
                       struct rte_mbuf **packets, uint16_t count);
struct rte_mbuf *dpdk_pktmbuf_alloc(struct rte_mempool *pool);
void dpdk_pktmbuf_free(struct rte_mbuf *packet);
void *dpdk_pktmbuf_append(struct rte_mbuf *packet, uint16_t length);
void *dpdk_pktmbuf_prepend(struct rte_mbuf *packet, uint16_t length);
void *dpdk_pktmbuf_adj(struct rte_mbuf *packet, uint16_t length);
int dpdk_pktmbuf_trim(struct rte_mbuf *packet, uint16_t length);
void *dpdk_mbuf_data(struct rte_mbuf *packet);
uint32_t dpdk_mbuf_packet_length(const struct rte_mbuf *packet);
uint16_t dpdk_mbuf_data_length(const struct rte_mbuf *packet);
uint16_t dpdk_mbuf_segment_count(const struct rte_mbuf *packet);
