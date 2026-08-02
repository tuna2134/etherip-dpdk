#include "wrapper.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <string.h>

int dpdk_eal_init(int argc, char **argv) { return rte_eal_init(argc, argv); }
unsigned dpdk_port_count(void) { return rte_eth_dev_count_avail(); }

struct rte_mempool *dpdk_pool_create(const char *name, unsigned count) {
    return rte_pktmbuf_pool_create(name, count, 256, 0,
                                   RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
}

int dpdk_port_open(uint16_t port, struct rte_mempool *pool) {
    struct rte_eth_conf conf = {0};
    int rc = rte_eth_dev_configure(port, 1, 1, &conf);
    if (rc < 0) return rc;
    rc = rte_eth_rx_queue_setup(port, 0, 1024, rte_eth_dev_socket_id(port), NULL, pool);
    if (rc < 0) return rc;
    rc = rte_eth_tx_queue_setup(port, 0, 1024, rte_eth_dev_socket_id(port), NULL);
    if (rc < 0) return rc;
    rc = rte_eth_dev_start(port);
    if (rc < 0) return rc;
    return rte_eth_promiscuous_enable(port);
}

int dpdk_port_mac(uint16_t port, uint8_t mac[6]) {
    struct rte_ether_addr addr;
    int rc = rte_eth_macaddr_get(port, &addr);
    if (rc == 0) memcpy(mac, addr.addr_bytes, sizeof(addr.addr_bytes));
    return rc;
}

uint16_t dpdk_receive(uint16_t port, uint8_t *data, uint16_t capacity) {
    struct rte_mbuf *m;
    if (rte_eth_rx_burst(port, 0, &m, 1) == 0) return 0;
    uint32_t length = rte_pktmbuf_pkt_len(m);
    if (length > capacity) {
        rte_pktmbuf_free(m);
        return UINT16_MAX;
    }
    uint32_t copied = 0;
    for (struct rte_mbuf *seg = m; seg; seg = seg->next) {
        memcpy(data + copied, rte_pktmbuf_mtod(seg, const void *), seg->data_len);
        copied += seg->data_len;
    }
    rte_pktmbuf_free(m);
    return (uint16_t)length;
}

int dpdk_send(uint16_t port, struct rte_mempool *pool, const uint8_t *data, uint16_t length) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    if (!m) return -1;
    void *dst = rte_pktmbuf_append(m, length);
    if (!dst) { rte_pktmbuf_free(m); return -2; }
    memcpy(dst, data, length);
    if (rte_eth_tx_burst(port, 0, &m, 1) == 1) return 0;
    rte_pktmbuf_free(m);
    return -3;
}

void dpdk_port_close(uint16_t port) {
    rte_eth_dev_stop(port);
    rte_eth_dev_close(port);
}
