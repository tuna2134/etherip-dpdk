#include <stddef.h>
#include <stdint.h>
#include <rte_mempool.h>

int dpdk_eal_init(int argc, char **argv);
unsigned dpdk_port_count(void);
struct rte_mempool *dpdk_pool_create(const char *name, unsigned count);
int dpdk_port_open(uint16_t port, struct rte_mempool *pool);
int dpdk_port_mac(uint16_t port, uint8_t mac[6]);
uint16_t dpdk_receive(uint16_t port, uint8_t *data, uint16_t capacity);
int dpdk_send(uint16_t port, struct rte_mempool *pool, const uint8_t *data, uint16_t length);
void dpdk_port_close(uint16_t port);
