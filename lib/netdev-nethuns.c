/*
 * Copyright (c) 2011, 2013, 2014 Gaetano Catalli.
 * Copyright (c) 2013, 2014 YAMAMOTO Takashi.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "netdev-provider.h"
#include "netdev-nethuns.h"

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openflow/openflow.h"
#include "ovs-thread.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "socket-util.h"
#include "svec.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_nethuns);

struct netdev_nethuns_tx_lock {
    /* Padding to make netdev_afxdp_tx_lock exactly one cache line long. */
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct ovs_spin lock;
    );
};

struct netdev_nethuns {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    nethuns_socket_t **socks;	/* nethuns sockets */
    int requested_n_rxq;
    struct netdev_nethuns_tx_lock *tx_locks;
};

//static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void netdev_nethuns_run(const struct netdev_class *);

static bool
is_netdev_nethuns_class(const struct netdev_class *netdev_class)
{
    return netdev_class->run == netdev_nethuns_run;
}

static struct netdev_nethuns *
netdev_nethuns_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_nethuns_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_nethuns, up);
}


static void nethuns_destroy_all(struct netdev_nethuns *dev);

static int
nethuns_configure_all(struct netdev *netdev)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
    char errbuf[NETHUNS_ERRBUF_SIZE];
    int i, n_rxq, n_txq;
    struct nethuns_socket_options netopt = {
        .numblocks       = 1
    ,   .numpackets      = 256
    /* we reuse the packet buffer to store the dp_packet */
    ,   .packetsize      = sizeof(struct dp_packet)
    ,   .timeout_ms      = 0
    ,   .dir             = nethuns_out
    ,   .capture         = nethuns_cap_zero_copy
    ,   .mode            = nethuns_socket_rx_tx
    ,   .promisc         = false
    ,   .rxhash          = false
    ,   .tx_qdisc_bypass = true
    ,   .xdp_prog        = NULL
    ,   .xdp_prog_sec    = NULL
    ,   .xsk_map_name    = NULL
    ,   .reuse_maps      = false
    ,   .pin_dir         = NULL
    };


    ovs_assert(dev->socks == NULL);
    ovs_assert(dev->tx_locks == NULL);

    n_rxq = netdev_n_rxq(netdev);
    dev->socks = xcalloc(n_rxq, sizeof *dev->socks);

    /* Configure remaining queues. */
    for (i = 0; i < n_rxq; i++) {
        dev->socks[i] = nethuns_open(&netopt, errbuf);
        if (dev->socks[i] == NULL) {
            VLOG_ERR("%s: creation of socket %d failed: %s",
                    netdev_get_name(netdev), i, errbuf);
            goto err;
        }
        if (nethuns_bind(dev->socks[i], netdev_get_name(netdev), i) < 0) {
            VLOG_WARN("%s: binding of socket %d failed: %s",
                    netdev_get_name(netdev), i, dev->socks[i]->base.errbuf);
            goto err;
        }
        VLOG_DBG("%s: created nethuns socket for queue %d",
                netdev_get_name(netdev), i);
    }

    n_txq = netdev_n_txq(netdev);
    dev->tx_locks = xzalloc_cacheline(n_txq * sizeof *dev->tx_locks);

    for (i = 0; i < n_txq; i++) {
        ovs_spin_init(&dev->tx_locks[i].lock);
    }

    return 0;

err:
    nethuns_destroy_all(dev);
    return EINVAL;
}

static void
nethuns_destroy_all(struct netdev_nethuns *dev)
{
    int i;

    if (dev->socks) {
        for (i = 0; i < netdev_n_rxq(&dev->up); i++) {
            if (dev->socks[i]) {
                nethuns_close(dev->socks[i]);
                dev->socks[i] = NULL;
                VLOG_DBG("%s: Destroyed socks[%d].", netdev_get_name(&dev->up), i);
            }
        }

        free(dev->socks);
        dev->socks = NULL;
    }

    if (dev->tx_locks) {
        for (i = 0; i < netdev_n_txq(&dev->up); i++) {
            ovs_spin_destroy(&dev->tx_locks[i].lock);
        }
        free_cacheline(dev->tx_locks);
        dev->tx_locks = NULL;
    }
}

//static const char *
//netdev_get_kernel_name(const struct netdev *netdev)
//{
//    return netdev_nethuns_cast(netdev)->kernel_name;
//}

/*
 * Perform periodic work needed by netdev. In NETHUNS netdevs it checks for any
 * interface status changes, and eventually calls all the user callbacks.
 */
static void
netdev_nethuns_run(const struct netdev_class *netdev_class OVS_UNUSED)
{
    // XXX: do we need this?
}

/*
 * Arranges for poll_block() to wake up if the "run" member function needs to
 * be called.
 */
static void
netdev_nethuns_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
    // XXX: do we need this?
}

static struct netdev *
netdev_nethuns_alloc(void)
{
    struct netdev_nethuns *dev = xzalloc(sizeof *dev);
    return &dev->up;
}

static int
netdev_nethuns_construct(struct netdev *netdev)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);

    ovs_mutex_init(&dev->mutex);
    netdev->n_rxq = 0;
    netdev->n_txq = 0;
    dev->requested_n_rxq = NR_QUEUE;
    dev->socks = NULL;
    dev->tx_locks = NULL;

    netdev_request_reconfigure(netdev);

    return 0;
}

static void
netdev_nethuns_destruct(struct netdev *netdev)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
   
    nethuns_destroy_all(dev);
    ovs_mutex_destroy(&dev->mutex);
}

static void
netdev_nethuns_dealloc(struct netdev *netdev)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);

    free(dev);
}

static struct dp_packet_nethuns *
dp_packet_cast_nethuns(const struct dp_packet *d)
{
    ovs_assert(d->source == DPBUF_NETHUNS);
    return CONTAINER_OF(d, struct dp_packet_nethuns, packet);
}

void free_nethuns_buf(struct dp_packet *p)
{
    struct dp_packet_nethuns *npacket;
   
    npacket = dp_packet_cast_nethuns(p);
    nethuns_rx_release(npacket->sock, npacket->pkt_id);
}

static int
netdev_nethuns_reconfigure(struct netdev *netdev)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
    int err = 0;
    ovs_mutex_lock(&dev->mutex);

    if (netdev->n_rxq == dev->requested_n_rxq) {
        goto out;
    }

    nethuns_destroy_all(dev);

    netdev->n_rxq = dev->requested_n_rxq;
    netdev->n_txq = netdev->n_rxq;

    err = nethuns_configure_all(netdev);
    if (err) {
        VLOG_ERR("%s: nethuns device reconfiguration failed.",
                 netdev_get_name(netdev));
    }
    netdev_change_seq_changed(netdev);
out:
    ovs_mutex_unlock(&dev->mutex);
    return err;
}

static struct netdev_rxq *
netdev_nethuns_rxq_alloc(void)
{
    struct netdev_rxq *rx = xzalloc(sizeof *rx);
    return rx;
}


static int
netdev_nethuns_rxq_construct(struct netdev_rxq *rxq OVS_UNUSED)
{
    return 0;
}

static void
netdev_nethuns_rxq_destruct(struct netdev_rxq *rxq OVS_UNUSED)
{
}

static void
netdev_nethuns_rxq_dealloc(struct netdev_rxq *rxq)
{
    free(rxq);
}

static int
netdev_nethuns_rxq_recv(struct netdev_rxq *rxq, struct dp_packet_batch *batch,
                    int *qfill)
{
    struct netdev *netdev = rxq->netdev;
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
    nethuns_socket_t *sock = dev->socks[rxq->queue_id];
    struct dp_packet_nethuns *npacket;
    struct dp_packet *packet;
    struct nethuns_ring_slot *slot;
    uint64_t pkt_id, n;
    nethuns_pkthdr_t const *pkthdr;
    uint8_t const *frame;

    for (n = 0; n < NETDEV_MAX_BURST; n++) {
        pkt_id = nethuns_recv(sock, &pkthdr, &frame);
        if (!pkt_id)
            break;
        //VLOG_DBG("%s: received pkt %lu", netdev_get_name(netdev), pkt_id);
        slot = nethuns_ring_get_slot(&nethuns_socket(sock)->rx_ring, pkt_id - 1);
        npacket = (struct dp_packet_nethuns *)&slot->packet;
        packet = &npacket->packet;
        npacket->sock = sock;
        npacket->pkt_id = pkt_id;
        dp_packet_use_nethuns(packet, (void *)frame, 2048);
        dp_packet_set_size(packet, pkthdr->len);
        dp_packet_batch_add(batch, packet);
    }

    if (qfill)
        *qfill = 0;

    return 0;
}

/*
 * Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_rxq_recv() on 'rxq'.
 */
static void
netdev_nethuns_rxq_wait(struct netdev_rxq *rxq)
{
    // XXX register here
    (void)rxq;
}

/* Discards all packets waiting to be received from 'rxq'. */
static int
netdev_nethuns_rxq_drain(struct netdev_rxq *rxq)
{
    // XXX dreain here
    (void)rxq;
    return 0;
}

static int
__netdev_nethuns_send(struct netdev_nethuns *dev, int qid,
        struct dp_packet_batch *batch)
{
    struct dp_packet *packet;
    nethuns_socket_t *sock = dev->socks[qid];

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        const void *data = dp_packet_data(packet);
        size_t size = dp_packet_size(packet);

        nethuns_send(sock, data, size);
        //VLOG_DBG("%s: sending %lu bytes", netdev_get_name(&dev->up), size);
    }
    nethuns_flush(sock);

    dp_packet_delete_batch(batch, true);

    return 0;
}

/*
 * Send a packet on the specified network device.
 */
static int
netdev_nethuns_send(struct netdev *netdev, int qid,
                struct dp_packet_batch *batch,
                bool concurrent_txq)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
    int ret;

    if (concurrent_txq) {
        qid = qid % netdev_n_txq(netdev);

        ovs_spin_lock(&dev->tx_locks[qid].lock);
        ret = __netdev_nethuns_send(dev, qid, batch);
        ovs_spin_unlock(&dev->tx_locks[qid].lock);
    } else {
        ret = __netdev_nethuns_send(dev, qid, batch);
    }

    return ret;
}

/*
 * Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 */
static void
netdev_nethuns_send_wait(struct netdev *netdev_, int qid OVS_UNUSED)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev_);

    ovs_mutex_lock(&dev->mutex);
    poll_immediate_wake();
    ovs_mutex_unlock(&dev->mutex);
}

/*
 * Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value.
 */
static int
netdev_nethuns_set_etheraddr(struct netdev *netdev_,
                         const struct eth_addr mac)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    // XXX: actually set etheraddr
    (void)mac;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/*
 * Returns a pointer to 'netdev''s MAC address.  The caller must not modify or
 * free the returned buffer.
 */
static int
netdev_nethuns_get_etheraddr(const struct netdev *netdev_, struct eth_addr *mac)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    // XXX: actually get etheraddr
    (void)mac;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/*
 * Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices.
 */
static int
netdev_nethuns_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    *mtup = 1500;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_nethuns_get_ifindex(const struct netdev *netdev_)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int ifindex = 0, error = EOPNOTSUPP;

    ovs_mutex_lock(&netdev->mutex);
    // XXX: actually get ifindex
    ovs_mutex_unlock(&netdev->mutex);

    return error ? -error : ifindex;
}

static int
netdev_nethuns_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = EOPNOTSUPP;

    ovs_mutex_lock(&netdev->mutex);
    // XXX: actually get carrier
    (void)carrier;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/* Retrieves current device stats for 'netdev'. */
static int
netdev_nethuns_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    // XXX get stats
    (void)stats;
    (void)netdev_;
    return 0;
}

/*
 * Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0.
 */
static int
netdev_nethuns_get_features(const struct netdev *netdev,
                        enum netdev_features *current, uint32_t *advertised,
                        enum netdev_features *supported, uint32_t *peer)
{
    // XXX: get features
    (void)netdev;
    (void)current;
    (void)advertised;
    (void)supported;
    (void)peer;
    return 0;
}

/*
 * Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value.
 */
static int
netdev_nethuns_set_in4(struct netdev *netdev_, struct in_addr addr,
                   struct in_addr mask)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    // XXX
    (void)addr;
    (void)mask;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_nethuns_get_addr_list(const struct netdev *netdev_,
                         struct in6_addr **addr, struct in6_addr **mask, int *n_cnt)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_get_addrs(netdev_get_name(netdev_), addr, mask, n_cnt);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_nethuns_get_next_hop(const struct in_addr *host OVS_UNUSED,
                        struct in_addr *next_hop OVS_UNUSED,
                        char **netdev_name OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
netdev_nethuns_arp_lookup(const struct netdev *netdev OVS_UNUSED,
                      ovs_be32 ip OVS_UNUSED,
                      struct eth_addr *mac OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static int
netdev_nethuns_update_flags(struct netdev *netdev_, enum netdev_flags off,
                        enum netdev_flags on, enum netdev_flags *old_flagsp)
{
    int error = 0;

    (void)netdev_;
    (void)off;
    (void)on;
    *old_flagsp = 0;
    return error;
}

static int
netdev_nethuns_set_config(struct netdev *netdev, const struct smap *args,
                        char **errp OVS_UNUSED)
{
    struct netdev_nethuns *dev = netdev_nethuns_cast(netdev);
    int new_n_rxq;

    ovs_mutex_lock(&dev->mutex);
    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    VLOG_DBG("%s: requested %d queues (old %d)",
            netdev_get_name(netdev), new_n_rxq, dev->requested_n_rxq);

    if (dev->requested_n_rxq != new_n_rxq) {
        dev->requested_n_rxq = new_n_rxq;
        netdev_request_reconfigure(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);
    return 0;
}

#define NETDEV_NETHUNS_CLASS_COMMON                      \
    .run = netdev_nethuns_run,                           \
    .wait = netdev_nethuns_wait,                         \
    .alloc = netdev_nethuns_alloc,                       \
    .construct = netdev_nethuns_construct,               \
    .reconfigure = netdev_nethuns_reconfigure,           \
    .destruct = netdev_nethuns_destruct,                 \
    .dealloc = netdev_nethuns_dealloc,                   \
    .send = netdev_nethuns_send,                         \
    .send_wait = netdev_nethuns_send_wait,               \
    .set_etheraddr = netdev_nethuns_set_etheraddr,       \
    .get_etheraddr = netdev_nethuns_get_etheraddr,       \
    .get_mtu = netdev_nethuns_get_mtu,                   \
    .get_ifindex = netdev_nethuns_get_ifindex,           \
    .get_carrier = netdev_nethuns_get_carrier,           \
    .get_stats = netdev_nethuns_get_stats,               \
    .get_features = netdev_nethuns_get_features,         \
    .set_in4 = netdev_nethuns_set_in4,                   \
    .get_addr_list = netdev_nethuns_get_addr_list,       \
    .get_next_hop = netdev_nethuns_get_next_hop,         \
    .arp_lookup = netdev_nethuns_arp_lookup,             \
    .update_flags = netdev_nethuns_update_flags,         \
    .rxq_alloc = netdev_nethuns_rxq_alloc,               \
    .rxq_construct = netdev_nethuns_rxq_construct,       \
    .rxq_destruct = netdev_nethuns_rxq_destruct,         \
    .rxq_dealloc = netdev_nethuns_rxq_dealloc,           \
    .rxq_recv = netdev_nethuns_rxq_recv,                 \
    .rxq_wait = netdev_nethuns_rxq_wait,                 \
    .rxq_drain = netdev_nethuns_rxq_drain,               \
    .set_config = netdev_nethuns_set_config

const struct netdev_class netdev_nethuns_class = {
    NETDEV_NETHUNS_CLASS_COMMON,
    .type = "nethuns",
    .is_pmd = true,
};
