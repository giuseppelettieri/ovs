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

struct netdev_rxq_nethuns {
    struct netdev_rxq up;
};

struct netdev_nethuns {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    nethuns_socket_t *sock;	/* nethuns socket */
};


//static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void netdev_nethuns_run(const struct netdev_class *);
static int netdev_nethuns_get_mtu(const struct netdev *netdev_, int *mtup);

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

static struct netdev_rxq_nethuns *
netdev_rxq_nethuns_cast(const struct netdev_rxq *rxq)
{
    ovs_assert(is_netdev_nethuns_class(netdev_get_class(rxq->netdev)));
    return CONTAINER_OF(rxq, struct netdev_rxq_nethuns, up);
}

//static const char *
//netdev_get_kernel_name(const struct netdev *netdev)
//{
//    return netdev_nethuns_cast(netdev)->kernel_name;
//}

/*
 * Perform periodic work needed by netdev. In BSD netdevs it checks for any
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
    struct netdev_nethuns *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_nethuns_construct(struct netdev *netdev_)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    char errbuf[NETHUNS_ERRBUF_SIZE];
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

    ovs_mutex_init(&netdev->mutex);

    VLOG_INFO("nethuns opening: %s", netdev_->name);
    netdev->sock = nethuns_open(&netopt, errbuf);
    if (netdev->sock == NULL) {
        VLOG_WARN("nethuns socket creation failed: %s", errbuf);
        goto error;
    }
    if (nethuns_bind(netdev->sock, netdev_->name, NETHUNS_ANY_QUEUE) < 0) {
        VLOG_WARN("nethuns socket bind failed: %s", netdev->sock->base.errbuf);
        goto error_close;
    }

    return 0;

error_close:
    nethuns_close(netdev->sock);
error:
    return errno ? errno : EINVAL;
}

static void
netdev_nethuns_destruct(struct netdev *netdev_)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
   
    nethuns_close(netdev->sock);

    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_nethuns_dealloc(struct netdev *netdev_)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);

    free(netdev);
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

static struct netdev_rxq *
netdev_nethuns_rxq_alloc(void)
{
    struct netdev_rxq_nethuns *rxq = xzalloc(sizeof *rxq);
    return &rxq->up;
}

static int
netdev_nethuns_rxq_construct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);
    struct netdev *netdev_ = rxq->up.netdev;
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);

    (void)rxq;
    (void)netdev_;
    (void)netdev;

    return 0;
}

static void
netdev_nethuns_rxq_destruct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);

    // XXX: undo something here?
    (void)rxq;
}

static void
netdev_nethuns_rxq_dealloc(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);

    free(rxq);
}

static int
netdev_nethuns_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch,
                    int *qfill)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);
    struct netdev *netdev_ = rxq->up.netdev;
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    nethuns_socket_t *sock = netdev->sock;
    struct dp_packet_nethuns *npacket;
    struct dp_packet *packet;
    struct nethuns_ring_slot *slot;
    uint64_t pkt_id, n;
    nethuns_pkthdr_t const *pkthdr;
    uint8_t const *frame;

    for (n = 0; n < NETDEV_MAX_BURST; n++) {
        pkt_id = nethuns_recv(netdev->sock, &pkthdr, &frame);
        if (!pkt_id)
            break;
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
netdev_nethuns_rxq_wait(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);

    // XXX register here
    (void)rxq;
}

/* Discards all packets waiting to be received from 'rxq'. */
static int
netdev_nethuns_rxq_drain(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_nethuns *rxq = netdev_rxq_nethuns_cast(rxq_);

    // XXX dreain here
    (void)rxq;
    return 0;
}

/*
 * Send a packet on the specified network device.
 */
static int
netdev_nethuns_send(struct netdev *netdev_, int qid OVS_UNUSED,
                struct dp_packet_batch *batch,
                bool concurrent_txq)
{
    struct netdev_nethuns *netdev = netdev_nethuns_cast(netdev_);
    struct dp_packet *packet;

    if (!concurrent_txq)
        ovs_mutex_lock(&netdev->mutex);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        const void *data = dp_packet_data(packet);
        size_t size = dp_packet_size(packet);

        nethuns_send(netdev->sock, data, size);
    }
    nethuns_flush(netdev->sock);

    if (!concurrent_txq)
        ovs_mutex_unlock(&netdev->mutex);
    dp_packet_delete_batch(batch, true);

    return 0;
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

#define NETDEV_BSD_CLASS_COMMON                      \
    .run = netdev_nethuns_run,                           \
    .wait = netdev_nethuns_wait,                         \
    .alloc = netdev_nethuns_alloc,                       \
    .construct = netdev_nethuns_construct,               \
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
    .rxq_drain = netdev_nethuns_rxq_drain

const struct netdev_class netdev_nethuns_class = {
    NETDEV_BSD_CLASS_COMMON,
    .type = "nethuns",
    .is_pmd = true,
};
