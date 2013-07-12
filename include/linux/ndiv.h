/*
 * Network frame Diverter Framework.
 *
 * Copyright (C) 2012-2013 Willy Tarreau <w@1wt.eu>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _LINUX_NDIV_H
#define _LINUX_NDIV_H

#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>

/* The handle_rx() function takes several composite arguments :
 *
 * u32 handle_rx(struct ndiv *ndiv, u8 *l3, u32 flags_l3len, u32 vlan_proto, u8 *l2, u8 *out)
 *   - ndiv        : this is the pointer to the ndiv structure
 *   - l3          : immediate pointer to layer 3 header (typically IP header)
 *   - flags_l3len : contains the L3 packet length in the 16 lower bits, and
 *                   some flags describing protocol information in the upper bits.
 *   - vlan_proto  : contains the L3 protocol in the 16 lower bits and the VLAN ID in
 *                   the 16 upper bits. Both are in network order.
 *   - l2          : this is the pointer to the beginning of the ethernet header.
 *                   Holes are allowed between L2 and L3 if that simplifies the
 *                   driver's work.
 *   - out         : pointer to an output buffer the function may use to return
 *                   a modified packet or a packet to be sent in response. The
 *                   pointer may be NULL if no buffer is available.
 *
 * The function's return code is also composite and made of the following elements :
 *   - the 16 lower bits contain the returned packet length if a packet needs to be
 *     sent or modified. Zero indicates that no output was made.
 *   - the next 8 bits contain the L4 offset (in bytes) relative to <out> when the
 *     L4 checksum needs to be computed.
 *   - an action indicates what to do with the incoming and outgoing packet by
 *     just checking two flags and a length :
 *
 *      0 (SKIP)      *      => can't process this packet now, present it later
 *      1 (PASS)      0      => pass this packet unmodified
 *      1 (PASS)     len     => the packet was modified in-place, use it as-is
 *      2 (DROP)      0      => simply drop this packet
 *      2 (DROP)     len     => drop this packet and send <out> for <len> bytes
 *      3 (MASK)      *      => do not produce it, no need to test for it.
 *
 * The algorithm for a packet processor is simple :
 *   - impossible to process the packet ? => return 0
 *   - want to accept the packet ?        => return PASS
 *   - want to drop the packet   ?        => return DROP
 *   - want to modify the packet ?        => return PASS + newlen
 *   - want to respond to packet ?        => return DROP + newlen
 *
 * The driver side remains simple as well :
 *   - (ret == 0)   => break out of the loop
 *   - (ret & PASS) => { newlen = (u16)ret ? : len ; deliver(); }
 *   - (ret & DROP) => { if ((u16)ret) queue_tx(out); recycle desc; continue; }
 *
 * The same codes are used to build the Tx status.
 */

/* handle_rx, flags_l3len arg components */
#define NDIV_RX_L3LN_MASK         0x0000ffff /* L3 packet length */
#define NDIV_RX_F_PROTO_MASK      0x000f0000 /* L3+L4 Protocols mask */
#define NDIV_RX_F_IPV4            0x00010000
#define NDIV_RX_F_IPV6            0x00020000
#define NDIV_RX_F_TCP             0x00040000
#define NDIV_RX_F_UDP             0x00080000
#define NDIV_RX_F_IP_EXT          0x00100000 /* IPv4 or IPv6 extension is present */
#define NDIV_RX_F_BADL4CSUM       0x00200000 /* invalid L4 csum */
#define NDIV_RX_F_BADL3CSUM       0x00400000 /* invalid IPv4 csum */

/* handle_rx, vlan_proto arg components */
#define NDIV_RX_PROTO_MASK        0x0000ffff /* L3 protocol (network order) */
#define NDIV_RX_VLAN_MASK         0xffff0000 /* vlan id (network order) */
#define NDIV_RX_VLAN_SHIFT        16

/* handle_rx, return code components */
#define NDIV_RX_R_LENGTH_MASK     0x0000ffff /* length of packet to sent on TX (no packet to send if == 0), or new length of incoming packet if NDIV_RX_R_F_MOD is set */
#define NDIV_RX_R_L4OFFSET_MASK   0x00ff0000 /* offset of the start of the L4 header, used for cksum computations */
#define NDIV_RX_R_L4OFFSET_SHIFT  16
#define NDIV_RX_R_F_PASS          0x01000000 /* accept this Rx packet */
#define NDIV_RX_R_F_DROP          0x02000000 /* drop this Rx packet */
#define NDIV_RX_R_F_ACT_MASK      0x03000000 /* mask to retrieve the actions above */
#define NDIV_RX_R_F_8021Q         0x04000000 /* a 802.1q header is present */
#define NDIV_RX_R_F_IPV6          0x08000000 /* packet is IPv6, used to know the pseudo header to use on L4 cksum */
#define NDIV_RX_R_F_IPCSUM        0x10000000 /* it is necessary to compute an IPv4 cksum */
#define NDIV_RX_R_F_TCPCSUM       0x20000000 /* it is necessary to compute a TCP cksum */
#define NDIV_RX_R_F_UDPCSUM       0x40000000 /* it is necessary to compute an UDP cksum */

/* handle_tx, return code components */
#define NDIV_TX_R_F_PASS          0x01000000 /* accept this Tx packet */
#define NDIV_TX_R_F_DROP          0x02000000 /* drop this Tx packet */


struct ndiv {
	struct net_device *dev;
	u32 (*handle_rx)(struct ndiv *ndiv, u8 *l3, u32 flags_l3len, u32 vlan_proto, u8 *l2, u8 *out);
	u32 (*handle_tx)(struct ndiv *ndiv, struct sk_buff *skb);
	void (*rx_done)(struct ndiv *ndiv);
};

static inline struct ndiv *netdev_get_ndiv(const struct net_device *dev)
{
	return (struct ndiv *)dev->ax25_ptr;
}

/* register an ndiv handler on interface <dev>. The caller must implement a
 * notifier and use it to unregister the ndiv from its interface when it is
 * unregistered (event is NETDEV_UNREGISTER). The caller is expected to hold a
 * reference to the interface.
 */
static inline int ndiv_register(struct net_device *dev, struct ndiv *ndiv)
{
	if (netdev_get_ndiv(dev))
		return -EBUSY; /* already registered */

	if (dev->type != ARPHRD_ETHER)
		return -EAFNOSUPPORT;

	ndiv->dev = dev;
	rcu_assign_pointer(dev->ax25_ptr, (void *)ndiv);
	return 0;
}

/* registers an interface by its name */
static inline int ndiv_register_byname(const char *name, struct ndiv *ndiv)
{
	struct net_device *dev;
	struct net *net;

	net = get_net_ns_by_pid(current->pid);
	dev = dev_get_by_name(net, name);
	put_net(net);
	if (!dev)
		return -ENODEV;
	return ndiv_register(dev, ndiv);
}

/* unregisters an interface and drop the reference */
static inline int ndiv_unregister(struct ndiv *ndiv)
{
	struct net_device *dev = ndiv->dev;

	if (!dev || !netdev_get_ndiv(dev))
		return -ENODEV; /* already un registered */

	/* FIXME: we really need to refcount current users and to do this only
	 * when we're done with the usual 2 steps (stopping->stopped), probably
	 * with one back-ptr per queue and no lock.
	 */
	rcu_assign_pointer(dev->ax25_ptr, NULL);
	synchronize_rcu();
	dev_put(dev);
	ndiv->dev = NULL;
	return 0;
}

/* This function is meant to be used as the application's event handler.
 * It's enough to declare a function that simply calls this one to have a
 * working notifier. The <mine> pointer should be a copy of the caller's
 * expected ndiv so that only this one will be considered. If it's NULL,
 * any ndiv is considered. This is not recommended.
 */
static inline int ndiv_handle_device_event(struct notifier_block *notif,
                                             unsigned long event, void *ptr,
                                             struct ndiv *mine)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct ndiv *ndiv;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	if (!dev) /* should never happen */
		return NOTIFY_DONE;

	ndiv = netdev_get_ndiv(dev);
	if (!ndiv) /* not an interface we're attached to */
		return NOTIFY_DONE;

	if (mine && ndiv != mine)
		return NOTIFY_DONE;

	ndiv_unregister(ndiv);
	return NOTIFY_DONE;
}

#endif /* _LINUX_NDIV_H */
