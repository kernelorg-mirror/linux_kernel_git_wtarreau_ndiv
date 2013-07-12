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
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

enum ndiv_rx_status {
	NDIV_RX_PASS, /* pass the Rx packet as-is */
	NDIV_RX_DROP, /* drop this Rx packet */
	NDIV_RX_XMIT, /* respond with the packet we're passing back */
	NDIV_RX_SKIP, /* can't process this packet now, skip it or present it again later */
};

enum ndiv_tx_status {
	NDIV_TX_PASS, /* pass the Tx packet as-is */
	NDIV_TX_DROP, /* drop this Tx packet */
	NDIV_TX_SKIP, /* can't process this packet now, skip it or present it again later */
};

struct ndiv {
	struct net_device *dev;
	enum ndiv_rx_status (*handle_rx)(struct ndiv *ndiv, const char *data, int len, char **resp, int *rlen);
	enum ndiv_tx_status (*handle_tx)(struct ndiv *ndiv, struct sk_buff *skb);
	void (*rx_done)(struct ndiv *ndiv);
	void (*detach)(struct ndiv *ndiv); /* to be called after down() */
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
	RCU_INIT_POINTER(dev->ax25_ptr, NULL);
	dev_put(dev);
	ndiv->dev = NULL;
	return 0;
}

#endif /* _LINUX_NDIV_H */
