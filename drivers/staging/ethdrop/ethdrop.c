/*
 * Ethernet Drop filter module.
 *
 * Copyright (C) 2012-2013 Willy Tarreau <w@1wt.eu>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/ndiv.h>
#include <linux/notifier.h>

static int every = 100;
static char *dev = "";

module_param(every, int, 0644);
module_param(dev, charp, 0644);

static int
handle_device_event(struct notifier_block *notif, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct ndiv *ndiv;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	if (!dev) /* should never happen */
		return NOTIFY_DONE;

	ndiv = netdev_get_ndiv(dev);
	if (!ndiv) /* not an interface we're attached to */
		return NOTIFY_DONE;

	ndiv_unregister(ndiv);
	return NOTIFY_DONE;
}

struct notifier_block notifier = {
	.notifier_call = handle_device_event,
};

/* handle packet Rx */
static enum ndiv_rx_status handle_rx(struct ndiv *ndiv, const char *data, int len, char **resp, int *rlen)
{
	static int pkt_cnt[CONFIG_NR_CPUS];
	int idx = smp_processor_id();

	if (++pkt_cnt[idx] >= every) {
		pkt_cnt[idx] = 0;
		return NDIV_RX_DROP;
	}
	return NDIV_RX_PASS;
}

static struct ndiv ndiv = {
	.handle_rx = handle_rx,
};

static int __init modinit(void)
{
	int ret;

	printk(KERN_DEBUG "Loading with every=<%d> and dev=<%s>\n", every, dev);

	ret = ndiv_register_byname(dev, &ndiv);
	if (ret < 0) {
		printk(KERN_DEBUG "ndiv_register(%s) returned %d\n", dev, ret);
		return ret;
	}
	register_netdevice_notifier(&notifier);
	printk(KERN_DEBUG "Attached to device %s\n", ndiv.dev->name);

        return ret;
}

static void __exit modexit(void)
{
	unregister_netdevice_notifier(&notifier);
	if (ndiv.dev)
		printk(KERN_DEBUG "Unregistering from device %s\n", ndiv.dev->name);
	ndiv_unregister(&ndiv);
	printk(KERN_DEBUG "Bye.\n");
}

module_init(modinit);
module_exit(modexit);

MODULE_DESCRIPTION("Experimental Ethernet Drop module");
MODULE_AUTHOR("Willy Tarreau");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");
