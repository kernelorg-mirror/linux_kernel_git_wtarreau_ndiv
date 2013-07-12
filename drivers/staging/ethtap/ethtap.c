/*
 * Ethernet Tap.
 *
 * Copyright (C) 2012-2013 Willy Tarreau <w@1wt.eu>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/ethdiv.h>
#include <linux/notifier.h>

static int every = 16384;
static char *dev = "";

module_param(every, int, 0644); MODULE_PARM_DESC(every, "print a dump this every packet count (power of two)");
module_param(dev, charp, 0644); MODULE_PARM_DESC(dev, "Interface name to attach to");


static int
handle_device_event(struct notifier_block *notif, unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct ethdiv *ethdiv;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	if (!dev) /* should never happen */
		return NOTIFY_DONE;

	ethdiv = netdev_get_ndiv(dev);
	if (!ethdiv) /* not an interface we're attached to */
		return NOTIFY_DONE;

	ethdiv_unregister(ethdiv);
	return NOTIFY_DONE;
}

static struct ethdiv ethdiv = {
	.handle_rx = print_pkt,
};

static enum ethdiv_rx_status print_pkt(struct ethdiv *ethdiv, const char *data, int len, char **resp, int *rlen)
{
	static int pkt_cnt[CONFIG_NR_CPUS];
	int idx = smp_processor_id();

	pkt_cnt[idx]++;

	if ((pkt_cnt[idx] & (every - 1)) == 0)
		printk(KERN_DEBUG "%s: ethdiv=%p d=%p l=%d cpu=%d cnt=%d: %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x\n",
		       dev_name(&ethdiv->dev->dev),
		       ethdiv, data, len, idx, pkt_cnt[idx],
		       data[0], data[1], data[2], data[3],
		       data[4], data[5], data[6], data[7],
		       data[8], data[9], data[10], data[11],
		       data[12], data[13], data[14], data[15]);

	return ETHDIV_RX_PASS;
}

struct notifier_block notifier = {
	.notifier_call = handle_device_event,
};

static int __init modinit(void)
{
	int ret;

	printk(KERN_DEBUG "Loading with every=<%d> and dev=<%s>\n", every, dev);

	ret = ethdiv_register_byname(dev, &ethdiv);
	if (ret < 0) {
		printk(KERN_DEBUG "ethdiv_register(%s) returned %d\n", dev, ret);
		return ret;
	}
	register_netdevice_notifier(&notifier);
	printk(KERN_DEBUG "Attached to device %s\n", ethdiv.dev->name);

        return ret;
}

static void __exit modexit(void)
{
	unregister_netdevice_notifier(&notifier);
	if (ethdiv.dev)
		printk(KERN_DEBUG "Unregistering from device %s\n", ethdiv.dev->name);
	ethdiv_unregister(&ethdiv);
	printk(KERN_DEBUG "Bye.\n");
}

module_init(modinit);
module_exit(modexit);

MODULE_DESCRIPTION("Experimental Ethernet Tap");
MODULE_AUTHOR("Willy Tarreau");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");
