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
#include <linux/ndiv.h>
#include <linux/notifier.h>

static int every = 16384;
static char *dev = "";

module_param(every, int, 0644); MODULE_PARM_DESC(every, "print a dump this every packet count (power of two)");
module_param(dev, charp, 0644); MODULE_PARM_DESC(dev, "Interface name to attach to");


static u32 print_pkt(struct ndiv *ndiv, u8 *l3, u32 flags_l3len, u32 vlan_proto, u8 *l2, u8 *out)
{
	static int pkt_cnt[CONFIG_NR_CPUS];
	int idx = smp_processor_id();

	pkt_cnt[idx]++;

	if ((pkt_cnt[idx] & (every - 1)) == 0)
		printk(KERN_DEBUG "%s: ndiv=%p l2=%p l3=%p l3len=%d cpu=%d cnt=%d: l2=%02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x\n",
		       dev_name(&ndiv->dev->dev),
		       ndiv, l2, l3, (u16)flags_l3len, idx, pkt_cnt[idx],
		       l2[0], l2[1], l2[2], l2[3],
		       l2[4], l2[5], l2[6], l2[7],
		       l2[8], l2[9], l2[10], l2[11],
		       l2[12], l2[13], l2[14], l2[15]);

	if (!out) {
		printk(KERN_CRIT "out=0\n");
	}
	else if (*(u16*)(l2+12) == 0x909) {
		/* swap MAC and return it */
		memcpy(out +  0, l2 +  6, 6);
		memcpy(out +  6, l2 +  0, 6);
		memcpy(out + 12, l2 + 12, 2);
		memcpy(out + 14, l3, (u16)flags_l3len);
		return NDIV_RX_R_F_DROP | (u16)flags_l3len;
	}

	return *(u16*)(l2+12) == 0x808 ? NDIV_RX_R_F_DROP : 0;
}

/* Code below is just for registration etc... */

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

static struct ndiv ndiv = {
	.handle_rx = print_pkt,
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

MODULE_DESCRIPTION("Experimental Ethernet Tap");
MODULE_AUTHOR("Willy Tarreau");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");
