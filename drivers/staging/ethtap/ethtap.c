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
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mman.h>

static int every = 16384;
static char *dev = "";
static char *dump = "";

static struct file *file = NULL;
static unsigned long map = 0;

module_param(every, int, 0644);  MODULE_PARM_DESC(every, "print a dump this every packet count (power of two)");
module_param(dev, charp, 0644);  MODULE_PARM_DESC(dev, "Interface name to attach to");
module_param(dump, charp, 0644); MODULE_PARM_DESC(dump, "File name to dump the output to");

/* unfortunately, none of the truncate flavors are exported, so we have to
 * do it ourselves :-(
 */
struct file *create_file(const char *name, loff_t size)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	struct path path;
	struct file *file;
	int error;
	mm_segment_t fs;

	file = filp_open(name, O_CREAT | O_RDWR | O_LARGEFILE, 0600);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		printk(KERN_DEBUG "Creation of file <%s> failed with error %d\n", name, error);
		return NULL;
	}
 retry:
	fs = get_fs();
	set_fs(KERNEL_DS);
	error = user_path_at(AT_FDCWD, name, lookup_flags, &path);
	set_fs(fs);

	if (!error) {
		printk(KERN_DEBUG "about to truncated file <%s> to size %d\n", name, (int)size);
		error = vfs_truncate(&path, size);
		path_put(&path);
	}
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	if (error) {
		printk(KERN_DEBUG "Truncate of file <%s> failed with error %d\n", name, error);
                filp_close(file, NULL);
		file = NULL;
	}
	printk(KERN_DEBUG "file=%p (name=%s)\n", file, name);
	return file;
}

static int
handle_device_event(struct notifier_block *notif, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
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

static enum ethdiv_rx_status print_pkt(struct ethdiv *ethdiv, const char *data, int len, char **resp, int *rlen)
{
	static int pkt_cnt[CONFIG_NR_CPUS];
	int idx = smp_processor_id();

	pkt_cnt[idx]++;

	if ((pkt_cnt[idx] & (every - 1)) == 0) {
		printk(KERN_DEBUG "%s: ethdiv=%p d=%p l=%d cpu=%d cnt=%d: %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x\n",
		       dev_name(&ethdiv->dev->dev),
		       ethdiv, data, len, idx, pkt_cnt[idx],
		       data[0], data[1], data[2], data[3],
		       data[4], data[5], data[6], data[7],
		       data[8], data[9], data[10], data[11],
		       data[12], data[13], data[14], data[15]);
		memcpy((void *)map, data, len);
	}

	return ETHDIV_RX_PASS;
}

static struct ethdiv ethdiv = {
	.handle_rx = print_pkt,
};

struct notifier_block notifier = {
	.notifier_call = handle_device_event,
};

static int __init modinit(void)
{
	int ret;

	printk(KERN_ERR "Loading with every=<%d> and dev=%p<%s>\n", every, dev, dev);

	ret = ethdiv_register_byname(dev, &ethdiv);
	if (ret < 0) {
		printk(KERN_DEBUG "ethdiv_register(%s) returned %d\n", dev, ret);
		return ret;
	}
	register_netdevice_notifier(&notifier);
	printk(KERN_DEBUG "Attached to device %s\n", ethdiv.dev->name);

	file = create_file(dump, 1048576);
	if (!file)
		goto fail_open;

	map = vm_mmap(file, 0, 1048576, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, 0);
	printk(KERN_DEBUG "mapped to address %lx, file->f_mapping=%p\n", map, file->f_mapping);

	if (map > -1024UL) {
		/* error */
		ret = (signed)map;
		goto fail_map;
	}
        return 0;

 fail_map:
	filp_close(file, NULL);
	file = NULL;
 fail_open:
	unregister_netdevice_notifier(&notifier);
	ethdiv_unregister(&ethdiv);
	return ret;
}

static void __exit modexit(void)
{
	if (file) {
		if (file->f_mapping)
			unmap_mapping_range(file->f_mapping, 0, 1048576, 1);
                filp_close(file, NULL);
		file = NULL;
	}

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
