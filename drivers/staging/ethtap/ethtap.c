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
#include <linux/pagemap.h>

static int every = 16384;
static char *dev = "";
static char *dump = "";
static int pol = ETHDIV_RX_PASS;

//static unsigned long map = 0;

static struct page *curr_page = NULL;
static loff_t curr_pos = 0;
static loff_t prev_pos = 0;
static char *curr_ptr = NULL;
static void *curr_fsdata = NULL;
static struct file *file;

module_param(every, int, 0644);  MODULE_PARM_DESC(every, "print a dump this every packet count (power of two)");
module_param(dev, charp, 0644);  MODULE_PARM_DESC(dev, "Interface name to attach to");
module_param(dump, charp, 0644); MODULE_PARM_DESC(dump, "File name to dump the output to");
module_param(pol, int, 0644);    MODULE_PARM_DESC(pol, "Policy on captured packets (0=pass, 1=drop)");

/* unfortunately, none of the truncate flavors are exported, so we have to
 * do it ourselves :-(
 */
struct file *create_file(const char *name, loff_t size)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	struct path path;
	int error;
	mm_segment_t fs;

	file = filp_open(name, O_CREAT | O_RDWR | O_LARGEFILE, 0600);
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		printk(KERN_DEBUG "Creation of file <%s> failed with error %d\n", name, error);
		return NULL;
	}
	printk(KERN_DEBUG "file %s opened\n", name);

	/*
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
	*/
	return file;
}

static int map_curr_page(void)
{
	int error;

	if (curr_page)
		return 0;

	printk(KERN_DEBUG "file=%p mapping=%p\n", file, file->f_mapping);
	error = pagecache_write_begin(file, file->f_mapping, curr_pos, PAGE_CACHE_SIZE - (curr_pos & ~PAGE_CACHE_MASK),
	                              AOP_FLAG_UNINTERRUPTIBLE, &curr_page, &curr_fsdata);
	prev_pos = curr_pos;
	printk(KERN_DEBUG "write_begin done, curr_page=%p, _count=%d\n", curr_page, curr_page->_count);
	if (!error) {
		curr_ptr = kmap_atomic(curr_page);
		printk(KERN_DEBUG "dst=%p, _count=%d\n", curr_ptr, curr_page->_count);
	}
	return error;
}

static int unmap_curr_page(void)
{
	int error;

	if (!curr_page)
		return 0;

	if (curr_ptr) {
		kunmap_atomic(curr_ptr);
		curr_ptr = NULL;
	}
	error = pagecache_write_end(file, file->f_mapping, prev_pos, PAGE_CACHE_SIZE - (prev_pos & ~PAGE_CACHE_MASK), curr_pos - prev_pos,
				    curr_page, curr_fsdata);
	printk(KERN_DEBUG "write_end done, %d->%d = %d bytes\n", (int)prev_pos, (int)curr_pos, (int)curr_pos - (int)prev_pos);
	printk(KERN_DEBUG "curr_page=%p, _count=%d\n", curr_page, curr_page->_count);

	printk(KERN_DEBUG "page=%p fsdata=%p error=%d\n", curr_page, curr_fsdata, error);

	curr_page = NULL;
	return error;
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

static enum ethdiv_rx_status handle_rx(struct ethdiv *ethdiv, const char *data, int len, char **resp, int *rlen)
{
	static int pkt_cnt[CONFIG_NR_CPUS];
	int idx = smp_processor_id();
	int len1, len2;

	pkt_cnt[idx]++;
	if ((pkt_cnt[idx] & (every - 1)) == 0) {
		printk(KERN_DEBUG "%s: ethdiv=%p d=%p l=%d cpu=%d cnt=%d: %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x:%02x%02x %02x%02x:%02x%02x\n",
		       dev_name(&ethdiv->dev->dev),
		       ethdiv, data, len, idx, pkt_cnt[idx],
		       data[0], data[1], data[2], data[3],
		       data[4], data[5], data[6], data[7],
		       data[8], data[9], data[10], data[11],
		       data[12], data[13], data[14], data[15]);
	}

	/* capture packets. They're assumed to be smaller than PAGE_CACHE_SIZE */
	if (!curr_page)
		map_curr_page();

	/* now let's copy the current block in one or two pages */
	len1 = PAGE_CACHE_SIZE - (curr_pos & ~PAGE_CACHE_MASK);
	len2 = len - len1;

	if (len2 >= 0) {
		/* we have to copy len1 in the first page, then possibly len2 */
		if (curr_page)
			memcpy(curr_ptr + (curr_pos & ~PAGE_CACHE_MASK), data, len1);
		curr_pos += len1;
		unmap_curr_page();
		map_curr_page();
	}
	else {
		/* copy everything at once */
		len2 = len;
	}

	/* len2 here can never reach the end of the current page */
	if (curr_page && len2)
		memcpy(curr_ptr + (curr_pos & ~PAGE_CACHE_MASK), data, len2);
	curr_pos += len2;

	return pol;
}

static void rx_done(struct ethdiv *ethdiv)
{
	unmap_curr_page();
}

static struct ethdiv ethdiv = {
	.handle_rx = handle_rx,
	.rx_done   = rx_done,
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

	if (!create_file(dump, 1048576))
		goto fail_open;

	//map = vm_mmap(file, 0, 1048576, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, 0);
	//printk(KERN_DEBUG "mapped to address %lx, file->f_mapping=%p\n", map, file->f_mapping);
	//
	//if (map > -1024UL) {
	//	/* error */
	//	ret = (signed)map;
	//	goto fail_map;
	//}
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
		//if (file->f_mapping)
		//	unmap_mapping_range(file->f_mapping, 0, 1048576, 1);
		unmap_curr_page();
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
