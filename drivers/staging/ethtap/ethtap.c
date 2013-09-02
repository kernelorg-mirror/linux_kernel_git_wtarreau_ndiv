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
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/writeback.h>

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

static void *buf1, *buf2;

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

	////////////////////
	// truncate file
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
	///////////////////////

	buf1 = vmalloc(8192);

	struct page *page;
	page = vmalloc_to_page(buf1);

	printk(KERN_DEBUG "buf1=%p page0=%p page1=%p, count0=%d, dirty=%d\n",
	       buf1, page, vmalloc_to_page(buf1 + 4096), page_count(page),
	       PageDirty(page));

	memcpy(buf1, "hello\n", 6);
	printk(KERN_DEBUG "memcpy: buf1=%p page0=%p count0=%d dirty=%d\n", buf1, page, page_count(page), PageDirty(page));

	set_page_dirty(page);
	printk(KERN_DEBUG "spd: count0=%d dirty=%d locked=%d f_mapping=%p mapping=%p\n",
	       page_count(page), PageDirty(page), PageLocked(page), file->f_mapping, page->mapping);

	SetPageUptodate(page);

	/* does +2 on page_count, sets lock, and page->mapping to f_mapping */
	error = add_to_page_cache_lru(page, file->f_mapping, 0, GFP_KERNEL);
	printk(KERN_DEBUG "atpcl: error=%d count=%d dirty=%d locked=%d mapping=%p\n", error, page_count(page), PageDirty(page), PageLocked(page), page->mapping);

	/* from now on, we have several possibilities :
	 *  - SetPageUptodate() + unlock_page() + vfree()
	 *  - page_cache_get() + vfree() + SetPageUptodate() + write_one_page() + page_cache_release() + unlock_page()
	 *  - page_cache_get() + vfree() + SetPageUptodate() + unlock_page() + page_cache_release() + unlock_page()
	 *  - page_cache_get() + vfree() + pagecache_write_begin() + pagecache_write_end() + page_cache_release() + unlock_page()
	 *  Note that only the last one clears the end of the page and is able to update the file size
	 */

	//SetPageUptodate(page);
	unlock_page(page);
	printk(KERN_DEBUG "unlock: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	//page_cache_get(page);
	//printk(KERN_DEBUG "get: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	vfree(buf1);
	printk(KERN_DEBUG "vfree: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	//mark_page_accessed(page);
	//printk(KERN_DEBUG "mpa: count0=%d, dirty=%d\n", page_count(page), PageDirty(page));
	//
	//set_page_dirty(page);
	//printk(KERN_DEBUG "spd: count0=%d\n", page_count(page));
	//
	//balance_dirty_pages_ratelimited(file->f_mapping);
	//printk(KERN_DEBUG "bdpr: count0=%d\n", page_count(page));

	//page_cache_release(page);
	//printk(KERN_DEBUG "pcr: count0=%d\n", page_count(page));

	//struct writeback_control wbc = { .sync_mode = WB_SYNC_NONE, .nr_to_write = 1, };
	//struct writeback_control wbc = { .sync_mode = WB_SYNC_ALL, .nr_to_write = 1, .range_start = 0, .range_end = 6, };
	//error = file->f_mapping->a_ops->writepage(page, &wbc);

	/* needed to have write_one_page() dump the page */
	//SetPageUptodate(page);

	/* removes lock */
	//error = write_one_page(page, 1);
	//printk(KERN_DEBUG "wb: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	//page_cache_release(page);
	//printk(KERN_DEBUG "pcr: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	//unlock_page(page);
	//printk(KERN_DEBUG "unlock: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	//error = simple_write_end(file, file->f_mapping, 0, PAGE_CACHE_SIZE, 6, page, NULL);
	//printk(KERN_DEBUG "swe: error=%d count=%d dirty=%d locked=%d\n", error, page_count(page), PageDirty(page), PageLocked(page));

	buf1 = page_address(page);
	printk(KERN_DEBUG "pa: buf1=%p, str=%s\n", buf1, buf1 ? buf1 : "");

	buf1 = kmap(page);
	printk(KERN_DEBUG "pa: buf1=%p, str=%s\n", buf1, buf1 ? buf1 : "");
	kunmap(page);

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

	if (!create_file(dump, 8192))
		goto fail_open;

	//map_curr_page();
	//curr_pos = 6;
	//unmap_curr_page();

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
