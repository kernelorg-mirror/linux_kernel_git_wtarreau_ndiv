#ifndef _IXGBE_NDIV_TYPE_H_
#define _IXGBE_NDIV_TYPE_H_

struct ixgbe_ndiv_rdesc {
	dma_addr_t dma;
	u32 len;
	u16 csum_off;
	u16 l4_off;
	u8 unused[NET_IP_ALIGN];
	u8 data[1500]; /* set to def MTU */
};

struct ixgbe_ndiv_rsp {
	struct ixgbe_ndiv_rdesc *descs;
	u16 size;
	u16 avail;
	u16 pending;
	u16 next_to_send;
	u16 next_to_use;
};

#endif /* _IXGBE_NDIV_TYPE_H_ */
