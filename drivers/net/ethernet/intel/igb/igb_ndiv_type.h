#ifndef _IGB_NDIV_TYPE_H_
#define _IGB_NDIV_TYPE_H_

struct igb_ndiv_rdesc {
	dma_addr_t dma;
	u32 len;
	u16 csum_off;
	u16 l4_off;
	u8 *data;
};

struct igb_ndiv_rsp {
	struct igb_ndiv_rdesc *descs;
	u16 size;
	u8 *data;
	dma_addr_t dma;
	u16 avail;
	u16 pending;
	u16 next_to_send;
	u16 next_to_use;
};

#endif /* _IGB_NDIV_TYPE_H_ */
