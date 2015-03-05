#ifndef _E1000_NDIV_H_
#define _E1000_NDIV_H_
#include <linux/ndiv.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "e1000_ndiv_type.h"
#include "e1000.h"

/* tcp len: 16 + 16 + 32 + 32 + 16 + 16 + 16 + 16
 *          10 x 16 bit
 */
static inline
unsigned short ip_sum(unsigned int sum, unsigned short *w, int len)
{
        unsigned int w0, w1;
        unsigned int w2, w3;

        while (__builtin_expect(len, 20) > 20) {
                sum += w[len / 2 - 1];
                len -= 2;
        }
        w0 = w[0]; w1 = w[1];
        w2 = w[2]; w3 = w[3];

        w0 += w1;
        w1 = w2 + w3;
        w2 = w[4]; w3 = w[5];

        w0 += w1;
        w1 = w2 + w3;
        w2 = w[6]; w3 = w[7];

        w0 += w1;
        w1 = w2 + w3;
        w2 = w[8]; w3 = w[9];

        w0 += w1;
        w1 = w2 + w3;

        sum += w0 + w1;

        sum  = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16);                  /* add carry */
        return ~sum;                         /* truncate to 16 bits */
}

static inline
void e1000_ndiv_fini_rsp(struct e1000_tx_ring *ring, struct pci_dev *pdev)
{
	if (ring->ndiv_rsp.dma != 0) {
		dma_unmap_single(&pdev->dev,
				 ring->ndiv_rsp.dma,
				 ring->ndiv_rsp.size*1536,
				  DMA_TO_DEVICE);
		ring->ndiv_rsp.dma = 0;
	}

	if (ring->ndiv_rsp.data) {
		kfree(ring->ndiv_rsp.data);
		ring->ndiv_rsp.data = NULL;
	}

	if (ring->ndiv_rsp.descs) {
		kfree(ring->ndiv_rsp.descs);
		ring->ndiv_rsp.descs = NULL;
	}

	ring->ndiv_rsp.size = 0;
	ring->ndiv_rsp.next_to_send = ring->ndiv_rsp.next_to_use =  ring->ndiv_rsp.avail = 0;
}

static inline
int e1000_ndiv_init_rsp(struct e1000_tx_ring *ring, struct pci_dev *pdev)
{
	int i;
	ring->ndiv_rsp.size = ring->count + ring->count;
	ring->ndiv_rsp.next_to_send = ring->ndiv_rsp.next_to_use =  ring->ndiv_rsp.avail = 0;
	ring->ndiv_rsp.descs =  kmalloc(ring->ndiv_rsp.size*sizeof(struct e1000_ndiv_rdesc), GFP_ATOMIC);
	if (!ring->ndiv_rsp.descs) {
		printk("e1000 ndiv: unable to allocate %d descripors.\n", ring->ndiv_rsp.size);
		ring->ndiv_rsp.size = 0;
		return -1;
	}
	ring->ndiv_rsp.data =  kmalloc(ring->ndiv_rsp.size*1536, GFP_ATOMIC);
	if (!ring->ndiv_rsp.data) {
		printk("e1000 ndiv: unable to allocate %d descripors.\n", ring->ndiv_rsp.size);
		kfree(ring->ndiv_rsp.descs);
		ring->ndiv_rsp.descs = NULL;
		ring->ndiv_rsp.size = 0;
		return -1;
	}

	ring->ndiv_rsp.dma = dma_map_single(&pdev->dev, ring->ndiv_rsp.data, ring->ndiv_rsp.size*1536, DMA_TO_DEVICE);
	if (dma_mapping_error(&pdev->dev, ring->ndiv_rsp.dma)) {
		printk("e1000 ndiv: unable to dma map %d descripors.\n", ring->ndiv_rsp.size);
		kfree(ring->ndiv_rsp.data);
		kfree(ring->ndiv_rsp.descs);
		ring->ndiv_rsp.data = NULL;
		ring->ndiv_rsp.descs = NULL;
		ring->ndiv_rsp.size = 0;
		return -2;
	}

	for (i = 0 ; i < ring->ndiv_rsp.size ; i++) {
		ring->ndiv_rsp.descs[i].data = ring->ndiv_rsp.data+(i*1536)+NET_IP_ALIGN;
		ring->ndiv_rsp.descs[i].dma = ring->ndiv_rsp.dma+(i*1536)+NET_IP_ALIGN;
		ring->ndiv_rsp.avail++;
	}

	printk("e1000 ndiv: %d descripors allocated.\n", ring->ndiv_rsp.size);
	return 0;
}

static inline
void e1000_ndiv_send_rsp(struct e1000_adapter *adapter) {
	struct e1000_tx_ring *tx_ring = adapter->tx_ring;
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_tx_buffer *tx_buffer;
	struct e1000_tx_desc *tx_desc;
	u32 len = 0;
	struct e1000_ndiv_rdesc *packet;

	__netif_tx_lock(netdev_get_tx_queue(adapter->netdev, 0), smp_processor_id());

	if (likely(!netif_xmit_frozen_or_stopped(netdev_get_tx_queue(adapter->netdev, 0)))) {
		while (likely(tx_ring->ndiv_rsp.pending && E1000_DESC_UNUSED(tx_ring) >= 1)) {
			packet = &tx_ring->ndiv_rsp.descs[tx_ring->ndiv_rsp.next_to_send];
			tx_desc = E1000_TX_DESC(*tx_ring, tx_ring->next_to_use);
			tx_buffer = &tx_ring->buffer_info[tx_ring->next_to_use];


			tx_desc->buffer_addr = cpu_to_le64(packet->dma);

			if (packet->csum_off)
				*(u16 *)(packet->data + packet->csum_off) = ip_sum(0, (u16 *)(packet->data + packet->l4_off), packet->len - packet->l4_off);
			tx_desc->lower.data = cpu_to_le32(packet->len) | cpu_to_le32(adapter->txd_cmd);
			tx_desc->upper.data = 0;

			/* write last descriptor with RS bit */
			// This optim cause hang up on e000e NICs
			//if (unlikely(e1000_desc_unused(tx_ring) == 1 || (tx_ring->ndiv_rsp.pending & 255) == 1))
			//	tx_desc->lower.data |= __constant_cpu_to_le32(E1000_TXD_CMD_RS);
			// So we prefer to always set the RS bit.
			tx_desc->lower.data |= __constant_cpu_to_le32(E1000_TXD_CMD_RS);
			tx_buffer->skb = (void *)(0x1);
			tx_buffer->bytecount = packet->len;
			tx_buffer->segs = 1;
			tx_buffer->time_stamp = jiffies;
			tx_buffer->dma = 0;
			tx_buffer->length = 0;
			tx_buffer->mapped_as_page = 0;

			/* record length, and DMA address */

			tx_buffer->next_to_watch = tx_ring->next_to_use;
			tx_ring->next_to_use++;
			if (unlikely(tx_ring->next_to_use == tx_ring->count))
				tx_ring->next_to_use = 0;

			tx_ring->ndiv_rsp.next_to_send++;
			if (unlikely(tx_ring->ndiv_rsp.next_to_send == tx_ring->ndiv_rsp.size))
				tx_ring->ndiv_rsp.next_to_send = 0;

			tx_ring->ndiv_rsp.pending--;
			len += packet->len;
		}

		if (likely(len)) {
			netdev_sent_queue(adapter->netdev, len);
			wmb();
			writel(tx_ring->next_to_use, hw->hw_addr + tx_ring->tdt);

			mmiowb();
		}
	}

	__netif_tx_unlock(netdev_get_tx_queue(adapter->netdev, 0));
#ifdef IXGBE_NDIV_DROP_ON_XMIT
	if (unlikely(tx_ring->ndiv_rsp.pending)) {
		tx_ring->ndiv_rsp.avail += tx_ring->ndiv_rsp.pending;
		tx_ring->ndiv_rsp.next_to_use = tx_ring->ndiv_rsp.next_to_send;
		tx_ring->ndiv_rsp.pending = 0;
	}
#endif
}

static inline
int e1000_ndiv_handle_rx(struct ndiv *ndiv, struct e1000_rx_ring *rx_ring, struct e1000_tx_ring *tx_ring, struct e1000_rx_buffer *rx_buffer, struct e1000_rx_desc *rx_desc)
{
	struct e1000_ndiv_rdesc *packet;
	u8 *out = NULL;
	int ret = 0;
	u8 *l2;
	u8 *l3;
	u32 flags = 0;
	u32 vlan_proto;
	u16 l3_len;

	/* sanity checks */
	if (unlikely(rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK))
		return NDIV_RX_R_F_DROP;

	if (!(rx_desc->status & E1000_RXD_STAT_IXSM)) {
		if (rx_desc->errors & E1000_RXD_ERR_IPE)
			flags |= NDIV_RX_F_BADL3CSUM;
		if (rx_desc->errors & E1000_RXD_ERR_TCPE)
			flags |= NDIV_RX_F_BADL4CSUM;
	}

	l2 = rx_buffer->rxbuf.data;

	vlan_proto = ((struct ethhdr *)l2)->h_proto;
	if (vlan_proto == __constant_htons(ETH_P_8021Q)) {
		vlan_proto = (u32)(((struct vlan_ethhdr *)l2)->h_vlan_TCI & 0xff0f) << NDIV_RX_VLAN_SHIFT | ((struct vlan_ethhdr *)l2)->h_vlan_encapsulated_proto;
		l3 = l2 + sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
		l3_len = le16_to_cpu(rx_desc->length) - (sizeof(struct ethhdr) + sizeof(struct vlan_hdr));
	}
	else {
		/* test if vlan has been stripped by hardware */
		if ((ndiv->dev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			(rx_desc->status & E1000_RXD_STAT_VP)) {
			vlan_proto |= (u32)htons(le16_to_cpu(rx_desc->special) & E1000_RXD_SPC_VLAN_MASK) << NDIV_RX_VLAN_SHIFT;
		}
		l3 = l2 + sizeof(struct ethhdr);
		l3_len = le16_to_cpu(rx_desc->length) - sizeof(struct ethhdr);
	}

	if ((u16)vlan_proto == __constant_htons(ETH_P_IP)) {
		flags |= NDIV_RX_F_IPV4;
		if ((l3[0] & 0x0f) > 5)
			flags |= NDIV_RX_F_IP_EXT;
		if (l3[9] == IPPROTO_TCP)
			flags |= NDIV_RX_F_TCP;
		else if (l3[9] == IPPROTO_UDP)
			flags |= NDIV_RX_F_UDP;
	}
	else if ((u16)vlan_proto == __constant_htons(ETH_P_IPV6)) {
		flags |= NDIV_RX_F_IPV6;
		if (l3[6] == IPPROTO_TCP)
			flags |= NDIV_RX_F_TCP;
		else if (l3[6] == IPPROTO_UDP)
			flags |= NDIV_RX_F_UDP;

	}
	packet = &tx_ring->ndiv_rsp.descs[tx_ring->ndiv_rsp.next_to_use];
	if (likely(tx_ring->ndiv_rsp.avail))
		out = packet->data;

	ret = ndiv->handle_rx(ndiv, l3, flags|l3_len, vlan_proto, l2, out);
	if ((u16)ret) {
		packet->len = (u16)ret;
		if (ret & NDIV_RX_R_F_PASS) {
			rx_desc->length = cpu_to_le16(packet->len);
		}
		else if (ret & NDIV_RX_R_F_DROP) {
			tx_ring->ndiv_rsp.next_to_use++;
			if (tx_ring->ndiv_rsp.next_to_use == tx_ring->ndiv_rsp.size)
				tx_ring->ndiv_rsp.next_to_use = 0;

			tx_ring->ndiv_rsp.avail--;
			tx_ring->ndiv_rsp.pending++;
			packet->csum_off = 0;

			if (NDIV_RX_R_L4OFFSET_MASK & ret) {
				packet->l4_off = (NDIV_RX_R_L4OFFSET_MASK & ret) >> NDIV_RX_R_L4OFFSET_SHIFT;

				if (ret & NDIV_RX_R_F_8021Q) {
					l3 = out + sizeof(struct vlan_hdr) + sizeof(struct ethhdr);
					if (ret & NDIV_RX_R_F_IPCSUM)
						 ((struct iphdr *)l3)->check = ip_sum(0, (short unsigned int *)l3, packet->l4_off - (sizeof(struct vlan_hdr) + sizeof(struct ethhdr)));
				}
				else {
					l3 = out + sizeof(struct ethhdr);
					if (ret & NDIV_RX_R_F_IPCSUM)
						 ((struct iphdr *)l3)->check = ip_sum(0, (short unsigned int *)l3, packet->l4_off - (sizeof(struct ethhdr)));
				}

				if (ret & NDIV_RX_R_F_TCPCSUM) {
					packet->csum_off = packet->l4_off + 16;
					if (ret & NDIV_RX_R_F_IPV6) {
						*(u16 *)(out + packet->csum_off) = ~csum_ipv6_magic(&((struct ipv6hdr *)l3)->saddr,  &((struct ipv6hdr *)l3)->daddr,
												    packet->len - packet->l4_off,
												    IPPROTO_TCP, 0);
					}
					else {
						*(u16 *)(out + packet->csum_off) = ~csum_tcpudp_magic(((struct iphdr *)l3)->saddr,  ((struct iphdr *)l3)->daddr,
												      packet->len -  packet->l4_off,
												      IPPROTO_TCP, 0);
					}
				}
				else if (ret & NDIV_RX_R_F_UDPCSUM) {
					packet->csum_off = packet->l4_off + 6;
					if (ret & NDIV_RX_R_F_IPV6) {
						*(u16 *)(out + packet->csum_off) = ~csum_ipv6_magic(&((struct ipv6hdr *)l3)->saddr,  &((struct ipv6hdr *)l3)->daddr,
												    packet->len - packet->l4_off,
												    IPPROTO_UDP, 0);
					}
					else {
						*(u16 *)(out + packet->csum_off) = ~csum_tcpudp_magic(((struct iphdr *)l3)->saddr,  ((struct iphdr *)l3)->daddr,
												      packet->len - packet->l4_off,
												      IPPROTO_UDP, 0);
					}
				}
			}
		}
	}

	return ret;
}



#endif /* _E1000_NDIV_H_ */
