#ifndef _IXGBE_NDIV_H_
#define _IXGBE_NDIV_H_
#include <linux/ndiv.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "ixgbe_ndiv_type.h"
#include "ixgbe.h"

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
void ixgbe_ndiv_fini_rsp(struct ixgbe_q_vector *q_vector)
{
	if (q_vector->ndiv_rsp.dma != 0) {
		dma_unmap_single(q_vector->tx.ring->dev,
				 q_vector->ndiv_rsp.dma,
				 q_vector->ndiv_rsp.size*1536,
				  DMA_TO_DEVICE);
		q_vector->ndiv_rsp.dma = 0;
	}

	if (q_vector->ndiv_rsp.data) {
		kfree(q_vector->ndiv_rsp.data);
		q_vector->ndiv_rsp.data = NULL;
	}

	if (q_vector->ndiv_rsp.descs) {
		kfree(q_vector->ndiv_rsp.descs);
		q_vector->ndiv_rsp.descs = NULL;
	}

	q_vector->ndiv_rsp.size = 0;
	q_vector->ndiv_rsp.next_to_send = q_vector->ndiv_rsp.next_to_use =  q_vector->ndiv_rsp.avail = 0;
}

static inline
int ixgbe_ndiv_init_rsp(struct ixgbe_q_vector *q_vector)
{
	int i;
	q_vector->ndiv_rsp.size = q_vector->rx.ring->count + q_vector->tx.ring->count;
	q_vector->ndiv_rsp.next_to_send = q_vector->ndiv_rsp.next_to_use =  q_vector->ndiv_rsp.avail = 0;
	q_vector->ndiv_rsp.descs =  kmalloc(q_vector->ndiv_rsp.size*sizeof(struct ixgbe_ndiv_rdesc), GFP_ATOMIC);
	if (!q_vector->ndiv_rsp.descs) {
		printk("ixgbe ndiv vector %p: unable to allocate %d descripors.\n", q_vector, q_vector->ndiv_rsp.size);
		q_vector->ndiv_rsp.size = 0;
		return -1;
	}
	q_vector->ndiv_rsp.data =  kmalloc(q_vector->ndiv_rsp.size*1536, GFP_ATOMIC);
	if (!q_vector->ndiv_rsp.data) {
		printk("ixgbe ndiv vector %p: unable to allocate %d descripors.\n", q_vector, q_vector->ndiv_rsp.size);
		kfree(q_vector->ndiv_rsp.descs);
		q_vector->ndiv_rsp.descs = NULL;
		q_vector->ndiv_rsp.size = 0;
		return -1;
	}

	q_vector->ndiv_rsp.dma = dma_map_single(q_vector->tx.ring->dev, q_vector->ndiv_rsp.data, q_vector->ndiv_rsp.size*1536, DMA_TO_DEVICE);
	if (dma_mapping_error(q_vector->tx.ring->dev, q_vector->ndiv_rsp.dma)) {
		printk("ixgbe ndiv vector %p: unable to dma map %d descripors.\n", q_vector, q_vector->ndiv_rsp.size);
		kfree(q_vector->ndiv_rsp.data);
		kfree(q_vector->ndiv_rsp.descs);
		q_vector->ndiv_rsp.data = NULL;
		q_vector->ndiv_rsp.descs = NULL;
		q_vector->ndiv_rsp.size = 0;
		return -2;
	}

	for (i = 0 ; i < q_vector->ndiv_rsp.size ; i++) {
		q_vector->ndiv_rsp.descs[i].data = q_vector->ndiv_rsp.data+(i*1536)+NET_IP_ALIGN;
		q_vector->ndiv_rsp.descs[i].dma = q_vector->ndiv_rsp.dma+(i*1536)+NET_IP_ALIGN;
		q_vector->ndiv_rsp.avail++;
	}

	printk("ixgbe ndiv vector %p: %d descripors allocated.\n", q_vector, q_vector->ndiv_rsp.size);
	return 0;
}

static inline
void ixgbe_ndiv_send_rsp(struct ixgbe_q_vector *q_vector) {
	struct ixgbe_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	u32 len = 0;
	struct ixgbe_ndiv_rdesc *packet;

	__netif_tx_lock(txring_txq(q_vector->tx.ring), smp_processor_id());

	if (likely(!netif_xmit_frozen_or_stopped(txring_txq(q_vector->tx.ring)))) {
		while (likely(q_vector->ndiv_rsp.pending && ixgbe_desc_unused(q_vector->tx.ring) >= 1)) {
			packet = &q_vector->ndiv_rsp.descs[q_vector->ndiv_rsp.next_to_send];
			tx_desc = IXGBE_TX_DESC(q_vector->tx.ring, q_vector->tx.ring->next_to_use);
			tx_buffer = &(q_vector->tx.ring)->tx_buffer_info[q_vector->tx.ring->next_to_use];


			tx_desc->read.buffer_addr = cpu_to_le64(packet->dma);
			if (packet->csum_off) {
				tx_desc->read.cmd_type_len = cpu_to_le32(packet->len) | cpu_to_le32(packet->csum_off << 16) | __constant_cpu_to_le32(IXGBE_ADVTXD_DCMD_IFCS|IXGBE_TXD_CMD_EOP|IXGBE_TXD_CMD_IC);
				tx_desc->read.olinfo_status =  cpu_to_le32(packet->l4_off << 8);
			}
			else {
				tx_desc->read.cmd_type_len = cpu_to_le32(packet->len) | __constant_cpu_to_le32(IXGBE_ADVTXD_DCMD_IFCS|IXGBE_TXD_CMD_EOP);
				tx_desc->read.olinfo_status = 0;
			}
			/* write last descriptor with RS and EOP bits */
			if (unlikely(ixgbe_desc_unused(q_vector->tx.ring) == 1 || (q_vector->ndiv_rsp.pending & 255) == 1))
				tx_desc->read.cmd_type_len |= __constant_cpu_to_le32(IXGBE_TXD_CMD_RS);

			tx_buffer->skb = (void *)(0x1);
			tx_buffer->bytecount = packet->len;
			tx_buffer->gso_segs = 1;
			tx_buffer->time_stamp = jiffies;
			tx_buffer->protocol = 0;
			tx_buffer->tx_flags = 0;

			/* record length, and DMA address */

			tx_buffer->next_to_watch = tx_desc;
			q_vector->tx.ring->next_to_use++;
			if (unlikely(q_vector->tx.ring->next_to_use == q_vector->tx.ring->count))
				q_vector->tx.ring->next_to_use = 0;

			q_vector->ndiv_rsp.next_to_send++;
			if (unlikely(q_vector->ndiv_rsp.next_to_send == q_vector->ndiv_rsp.size))
				q_vector->ndiv_rsp.next_to_send = 0;

			q_vector->ndiv_rsp.pending--;
			len += packet->len;
		}

		if (likely(len)) {
			netdev_tx_sent_queue(txring_txq(q_vector->tx.ring), len);
			wmb();
			writel(q_vector->tx.ring->next_to_use, q_vector->tx.ring->tail);
		}
	}

	__netif_tx_unlock(txring_txq(q_vector->tx.ring));
#ifdef IXGBE_NDIV_DROP_ON_XMIT
	if (unlikely(q_vector->ndiv_rsp.pending)) {
		q_vector->ndiv_rsp.avail += q_vector->ndiv_rsp.pending;
		q_vector->ndiv_rsp.next_to_use = q_vector->ndiv_rsp.next_to_send;
		q_vector->ndiv_rsp.pending = 0;
	}
#endif
}

static inline
int ixgbe_ndiv_handle_rx(struct ndiv *ndiv, struct ixgbe_q_vector *q_vector, struct ixgbe_ring *rx_ring, struct ixgbe_rx_buffer *rx_buffer, union ixgbe_adv_rx_desc *rx_desc)
{
	struct ixgbe_ndiv_rdesc *packet;
	u8 *out = NULL;
	__le16 pkt_info = rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;
	int ret = 0;
	u8 *l2;
	u8 *l3;
	u32 flags = 0;
	u32 vlan_proto;
	u16 l3_len;


	/* sanity checks */
	if (unlikely(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_FRAME_ERR_MASK)))
		return NDIV_RX_R_F_DROP;

	if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_IPV4|IXGBE_RXDADV_PKTTYPE_IPV4_EX)) {
		flags |= NDIV_RX_F_IPV4;
		if (!(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_IPCS)) ||
		    (rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_IPE)))
			flags |= NDIV_RX_F_BADL3CSUM;

		if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_IPV4_EX))
			flags |= NDIV_RX_F_IP_EXT;

		if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_TCP)) {
			flags |= NDIV_RX_F_TCP;
			if (!(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_L4CS)) ||
			    (rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_TCPE)))
				flags |= NDIV_RX_F_BADL4CSUM;
		}
		else if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_UDP)) {
			flags |= NDIV_RX_F_UDP;
			if (!(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_L4CS)) ||
			    (rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_TCPE)))
				flags |= NDIV_RX_F_BADL4CSUM;
		}
	}
	else if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_IPV6|IXGBE_RXDADV_PKTTYPE_IPV6_EX)) {
		flags |= NDIV_RX_F_IPV4;
		if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_IPV6_EX))
			flags |= NDIV_RX_F_IP_EXT;

		if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_TCP)) {
			flags |= NDIV_RX_F_TCP;
			if (!(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_L4CS)) ||
			    (rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_TCPE)))
				flags |= NDIV_RX_F_BADL4CSUM;
		}
		else if (pkt_info & __constant_cpu_to_le16(IXGBE_RXDADV_PKTTYPE_UDP)) {
			flags |= NDIV_RX_F_UDP;
			if (!(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_L4CS)) ||
			    (rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXDADV_ERR_TCPE)))
				flags |= NDIV_RX_F_BADL4CSUM;
		}
	}

	l2 = page_address(rx_buffer->page) + rx_buffer->page_offset;
	vlan_proto = ((struct ethhdr *)l2)->h_proto;
	if (vlan_proto == __constant_cpu_to_le16(ETH_P_8021Q)) {
		vlan_proto = (u32)((struct vlan_ethhdr *)l2)->h_vlan_TCI << NDIV_RX_VLAN_SHIFT | ((struct vlan_ethhdr *)l2)->h_vlan_encapsulated_proto;
		l3 = l2 + sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
		l3_len = le16_to_cpu(rx_desc->wb.upper.length) - (sizeof(struct ethhdr) + sizeof(struct vlan_hdr));
	}
	else {
		/* test if vlan has been stripped by hardware */
		if ((rx_ring->netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_VP))) {
			vlan_proto |= (u32)rx_desc->wb.upper.vlan << NDIV_RX_VLAN_SHIFT;
		}
		l3 = l2 + sizeof(struct ethhdr);
		l3_len = le16_to_cpu(rx_desc->wb.upper.length) - sizeof(struct ethhdr);
	}


	packet = &q_vector->ndiv_rsp.descs[q_vector->ndiv_rsp.next_to_use];
	if (likely(q_vector->ndiv_rsp.avail))
		out = packet->data;

	ret = ndiv->handle_rx(ndiv, l3, flags|l3_len, vlan_proto, l2, out);
	packet->len = (u16)ret;
	if (packet->len) {
		if (ret & NDIV_RX_R_F_PASS) {
			rx_desc->wb.upper.length = cpu_to_le16(packet->len);
		}
		else if (ret & NDIV_RX_R_F_DROP) {
			q_vector->ndiv_rsp.next_to_use++;
			if (q_vector->ndiv_rsp.next_to_use == q_vector->ndiv_rsp.size)
				q_vector->ndiv_rsp.next_to_use = 0;

			q_vector->ndiv_rsp.avail--;
			q_vector->ndiv_rsp.pending++;
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
					packet->csum_off = packet->l4_off + 14;
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



#endif /* _IXGBE_NDIV_H_ */
