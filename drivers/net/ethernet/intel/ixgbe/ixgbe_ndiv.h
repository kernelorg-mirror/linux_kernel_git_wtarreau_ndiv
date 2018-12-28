#ifndef _IXGBE_NDIV_H_
#define _IXGBE_NDIV_H_
#include <linux/ndiv.h>
#include "ixgbe.h"

static inline
int ixgbe_ndiv_handle_rx(struct ndiv *ndiv, struct ixgbe_ring *rx_ring, struct xdp_buff *xdp, union ixgbe_adv_rx_desc *rx_desc)
{
	u8 *out = ndiv_out[smp_processor_id()];
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
		flags |= NDIV_RX_F_IPV6;
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

	l2 = xdp->data;
	vlan_proto = ((struct ethhdr *)l2)->h_proto;
	if (vlan_proto == __constant_htons(ETH_P_8021Q)) {
		vlan_proto = (u32)(((struct vlan_ethhdr *)l2)->h_vlan_TCI & 0xff0f) << NDIV_RX_VLAN_SHIFT | ((struct vlan_ethhdr *)l2)->h_vlan_encapsulated_proto;
		l3 = l2 + sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
		l3_len = le16_to_cpu(rx_desc->wb.upper.length) - (sizeof(struct ethhdr) + sizeof(struct vlan_hdr));
	}
	else {
		/* test if vlan has been stripped by hardware */
		if ((rx_ring->netdev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
			(rx_desc->wb.upper.status_error & __constant_cpu_to_le32(IXGBE_RXD_STAT_VP))) {
			vlan_proto |= (u32)htons(le16_to_cpu(rx_desc->wb.upper.vlan) & 0x0fff) << NDIV_RX_VLAN_SHIFT;
		}
		l3 = l2 + sizeof(struct ethhdr);
		l3_len = le16_to_cpu(rx_desc->wb.upper.length) - sizeof(struct ethhdr);
	}

	ret = ndiv->handle_rx(ndiv, l3, flags|l3_len, vlan_proto, l2, out);
	if (ret & NDIV_RX_R_F_PASS) {
		if ((u16)ret) {
			u16 len = (u16)ret;

			xdp->data_end = xdp->data + len;
		}
		ret = XDP_PASS;
	}
	else if (ret & NDIV_RX_R_F_DROP) {
		if ((u16)ret) {
			u16 len = (u16)ret;

			if (NDIV_RX_R_L4OFFSET_MASK & ret) {
				u16 l4_off = (NDIV_RX_R_L4OFFSET_MASK & ret) >> NDIV_RX_R_L4OFFSET_SHIFT;

				if (ret & NDIV_RX_R_F_8021Q) {
					l3 = out + sizeof(struct vlan_hdr) + sizeof(struct ethhdr);
					if (ret & NDIV_RX_R_F_IPCSUM)
						((struct iphdr *)l3)->check = ip_fast_csum((unsigned char *)l3,
											   (l4_off - (sizeof(struct vlan_hdr) + sizeof(struct ethhdr))) >> 2);
				}
				else {
					l3 = out + sizeof(struct ethhdr);
					if (ret & NDIV_RX_R_F_IPCSUM)
						((struct iphdr *)l3)->check = ip_fast_csum((unsigned char *)l3,
											   (l4_off - (sizeof(struct ethhdr))) >> 2);
				}

				if (ret & NDIV_RX_R_F_TCPCSUM) {
					u16 *csum = (u16 *)&out[l4_off + 16];

					if (ret & NDIV_RX_R_F_IPV6) {
						*csum = csum_ipv6_magic(&((struct ipv6hdr *)l3)->saddr,
									&((struct ipv6hdr *)l3)->daddr,
									len - l4_off, IPPROTO_TCP,
									csum_partial((unsigned char *)(out + l4_off), len - l4_off, 0));
					}
					else {
						*csum = csum_tcpudp_magic(((struct iphdr *)l3)->saddr,
									  ((struct iphdr *)l3)->daddr,
									  len - l4_off, IPPROTO_TCP,
									  csum_partial((unsigned char *)(out + l4_off),  len - l4_off, 0));
					}
				}
				else if (ret & NDIV_RX_R_F_UDPCSUM) {
					u16 *csum = (u16 *)&out[l4_off + 6];

					if (ret & NDIV_RX_R_F_IPV6) {
						*csum = csum_ipv6_magic(&((struct ipv6hdr *)l3)->saddr,
									&((struct ipv6hdr *)l3)->daddr,
									len - l4_off, IPPROTO_UDP,
									csum_partial((unsigned char *)(out + l4_off),  len - l4_off, 0));
					}
					else {
						*csum = csum_tcpudp_magic(((struct iphdr *)l3)->saddr,
									  ((struct iphdr *)l3)->daddr,
									  len - l4_off, IPPROTO_UDP,
									  csum_partial((unsigned char *)(out + l4_off),  len - l4_off, 0));
					}
				}
			}
			memcpy(xdp->data, out, len);
			xdp->data_end = xdp->data + len;
			ret = XDP_TX;
		}
		else {
			ret = XDP_DROP;
		}
	}
	else {
		ret = XDP_DROP;
	}

	return ret;
}



#endif /* _IXGBE_NDIV_H_ */

