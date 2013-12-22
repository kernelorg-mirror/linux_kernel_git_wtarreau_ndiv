/*
 * slhttpd.c: a stateless HTTP server for the ndiv framework
 *
 * Copyright (C) 2013 Willy Tarreau <w@1wt.eu>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/ndiv.h>
#include <linux/notifier.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define uint64_t u64
#define uint32_t u32
#define uint16_t u16

#define MAX_NDIV 4

static int portl = 8000;
static int porth = 8999;

static char *dev[MAX_NDIV];

module_param_array(dev, charp, NULL, 0);  MODULE_PARM_DESC(dev, "Interfaces names to attach to");
module_param(portl, uint, 0644); MODULE_PARM_DESC(dev, "Lowest TCP port to intercept (8000)");
module_param(porth, uint, 0644); MODULE_PARM_DESC(dev, "Highest TCP port to intercept (8999)");

static struct ndiv ndiv[MAX_NDIV];
static int nbndiv;

enum {
	SLH_ST_REQ           = 0,
	SLH_ST_LASTACK       = 1,
	/* data states for close mode: up to 8 packets may be sent (1 + 7 extra) */
	SLH_ST_ACK_CL_LAST_7 = 2,
	SLH_ST_ACK_CL_LAST_6 = 3,
	SLH_ST_ACK_CL_LAST_5 = 4,
	SLH_ST_ACK_CL_LAST_4 = 5,
	SLH_ST_ACK_CL_LAST_3 = 6,
	SLH_ST_ACK_CL_LAST_2 = 7,
	SLH_ST_ACK_CL_LAST_1 = 8,
	SLH_ST_ACK_CL_LAST   = 9,  /* last packetd ACKed, send FIN */
	SLH_ST_ACK_CL_FIN    = 10, /* must absolutely equal SLH_ST_ACK_CL_LAST + 1 */
	/* the last states must be the ones for the keep-alive mode, because we
	 * want them to count +1 modulo 16 and automatically loop to 0, so up to
	 * 6 packets may be sent (1 + 5 extra).
	 */
	SLH_ST_ACK_KA_LAST_5 = 11,
	SLH_ST_ACK_KA_LAST_4 = 12,
	SLH_ST_ACK_KA_LAST_3 = 13,
	SLH_ST_ACK_KA_LAST_2 = 14,
	SLH_ST_ACK_KA_LAST_1 = 15,
};

/* flags used to build our return packets */
enum {
	FLG_FIN = 1,
	FLG_SYN = 2,
	FLG_RST = 4,
	FLG_PSH = 8,
	FLG_ACK = 16,
};

/* This one has to be increased by 16 for each SYN emitted. It does not
 * require any locking as we only increase it to avoid confuse the client
 * in case we get a late packet.
 * We can have an array of a few isns per source port hash if needed.
 */
static uint32_t isn;


/* returns the last char '\0'. The output must be large enough. */
char *u16toa(char *dst, uint16_t n)
{
	int i = 0;
	char *res;

	switch (n) {
		case 0U ... 9U:
			i = 0;
			break;

		case 10U ... 99U:
			i = 1;
			break;

		case 100U ... 999U:
			i = 2;
			break;

		case 1000U ... 9999U:
			i = 3;
			break;

		case 10000U ... 65535U:
			i = 4;
			break;
	}
	res = dst + i + 1;
	*res = '\0';
	for (; i >= 0; i--) {
		dst[i] = n % 10U + '0';
		n /= 10U;
	}
	return res;
}

/* append 6 bytes from <da>, 6 bytes from <sa>, <proto> for <plen> bytes to
 * <tail> and return the pointer to the next byte.
 */
static inline uint8_t *append_eth(uint8_t *tail, void *da, void *sa, void *proto, int plen)
{
	memcpy(tail +  0, da, 6);
	memcpy(tail +  6, sa, 6);
	memcpy(tail + 12, proto, plen);
	return tail + 12 + plen;
}

/* append a 20-bytes IP header at the end of an existing packet. The length and
 * IP header checksum are left to zero. The pointer to the next byte is returned.
 * It is assumed that the buffer is 32-bit aligned.
 */
static uint8_t *append_ip(uint8_t *data, uint16_t id, uint32_t saddr, uint32_t daddr)
{
	/* build IP header */
	*(uint16_t *)(data +  0)  = htons(0x4510);     /* IP, tos 10 */
	*(uint16_t *)(data +  2)  = 0;                 /* IP+TCP real len */
	*(uint16_t *)(data +  4)  = id;                /* same ID as sender */
	*(uint16_t *)(data +  6)  = htons(0x4000);     /* DF, ofs=0 */
	*(uint32_t *)(data +  8)  = htonl(0x40060000); /* TTL=64, TCP, check=0 */
	*(uint32_t *)(data + 12)  = saddr;
	*(uint32_t *)(data + 16)  = daddr;
	return data + 20;
}

/* append a TCP header to a pre-allocated buffer and build an RST packet.
 * The pointer to the next byte is returned. It is assumed that the buffer
 * is 32-bit aligned.
 */
static uint8_t *append_rst(uint8_t *data, uint16_t spt, uint16_t dpt, uint32_t seq)
{
	*(uint16_t *)(data +  0)  = spt;
	*(uint16_t *)(data +  2)  = dpt;
	*(uint32_t *)(data +  4)  = seq;
	*(uint32_t *)(data +  8)  = 0;
	*(uint32_t *)(data + 12)  = htonl(0x500405b4); /* doff=20, rst, win=1460 */
	*(uint32_t *)(data + 16)  = 0;                 /* check, urgptr */
	return data + 20;
}

/* append a TCP header to a pre-allocated buffer and build an empty FIN
 * packet. The pointer to the next byte is returned. It is assumed that
 * the buffer is 32-bit aligned.
 */
static uint8_t *append_fin(uint8_t *data, uint16_t spt, uint16_t dpt, uint32_t seq, uint32_t ack)
{
	*(uint16_t *)(data +  0)  = spt;
	*(uint16_t *)(data +  2)  = dpt;
	*(uint32_t *)(data +  4)  = seq;
	*(uint32_t *)(data +  8)  = ack;
	*(uint32_t *)(data + 12)  = htonl(0x501105b4); /* doff=20, fin+ack, win=1460 */
	*(uint32_t *)(data + 16)  = 0;                 /* check, urgptr */
	return data + 20;
}

/* append a TCP header to a pre-allocated buffer and build an SYN/ACK packet.
 * The pointer to the next byte is returned. It is assumed that the buffer
 * is 32-bit aligned.
 */
static uint8_t *append_syn_ack(uint8_t *data, uint16_t spt, uint16_t dpt, uint32_t seq, uint32_t ack)
{
	*(uint16_t *)(data +  0)  = spt;
	*(uint16_t *)(data +  2)  = dpt;
	*(uint32_t *)(data +  4)  = seq;
	*(uint32_t *)(data +  8)  = ack;
	*(uint32_t *)(data + 12)  = htonl(0x601205b4); /* doff=24, synack, win=1460 */
	*(uint32_t *)(data + 16)  = 0;                 /* check, urgptr */
	*(uint32_t *)(data + 20)  = htonl(0x020405b4); /* opt: MSS=<1460> */
	return data + 24;
}

/* append a TCP header to a pre-allocated buffer and build a data ACK packet.
 * Extra flags may be passed in <flags> (PSH, FIN, ...). The pointer to the
 * next byte is returned. It is assumed that the buffer is 32-bit aligned.
 */
static uint8_t *append_data_ack(uint8_t *data, uint16_t spt, uint16_t dpt, uint32_t seq, uint32_t ack, uint8_t flags)
{
	*(uint16_t *)(data +  0)  = spt;
	*(uint16_t *)(data +  2)  = dpt;
	*(uint32_t *)(data +  4)  = seq;
	*(uint32_t *)(data +  8)  = ack;
	*(uint32_t *)(data + 12)  = htonl(0x501005b4); /* doff=20, ack, win=1460 */
	*(uint8_t  *)(data + 13) |= flags;
	*(uint32_t *)(data + 16)  = 0;                 /* check, urgptr */
	return data + 20;
}

/* This callback is called for each incoming packet. Returns < 0 to stop
 * processing.
 */
static u32 handle_rx(struct ndiv *ndiv, u8 *l3, u32 flags_l3len, u32 vlan_proto, u8 *l2, u8 *obuf)
{
	/* input packet */
	const uint8_t *idata, *itail;
	struct iphdr  *iih;
	struct tcphdr *ith;
	int ilen;
	int st;

	/* output packet */
	uint8_t *odata, *otail;
	uint8_t *oih;
	uint8_t *oth;

	/* The input and output buffers are arranged like this :
	 * buf : [ headroom | IP | TCP | DATA | tailroom ]
	 *                  ^.   ^.    ^.     ^._ tail
	 *                    \    \     \_______ data
	 *                     \    \____________ th
	 *                      \________________ ih
	 *
	 * The input buffer has no headroom since IP begins at l3.
	 */

	/* Let all non-ip traffic pass through (ARP, ...) */
	if (ntohs(vlan_proto) != 0x0800)
		goto accept;

	/* get payload */
	ilen = (u16)flags_l3len;
	if (ilen < sizeof(*iih))
		goto drop;

	iih = (void *)l3;
	if (iih->ihl < sizeof(*iih) / 4)
		goto drop;

	/* do not intercept non-tcp */
	if (iih->protocol != IPPROTO_TCP)
		goto accept;

	if (ilen < sizeof(*iih) + sizeof(*ith))
		goto drop;

	ith = (void *)((uint32_t *)iih + iih->ihl);
	if (ith->doff < sizeof(*ith) / 4)
		goto drop;

	if (ith->doff > (ilen - sizeof(*iih) + sizeof(*ith)) / 4)
		goto drop;

	/* check that the port is well within the portl..porth range */
	if ((uint16_t)(ntohs(ith->dest) - portl) > (porth - portl))
		goto accept;

	/* Prepare a pointer to the beginning of data in the outgoing packet.
	 * We reserve the first 64 bytes to build the IP and TCP headers.
	 */
	otail = odata = obuf + 64;

	/* retrieve the next state requested by the peer */
	st = ntohl(ith->ack_seq) & 15;

	idata = (uint8_t *)((uint32_t *)ith + ith->doff);
	itail = l3 + ilen;

	/* OK prepare to respond. We swap MAC and IP */
	oih = otail = append_eth(obuf, l2 + 6, l2, l2 + 12, 2);
	oth = otail = append_ip(otail, iih->id, iih->daddr, iih->saddr);

	/* note that all sources and destinations are swapped since we're
	 * responding to a peer.
	 */
	if (ith->rst) {
		/* never reply anything to an RST */
		goto drop;
	}
	else if (!ith->ack) {
		if (ith->syn) {
			/* we got a SYN, we return a SYN-ACK with SEQ%16=0 for state REQ */
			odata = otail = append_syn_ack(otail, ith->dest, ith->source,
						       htonl((isn << 4) + SLH_ST_REQ - 1),  /* -1 for the SYN */
						       htonl(ntohl(ith->seq) + 1));
			isn++;
			goto send_ip;
		}
		/* for all other cases, we want an ACK */
		goto send_rst;
	}
	else if (st == SLH_ST_REQ) {
		int ka   = 0;  /* 0 = close, 1 = keep-alive */
		int size = 0;  /* requested object size */
		int ver  = 0;  /* 0 = HTTP/1.0, 1 = HTTP/1.1 */
		int budget;    /* how much left in the first packet */
		int sizelen;   /* bytes needed to encode <size> */
		int hdrlen;    /* header len for the first packet */
		int pkt1_size = 0;   /* data in the first packet */
		int nb_data_pkt = 0; /* # of extra packets */
		int final_state;
		int pad = 0;   /* amount of padding to add */
		int fin = 0;   /* send fin */
		const uint8_t *parse;

		if (itail <= idata) {
			/* we got an empty ACK, it could be the connection
			 * setup ACK (which we ignore and drop) or a FIN after
			 * a port probe.
			 */
			if (ith->fin) {
				/* return a FIN and go to the LASTACK state on FIN */
				odata = otail = append_fin(otail, ith->dest, ith->source,
							   ith->ack_seq, htonl(ntohl(ith->seq) + 1));
				goto send_ip;
			}
			goto drop;
		}

		/* we need enough space for the response */
		if (ntohs(ith->window) < 1460)
			goto drop;

		if ((itail - idata) < 15) /* "GET / HTTP/1.0\n", at least supports telnet */
			goto send_rst;

		parse = idata + 5;
		if (*(uint32_t *)idata == ntohl(0x47455420)) { // "GET "
			/* parse the request : get requested object size */
			while (parse < itail && (uint8_t)(*parse - '0') <= 9) {
				size = (size * 10) + (*parse - '0');
				parse++;
			}

			sizelen = 1;
			if (unlikely(size >= 10)) {
				if (size < 100)
					sizelen = 2;
				else if (size < 1000)
					sizelen = 3;
				else if (size < 10000)
					sizelen = 4;
				else
					sizelen = 5;
			}
		}
		else if (*(uint32_t *)idata == ntohl(0x48454144)) { // "HEAD "
			size = -1;
		}
		else
			goto send_rst;

		/* check HTTP version */
		while (parse < itail && *parse != ' ' && *parse != '\n')
			parse++;

		if (parse + 9 <= itail && *((u32 *)(parse+1)) == ntohl(0x48545450)) { /* "HTTP" */
			ver = parse[8] == '1';
			parse += 9;
		}

		/* principle :
		 *   - if a FIN is present, there is no keep-alive.
		 *   - in HTTP/1.0 a client has a chance to have keep-alive only
		 *     if the Connection header is the first one (avoid parsing
		 *     all headers for nothing)
		 *   - in HTTP/1.1, we search for Connection: close along the whole
		 *     request.
		 */
		ka = 0; /* no keep-alive if FIN present */
		if (!ith->fin) {
			ka = ver;  /* no keep-alive in 1.0 by default */

			for ( ; parse < itail - 13; parse++) {
				if (*parse != '\n')
					continue;
				if (likely(parse[1] != 'C') || memcmp(parse + 2, "onnection: ", 11) != 0) {
					if (!ka)
						break;
					continue;
				}
				/* "keep-alive" is OK, the rest is "close" */
				ka = (parse[13] == 'K' || parse[13] == 'k');
				break;
			}
		}

		/* Now let's see how we'll build the response. We have to send :
		 *   "HTTP/1.x 200 OK\r\n"        => 17 chars
		 *   "Connection: keep-alive\r\n" => 24 chars when in 1.0 with keep-alive
		 *   "Content-length: x\r\n"      => 19 chars for 0..9, 20 for 10..99,
		 *                                   21 for 100..999, 22 for 1000..9999,
		 *                                   23 for 10000..99999, RST above
		 *   "X-Pad:xxxxx\r\n"            => 8..23 (0..15 spaces) if padding is required
		 *   "\r\n"                       => 2 chars
		 *
		 * Total:
		 *   - 17+24+2+18+sizelen in 1.0 + keep-alive = 61+sizelen
		 *   - 17+2+18+sizelen in 1.1 or 1.0+close    = 37+sizelen
		 *   - plus up to 23 if padding is required =>
		 *        61 + 5 + 23 = 89 in 1.0 + keep-alive
		 *        37 + 5 + 23 = 65 otherwise
		 *
		 * We need to adjust the amount of output data so that the sum
		 * of data emitted modulo 16 equals :
		 *   - 16 - #extra_packets if responding in keep-alive as we
		 *     want to get back to this state after #extra packets ;
		 *   - 0 if doing keep-alive with a single packet (same as above)
		 *   - 0 if we're on the last packet and FIN was present, because
		 *     we're going to emit a FIN which counts as one and will go to
		 *     LASTACK ;
		 *   - CL_LAST if we're emitting the last packet + a FIN so that
		 *     the sum equals ACK_CL_FIN
		 *
		 * The data in the first packet may not be larger than 1370 bytes
		 * so that we still have up to 90 bytes to the headers.
		 */

		budget  = 1460;
		hdrlen  = 0;
		if (size >= 0) {
			/* GET request */

			hdrlen += 17;           /* status line */
			hdrlen += 2;            /* CRLF */
			hdrlen += 18 + sizelen; /* content-length */
			pkt1_size = size;
		}
		else {
			/* HEAD request */

			hdrlen += 30;           /* status line */
			hdrlen += 2;            /* CRLF */
			pkt1_size = 0;
		}

		if (!ver && ka)         /* connection */
			hdrlen += 24;

		budget -= hdrlen + 23;  /* if X-Pad is needed */

		if (pkt1_size > budget) {
			int max_pkt;

			/* need more than one packet. Each other packet will be
			 * 1457 bytes (=1 modulo 16). The first one will carry
			 * the complement.
			 *
			 * This means that there are a number of sizes we cannot
			 * handle, they're all those which add more than budget to
			 * multiples of 1457. We don't care much, we simply truncate
			 * the size so that the first packet can be sent and that we
			 * don't send too many packets.
			 */
			if (ka || ith->fin)
				max_pkt = 5; /* 5 data states in the keep-alive chain */
			else
				max_pkt = 7; /* 7 data states in the close chain */

			nb_data_pkt = size / 1457;

			if (nb_data_pkt > max_pkt) {
				nb_data_pkt = max_pkt;
				size = nb_data_pkt * 1457 + budget;
			}

			pkt1_size = size - (nb_data_pkt * 1457);
			if (pkt1_size > budget) {
				pkt1_size = budget;
				size = pkt1_size + nb_data_pkt * 1457;
			}
		}

		/* We don't consider our FIN here. It equals one byte but since
		 * our post-FIN states are exactly the previous one plus 1, we
		 * must ignore it for now. However, we want to go to the LASTACK
		 * state if the client has presented a FIN first, so this is
		 * equivalent to going into ST_REQ without FIN.
		 */
		if (ka || ith->fin)
			final_state = SLH_ST_REQ;
		else
			final_state = SLH_ST_ACK_CL_LAST;

		/* remember, each packet counts 1 step */
		pad  = final_state - st - nb_data_pkt;
		pad -= hdrlen + pkt1_size;
		pad  = pad & 15;
		/* pad is the size we need to add using the "X-Pad" header */

		/* now it's getting tricky. We ack the peer's possible FIN only
		 * if we're in the last packet so that it continues sending it.
		 * We send a FIN if we're on the last packet and we have a FIN
		 * in the request, or if the final state is ACK_CL_LAST because
		 * we're sending the last packet of a close transfer.
		 */
		fin = !nb_data_pkt && (ith->fin || final_state == SLH_ST_ACK_CL_LAST);

		odata = otail = append_data_ack(otail, ith->dest, ith->source,
						ith->ack_seq,
						htonl(ntohl(ith->seq) + (itail - idata) + (nb_data_pkt ? 0 : ith->fin)),
						FLG_PSH + (fin ? FLG_FIN : 0));

		memcpy(otail, "HTTP/1.0", 8);
		otail[7] = '0' + ver;

		if (size >= 0) {
			memcpy(otail + 8, " 200 OK\r\nContent-length: 0\r\n", 28);
			otail += 36;

			if (size > 0) {
				otail = u16toa(otail - 3, size);
				*otail++ = '\r';
				*otail++ = '\n';
			}
		}
		else {
			memcpy(otail + 8, " 304 Not Modified...\r\n", 22);
			otail += 30;
		}

		if (!ver && ka) {
			memcpy(otail, "Connection: keep-alive\r\n", 24);
			otail += 24;
		}

		if (pad) {
			/* we have 8 non-reductible bytes */
			memcpy(otail, "X-Pad: 0123456789abcde", 22);
			otail[((pad - 8) & 15) + 6] = '\r';
			otail[((pad - 8) & 15) + 7] = '\n';
			otail += ((pad - 8) & 15) + 8;
		}

		/* final CRLF */
		*otail++ = '\r';
		*otail++ = '\n';

		/* fill with readable data for small packets, and skip one line for last char */
		if (unlikely(pkt1_size)) {
			if (pkt1_size < 200) {
				int i;
				for (i = 0; i < pkt1_size; i++) {
					if (i == pkt1_size - 1)
						*otail++ = '\n';
					else
						*otail++ = ".123456789ABCDEF"[i & 15];
				}
			}
			else {
				otail += pkt1_size;
			}

			/* payload size */
			pkt1_size = otail - odata;
		}
	}
	else if ((st >= SLH_ST_ACK_CL_LAST_7 && st <= SLH_ST_ACK_CL_LAST_1) ||
		 (st >= SLH_ST_ACK_KA_LAST_5 && st <= SLH_ST_ACK_KA_LAST_1)) {
		int fin;

		/* we need enough space for the response */
		if (ntohs(ith->window) < 1460)
			goto drop;

		/* we want to send a FIN if we're sending the last packet in the
		 * CLOSE mode, or if we're sending the last one in the keep-alive
		 * mode and the client has already sent its FIN. It's also the
		 * only case where we're ready to ACK the client's FIN.
		 */
		fin = (st == SLH_ST_ACK_KA_LAST_1 && ith->fin) || (st == SLH_ST_ACK_CL_LAST_1);

		odata = otail = append_data_ack(otail, ith->dest, ith->source,
						ith->ack_seq, htonl(ntohl(ith->seq) + (itail - idata) + (fin && ith->fin)),
						FLG_PSH + (fin ? FLG_FIN : 0));

		otail += 1457; /* 91*16 + 1 => one step forward */
	}
	else if (st == SLH_ST_LASTACK) {
		/* We have already got the client's FIN. Silently drop
		 * the empty ACKs in this state. However we may encounter
		 * late retransmitted FINs, let's re-ACK them. All other
		 * packets are reset.
		 */
		if (ith->fin) {
			/* return a FIN and go to the LASTACK state on FIN */
			odata = otail = append_fin(otail, ith->dest, ith->source,
						   ith->ack_seq, htonl(ntohl(ith->seq) + (itail - idata) + 1));
			goto send_ip;
		}
		if ((itail - idata))
			goto send_rst; /* forbidden to send data after FIN */
		goto drop;
	}
	else if (st == SLH_ST_ACK_CL_LAST) {
		/* our FIN was not ACKed, let's retransmit it, it will push us
		 * automatically to state ACK_CL_FIN
		 */
		odata = otail = append_data_ack(otail, ith->dest, ith->source,
						ith->ack_seq, ith->seq, FLG_FIN);
	}
	else if (st == SLH_ST_ACK_CL_FIN) {
		/* our FIN was ACKed. If the client sent its FIN, we must ACK it.
		 * Otherwise it might be the remote stack which is ACKing our
		 * last packet, in which case we have nothing more to say. The
		 * client will happily close with its FIN later or with an RST.
		 * We must not emit any FIN since it was already sent and ACKed.
		 */
		if (!ith->fin)
			goto drop;

		odata = otail = append_data_ack(otail, ith->dest, ith->source,
						ith->ack_seq, htonl(ntohl(ith->seq) + (itail - idata) + ith->fin),
						0);
	}
	else {
		/* for now on, we reset everything */
		odata = otail = append_rst(otail, ith->dest, ith->source, ith->ack_seq);
	}

 send_ip:
	*(uint16_t *)(oih + 2) = htons(otail - oih);  /* IP+TCP real len */

	return NDIV_RX_R_F_DROP | (20 << NDIV_RX_R_L4OFFSET_SHIFT) | NDIV_RX_R_F_IPCSUM | NDIV_RX_R_F_TCPCSUM | (otail - obuf);

 drop:
	return NDIV_RX_R_F_DROP;

 accept:
	return NDIV_RX_R_F_PASS;

 send_rst:
	odata = otail = append_rst(otail, ith->dest, ith->source, ith->ack_seq);
	goto send_ip;
}


/*
 * All the Code below is boring stuff like registration etc...
 */

static int handle_device_event(struct notifier_block *notif,
                               unsigned long event, void *ptr)
{
	int i;

	/* only the matching ndiv will be handled */
	for (i = 0; i < nbndiv; i++)
		ndiv_handle_device_event(notif, event, ptr, &ndiv[i]);

	return NOTIFY_DONE;
}

static struct notifier_block notifier = {
	.notifier_call = handle_device_event,
};

static int __init modinit(void)
{
	int ret = -ENODEV;

	for (nbndiv = 0; nbndiv < MAX_NDIV && dev[nbndiv]; nbndiv++) {
		printk(KERN_DEBUG "Attaching to device %s\n", dev[nbndiv]);
		ndiv[nbndiv].handle_rx = handle_rx;
		ret = ndiv_register_byname(dev[nbndiv], ndiv + nbndiv);
		if (ret < 0) {
			printk(KERN_DEBUG "ndiv_register(%s) returned %d\n", dev[nbndiv], ret);
			goto fail;
		}
		printk(KERN_DEBUG "Attached to device %s\n", ndiv[nbndiv].dev->name);
	}

	if (nbndiv > 0)
		register_netdevice_notifier(&notifier);

        return ret;

 fail:
	while (nbndiv) {
		ndiv_unregister(ndiv + nbndiv);
		nbndiv--;
	}
	return ret;
}

static void __exit modexit(void)
{
	unregister_netdevice_notifier(&notifier);

	rtnl_lock();
	while (nbndiv--) {
		printk(KERN_DEBUG "Unregistering from device %s\n", ndiv[nbndiv].dev->name);
		ndiv_unregister(ndiv + nbndiv);
	}
	rtnl_unlock();

	printk(KERN_DEBUG "Bye.\n");
}

module_init(modinit);
module_exit(modexit);

MODULE_DESCRIPTION("Stateless HTTP server");
MODULE_AUTHOR("Willy Tarreau");
MODULE_VERSION("0.0.3");
MODULE_LICENSE("GPL");
