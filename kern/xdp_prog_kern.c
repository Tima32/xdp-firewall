/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + sizeof(struct ethhdr) > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return bpf_htons(eth->h_proto); /* network-byte-order */
}

static __always_inline int parse_ip(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **hdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = sizeof(*iph);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + sizeof(struct iphdr) > data_end)
		return -1;

	nh->pos += hdrsize;
	*hdr = iph;

	return iph->protocol; /* network-byte-order */
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *iph;
	struct udphdr *udph;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int ip_proto;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type != ETH_P_IP)
		goto out;

	ip_proto = parse_ip(&nh, data_end, &iph);
	if (ip_proto != IPPROTO_ICMP && ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP)
		goto out;
	
	uint16_t port_src = 0;
	uint16_t port_dst = 0;
	if (ip_proto != IPPROTO_ICMP)
	{
		if (nh.pos + sizeof(struct udphdr) > data_end)
		{
			action = XDP_ABORTED;
			goto out;
		}
		udph = nh.pos;
		port_src = udph->source;
		port_dst = udph->dest;
	}

	if (xdp_check_block(ip_proto, iph->saddr, iph->daddr, port_src, port_dst))
	{
		action = XDP_DROP;
	}
	

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
