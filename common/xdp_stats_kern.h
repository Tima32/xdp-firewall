/* SPDX-License-Identifier: GPL-2.0 */

/* Used *ONLY* by BPF-prog running kernel side. */
#ifndef __XDP_STATS_KERN_H
#define __XDP_STATS_KERN_H

/* Data record type 'struct datarec' is defined in common/xdp_stats_kern_user.h,
 * programs using this header must first include that file.
 */
#ifndef __XDP_STATS_KERN_USER_H
#warning "You forgot to #include <../common/xdp_stats_kern_user.h>"
#include <../common/xdp_stats_kern_user.h>
#endif

#include <stdint.h>

/* Keeps stats per (enum) xdp_action */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

struct Filter
{
	uint8_t proto;

	uint32_t ip_src_begin;
    uint32_t ip_src_end;
	uint32_t ip_dst_begin;
    uint32_t ip_dst_end;
	
	uint16_t port_src_begin;
    uint16_t port_src_end;
	uint16_t port_dst_begin;
    uint16_t port_dst_end;
};
/* Filter param */
struct bpf_map_def SEC("maps") xdp_config_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct Filter),
	.max_entries = 256,
};

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

static __always_inline
__u32 xdp_check_block_loop(size_t i, int ip_proto, uint32_t saddr, uint32_t daddr, uint16_t sp, uint16_t dp)
{
	struct Filter *filter = bpf_map_lookup_elem(&xdp_config_map, &i);
	if (!filter)
		return 1;

	if (filter->proto == 0)
		return 0;

	uint8_t count = 0;
	if (filter->proto == ip_proto || filter->proto == 0xFF)
		count++;

	if (filter->ip_src_begin <= saddr && saddr <= filter->ip_src_end)
		count++;
	if (filter->ip_dst_begin <= daddr && daddr <= filter->ip_dst_end)
		count++;

	if (filter->port_src_begin <= sp && sp <= filter->port_src_end)
		count++;
	if (filter->port_dst_begin <= dp && dp <= filter->port_dst_end)
		count++;
	
	if (count == 5)
		return 1;

	return 0;
}
static __always_inline
__u32 xdp_check_block(int ip_proto, uint32_t saddr, uint32_t daddr, uint16_t sp, uint16_t dp)
{
	#pragma clang loop unroll(full)
	for (size_t i = 0; i < 256; ++i)
	{
		if (xdp_check_block_loop(i, ip_proto, saddr, daddr, sp, dp))
			return 1;
	}
	return 0; // XDP_PASS
}

#endif /* __XDP_STATS_KERN_H */
