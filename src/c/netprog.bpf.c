/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IPV6		0x86DD	/* IPv6 */
#define ETH_P_IP		0x0800	/* IPv4 */
#define IPPROTO_TCP		6	/* TCP */
#define IPPROTO_UDP		17	/* UDP */

/* Protocol ports */
#define HTTP_PORT		80
#define HTTPS_PORT		443
#define DNS_PORT		53
#define SSH_PORT		22

/* Protocol types for counting */
#define PROTO_HTTP		0
#define PROTO_DNS		1
#define PROTO_SSH		2
#define PROTO_MAX		3

/* Byte-count bounds check; check if current pointer at @start + @off of header
 * is after @end.
 */
#define __may_pull(start, off, end) \
	(((unsigned char *)(start)) + (off) <= ((unsigned char *)(end)))

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

struct proc_stats {
	__u64 drop;
};

struct protocol_stats {
	__u64 packets;
	__u64 bytes;
};

#define XDP_STATS_MAP_NELEM_MAX 1
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct proc_stats);
	__uint(max_entries, XDP_STATS_MAP_NELEM_MAX);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct protocol_stats);
	__uint(max_entries, PROTO_MAX);
} protocol_stats_map SEC(".maps");

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

SEC("xdp")
int  xdp_prog_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

static __always_inline int
parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	__u16 h_proto;

	if (!__may_pull(eth, hdrsize, data_end))
		return -EINVAL;

	/* Move the cursor ahead as we have parsed the ethernet header */
	nh->pos += hdrsize;
	/* network-byte-order */
	h_proto = eth->h_proto;

	if (ethhdr)
		*ethhdr = eth;

	return h_proto;
}

static __always_inline int
parse_ip6hdr(struct hdr_cursor *nh, void *data_end, struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to.
	 */
	if (!__may_pull(ip6h, hdrsize, data_end))
		return -EINVAL;

	nh->pos += hdrsize;

	if (ip6hdr)
		*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int
parse_ip4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = sizeof(*iph);

	if (!__may_pull(iph, hdrsize, data_end))
		return -EINVAL;

	nh->pos += hdrsize;

	if (iphdr)
		*iphdr = iph;

	return iph->protocol;
}

static __always_inline int
parse_tcphdr(struct hdr_cursor *nh, void *data_end, struct tcphdr **tcphdr)
{
	struct tcphdr *tcp = nh->pos;
	int hdrsize = sizeof(*tcp);

	if (!__may_pull(tcp, hdrsize, data_end))
		return -EINVAL;

	nh->pos += hdrsize;

	if (tcphdr)
		*tcphdr = tcp;

	return 0;
}

static __always_inline int
parse_udphdr(struct hdr_cursor *nh, void *data_end, struct udphdr **udphdr)
{
	struct udphdr *udp = nh->pos;
	int hdrsize = sizeof(*udp);

	if (!__may_pull(udp, hdrsize, data_end))
		return -EINVAL;

	nh->pos += hdrsize;

	if (udphdr)
		*udphdr = udp;

	return 0;
}

static __always_inline int
process_ipv6hdr(struct hdr_cursor *nh, void *data_end)
{
	struct protocol_stats *pstats;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;
	struct udphdr *udp;
	int nexthdr;
	__u16 sport, dport;
	__u32 key;

	nexthdr = parse_ip6hdr(nh, data_end, &ip6h);
	if (nexthdr < 0)
		return XDP_PASS;

	switch (nexthdr) {
	case IPPROTO_TCP:
		if (parse_tcphdr(nh, data_end, &tcp) < 0)
			return XDP_PASS;
		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		break;
	case IPPROTO_UDP:
		if (parse_udphdr(nh, data_end, &udp) < 0)
			return XDP_PASS;
		sport = bpf_ntohs(udp->source);
		dport = bpf_ntohs(udp->dest);
		break;
	default:
		return XDP_PASS;
	}

	/* Classify protocol based on ports */
	if (sport == HTTP_PORT || dport == HTTP_PORT || 
	    sport == HTTPS_PORT || dport == HTTPS_PORT) {
		key = PROTO_HTTP;
		bpf_printk("XDP: received a HTTP packet!");
	} else if (sport == DNS_PORT || dport == DNS_PORT) {
		key = PROTO_DNS;
		bpf_printk("XDP: received a DNS packet!");
	} else if (sport == SSH_PORT || dport == SSH_PORT) {
		key = PROTO_SSH;
		bpf_printk("XDP: received a SSH packet!");
	} else {
		return XDP_PASS;
	}

	/* Update protocol statistics */
	pstats = bpf_map_lookup_elem(&protocol_stats_map, &key);
	if (!pstats)
		return XDP_PASS;

	lock_xadd(&pstats->packets, 1);
	lock_xadd(&pstats->bytes, bpf_ntohs(ip6h->payload_len) + sizeof(*ip6h));

	return XDP_PASS;
}

static __always_inline int
process_ipv4hdr(struct hdr_cursor *nh, void *data_end)
{
	struct protocol_stats *pstats;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;
	int nexthdr;
	__u16 sport, dport;
	__u32 key;

	nexthdr = parse_ip4hdr(nh, data_end, &iph);
	if (nexthdr < 0)
		return XDP_PASS;

	switch (nexthdr) {
	case IPPROTO_TCP:
		if (parse_tcphdr(nh, data_end, &tcp) < 0)
			return XDP_PASS;
		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
		break;
	case IPPROTO_UDP:
		if (parse_udphdr(nh, data_end, &udp) < 0)
			return XDP_PASS;
		sport = bpf_ntohs(udp->source);
		dport = bpf_ntohs(udp->dest);
		break;
	default:
		return XDP_PASS;
	}

	/* Classify protocol based on ports */
	if (sport == HTTP_PORT || dport == HTTP_PORT || 
	    sport == HTTPS_PORT || dport == HTTPS_PORT) {
		key = PROTO_HTTP;
		bpf_printk("XDP: received a HTTP packet!");
	} else if (sport == DNS_PORT || dport == DNS_PORT) {
		key = PROTO_DNS;
		bpf_printk("XDP: received a DNS packet!");
	} else if (sport == SSH_PORT || dport == SSH_PORT) {
		key = PROTO_SSH;
		bpf_printk("XDP: received a SSH packet!");
	} else {
		return XDP_PASS;
	}

	/* Update protocol statistics */
	pstats = bpf_map_lookup_elem(&protocol_stats_map, &key);
	if (!pstats)
		return XDP_PASS;

	lock_xadd(&pstats->packets, 1);
	lock_xadd(&pstats->bytes, bpf_ntohs(iph->tot_len));

	return XDP_PASS;
}

SEC("xdp")
int xdp_prog_protocol_classifier(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int h_proto;
	__u16 proto;

	nh.pos = data;

	h_proto = parse_ethhdr(&nh, data_end, &eth);
	if (h_proto < 0)
		return XDP_PASS;

	proto = bpf_ntohs(h_proto);
	switch (proto) {
	case ETH_P_IP:
		return process_ipv4hdr(&nh, data_end);
	case ETH_P_IPV6:
		return process_ipv6hdr(&nh, data_end);
	default:
		return XDP_PASS;
	}
}

char _license[] SEC("license") = "Dual BSD/GPL";