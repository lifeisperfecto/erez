#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// -- Linux compat.

// vmlinux.h has BTF types, but not all preprocessor constants,
// e.g. TC_ACT_OK. We need to define these manually.

// #include <linux/pkt_cls.h>
enum {
	TC_ACT_UNSPEC     = -1,
	TC_ACT_OK         = 0,
	TC_ACT_RECLASSIFY = 1,
	TC_ACT_SHOT       = 2,
	TC_ACT_PIPE       = 3,
	TC_ACT_STOLEN     = 4,
	TC_ACT_QUEUED     = 5,
	TC_ACT_REPEAT     = 6,
	TC_ACT_REDIRECT   = 7,
	TC_ACT_TRAP       = 8,
	TC_ACT_VALUE_MAX  = TC_ACT_TRAP,
};

// #include <linux/if_ether.h>
enum {
	ETH_P_IP   = 0x0800,
	ETH_P_IPV6 = 0x86DD,
};

// #include <linux/if_ether.h>
enum {
	ETH_ALEN = 6, // Octets in one Ethernet address.
};

// #include <linux/socket.h>
enum {
	AF_INET  = 2,
	AF_INET6 = 10,
};

// -- IPv6 helpers.

static __always_inline bool ipv6_addr_is_unspecified(const struct in6_addr *addr) {
	return addr->in6_u.u6_addr32[0] == 0 &&
	       addr->in6_u.u6_addr32[1] == 0 &&
	       addr->in6_u.u6_addr32[2] == 0 &&
	       addr->in6_u.u6_addr32[3] == 0;
}

static __always_inline bool ipv6_addr_is_mapped_ipv4(const struct in6_addr *addr) {
	return addr->in6_u.u6_addr32[0] == 0 &&
	       addr->in6_u.u6_addr32[1] == 0 &&
	       addr->in6_u.u6_addr16[4] == 0 &&
	       addr->in6_u.u6_addr16[5] == 0xffff;
}

// -- Routing decisions.

#define MAX_NEXTHOPS 4
#define WEIGHT_DENOMINATOR 10000

struct __attribute__((__packed__)) nlri_t {
  struct bpf_lpm_trie_key_hdr hdr;
  struct in6_addr addr; // May be an IPv4-mapped IPv6 address.
};
_Static_assert(sizeof(struct nlri_t) == 20, "sizeof(struct nlri_t) must be 20");

struct fib_entry_t {
  struct nlri_t matched_nlri;
  __u32 nexthop_count;
  struct in6_addr nexthops[MAX_NEXTHOPS];
  __u16 weights[MAX_NEXTHOPS];
};
_Static_assert(sizeof(struct fib_entry_t) == 96, "sizeof(struct fib_entry_t) must be 96");

struct socket_sticky_nexthop_t {
	struct nlri_t matched_nlri;
	struct in6_addr nexthop;
};
_Static_assert(
	sizeof(struct socket_sticky_nexthop_t) == 36,
	"sizeof(struct socket_sticky_nexthop_t) must be 36");

struct tcp_rtt_event_t {
	struct nlri_t matched_nlri;
	struct in6_addr nexthop;
	__u32 _padding;
	__u64 ts_ns;
	__u32 srtt_us;
	__u32 rtt_min;
};
_Static_assert(sizeof(struct tcp_rtt_event_t) == 56, "sizeof(struct tcp_rtt_event_t) must be 56");

// -- Aggregation.

static __always_inline bool sockops_remote_nlri(struct bpf_sock_ops* ops, struct nlri_t* nlri) {
	nlri->hdr.prefixlen = 128;

	switch (ops->family) {
	case AF_INET:
		nlri->addr.in6_u.u6_addr16[5] = 0xffff;
		nlri->addr.in6_u.u6_addr32[3] = ops->remote_ip4;
		return true;
	case AF_INET6:
		nlri->addr.in6_u.u6_addr32[0] = ops->remote_ip6[0];
		nlri->addr.in6_u.u6_addr32[1] = ops->remote_ip6[1];
		nlri->addr.in6_u.u6_addr32[2] = ops->remote_ip6[2];
		nlri->addr.in6_u.u6_addr32[3] = ops->remote_ip6[3];
		return true;
	default:
		return false;
	}
}

// -- Packet manipulation.

struct metrics_t {
	// erez_decap metrics.
	__u64 decap_decapsulated_packets_total;
	__u64 decap_errors_total_decap_failed;
	__u64 decap_errors_total_decrement_inner_ttl_failed;
	__u64 decap_errors_total_fib_lookup_failed;
	__u64 decap_errors_total_redirect_failed;
	__u64 decap_errors_total_same_ifindex;
	__u64 decap_parse_errors_total_short_packet;
	__u64 decap_processed_packets_total;
	__u64 decap_redirected_packets_total;
	__u64 decap_skipped_packets_total_unsupported_inner_l3_proto;
	__u64 decap_skipped_packets_total_unsupported_outer_l3_proto;
	__u64 decap_skipped_packets_total_unsupported_outer_l4_proto;
	// erez_encap metrics.
	__u64 encap_encapsulated_packets_total;
	__u64 encap_errors_total_encap_failed;
	__u64 encap_fib_entry_validation_errors_total_invalid_nexthop_count;
	__u64 encap_fib_entry_validation_errors_total_zero_weight;
	__u64 encap_fib_entry_validation_errors_total_invalid_weight_sum;
	__u64 encap_fib_hits_total;
	__u64 encap_fib_misses_total;
	__u64 encap_parse_errors_total_dest_nlri_load;
	__u64 encap_parse_errors_total_l4_proto_load;
	__u64 encap_processed_packets_total;
	__u64 encap_skipped_packets_total_unsupported_l3_proto;
	__u64 encap_skipped_packets_total_unsupported_l4_proto;
	__u64 encap_sticky_nexthop_total_hit;
	__u64 encap_sticky_nexthop_total_miss;
	__u64 encap_sticky_nexthop_total_store;
	// erez_sockops metrics.
	__u64 sockops_rtt_callback_registrations_total_success;
	__u64 sockops_rtt_callback_registrations_total_failed;
	__u64 sockops_rtt_callbacks_total;
	__u64 sockops_rtt_events_total;
	__u64 sockops_rtt_event_drops_total_ringbuf_full;
	__u64 sockops_rtt_skipped_total_sticky_nexthop_miss;
	__u64 sockops_rtt_skipped_total_unsupported_family;
};
_Static_assert(sizeof(struct metrics_t) % sizeof(__u64) == 0, "struct metrics_t has unexpected padding");

static __always_inline bool fib_entry_select_nexthop(
	const struct fib_entry_t* entry,
	struct in6_addr* nexthop,
	struct metrics_t* metrics
) {
	__u32 nexthop_count = entry->nexthop_count;
	if (nexthop_count == 0 || nexthop_count > MAX_NEXTHOPS) {
		metrics->encap_fib_entry_validation_errors_total_invalid_nexthop_count++;
		return false;
	}

	__u32 ticket = bpf_get_prandom_u32() % WEIGHT_DENOMINATOR;
	__u32 total_weight = 0;
	bool selected = false;
	bool zero_weight = false;
	struct in6_addr selected_nexthop = {};

#pragma unroll
	for (int i = 0; i < MAX_NEXTHOPS; i++) {
		if (i < nexthop_count) {
			__u32 weight = entry->weights[i];

			if (weight == 0) {
				zero_weight = true;
				continue;
			}

			total_weight += weight;
			if (!selected && ticket < total_weight) {
				selected_nexthop = entry->nexthops[i];
				selected = true;
			}
		}
	}

	if (zero_weight) {
		metrics->encap_fib_entry_validation_errors_total_zero_weight++;
		return false;
	}
	if (total_weight != WEIGHT_DENOMINATOR) {
		metrics->encap_fib_entry_validation_errors_total_invalid_weight_sum++;
		return false;
	}

	*nexthop = selected_nexthop;
	return true;
}

#define CONTINUE_PROCESSING -1

// The combined size of the IPv6 and GRE headers
// that we prepend when encapsulating a packet.
#define ENCAP_LEN (sizeof(struct ipv6hdr) + sizeof(struct gre_base_hdr))
_Static_assert(ENCAP_LEN == 44, "ENCAP_LEN must be 44");

struct encap_packet_t {
	struct __sk_buff *skb;
	__u16 l3_proto;
	__u8 l4_proto;
	struct nlri_t nlri;
};

struct decap_packet_t {
	struct xdp_md *ctx;
	__u16 inner_l3_proto;
	struct in6_addr nexthop;
};

static __always_inline bool valid_encap_l3_proto(__u32 proto) {
  // We only process packets that can be IP-routed to the Internet (via BGP).
  return proto == ETH_P_IP || proto == ETH_P_IPV6;
}

static __always_inline bool valid_encap_l4_proto(__u8 proto) {
  // We only process TCP/UDP/ICMP packets.
  return proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP;
}

static __always_inline bool valid_decap_l3_proto(__u16 proto) {
  // Packets should only be encapsulated in IPv6.
  return proto == ETH_P_IPV6;
}

static __always_inline bool valid_decap_l4_proto(__u8 proto) {
  // Packets should only be encapsulated in GRE.
  return proto == IPPROTO_GRE;
}

static __always_inline __s64 encap_pkt_load_l4_proto(struct encap_packet_t* pkt) {
	__u32 offset;

	switch (pkt->l3_proto) {
	case ETH_P_IP:
		offset = sizeof(struct ethhdr) + offsetof(struct iphdr, protocol);
		break;
	case ETH_P_IPV6:
		offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, nexthdr);
		break;
	default:
		return -1;
	}

	return bpf_skb_load_bytes(pkt->skb, offset, &pkt->l4_proto, sizeof(pkt->l4_proto));
}

static __always_inline __s64 encap_pkt_load_dest_nlri(struct encap_packet_t* pkt) {
	pkt->nlri.hdr.prefixlen = 128;

	switch (pkt->l3_proto) {
	case ETH_P_IP: {
		__u32 offset = sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
		if (bpf_skb_load_bytes(pkt->skb, offset, &pkt->nlri.addr.in6_u.u6_addr32[3], sizeof(__be32)) < 0)
			return -1;
		pkt->nlri.addr.in6_u.u6_addr16[5] = 0xffff;
		return 0;
	}
	case ETH_P_IPV6: {
		__u32 offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr);
		return bpf_skb_load_bytes(pkt->skb, offset, &pkt->nlri.addr, sizeof(pkt->nlri.addr));
	}
	default:
		return -1;
	}
}

static __always_inline __s64 encap_pkt_parse(struct __sk_buff* skb, struct encap_packet_t* pkt, struct metrics_t* metrics) {
	pkt->skb = skb;
	pkt->l3_proto = bpf_ntohs(skb->protocol);

	if (!valid_encap_l3_proto(pkt->l3_proto)) {
		metrics->encap_skipped_packets_total_unsupported_l3_proto++;
		return TC_ACT_OK;
	}
	if (encap_pkt_load_l4_proto(pkt) < 0) {
		metrics->encap_parse_errors_total_l4_proto_load++;
		return TC_ACT_OK;
	}
	if (!valid_encap_l4_proto(pkt->l4_proto)) {
		metrics->encap_skipped_packets_total_unsupported_l4_proto++;
		return TC_ACT_OK;
	}
	if (encap_pkt_load_dest_nlri(pkt) < 0) {
		metrics->encap_parse_errors_total_dest_nlri_load++;
		return TC_ACT_OK;
	}
	return CONTINUE_PROCESSING;
}

static __always_inline __s64 encap_pkt_load_saddr(struct encap_packet_t* pkt, struct in6_addr* saddr) {
	switch (pkt->l3_proto) {
	case ETH_P_IP: {
		__u32 offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
		if (bpf_skb_load_bytes(pkt->skb, offset, &saddr->in6_u.u6_addr32[3], sizeof(__be32)) < 0)
			return -1;
		saddr->in6_u.u6_addr16[5] = 0xffff;
		return 0;
	}
	case ETH_P_IPV6: {
		__u32 offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr);
		return bpf_skb_load_bytes(pkt->skb, offset, saddr, sizeof(*saddr));
	}
	default:
		return -1;
	}
}

// Reference: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/test_tc_tunnel.c.
static __always_inline __s64 encap_pkt_encapsulate_ip6_gre(struct encap_packet_t* pkt, const struct in6_addr nexthop) {
  // Before we adjust room via direct memory access
  // we need to extract the packet's source address.
  struct in6_addr saddr = {0};
  if (encap_pkt_load_saddr(pkt, &saddr) < 0)
		return -1;
  
  // Ok, now we're ready to adjust room.
	__u64 adj_room_flags = BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_ENCAP_L4_GRE;

  // We don't want gso_size to be changed when encapsulating UDP, since
  // this will change the point at which datagrams are delineated, which
  // fragments them incorrectly.
  if (pkt->l4_proto== IPPROTO_UDP)
    adj_room_flags |= BPF_F_ADJ_ROOM_FIXED_GSO;

  __s64 ret = bpf_skb_adjust_room(pkt->skb, ENCAP_LEN, BPF_ADJ_ROOM_MAC, adj_room_flags);
  if (ret < 0)
    return -1;

  void *head = (void*)(__u64)pkt->skb->data;
  void *tail = (void*)(__u64)pkt->skb->data_end;
  if (head + sizeof(struct ethhdr) + ENCAP_LEN > tail)
     return -1;

  struct ethhdr *eth = (struct ethhdr *)(head);
  eth->h_proto = bpf_htons(ETH_P_IPV6);

  struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + sizeof(struct ethhdr));
  ip6->version = 6;
  ip6->hop_limit = 255;
	ip6->nexthdr = IPPROTO_GRE;
	ip6->saddr = saddr;
	ip6->daddr = nexthop;
	ip6->payload_len = bpf_htons(pkt->skb->len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr));

  struct gre_base_hdr *gre = (struct gre_base_hdr *)(head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  gre->flags = 0;
  gre->protocol = bpf_htons(pkt->l3_proto);

  return 0;
}

static __always_inline __s64 decap_pkt_parse(struct xdp_md* ctx, struct decap_packet_t* pkt, struct metrics_t* metrics) {
	pkt->ctx = ctx;
	
	void *head = (void *)(__u64)ctx->data;
	void *tail = (void *)(__u64)ctx->data_end;

	if (head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct gre_base_hdr) > tail) {
		metrics->decap_parse_errors_total_short_packet++;
		return XDP_PASS;
	}

	struct ethhdr *eth = head;
	__u16 outer_l3_proto = bpf_ntohs(eth->h_proto);
	if (!valid_decap_l3_proto(outer_l3_proto)) {
		metrics->decap_skipped_packets_total_unsupported_outer_l3_proto++;
		return XDP_PASS;
	}

	struct ipv6hdr *ip6 = head + sizeof(*eth);
	__u8 outer_l4_proto = ip6->nexthdr;
	if (!valid_decap_l4_proto(outer_l4_proto)) {
		metrics->decap_skipped_packets_total_unsupported_outer_l4_proto++;
		return XDP_PASS;
	}

	struct gre_base_hdr *gre = head + sizeof(*eth) + sizeof(*ip6);
	pkt->inner_l3_proto = bpf_ntohs(gre->protocol);
	if (!valid_encap_l3_proto(pkt->inner_l3_proto)) {
		metrics->decap_skipped_packets_total_unsupported_inner_l3_proto++;
		return XDP_PASS;
	}

  // Extract nexthop we're supposed to forward to.
	pkt->nexthop = ip6->daddr;
	return CONTINUE_PROCESSING;
}

static __always_inline __s64 decap_pkt_decapsulate_ip6_gre(struct decap_packet_t* pkt) {
	void *head = (void *)(__u64)pkt->ctx->data;
	void *tail = (void *)(__u64)pkt->ctx->data_end;

	if (head + sizeof(struct ethhdr) + ENCAP_LEN > tail)
		return -1;

	struct ethhdr *eth = head;
	eth->h_proto = bpf_htons(pkt->inner_l3_proto);

	__builtin_memmove(head + ENCAP_LEN, head, sizeof(*eth));
	return bpf_xdp_adjust_head(pkt->ctx, ENCAP_LEN);
}

static __always_inline __s64 decap_pkt_decrement_inner_ttl(struct decap_packet_t* pkt) {
	void *head = (void *)(__u64)pkt->ctx->data;
	void *tail = (void *)(__u64)pkt->ctx->data_end;

	switch (pkt->inner_l3_proto) {
	case ETH_P_IP: {
		if (head + sizeof(struct ethhdr) + sizeof(struct iphdr) > tail)
			return -1;

		struct iphdr *ip = head + sizeof(struct ethhdr);
		if (ip->ttl <= 1)
			return -1;

		// Matches the kernel's ip_decrease_ttl implementation.
		ip->ttl -= 1;
		__u32 sum = (__u32)ip->check + bpf_htons(0x0100);
		ip->check = (__u16)(sum + (sum >= 0xffff));
		return 0;
	}
	case ETH_P_IPV6: {
		if (head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > tail)
			return -1;

		struct ipv6hdr *ip6 = head + sizeof(struct ethhdr);
		if (ip6->hop_limit <= 1)
			return -1;

		ip6->hop_limit -= 1;
		return 0;
	}
	default:
		return -1;
	}
}

static __always_inline __s64 decap_pkt_forward_to_nexthop(struct decap_packet_t* pkt, struct metrics_t* metrics) {
  // Since we do a direct FIB lookup which solely depends on the
  // destination IP, we don't need to supply any source address
  // in the lookup.
  struct bpf_fib_lookup fib_params = {
    .ifindex = pkt->ctx->ingress_ifindex,
  };
  if (ipv6_addr_is_mapped_ipv4(&pkt->nexthop)) {
    fib_params.family = AF_INET;
    fib_params.ipv4_dst = pkt->nexthop.in6_u.u6_addr32[3];
  } else {
    fib_params.family = AF_INET6;
    __builtin_memcpy(fib_params.ipv6_dst, &pkt->nexthop, sizeof(pkt->nexthop));
  }

  // All our routes are installed by BIRD into the default routing table,
  // so, to increase performance, we skip evaluating any FIB rules which
  // may cause us to evaluate routes from a different table.
  __u32 fib_lookup_flags = BPF_FIB_LOOKUP_DIRECT; 
  __u64 ret = bpf_fib_lookup(pkt->ctx, &fib_params, sizeof(struct bpf_fib_lookup), fib_lookup_flags);
  if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
    metrics->decap_errors_total_fib_lookup_failed++;
    return XDP_PASS;
  }

  // Now that we want to forward the packet, let's decrement its TTL.
  __s64 ttl_ret = decap_pkt_decrement_inner_ttl(pkt);
  if (ttl_ret < 0) {
      metrics->decap_errors_total_decrement_inner_ttl_failed++;
      return XDP_PASS;
  }

  // Rewrite Ethernet headers, so that the packets
  // are switched to the correct remote interface.
  void *head = (void*)(__u64)pkt->ctx->data;
  void *tail = (void*)(__u64)pkt->ctx->data_end;
  if (head + sizeof(struct ethhdr) > tail)
     return XDP_PASS;
  struct ethhdr *eth = (struct ethhdr *)(head);
  __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

  // This should never happen, unless a peer is messing with us,
  // as these types of packets should only originate from inside
  // our network.
  if (fib_params.ifindex == pkt->ctx->ingress_ifindex) {
    metrics->decap_errors_total_same_ifindex++;
    return XDP_PASS;
  }
  // XDP version of this function accepts no flags.
  __s64 redirect_ret = bpf_redirect(fib_params.ifindex, 0);
  if (redirect_ret == XDP_ABORTED) {
    metrics->decap_errors_total_redirect_failed++;
    return redirect_ret;
  }
  metrics->decap_redirected_packets_total++;
  return redirect_ret;
}
