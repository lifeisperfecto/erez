#include "erez.bpf.h"
#include "vmlinux.h"

// Maps an NLRI to the nexthops that packets
// destined to it should be sent to.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nlri_t);
	__type(value, struct fib_entry_t);
  __uint(map_flags, BPF_F_NO_PREALLOC);
 	__uint(max_entries, 1024);
} e_fib SEC(".maps") ;

// Ensures stickiness where all packets from
// a socket are sent to the same nexthop, so
// we avoid out-of-order routing.
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct socket_sticky_nexthop_t);
} e_socket_sticky_nexthops SEC(".maps");

// RTT events aggregated in userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // Roughly 16 million.
} e_tcp_rtt_events SEC(".maps");

// Metrics aggregated in userspace.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct metrics_t);
} e_metrics SEC(".maps");

static __always_inline struct metrics_t* get_metrics(void) {
	__u32 key = 0;
	return bpf_map_lookup_elem(&e_metrics, &key);
}

static __always_inline bool socket_sticky_nexthop_lookup(struct encap_packet_t* pkt, struct in6_addr* nexthop) {
	struct bpf_sock* sk = pkt->skb->sk;
	if (sk == NULL)
		return false;

	struct socket_sticky_nexthop_t* sticky_nexthop = bpf_sk_storage_get(&e_socket_sticky_nexthops, sk, NULL, 0);
	if (sticky_nexthop == NULL)
		return false;
	*nexthop = sticky_nexthop->nexthop;
	return true;
}

static __always_inline bool socket_sticky_nexthop_store(
	struct encap_packet_t* pkt,
	const struct nlri_t* matched_nlri,
	const struct in6_addr* nexthop
) {
	struct bpf_sock* sk = pkt->skb->sk;
	if (sk == NULL)
		return false;

	struct socket_sticky_nexthop_t sticky_nexthop = {
		.matched_nlri = *matched_nlri,
		.nexthop = *nexthop,
	};

	return bpf_sk_storage_get(
		&e_socket_sticky_nexthops,
		sk,
		&sticky_nexthop,
		BPF_SK_STORAGE_GET_F_CREATE) != NULL;
}

static __always_inline void emit_tcp_rtt_event(struct bpf_sock_ops* ops, struct metrics_t* metrics) {
	metrics->sockops_rtt_callbacks_total++;

	struct nlri_t nlri = {};
	if (!sockops_remote_nlri(ops, &nlri)) {
		metrics->sockops_rtt_skipped_total_unsupported_family++;
		return;
	}
	struct bpf_sock* sk = ops->sk;
	if (sk == NULL) {
		metrics->sockops_rtt_skipped_total_sticky_nexthop_miss++;
		return;
	}
	struct socket_sticky_nexthop_t* sticky_nexthop = bpf_sk_storage_get(&e_socket_sticky_nexthops, sk, NULL, 0);
	if (sticky_nexthop == NULL) {
		metrics->sockops_rtt_skipped_total_sticky_nexthop_miss++;
		return;
	}
	struct tcp_rtt_event_t* event = bpf_ringbuf_reserve(&e_tcp_rtt_events, sizeof(*event), 0);
	if (event == NULL) {
		metrics->sockops_rtt_event_drops_total_ringbuf_full++;
		return;
	}

	__builtin_memcpy(&event->matched_nlri, &sticky_nexthop->matched_nlri, sizeof(event->matched_nlri));
	__builtin_memcpy( &event->nexthop, &sticky_nexthop->nexthop, sizeof(event->nexthop));
	event->_padding = 0;
	event->ts_ns = bpf_ktime_get_ns();
	event->srtt_us = ops->srtt_us;
	event->rtt_min = ops->rtt_min;

	bpf_ringbuf_submit(event, 0);
	metrics->sockops_rtt_events_total++;
}

SEC("sockops")
int erez_sockops(struct bpf_sock_ops* ops) {
	struct metrics_t* metrics = get_metrics();
	if (metrics == NULL)
		return 0;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_RTT_CB_FLAG) == 0) {
			metrics->sockops_rtt_callback_registrations_total_success++;
		} else {
			metrics->sockops_rtt_callback_registrations_total_failed++;
		}
		return 0;
	case BPF_SOCK_OPS_RTT_CB:
		emit_tcp_rtt_event(ops, metrics);
		return 0;
	default:
		return 0;
	}
}

SEC("tc")
int erez_encap(struct __sk_buff *skb) {
  struct metrics_t* metrics = get_metrics();
  if (metrics == NULL)
    return TC_ACT_SHOT;
  metrics->encap_processed_packets_total++;

  struct encap_packet_t pkt = {};
	__s64 ret = encap_pkt_parse(skb, &pkt, metrics);
	if (ret != CONTINUE_PROCESSING)
		return ret;

	// Prefer sticky nexthops.
	struct in6_addr nexthop = {0};
	if (socket_sticky_nexthop_lookup(&pkt, &nexthop)) {
		metrics->encap_sticky_nexthop_total_hit++;
	} else {
		metrics->encap_sticky_nexthop_total_miss++;
		struct fib_entry_t* entry = bpf_map_lookup_elem(&e_fib, &pkt.nlri);
		if (entry == NULL) {
			metrics->encap_fib_misses_total++;
			return TC_ACT_OK;
		}
		metrics->encap_fib_hits_total++;
		if (!fib_entry_select_nexthop(entry, &nexthop, metrics))
			return TC_ACT_OK;
		if (socket_sticky_nexthop_store(&pkt, &entry->matched_nlri, &nexthop))
			metrics->encap_sticky_nexthop_total_store++;
	}
	  
  if (encap_pkt_encapsulate_ip6_gre(&pkt, nexthop) < 0) {
    metrics->encap_errors_total_encap_failed++;
    // We may have modified the packet when attempting encap,
    // meaning it's not valid to continue sending through the
    // networking stack, so we drop it.
    return TC_ACT_SHOT;
  }

  metrics->encap_encapsulated_packets_total++;

  return TC_ACT_OK;
}

SEC("xdp")
int erez_decap(struct xdp_md *ctx) {
  struct metrics_t* metrics = get_metrics();
  if (metrics == NULL)
    return XDP_ABORTED;
  metrics->decap_processed_packets_total++;

  struct decap_packet_t pkt = {};
	__s64 ret = decap_pkt_parse(ctx, &pkt, metrics);
	if (ret != CONTINUE_PROCESSING)
		return ret;

  // Always decap the header, so that if we aren't able
  // to process the packet at a later point, we let it
  // be handled normally by the kernel.
	if (decap_pkt_decapsulate_ip6_gre(&pkt) < 0) {
		metrics->decap_errors_total_decap_failed++;
	  // If the packet can't be decapsulated, it can't
    // be handled by the kernel, so we must drop it.
		return XDP_DROP;
	}
	metrics->decap_decapsulated_packets_total++;

	return decap_pkt_forward_to_nexthop(&pkt, metrics);
}

char LICENSE[] SEC("license") = "GPL v2";
