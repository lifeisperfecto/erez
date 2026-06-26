use std::{
    mem,
    net::{IpAddr, Ipv6Addr},
    ops::AddAssign,
};

use bytemuck::{Pod, Zeroable};
use ipnet::IpNet;

/// Size of IPv6 address in bytes.
const IPV6_ADDR_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct CIpv6Addr {
    pub octets: [u8; IPV6_ADDR_SIZE],
}
const _: () = assert!(mem::size_of::<CIpv6Addr>() == 16);

impl CIpv6Addr {
    const UNSPECIFIED: Self = CIpv6Addr {
        octets: [0; IPV6_ADDR_SIZE],
    };
}

impl From<IpAddr> for CIpv6Addr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                // https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
                let mut v6 = [0; IPV6_ADDR_SIZE];
                v6[10] = 0xFF;
                v6[11] = 0xFF;
                v6[12..].copy_from_slice(&addr.octets());
                Self { octets: v6 }
            }
            IpAddr::V6(addr) => Self {
                octets: addr.octets(),
            },
        }
    }
}

impl From<CIpv6Addr> for IpAddr {
    fn from(addr: CIpv6Addr) -> Self {
        let addr = Ipv6Addr::from(addr.octets);
        if let Some(v4) = addr.to_ipv4_mapped() {
            IpAddr::V4(v4)
        } else {
            IpAddr::V6(addr)
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct CNlri {
    prefix_len: u32,
    address: CIpv6Addr,
}
const _: () = assert!(mem::size_of::<CNlri>() == 20);

impl From<IpNet> for CNlri {
    fn from(prefix: IpNet) -> Self {
        let addr = prefix.addr();
        let prefix_len = u32::from(prefix.prefix_len());
        Self {
            prefix_len: match addr {
                // Shift the prefix length by 96 bits to account for the fixed mapping prefix,
                // otherwise all IPv4 LPM lookups will give an arbitrary ::ffff:0:0/96 prefix.
                IpAddr::V4(_) => prefix_len + 96,
                IpAddr::V6(_) => prefix_len,
            },
            address: CIpv6Addr::from(addr),
        }
    }
}

impl TryFrom<CNlri> for IpNet {
    type Error = anyhow::Error;

    fn try_from(nlri: CNlri) -> Result<Self, Self::Error> {
        let addr = Ipv6Addr::from(nlri.address.octets);

        if let Some(v4) = addr.to_ipv4_mapped() {
            if nlri.prefix_len < 96 || nlri.prefix_len - 96 > 32 {
                anyhow::bail!(
                    "ipv4-mapped nlri has invalid prefix length {}",
                    nlri.prefix_len
                );
            }
            let v4_prefix_len = nlri.prefix_len - 96;
            return Ok(IpNet::new(IpAddr::V4(v4), v4_prefix_len as u8)?);
        }

        if nlri.prefix_len > 128 {
            anyhow::bail!("ipv6 nlri has invalid prefix length {}", nlri.prefix_len);
        }
        Ok(IpNet::new(IpAddr::V6(addr), nlri.prefix_len as u8)?)
    }
}

/// Maximum number of nexthops in one FIB entry.
pub const MAX_NEXTHOPS: usize = 4;
/// The denominator for weights used to steer traffic,
/// all weights should sum to this number.
pub const WEIGHT_DENOMINATOR: u16 = 10_000;

#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct CFibEntry {
    pub matched_nlri: CNlri,
    pub nexthop_count: u32,
    pub nexthops: [CIpv6Addr; MAX_NEXTHOPS],
    pub weights: [u16; MAX_NEXTHOPS],
}
const _: () = assert!(mem::size_of::<CFibEntry>() == 96);

impl CFibEntry {
    pub(crate) fn new(
        matched_nlri: IpNet,
        nexthop_count: usize,
        nexthop_addrs: &[IpAddr; MAX_NEXTHOPS],
        weights: &[u16; MAX_NEXTHOPS],
    ) -> Self {
        let mut nexthops = [CIpv6Addr::UNSPECIFIED; MAX_NEXTHOPS];
        for (c_nexthop, nexthop) in nexthops.iter_mut().zip(nexthop_addrs) {
            *c_nexthop = CIpv6Addr::from(*nexthop);
        }

        Self {
            matched_nlri: CNlri::from(matched_nlri),
            nexthop_count: nexthop_count as u32,
            nexthops,
            weights: *weights,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct CTcpRttEvent {
    pub matched_nlri: CNlri,
    pub nexthop: CIpv6Addr,
    _padding: u32,
    pub ts_ns: u64,
    pub srtt_us: u32,
    pub rtt_min: u32,
}
const _: () = assert!(mem::size_of::<CTcpRttEvent>() == 56);

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq, Pod, Zeroable)]
pub struct CEbpfMetrics {
    // erez_decap metrics.
    pub decap_decapsulated_packets_total: u64,
    pub decap_errors_total_decap_failed: u64,
    pub decap_errors_total_decrement_inner_ttl_failed: u64,
    pub decap_errors_total_fib_lookup_failed: u64,
    pub decap_errors_total_redirect_failed: u64,
    pub decap_errors_total_same_ifindex: u64,
    pub decap_parse_errors_total_short_packet: u64,
    pub decap_processed_packets_total: u64,
    pub decap_redirected_packets_total: u64,
    pub decap_skipped_packets_total_unsupported_inner_l3_proto: u64,
    pub decap_skipped_packets_total_unsupported_outer_l3_proto: u64,
    pub decap_skipped_packets_total_unsupported_outer_l4_proto: u64,
    // erez_encap metrics.
    pub encap_encapsulated_packets_total: u64,
    pub encap_errors_total_encap_failed: u64,
    pub encap_fib_entry_validation_errors_total_invalid_nexthop_count: u64,
    pub encap_fib_entry_validation_errors_total_zero_weight: u64,
    pub encap_fib_entry_validation_errors_total_invalid_weight_sum: u64,
    pub encap_fib_hits_total: u64,
    pub encap_fib_misses_total: u64,
    pub encap_parse_errors_total_dest_nlri_load: u64,
    pub encap_parse_errors_total_l4_proto_load: u64,
    pub encap_processed_packets_total: u64,
    pub encap_skipped_packets_total_unsupported_l3_proto: u64,
    pub encap_skipped_packets_total_unsupported_l4_proto: u64,
    pub encap_sticky_nexthop_total_hit: u64,
    pub encap_sticky_nexthop_total_miss: u64,
    pub encap_sticky_nexthop_total_store: u64,
    // erez_sockops metrics.
    pub sockops_rtt_callback_registrations_total_success: u64,
    pub sockops_rtt_callback_registrations_total_failed: u64,
    pub sockops_rtt_callbacks_total: u64,
    pub sockops_rtt_events_total: u64,
    pub sockops_rtt_event_drops_total_ringbuf_full: u64,
    pub sockops_rtt_skipped_total_sticky_nexthop_miss: u64,
    pub sockops_rtt_skipped_total_unsupported_family: u64,
}
const _: () = assert!(mem::size_of::<CEbpfMetrics>() % mem::size_of::<u64>() == 0);

impl CEbpfMetrics {
    pub fn as_counter_slice(&self) -> &[u64] {
        bytemuck::cast_slice(std::slice::from_ref(self))
    }

    fn as_counter_slice_mut(&mut self) -> &mut [u64] {
        bytemuck::cast_slice_mut(std::slice::from_mut(self))
    }
}

impl AddAssign for CEbpfMetrics {
    fn add_assign(&mut self, other: Self) {
        for (value, other_value) in self
            .as_counter_slice_mut()
            .iter_mut()
            .zip(other.as_counter_slice())
        {
            *value += *other_value;
        }
    }
}
