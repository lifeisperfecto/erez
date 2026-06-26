use std::{
    fmt,
    mem::MaybeUninit,
    net::{IpAddr, Ipv6Addr},
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};

use anyhow::Context;
use ipnet::IpNet;
use libbpf_rs::{
    MapCore, MapFlags, MapHandle, OpenObject, PrintLevel, RingBufferBuilder, TC_EGRESS,
    TcHookBuilder, Xdp, XdpFlags,
    libbpf_sys::{self},
    skel::{OpenSkel, SkelBuilder},
};
use nix::errno::Errno;
use prometheus_client::{
    collector::Collector,
    encoding::{DescriptorEncoder, EncodeMetric},
    metrics::{TypedMetric, counter::ConstCounter, gauge::ConstGauge},
    registry::Registry,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

#[rustfmt::skip]
mod erez_bpf {
    #![allow(warnings)]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/erez.skel.rs"));
}

use crate::{
    bpf_abi::{CEbpfMetrics, CFibEntry, CIpv6Addr, CNlri, CTcpRttEvent},
    interface::Interface,
};
use erez_bpf::*;

pub use crate::bpf_abi::{MAX_NEXTHOPS, WEIGHT_DENOMINATOR};

/// eBPF TC handle number for Erez programs.
const TC_HANDLE: u32 = 1;
/// eBPF TC priority value for Erez programs.
const TC_PRIORITY: u32 = 1;

/// cgroup root used for cgroup sockops attachment.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub struct EncapLinks {
    _sockops: libbpf_rs::Link,
}

pub struct EncapMaps {
    pub fib: Fib,
    pub tcp_rtt_events: TcpRttEvents,
}

pub fn set_libbpf_logger() {
    // We request the most detailed log level on the
    // eBPF side, and userspace is responsible for
    // filtering logs.
    let _ = libbpf_rs::set_print(Some((PrintLevel::Debug, print_callback)));
}

/// Noise produced by libbpf when querying and attaching eBPF
/// programs/maps. These messages are logged at debug level.
const NOISY_LIBBPF_MESSAGES: [&str; 1] =
    // We often see this when trying to detach a TC program
    // that doesn't exist; once we move to TCX this shouldn't
    // happen anymore.
    ["libbpf: Kernel error message: Parent Qdisc doesn't exists"];

#[allow(clippy::needless_pass_by_value)]
fn print_callback(level: PrintLevel, message: String) {
    let message = message.trim();
    if NOISY_LIBBPF_MESSAGES.contains(&message) {
        trace!("{message}");
        return;
    }

    match level {
        // These are really verbose, even at debug
        // level so we're going to trace-log them.
        PrintLevel::Debug => trace!("{message}"),
        PrintLevel::Info => info!("{message}"),
        PrintLevel::Warn => warn!("{message}"),
    }
}

fn load_skel(open_object: &mut MaybeUninit<OpenObject>) -> anyhow::Result<ErezSkel> {
    let skel_builder = ErezSkelBuilder::default();
    let open_skel = skel_builder
        .open(open_object)
        .context("failed to open ebpf skeleton")?;
    let skel = open_skel.load().context("failed to load ebpf skeleton")?;
    Ok(skel)
}

pub fn attach_encap(
    iface: &Interface,
    registry: &mut Registry,
) -> anyhow::Result<(EncapLinks, EncapMaps)> {
    // Initialise the skeleton.
    let mut open_object = MaybeUninit::uninit();
    let skel = load_skel(&mut open_object)?;

    // Attach the program to the network interface on egress.
    let mut tc_builder = TcHookBuilder::new(skel.progs.erez_encap.as_fd());
    let mut egress_hook = tc_builder
        .ifindex(iface.index.get())
        .replace(true)
        .handle(TC_HANDLE)
        .priority(TC_PRIORITY)
        .hook(TC_EGRESS);
    egress_hook
        .create()
        .with_context(|| format!("failed to create tc hook for interface {}", iface.name))?;
    egress_hook
        .attach()
        .with_context(|| format!("failed to attach tc hook to interface {}", iface.name))?;

    let cgroup = std::fs::File::open(CGROUP_ROOT).context("failed to open cgroup root")?;
    let sockops = skel
        .progs
        .erez_sockops
        .attach_cgroup(cgroup.as_raw_fd())
        .context("failed to attach erez_sockops to cgroup")?;

    let fib = Fib::from_map(&skel.maps.e_fib)?;
    let fib_collector = Fib::from_map(&skel.maps.e_fib)?;
    registry.register_collector(Box::new(fib_collector));
    let metrics = MetricsMap::from_map(&skel.maps.e_metrics, MetricsSet::Encap)?;
    registry.register_collector(Box::new(metrics));
    let tcp_rtt_events = TcpRttEvents::from_map(&skel.maps.e_tcp_rtt_events)?;

    Ok((
        EncapLinks { _sockops: sockops },
        EncapMaps {
            fib,
            tcp_rtt_events,
        },
    ))
}

pub fn attach_decap(iface: &Interface, registry: &mut Registry) -> anyhow::Result<()> {
    // Initialise the skeleton.
    let mut open_object = MaybeUninit::uninit();
    let skel = load_skel(&mut open_object)?;

    // Attach the program to the network interface on ingress.
    let xdp = Xdp::new(skel.progs.erez_decap.as_fd());
    xdp.attach(iface.index.get(), XdpFlags::empty())
        .with_context(|| format!("failed to attach xdp program to interface {}", iface.name))?;

    let metrics = MetricsMap::from_map(&skel.maps.e_metrics, MetricsSet::Decap)?;
    registry.register_collector(Box::new(metrics));

    Ok(())
}

/// Recreates a TC hook using libbpf constructs, this is useful for
/// cases where we don't have prior access to a libbpf_rs::TcHook,
/// but we still want to perform some action on it, e.g. detaching
/// the eBPF program from a specific interface.
fn reconstruct_tc_hook(iface: &Interface) -> (libbpf_sys::bpf_tc_hook, libbpf_sys::bpf_tc_opts) {
    let hook = libbpf_sys::bpf_tc_hook {
        sz: size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
        ifindex: iface.index.get(),
        attach_point: TC_EGRESS,
        ..libbpf_sys::bpf_tc_hook::default()
    };
    // If flags, prog_id, or prog_fd are non-zero, the kernel
    // errors (when detaching), so we don't specify them.
    let opts = libbpf_sys::bpf_tc_opts {
        sz: size_of::<libbpf_sys::bpf_tc_opts>() as libbpf_sys::size_t,
        handle: TC_HANDLE,
        priority: TC_PRIORITY,
        ..libbpf_sys::bpf_tc_opts::default()
    };

    (hook, opts)
}

pub fn detach(iface: &Interface) -> anyhow::Result<()> {
    let tc_result = detach_tc(iface);
    let xdp_result = detach_xdp(iface);

    // We only process results after trying to detach,
    // so that failure to detach one program type
    // does not affect others.
    tc_result?;
    xdp_result?;

    Ok(())
}

fn detach_tc(iface: &Interface) -> anyhow::Result<()> {
    let (tc_hook, tc_opts) = reconstruct_tc_hook(iface);
    let ret: i32 = unsafe { libbpf_sys::bpf_tc_detach(&raw const tc_hook, &raw const tc_opts) };
    if ret != 0 && !is_not_attached(ret) {
        anyhow::bail!(
            "bpf_tc_detach: {}",
            libbpf_rs::Error::from_raw_os_error(ret)
        )
    } else {
        Ok(())
    }
}

fn detach_xdp(iface: &Interface) -> anyhow::Result<()> {
    let xdp_flags = XdpFlags::empty().bits();
    let xdp_attach_opts = libbpf_sys::bpf_xdp_attach_opts {
        sz: size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t,
        ..libbpf_sys::bpf_xdp_attach_opts::default()
    };
    let ret: i32 = unsafe {
        libbpf_sys::bpf_xdp_detach(iface.index.get(), xdp_flags, &raw const xdp_attach_opts)
    };
    if ret != 0 && !is_not_attached(ret) {
        anyhow::bail!(
            "bpf_xdp_detach: {}",
            libbpf_rs::Error::from_raw_os_error(ret)
        )
    } else {
        Ok(())
    }
}

fn is_not_attached(ret: i32) -> bool {
    // For TC/XDP:
    //   - If the parent qdisc doesn't exist => -EINVAL
    //   - If the parent exists but the hook
    //     is not found in the filter chain  => -ENOENT
    matches!(Errno::from_raw(ret), Errno::EINVAL | Errno::ENOENT)
}

#[derive(Debug)]
pub struct TcpRttEvents(MapHandle);

impl TcpRttEvents {
    fn from_map(map: &libbpf_rs::MapMut<'_>) -> anyhow::Result<Self> {
        MapHandle::try_from(map)
            .map(TcpRttEvents)
            .context("failed to duplicate e_tcp_rtt_events map fd")
    }

    pub async fn poll<F>(self, token: CancellationToken, mut observe: F) -> anyhow::Result<()>
    where
        F: FnMut(CTcpRttEvent) -> anyhow::Result<()> + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let mut rb_builder = RingBufferBuilder::new();
            rb_builder
                .add(&self.0, move |data| {
                    match bytemuck::try_pod_read_unaligned::<CTcpRttEvent>(data) {
                        Ok(event) => {
                            if let Err(e) = observe(event) {
                                warn!(error = %format!("{e:#}"), "failed observing tcp rtt event");
                            }
                        }
                        Err(e) => warn!(error = ?e, "failed to deserialise tcp rtt event"),
                    }
                    0
                })
                .context("failed to add map and callback to ring buffer builder")?;
            let ringbuf = rb_builder.build().context("failed to build ring buffer")?;

            while !token.is_cancelled() {
                ringbuf
                    .poll(Duration::from_millis(100))
                    .context("failed to poll tcp rtt events ring buffer")?;
            }

            Ok(())
        })
        .await
        .context("tcp rtt events task panicked")?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightedNexthop {
    pub nexthop: IpAddr,
    pub weight: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FibEntry {
    nexthop_count: usize,
    nexthops: [IpAddr; MAX_NEXTHOPS],
    weights: [u16; MAX_NEXTHOPS],
}

impl FibEntry {
    pub fn new(mut nexthops: Vec<WeightedNexthop>) -> anyhow::Result<Self> {
        if nexthops.is_empty() {
            anyhow::bail!("fib entry requires at least one nexthop");
        }
        if nexthops.len() > MAX_NEXTHOPS {
            anyhow::bail!("fib entry has too many nexthops");
        }

        let weight_sum: u32 = nexthops
            .iter()
            .map(|weighted| u32::from(weighted.weight))
            .sum();
        if weight_sum != u32::from(WEIGHT_DENOMINATOR) {
            anyhow::bail!("fib entry weights must sum to {WEIGHT_DENOMINATOR}");
        }
        if nexthops.iter().any(|weighted| weighted.weight == 0) {
            anyhow::bail!("fib entry active nexthops must have non-zero weight");
        }

        // Sort nexthops so we route predictably.
        nexthops.sort_by_key(|weighted| CIpv6Addr::from(weighted.nexthop).octets);

        let mut packed_nexthops = [IpAddr::V6(Ipv6Addr::UNSPECIFIED); MAX_NEXTHOPS];
        let mut packed_weights = [0; MAX_NEXTHOPS];
        for (i, weighted) in nexthops.iter().enumerate() {
            packed_nexthops[i] = weighted.nexthop;
            packed_weights[i] = weighted.weight;
        }

        Ok(Self {
            nexthop_count: nexthops.len(),
            nexthops: packed_nexthops,
            weights: packed_weights,
        })
    }

    pub fn nexthops(&self) -> impl Iterator<Item = WeightedNexthop> + '_ {
        self.nexthops[..self.nexthop_count]
            .iter()
            .copied()
            .zip(self.weights[..self.nexthop_count].iter().copied())
            .map(|(nexthop, weight)| WeightedNexthop { nexthop, weight })
    }
}

#[derive(Debug)]
pub struct Fib(MapHandle);

impl Fib {
    fn from_map(map: &libbpf_rs::MapMut<'_>) -> anyhow::Result<Self> {
        MapHandle::try_from(map)
            .map(Fib)
            .context("failed to duplicate e_fib map fd")
    }

    pub fn insert(&self, nlri: IpNet, fib_entry: FibEntry) -> anyhow::Result<()> {
        let cnlri = CNlri::from(nlri);
        let cfib_entry = CFibEntry::new(
            nlri,
            fib_entry.nexthop_count,
            &fib_entry.nexthops,
            &fib_entry.weights,
        );

        self.0
            .update(
                bytemuck::bytes_of(&cnlri),
                bytemuck::bytes_of(&cfib_entry),
                MapFlags::empty(),
            )
            .context("failed to update e_fib")
    }

    pub fn delete(&self, nlri: IpNet) -> anyhow::Result<()> {
        let cnlri = CNlri::from(nlri);
        self.0
            .delete(bytemuck::bytes_of(&cnlri))
            .context("failed to delete from e_fib")
    }
}

impl Collector for Fib {
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> Result<(), fmt::Error> {
        let mut family_encoder = encoder.encode_descriptor(
            "erez_steering_nexthop_weight",
            "Current weight assigned to each nexthop in the steering FIB",
            None,
            ConstGauge::<u64>::TYPE,
        )?;

        for key in self.0.keys() {
            let cnlri = match bytemuck::try_pod_read_unaligned::<CNlri>(&key) {
                Ok(cnlri) => cnlri,
                Err(e) => {
                    warn!(error = ?e, "failed to parse fib key");
                    continue;
                }
            };
            let nlri = match IpNet::try_from(cnlri) {
                Ok(nlri) => nlri,
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "failed to convert fib cnlri");
                    continue;
                }
            };

            let value = match self.0.lookup(&key, MapFlags::empty()) {
                Ok(Some(value)) => value,
                Ok(None) => continue,
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "failed to lookup fib entry");
                    continue;
                }
            };
            let cfib = match bytemuck::try_pod_read_unaligned::<CFibEntry>(&value) {
                Ok(cfib) => cfib,
                Err(e) => {
                    warn!(error = ?e, "failed to parse fib entry");
                    continue;
                }
            };

            let count = (cfib.nexthop_count as usize).min(MAX_NEXTHOPS);
            let nlri_str = nlri.to_string();
            for i in 0..count {
                let nexthop = IpAddr::from(cfib.nexthops[i]);
                let nexthop_str = nexthop.to_string();
                let labels = [
                    ("nlri", nlri_str.as_str()),
                    ("nexthop", nexthop_str.as_str()),
                ];
                ConstGauge::new(u64::from(cfib.weights[i]))
                    .encode(family_encoder.encode_family(&labels)?)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct MetricsMap {
    map: MapHandle,
    // The eBPF map contains metrics for both the encapsulation and
    // decapsulation daemons, but we only expect one set of metrics
    // to be populated, so we restrict the set of collected metrics.
    families: &'static [BpfMetricFamily],
}

impl MetricsMap {
    fn from_map(map: &libbpf_rs::MapMut<'_>, set: MetricsSet) -> anyhow::Result<Self> {
        let families = match set {
            MetricsSet::Encap => ENCAP_METRIC_FAMILIES,
            MetricsSet::Decap => DECAP_METRIC_FAMILIES,
        };
        let map = MapHandle::try_from(map).context("failed to duplicate e_metrics map fd")?;
        Ok(Self { map, families })
    }

    pub fn read(&self) -> anyhow::Result<CEbpfMetrics> {
        let key = 0_u32.to_ne_bytes();
        let values = self
            .map
            .lookup_percpu(&key, MapFlags::empty())
            .context("failed to lookup e_metrics")?
            .context("e_metrics entry doesn't exist")?;

        let mut total = CEbpfMetrics::default();
        for value in values {
            let cpu_metrics = bytemuck::try_pod_read_unaligned::<CEbpfMetrics>(&value)
                .map_err(|e| anyhow::anyhow!("failed to deserialise e_metrics: {e:?}"))?;
            total += cpu_metrics;
        }
        Ok(total)
    }
}

impl Collector for MetricsMap {
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> Result<(), fmt::Error> {
        let metrics = match self.read() {
            Ok(metrics) => metrics,
            Err(error) => {
                warn!(error = %format!("{error:#}"), "failed reading ebpf metrics");
                return Err(fmt::Error);
            }
        };
        for family in self.families {
            encode_counter_family(&mut encoder, &metrics, family)?;
        }
        Ok(())
    }
}

fn encode_counter_family(
    encoder: &mut DescriptorEncoder<'_>,
    metrics: &CEbpfMetrics,
    family: &BpfMetricFamily,
) -> Result<(), fmt::Error> {
    let mut encoder =
        encoder.encode_descriptor(family.name, family.help, None, ConstCounter::<u64>::TYPE)?;

    let counters = metrics.as_counter_slice();
    for series in family.series {
        ConstCounter::new(counters[series.index]).encode(encoder.encode_family(&series.labels)?)?
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum MetricsSet {
    Encap,
    Decap,
}

#[derive(Debug)]
struct BpfMetricSeries {
    index: usize,
    labels: &'static [(&'static str, &'static str)],
}

#[derive(Debug)]
struct BpfMetricFamily {
    name: &'static str,
    help: &'static str,
    series: &'static [BpfMetricSeries],
}

const DECAP_METRIC_FAMILIES: &[BpfMetricFamily] = &[
    BpfMetricFamily {
        name: "erez_decap_decapsulated_packets",
        help: "Total number of packets successfully decapsulated by erez_decap",
        series: &[BpfMetricSeries {
            index: 0,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_decap_errors",
        help: "Total number of errors encountered by erez_decap",
        series: &[
            BpfMetricSeries {
                index: 1,
                labels: &[("reason", "decap-failed")],
            },
            BpfMetricSeries {
                index: 2,
                labels: &[("reason", "decrement-inner-ttl-failed")],
            },
            BpfMetricSeries {
                index: 3,
                labels: &[("reason", "fib-lookup-failed")],
            },
            BpfMetricSeries {
                index: 4,
                labels: &[("reason", "redirect-failed")],
            },
            BpfMetricSeries {
                index: 5,
                labels: &[("reason", "same-ifindex")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_decap_parse_errors",
        help: "Total number of parse errors encountered by erez_decap",
        series: &[BpfMetricSeries {
            index: 6,
            labels: &[("reason", "short-packet")],
        }],
    },
    BpfMetricFamily {
        name: "erez_decap_processed_packets",
        help: "Total number of packets processed by erez_decap",
        series: &[BpfMetricSeries {
            index: 7,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_decap_redirected_packets",
        help: "Total number of packets redirected by erez_decap",
        series: &[BpfMetricSeries {
            index: 8,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_decap_skipped_packets",
        help: "Total number of packets skipped by erez_decap",
        series: &[
            BpfMetricSeries {
                index: 9,
                labels: &[("reason", "unsupported-inner-l3-proto")],
            },
            BpfMetricSeries {
                index: 10,
                labels: &[("reason", "unsupported-outer-l3-proto")],
            },
            BpfMetricSeries {
                index: 11,
                labels: &[("reason", "unsupported-outer-l4-proto")],
            },
        ],
    },
];

const ENCAP_METRIC_FAMILIES: &[BpfMetricFamily] = &[
    BpfMetricFamily {
        name: "erez_encap_encapsulated_packets",
        help: "Total number of packets successfully encapsulated by erez_encap",
        series: &[BpfMetricSeries {
            index: 12,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_encap_errors",
        help: "Total number of errors encountered by erez_encap",
        series: &[BpfMetricSeries {
            index: 13,
            labels: &[("reason", "encap-failed")],
        }],
    },
    BpfMetricFamily {
        name: "erez_encap_fib_entry_validation_errors",
        help: "Total number of invalid FIB entries observed by erez_encap",
        series: &[
            BpfMetricSeries {
                index: 14,
                labels: &[("reason", "invalid-nexthop-count")],
            },
            BpfMetricSeries {
                index: 15,
                labels: &[("reason", "zero-weight")],
            },
            BpfMetricSeries {
                index: 16,
                labels: &[("reason", "invalid-weight-sum")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_encap_fib_hits",
        help: "Total number of e_fib hits encountered by erez_encap",
        series: &[BpfMetricSeries {
            index: 17,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_encap_fib_misses",
        help: "Total number of e_fib misses encountered by erez_encap",
        series: &[BpfMetricSeries {
            index: 18,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_encap_parse_errors",
        help: "Total number of parse errors encountered by erez_encap",
        series: &[
            BpfMetricSeries {
                index: 19,
                labels: &[("reason", "dest-nlri-load")],
            },
            BpfMetricSeries {
                index: 20,
                labels: &[("reason", "l4-proto-load")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_encap_processed_packets",
        help: "Total number of packets processed by erez_encap",
        series: &[BpfMetricSeries {
            index: 21,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_encap_skipped_packets",
        help: "Total number of packets skipped by erez_encap",
        series: &[
            BpfMetricSeries {
                index: 22,
                labels: &[("reason", "unsupported-l3-proto")],
            },
            BpfMetricSeries {
                index: 23,
                labels: &[("reason", "unsupported-l4-proto")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_encap_sticky_nexthop",
        help: "Total number of sticky nexthop lookups and stores by erez_encap",
        series: &[
            BpfMetricSeries {
                index: 24,
                labels: &[("result", "hit")],
            },
            BpfMetricSeries {
                index: 25,
                labels: &[("result", "miss")],
            },
            BpfMetricSeries {
                index: 26,
                labels: &[("result", "store")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_sockops_rtt_callback_registrations",
        help: "Total number of RTT callback registration attempts by erez_sockops",
        series: &[
            BpfMetricSeries {
                index: 27,
                labels: &[("result", "success")],
            },
            BpfMetricSeries {
                index: 28,
                labels: &[("result", "failed")],
            },
        ],
    },
    BpfMetricFamily {
        name: "erez_sockops_rtt_callbacks",
        help: "Total number of RTT callbacks processed by erez_sockops",
        series: &[BpfMetricSeries {
            index: 29,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_sockops_rtt_events",
        help: "Total number of RTT events emitted by erez_sockops",
        series: &[BpfMetricSeries {
            index: 30,
            labels: &[],
        }],
    },
    BpfMetricFamily {
        name: "erez_sockops_rtt_event_drops",
        help: "Total number of RTT events dropped by erez_sockops",
        series: &[BpfMetricSeries {
            index: 31,
            labels: &[("reason", "ringbuf-full")],
        }],
    },
    BpfMetricFamily {
        name: "erez_sockops_rtt_skipped",
        help: "Total number of RTT callbacks skipped by erez_sockops",
        series: &[
            BpfMetricSeries {
                index: 32,
                labels: &[("reason", "sticky-nexthop-miss")],
            },
            BpfMetricSeries {
                index: 33,
                labels: &[("reason", "unsupported-family")],
            },
        ],
    },
];
