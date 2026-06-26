use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use ipnet::IpNet;
use nix::{
    sys::time::TimeValLike,
    time::{ClockId, clock_gettime},
};
use prometheus_client::{
    collector::Collector,
    encoding::{DescriptorEncoder, EncodeMetric},
    metrics::{TypedMetric, gauge::ConstGauge},
    registry::Registry,
};
use tokio_util::sync::CancellationToken;

use crate::{
    bgp::{Nexthop, Nlri},
    bpf,
    bpf_abi::CTcpRttEvent,
};

/// Time in nanoseconds after which we drop samples.
const AGGREGATION_WINDOW_NS: u64 = 10 * 1_000_000_000; // 10 seconds.

#[derive(Clone, Debug)]
pub struct TcpRttAggregator {
    inner: Arc<Mutex<TcpRttAggregatorState>>,
}

impl TcpRttAggregator {
    pub fn new(registry: &mut Registry) -> Self {
        let aggregator = Self {
            inner: Arc::new(Mutex::new(TcpRttAggregatorState::default())),
        };
        registry.register_collector(Box::new(aggregator.clone()));
        aggregator
    }

    pub async fn run(
        self,
        events: bpf::TcpRttEvents,
        token: CancellationToken,
    ) -> anyhow::Result<()> {
        events.poll(token, move |event| self.observe(event)).await
    }

    pub fn snapshot(&self) -> anyhow::Result<TcpRttSnapshot> {
        let now_ns = monotonic_now_ns()?;
        let mut state = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("tcp rtt aggregator lock poisoned: {e}"))?;
        state.prune(now_ns);

        let windows = state
            .samples
            .iter()
            .map(|(&nlri, samples_by_nexthop)| {
                let windows_by_nexthop = samples_by_nexthop
                    .iter()
                    .map(|(&nexthop, samples)| (nexthop, TcpRttWindow::from_samples(samples)))
                    .collect();
                (nlri, windows_by_nexthop)
            })
            .collect();
        Ok(TcpRttSnapshot { windows })
    }

    fn observe(&self, event: CTcpRttEvent) -> anyhow::Result<()> {
        // We only want to keep a 10 second sliding window,
        // so let's ignore older events which are useless.
        let now_ns = monotonic_now_ns()?;
        if now_ns.saturating_sub(event.ts_ns) > AGGREGATION_WINDOW_NS {
            return Ok(());
        }

        let mut state = self
            .inner
            .lock()
            .map_err(|e| anyhow::anyhow!("tcp rtt aggregator lock poisoned: {e}"))?;
        state.prune(now_ns);

        let nlri = IpNet::try_from(event.matched_nlri).context("failed parsing matched cnlri")?;
        let nexthop = event.nexthop.into();
        state
            .samples
            .entry(nlri)
            .or_default()
            .entry(nexthop)
            .or_default()
            .push_back(TcpRttSample {
                ts_ns: event.ts_ns,
                srtt_us: event.srtt_us,
                rtt_min: event.rtt_min,
            });
        Ok(())
    }
}

impl Collector for TcpRttAggregator {
    fn encode(&self, mut encoder: DescriptorEncoder<'_>) -> Result<(), std::fmt::Error> {
        let snapshot = self.snapshot().map_err(|_| std::fmt::Error)?;

        // Helper function so we can avoid nested flatmap boilerplate.
        fn get_samples(
            snapshot: &TcpRttSnapshot,
            extractor: fn(&TcpRttWindow) -> u64,
        ) -> impl Iterator<Item = (String, String, u64)> {
            snapshot.windows.iter().flat_map(move |(nlri, nexthops)| {
                nexthops.iter().map(move |(nexthop, window)| {
                    (nlri.to_string(), nexthop.to_string(), extractor(window))
                })
            })
        }

        encode_gauge_family(
            &mut encoder,
            "erez_tcp_rtt_window_samples",
            "Number of TCP RTT samples in the current aggregation window",
            get_samples(&snapshot, |w| w.samples as u64),
        )?;
        encode_gauge_family(
            &mut encoder,
            "erez_tcp_rtt_window_srtt_us_avg",
            "Average smoothed TCP RTT in the current aggregation window",
            get_samples(&snapshot, |w| w.avg_srtt_us),
        )?;
        encode_gauge_family(
            &mut encoder,
            "erez_tcp_rtt_window_srtt_us_max",
            "Maximum smoothed TCP RTT in the current aggregation window",
            get_samples(&snapshot, |w| w.max_srtt_us as u64),
        )?;
        encode_gauge_family(
            &mut encoder,
            "erez_tcp_rtt_window_rtt_min_us_min",
            "Minimum TCP RTT minimum in the current aggregation window",
            get_samples(&snapshot, |w| w.min_rtt_min as u64),
        )?;
        Ok(())
    }
}

fn encode_gauge_family(
    encoder: &mut DescriptorEncoder<'_>,
    name: &'static str,
    help: &'static str,
    samples: impl IntoIterator<Item = (String, String, u64)>,
) -> Result<(), std::fmt::Error> {
    let mut family_encoder =
        encoder.encode_descriptor(name, help, None, ConstGauge::<u64>::TYPE)?;

    for (nlri, nexthop, value) in samples {
        let labels = [("nlri", nlri.as_str()), ("nexthop", nexthop.as_str())];
        let gauge_encoder = family_encoder.encode_family(&labels)?;
        ConstGauge::new(value).encode(gauge_encoder)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct TcpRttAggregatorState {
    samples: HashMap<Nlri, HashMap<Nexthop, VecDeque<TcpRttSample>>>,
}

impl TcpRttAggregatorState {
    fn prune(&mut self, now_ns: u64) {
        self.samples.retain(|_, samples_by_nexthop| {
            samples_by_nexthop.retain(|_, samples| {
                samples
                    .retain(|sample| now_ns.saturating_sub(sample.ts_ns) <= AGGREGATION_WINDOW_NS);
                !samples.is_empty()
            });
            !samples_by_nexthop.is_empty()
        });
    }
}

#[derive(Clone, Debug, Default)]
pub struct TcpRttSnapshot {
    pub windows: HashMap<Nlri, HashMap<Nexthop, TcpRttWindow>>,
}

// A window is a summarised view for samples from an NLRI/nexthop pair.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpRttWindow {
    pub samples: usize,
    pub avg_srtt_us: u64,
    pub max_srtt_us: u32,
    pub min_rtt_min: u32,
}

impl TcpRttWindow {
    fn from_samples(samples: &VecDeque<TcpRttSample>) -> Self {
        // Avoid division by zero errors.
        if samples.is_empty() {
            return Self::default();
        }

        let srtt_sum: u64 = samples.iter().map(|sample| u64::from(sample.srtt_us)).sum();
        let max_srtt_us = samples
            .iter()
            .map(|sample| sample.srtt_us)
            .max()
            .unwrap_or_default();
        let min_rtt_min = samples
            .iter()
            .map(|sample| sample.rtt_min)
            .min()
            .unwrap_or_default();

        Self {
            samples: samples.len(),
            avg_srtt_us: srtt_sum / samples.len() as u64,
            max_srtt_us,
            min_rtt_min,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TcpRttSample {
    ts_ns: u64,
    srtt_us: u32,
    rtt_min: u32,
}

fn monotonic_now_ns() -> anyhow::Result<u64> {
    // eBPF timestamps use the monotonic clock,
    // so we match it instead of system time.
    let now_ns = u64::try_from(
        clock_gettime(ClockId::CLOCK_MONOTONIC)
            .context("failed to read monotonic clock")?
            .num_nanoseconds(),
    )
    .context("monotonic clock returned a negative timestamp")?;
    Ok(now_ns)
}
