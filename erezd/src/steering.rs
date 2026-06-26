use std::collections::HashMap;
use std::time::Duration;

use ipnet::IpNet;
use tokio::{sync::mpsc::Receiver, time};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::bgp::{self};
use crate::bpf;
use crate::rtt_aggregation::TcpRttAggregator;

pub struct Controller {
    /// Input stream of BGP updates that mutate the RIB.
    bgp_updates_rx: Receiver<bgp::Update>,
    /// eBPF FIB map updated with selected nexthop weights.
    fib: bpf::Fib,
    /// Active BGP nexthops keyed by NLRI.
    rib: Rib,
    /// Recent TCP RTT windows used to score nexthops.
    rtt_aggregator: TcpRttAggregator,
    /// Stores gradients we use to manipulate weights.
    descent: descent::Descent,
    /// Cancels the controller event loop.
    shutdown: CancellationToken,
}

impl Controller {
    pub fn new(
        updates_rx: Receiver<bgp::Update>,
        fib: bpf::Fib,
        rtt_aggregator: TcpRttAggregator,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            bgp_updates_rx: updates_rx,
            fib,
            rib: Rib::default(),
            rtt_aggregator,
            shutdown,
            descent: descent::Descent::default(),
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut steering_tick = time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                _ = steering_tick.tick() => {
                    self.steer_fib()
                }
                update = self.bgp_updates_rx.recv() => {
                    let Some(update) = update else {
                        info!("bgp channel closed, shutting down");
                        break;
                    };

                    // Update the RIB with the routes we learnt from the update.
                    for announcement in &update.announcements {
                        for route in &announcement.routes {
                            self.rib.insert(route, &announcement.nexthop);
                            self.update_fib(route.nlri);
                        }
                    }
                    for route in &update.withdrawals {
                        self.rib.remove(route);
                        self.update_fib(route.nlri);
                    }
                }
            }
        }

        info!("controller finished running");
        Ok(())
    }

    fn update_fib(&self, nlri: IpNet) {
        let nexthops = self.rib.nexthops(&nlri);
        let res = match balance_equally(nexthops) {
            Ok(Some(fib_entry)) => self.fib.insert(nlri, fib_entry),
            Ok(None) => self.fib.delete(nlri),
            Err(e) => Err(e),
        };
        if let Err(e) = res {
            warn!(error = %format!("{e:#}"), "failed updating fib entry")
        }
    }

    fn steer_fib(&mut self) {
        let snapshot = match self.rtt_aggregator.snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "failed snapshotting tcp rtt");
                return;
            }
        };

        let nlris: Vec<_> = self.rib.nlris().collect();
        for nlri in nlris {
            // Not great practice, but this is just an MVP, so
            // let's silently ignore cases where we have too
            // many nexthops.
            let nexthops: Vec<_> = self
                .rib
                .nexthops(&nlri)
                .into_iter()
                .take(bpf::MAX_NEXTHOPS)
                .collect();

            let res = match self.descent.step(nlri, &nexthops, &snapshot) {
                Some(weighted) => match bpf::FibEntry::new(weighted) {
                    Ok(entry) => self.fib.insert(nlri, entry),
                    Err(e) => Err(e),
                },
                None => self.fib.delete(nlri),
            };
            if let Err(e) = res {
                warn!(error = %format!("{e:#}"), "failed updating fib entry");
            }
        }
    }
}

#[derive(Default)]
pub struct Rib {
    table: HashMap<bgp::Nlri, Vec<(bgp::PathId, bgp::Nexthop)>>,
}

impl Rib {
    pub fn insert(&mut self, route: &bgp::Route, nexthop: &bgp::Nexthop) {
        let entries = self.table.entry(route.nlri).or_default();
        entries.retain(|&(path_id, _)| path_id != route.path_id);
        entries.push((route.path_id, *nexthop));
    }

    pub fn remove(&mut self, route: &bgp::Route) {
        let Some(entries) = self.table.get_mut(&route.nlri) else {
            return;
        };
        entries.retain(|&(path_id, _)| route.path_id != path_id);
        if entries.is_empty() {
            self.table.remove(&route.nlri);
        }
    }

    pub fn nlris(&self) -> impl Iterator<Item = bgp::Nlri> {
        self.table.keys().copied()
    }

    pub fn nexthops(&self, nlri: &IpNet) -> impl Iterator<Item = bgp::Nexthop> {
        self.table
            .get(nlri)
            .into_iter()
            .flat_map(|paths| paths.iter().map(|(_, nexthop)| *nexthop))
    }
}

fn balance_equally(
    nexthops: impl IntoIterator<Item = bgp::Nexthop>,
) -> anyhow::Result<Option<bpf::FibEntry>> {
    // Not great practice, but this is just an MVP, so
    // let's silently ignore cases where we have too
    // many nexthops.
    let nexthops: Vec<_> = nexthops.into_iter().take(bpf::MAX_NEXTHOPS).collect();
    if nexthops.is_empty() {
        return Ok(None);
    }

    // The remainder is spread across the nexthops, first to last.
    let base_weight = bpf::WEIGHT_DENOMINATOR / nexthops.len() as u16;
    let remainder = usize::from(bpf::WEIGHT_DENOMINATOR % nexthops.len() as u16);

    let weighted = nexthops
        .into_iter()
        .enumerate()
        .map(|(i, nexthop)| bpf::WeightedNexthop {
            nexthop,
            weight: base_weight + u16::from(i < remainder),
        })
        .collect();
    let fib_entry = bpf::FibEntry::new(weighted)?;
    Ok(Some(fib_entry))
}

/// Based on "Projected Online Gradient Descent" from https://arxiv.org/pdf/1912.13213.
mod descent {
    use std::collections::HashMap;

    use crate::{
        bgp, bpf,
        rtt_aggregation::{TcpRttSnapshot, TcpRttWindow},
    };

    /// Step-size, controls how aggresively weights are updated
    /// based on the gradient. It's set to small because the
    /// gradient function isn't normalised against weights, we
    /// just see a "pure" latency cost.
    const LEARNING_RATE: f64 = 0.00000005;
    /// Minimum fraction of traffic assigned to any nexthop (1%).
    /// Ensures every nexthop is probed so we can observe its cost.
    const MINIMUM_WEIGHT: f64 = 0.01;

    #[derive(Default)]
    pub struct Descent {
        weights: HashMap<bgp::Nlri, HashMap<bgp::Nexthop, f64>>,
    }

    impl Descent {
        pub fn step(
            &mut self,
            nlri: bgp::Nlri,
            nexthops: &[bgp::Nexthop],
            snapshot: &TcpRttSnapshot,
        ) -> Option<Vec<bpf::WeightedNexthop>> {
            if nexthops.is_empty() {
                self.weights.remove(&nlri);
                return None;
            }

            // We initialise/remove new/old weights and redistribute capacity
            // as-needed.
            let nlri_weights = self.weights.entry(nlri).or_default();
            reconcile(nlri_weights, &nexthops);

            // Our loss function is the weighted average for incurred latency
            // and congestion.
            //
            // Formally, it's something like: ℓ(w) = Σ w_i · cost_i. The thing
            // is, when we derive this function, the differentiation drops the
            // w_i terms, since there's a linear relationship between weights
            // and cost.
            //
            // To calculate the gradient vector we just take the cost for each
            // nexthop, i.e g = [cost_1, cost_2, cost_3, ..., cost_n].
            let windows = snapshot.windows.get(&nlri);
            let g: Vec<Option<f64>> = nexthops
                .iter()
                .map(|nh| windows.and_then(|ws| ws.get(nh)).map(|win| gradient(win)))
                .collect();

            // Update weights based on the gradient vector.
            for (nh, g_i) in nexthops.iter().zip(&g) {
                let Some(w_i) = nlri_weights.get_mut(nh) else {
                    // If we reconciled correctly, this shouldn't happen.
                    continue;
                };
                match g_i {
                    Some(g_i) => *w_i -= LEARNING_RATE * g_i,
                    // If we have no RTT data for a nexthop, we can't reason
                    // about it, so we relegate it to the floor weight.
                    None => *w_i = MINIMUM_WEIGHT,
                }
            }

            // After the gradient step, weights may be negative or not sum
            // to one. This finds the closest valid point for each weight.
            project(nlri_weights);

            // Distribute these weights across our denominator.
            Some(quantise(nlri_weights))
        }
    }

    // AKA the cost, see above for an explanation.
    fn gradient(win: &TcpRttWindow) -> f64 {
        let latency = win.avg_srtt_us as f64;
        let congestion = win.avg_srtt_us.saturating_sub(u64::from(win.min_rtt_min)) as f64;
        latency + congestion
    }

    fn reconcile(weights: &mut HashMap<bgp::Nexthop, f64>, nexthops: &[bgp::Nexthop]) {
        let changed =
            weights.len() != nexthops.len() || nexthops.iter().any(|nh| !weights.contains_key(nh));
        if changed {
            // Instead of resetting on change, it would be better to redistribute weight
            // proportionally, so (1) remove departed nexthops and scale survivors to
            // absorb freed weight, or (2) give new nexthops MINIMUM_WEIGHT  deducted
            // from active nexthops.
            weights.clear();
            let uniform = 1.0 / nexthops.len() as f64;
            for &nh in nexthops {
                weights.insert(nh, uniform);
            }
        }
    }

    fn project(weights: &mut HashMap<bgp::Nexthop, f64>) {
        let n = weights.len() as f64;
        let r = 1.0 - n * MINIMUM_WEIGHT;

        // Projection assumes the lower bound is zero,
        // so we need to adjust the weights for this.
        let mut v: Vec<f64> = weights.values().map(|w| w - MINIMUM_WEIGHT).collect();

        // Find a threshold tau, that can be subtracted from every
        // number so that all numbers which remain above zero sum
        // to r. We want to find tau such at most numbers survive
        // instead of being clamped to the floor.
        //
        // We explore largest values first, as if a larger value
        // won't survive clamping, smaller values won't either.
        v.sort_by(|a, b| b.total_cmp(a));
        let mut cumsum = 0.0;
        let mut tau = 0.0;
        for (k, &v_k) in v.iter().enumerate() {
            cumsum += v_k;
            let candidate = (cumsum - r) / (k + 1) as f64;
            if v_k - candidate > 0.0 {
                tau = candidate;
            }
        }

        // Apply threshold, clamp to zero, and shift by the floor.
        for w in weights.values_mut() {
            *w = (*w - MINIMUM_WEIGHT - tau).max(0.0) + MINIMUM_WEIGHT;
        }
    }

    fn quantise(weights: &HashMap<bgp::Nexthop, f64>) -> Vec<bpf::WeightedNexthop> {
        let denominator = f64::from(bpf::WEIGHT_DENOMINATOR);

        // Floor each weight and track the fractional remainder.
        let mut entries: Vec<(bgp::Nexthop, u16, f64)> = weights
            .iter()
            .map(|(&nexthop, &w)| {
                let scaled = w * denominator;
                let floor = scaled as u16;
                (nexthop, floor, scaled - f64::from(floor))
            })
            .collect();

        // The floors might sum to less than 10,000 due to truncation.
        let allocated: u16 = entries.iter().map(|(_, floor, _)| floor).sum();
        let leftover = bpf::WEIGHT_DENOMINATOR - allocated;
        debug_assert!(leftover <= entries.len() as u16);

        // Give +1 to the nexthops with the largest remainders.
        entries.sort_by(|(_, _, a), (_, _, b)| b.total_cmp(a));
        for (_, weight, _) in entries.iter_mut().take(leftover as usize) {
            *weight += 1;
        }

        entries
            .into_iter()
            .map(|(nexthop, weight, _)| bpf::WeightedNexthop { nexthop, weight })
            .collect()
    }
}
