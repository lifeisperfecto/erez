use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use ratelimit::{Ratelimiter, TryWaitError};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::ns::Ns;

/// TCP server that discards data.
pub struct Sink {
    pub addr: SocketAddr,
    cancel: CancellationToken, // Fire-and-forget cancellation to keep it simple.
}

impl Sink {
    pub async fn run(ns: &Ns, addr: IpAddr) -> anyhow::Result<Self> {
        ns.spawn(async move {
            let listener = TcpListener::bind((addr, 0)).await?;
            let addr = listener.local_addr()?;
            let cancel = CancellationToken::new();
            let cancel2 = cancel.clone();
            tokio::spawn(async move {
                loop {
                    if cancel2.is_cancelled() {
                        return;
                    }
                    let Ok((mut stream, _)) = listener.accept().await else {
                        continue;
                    };
                    tokio::spawn(async move {
                        // Discard all data instead so the traffic generator
                        // doesn't need to care about draining the receive
                        // buffer.
                        let (mut reader, _) = stream.split();
                        let mut discard = tokio::io::sink();
                        let _ = tokio::io::copy(&mut reader, &mut discard).await;
                    });
                }
            });
            Ok::<_, anyhow::Error>(Self { addr, cancel })
        })
        .await?
    }

    pub async fn stop(self) {
        self.cancel.cancel();
    }
}

pub const CHUNK_SIZE_BYTES: usize = 50 * 1000 / 8; // 50 Kbps.

pub struct Generator {
    limiter: Arc<Ratelimiter>,
    rate_gauge: Gauge,
    cancel: CancellationToken, // Fire-and-forget cancellation to keep it simple.
}

impl Generator {
    pub async fn run(
        ns: &Ns,
        target: SocketAddr,
        flow_concurrency: usize,
        flow_duration: Duration,
        registry: &mut Registry,
    ) -> anyhow::Result<Self> {
        let rate_gauge = Gauge::<i64>::default();
        registry.register(
            "traffic_generator_rate_kbps",
            "Current traffic generator rate in kbit/s",
            rate_gauge.clone(),
        );

        ns.spawn(async move {
            let limiter = Arc::new(
                Ratelimiter::builder(250 * 1000 / 8) // 250 Kbps.
                    .period(Duration::from_secs(1))
                    .build()?,
            );
            let cancel = CancellationToken::new();

            for i in 0..flow_concurrency {
                let limiter = Arc::clone(&limiter);
                let cancel = cancel.clone();

                let stagger = flow_duration * i as u32 / flow_concurrency as u32;
                tokio::spawn(async move {
                    tokio::time::sleep(stagger).await;
                    loop {
                        if cancel.is_cancelled() {
                            return;
                        }
                        match TcpStream::connect(&target).await {
                            Ok(mut stream) => {
                                let _ = tokio::time::timeout(
                                    flow_duration,
                                    send_traffic(&mut stream, &limiter),
                                )
                                .await;
                            }
                            Err(_) => {
                                // Try again.
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                });
            }

            Ok::<_, anyhow::Error>(Generator {
                limiter,
                rate_gauge,
                cancel,
            })
        })
        .await?
    }

    pub async fn stop(self) {
        self.cancel.cancel();
    }

    pub fn update_rate(&self, kbits_per_sec: u64) {
        self.limiter.set_rate(kbits_per_sec * 1000 / 8);
        self.rate_gauge.set(kbits_per_sec as i64);
    }

    pub async fn oscillate_rate(&self, low_kbps: u64, high_kbps: u64, period: Duration) {
        let mid = (low_kbps + high_kbps) as f64 / 2.0;
        let amp = (high_kbps - low_kbps) as f64 / 2.0;
        let tick = Duration::from_millis(25);
        let start = tokio::time::Instant::now();

        loop {
            let t = start.elapsed().as_secs_f64();
            // Shift by π/2 so we start at the low point.
            let phase =
                2.0 * std::f64::consts::PI * t / period.as_secs_f64() - std::f64::consts::FRAC_PI_2;
            let rate = mid + amp * phase.sin();
            self.update_rate(rate as u64);
            tokio::time::sleep(tick).await;
        }
    }
}

async fn send_traffic(stream: &mut TcpStream, limiter: &Ratelimiter) -> std::io::Result<()> {
    let payload = vec![0u8; CHUNK_SIZE_BYTES];

    loop {
        loop {
            match limiter.try_wait_n(CHUNK_SIZE_BYTES as u64) {
                Ok(()) => break,
                Err(TryWaitError::Insufficient(wait)) => tokio::time::sleep(wait).await,
                Err(_) => unreachable!(), // The limiter is configured in a way where it can never serve traffic.
            };
        }

        stream.write_all(&payload).await?;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        netlink::Netlink,
        topology::{VethPair, VethPlacement},
    };

    use super::*;

    /// Samples are in Kbps.
    async fn measure_tx_samples(ns: &Ns, iface: String, seconds: usize) -> Vec<f64> {
        ns.spawn(async move {
            let nl = Netlink::connect().unwrap();
            let mut samples = Vec::with_capacity(seconds);
            let mut prev = nl.link_get_stats(&iface).await.unwrap();

            for _ in 0..seconds {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let curr = nl.link_get_stats(&iface).await.unwrap();
                let tx_delta_bytes = curr.tx_bytes.saturating_sub(prev.tx_bytes);
                let tx_delta_kbps = tx_delta_bytes as f64 * 8.0 / 1_000.0;
                eprintln!("Mbps: {}", tx_delta_kbps / 1000.0);
                samples.push(tx_delta_kbps as f64);
                prev = curr;
            }

            samples
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn generate_constant_rate() {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();

        let net = "192.168.0.2/24".parse().unwrap();
        let link = VethPair::new(
            VethPlacement::Addr(ns_a.clone(), "192.168.0.1/24".parse().unwrap()),
            VethPlacement::Addr(ns_b.clone(), net),
        )
        .await
        .unwrap();

        let tsink = Sink::run(&ns_b, net.addr()).await.unwrap();
        let tgen = Generator::run(
            &ns_a,
            tsink.addr,
            1,
            Duration::from_secs(5),
            &mut Registry::default(),
        )
        .await
        .unwrap();

        let cases = [
            250,        // 250 Kbps.
            1000,       // 1 Mbps.
            5 * 1000,   // 5 Mbps.
            10 * 1000,  // 10 Mbps.
            100 * 1000, // 100 Mbps.
        ];
        for target in cases {
            let tolerance = target as f64 * 0.1; // 10% tolerance.
            tgen.update_rate(target);
            let samples = measure_tx_samples(&ns_a, link.device.name.clone(), 10).await;
            for sample in &samples {
                let lo = target as f64 - tolerance;
                let hi = target as f64 + tolerance;
                assert!(
                    lo <= *sample && *sample <= hi,
                    "sampled rate was {sample} Kbps, expected {target} Kbps (±{tolerance} Kbps)",
                );
            }
        }
    }

    #[tokio::test]
    async fn generate_oscillated_rate() {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();

        let net = "192.168.0.2/24".parse().unwrap();
        let link = VethPair::new(
            VethPlacement::Addr(ns_a.clone(), "192.168.0.1/24".parse().unwrap()),
            VethPlacement::Addr(ns_b.clone(), net),
        )
        .await
        .unwrap();

        let tsink = Sink::run(&ns_b, net.addr()).await.unwrap();
        let tgen = Generator::run(
            &ns_a,
            tsink.addr,
            1,
            Duration::from_secs(5),
            &mut Registry::default(),
        )
        .await
        .unwrap();

        let samples = tokio::select! {
            _ = tgen.oscillate_rate(500, 1500, Duration::from_secs(30)) => unreachable!(),
            samples = measure_tx_samples(&ns_a, link.device.name.clone(), 30) => samples,
        };

        // Precomputed sine wave over 30 seconds.
        #[rustfmt::skip]
        let expected: [f64; 30] = [
             502.7,  524.5,  567.0,  628.4,  706.1,
             796.6,  896.0, 1000.0, 1104.0, 1203.4,
            1293.9, 1371.6, 1433.0, 1475.5, 1497.3,
            1497.3, 1475.5, 1433.0, 1371.6, 1293.9,
            1203.4, 1104.0, 1000.0,  896.0,  796.6,
             706.1,  628.4,  567.0,  524.5,  502.7,
        ];

        let tolerance_kbps = 150.0;
        for (i, (sample, expected)) in samples.iter().zip(&expected).enumerate() {
            assert!(
                (sample - expected).abs() <= tolerance_kbps,
                "sample {i}: got {sample:.1} Kbps, expected {expected:.1} Kbps (±{tolerance_kbps} Kbps)",
            );
        }
    }
}
