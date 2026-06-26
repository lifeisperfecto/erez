use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Context;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::fs;

pub async fn from_path<T: DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let str = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file: {path}"))?;
    let config = toml::from_str(&str)
        .with_context(|| format!("failed to deserialise config from file: {path}"))?;

    Ok(config)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncapConfig {
    pub bgp: BgpConfig,
    pub ebpf: EbpfConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecapConfig {
    pub ebpf: EbpfConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BgpConfig {
    /// ASN of the AS that we're running in.
    pub asn: u32,
    /// Our BGP ID.
    pub bgp_id: Ipv4Addr,
    /// IPv6 addresses of the peers that we establish BGP sessions with.
    pub peer_ips: Vec<Ipv6Addr>,
    /// BGP port used for both binding locally and connecting to peers.
    #[serde(default = "default_bgp_port")]
    pub port: u16,
    /// Network interface name for link-local peer scoping.
    pub interface: Option<String>,
}

fn default_bgp_port() -> u16 {
    179
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EbpfConfig {
    /// Name of the network interface the eBPF program will bind to.
    pub interface: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// One of ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"].
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_log_level() -> String {
    "INFO".into()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Address serving Prometheus metrics.
    #[serde(default = "default_metrics_listen_addr")]
    pub listen_addr: SocketAddr,
}

fn default_metrics_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9100))
}
