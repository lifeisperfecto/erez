use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use prometheus_client::registry::Registry;
use tokio_util::sync::CancellationToken;

use erez_test::{
    ns::{self, NsChild},
    repl,
    topology::{self, Edge, LinkImpairment, Metal, Router, Transit},
    traffic_gen::{Generator, Sink},
};
use erezd::config::{
    BgpConfig, DecapConfig, EbpfConfig, EncapConfig, LoggingConfig, MetricsConfig,
};

const EREZD_BIN: &str = concat!(env!("CARGO_TARGET_DIR"), "/debug/erezd");
const EREZD_BGP_PORT: u16 = 1179; // Can't be 179 which is already in use.

#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Log level for erezd processes.
    #[arg(long, env = "EREZD_LOG", default_value = "INFO")]
    erezd_log_level: String,

    /// Run without an interactive REPL, waiting for a signal to exit.
    #[arg(long, env = "NO_REPL")]
    no_repl: bool,

    /// Run without the traffic generator.
    #[arg(long, env = "NO_TRAFFIC")]
    no_traffic: bool,
}

fn main() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("Lab must be run as root");
        std::process::exit(1);
    }

    let args = Args::parse();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        ns::cleanup_netns().await?;

        if !args.no_repl {
            ns::set_stderr_suppressed(true);
            println!("Loading lab...");
        }

        run(&args).await?;

        if !args.no_repl {
            println!("Exited REPL!");
        }

        Ok(())
    })
}

// ┌───────────┐                               ┌───────────┐
// │           │                               │ Transit A │
// │  Metal 1  │────┐                     ┌────│           │────┐
// │           │    │    ┌───────────┐    │    │ ASN 64512 │    │    ┌───────────┐    ┌───────────┐
// └───────────┘    │    │   Edge    │    │    └───────────┘    │    │  Origin   │    │           │
//                  ├────│           │────┤                     ├────│           │────│   Metal   │
// ┌───────────┐    │    │ ASN 4181  │    │    ┌───────────┐    │    │ ASN 64514 │    │           │
// │           │    │    └───────────┘    │    │ Transit B │    │    └───────────┘    └───────────┘
// │  Metal 2  │────┘          │          └────│           │────┘          │
// │           │                               │ ASN 64513 │
// └───────────┘          172.16.0.0/24        └───────────┘          10.41.0.0/24
//                      3ffff:172:16::/64                           3ffff:10:41::/64
async fn run(args: &Args) -> anyhow::Result<()> {
    let mut edge = Router::<Edge>::new(
        "edge",
        4181,
        "172.16.0.0/24".parse()?,
        "3fff:172:16::/64".parse()?,
        &[("erezd", EREZD_BGP_PORT)],
    )
    .await?;
    let edge_metal_1 = edge.add_metal("edge_metal_1").await?;
    let edge_metal_2 = edge.add_metal("edge_metal_2").await?;

    // Raise the MTU internally so encapsulated full-size
    // packets which end up being larger than 1500 bytes
    // aren't dropped. This is like simulating jumbo
    // packets inside a data centre.
    edge.kind.interface.bridge.set_mtu(1600).await?;
    edge_metal_1.set_uplink_mtu(1600).await?;
    edge_metal_2.set_uplink_mtu(1600).await?;

    // With GSO enabled, the kernel generates super-packets which are
    // supposed to be segmented when they hit the NIC (veth device in
    // our case).
    //
    // Veth devices have an exemption, where the kernel will punt the
    // super-packet between veth pairs if it's marked as GSO. For XDP
    // this exemption is not implemented, so when super-packets are
    // redirected, they're dropped because they exceed the MTU limit.
    //
    // Presumably, if we redirected from TC this exemption would apply
    // and everyone would be happy and we would be able to send packets
    // between veth pairs.
    //
    // Anyways, due to this we disable GSO.
    edge_metal_1.disable_uplink_offloads().await?;
    edge_metal_2.disable_uplink_offloads().await?;

    let mut origin_edge = Router::<Edge>::new(
        "origin_edge",
        64514,
        "10.41.0.0/24".parse()?,
        "3fff:10:41::/64".parse()?,
        &[],
    )
    .await?;
    let origin_metal = origin_edge.add_metal("origin_metal").await?;

    let mut transit_a = Router::<Transit>::new("transit_a", 64512).await?;
    let mut transit_b = Router::<Transit>::new("transit_b", 64513).await?;
    topology::peer(&mut edge, &mut transit_a).await?;
    let transit_a_upstream = topology::peer(&mut transit_a, &mut origin_edge).await?;
    transit_a_upstream
        .device
        .impair(LinkImpairment {
            delay_ms: 1,
            rate_kbit: 9_000, // 9 Mbps.
        })
        .await?;

    topology::peer(&mut edge, &mut transit_b).await?;
    let transit_b_upstream = topology::peer(&mut transit_b, &mut origin_edge).await?;
    transit_b_upstream
        .device
        .impair(LinkImpairment {
            delay_ms: 100,
            rate_kbit: 1_000_000_000, // Effectively infinite.
        })
        .await?;

    let _edge_metal_1_encap = run_erez_encap(&edge_metal_1, &edge, &args.erezd_log_level).await?;
    let _edge_metal_2_encap = run_erez_encap(&edge_metal_2, &edge, &args.erezd_log_level).await?;
    let _edge_decap = run_erez_decap(&edge, &args.erezd_log_level).await?;

    if !args.no_traffic {
        let mut registry = Registry::default();

        let tsink = Sink::run(&origin_metal.ns, origin_metal.sitelocal_v4.addr().into())
            .await
            .unwrap();
        let tgen = Generator::run(
            &edge_metal_1.ns,
            tsink.addr,
            100,
            Duration::from_secs(5),
            &mut registry,
        )
        .await
        .unwrap();

        // Spawn this in the same namespace as the generator.
        edge_metal_1
            .ns
            .spawn(async move {
                let token = CancellationToken::new();
                tokio::spawn(erez_lib::metrics::serve(
                    SocketAddr::from(([0, 0, 0, 0], 9101)),
                    registry,
                    token,
                ));
            })
            .await?;

        tokio::spawn(async move {
            // 5 Mbps to 15 Mbps and back over two minutes.
            tgen.oscillate_rate(5000, 15000, Duration::from_secs(120))
                .await;
        });
    }

    if args.no_repl {
        erez_lib::signal::shutdown_signal().await;
    } else {
        repl::run(&[
            &edge.bird.ns,
            &edge_metal_1.ns,
            &edge_metal_1.bird.ns,
            &edge_metal_2.ns,
            &edge_metal_2.bird.ns,
            &origin_edge.bird.ns,
            &origin_metal.ns,
            &origin_metal.bird.ns,
            &transit_a.bird.ns,
            &transit_b.bird.ns,
        ])?;
    }

    Ok(())
}

async fn run_erez_encap(
    metal: &Metal,
    edge: &Router<Edge>,
    log_level: &str,
) -> anyhow::Result<NsChild> {
    let config = EncapConfig {
        bgp: BgpConfig {
            asn: edge.bird.asn,
            bgp_id: metal.sitelocal_v4.addr(),
            peer_ips: vec![edge.kind.interface.bridge.link_local],
            port: EREZD_BGP_PORT,
            interface: Some(metal.uplink.clone()),
        },
        ebpf: EbpfConfig {
            interface: metal.uplink.clone(),
        },
        logging: LoggingConfig {
            level: log_level.to_string(),
        },
        metrics: MetricsConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9100)),
        },
    };
    let encap_toml = toml::to_string(&config)?;
    metal
        .ns
        .spawn(async { tokio::fs::write("/tmp/encap.toml", encap_toml).await })
        .await??;
    let encap = metal
        .ns
        .spawn_process(EREZD_BIN, &["encap", "--config", "/tmp/encap.toml"])
        .await?;
    Ok(encap)
}

async fn run_erez_decap(edge: &Router<Edge>, log_level: &str) -> anyhow::Result<NsChild> {
    let config = DecapConfig {
        ebpf: EbpfConfig {
            interface: edge.kind.interface.bridge.name.clone(),
        },
        logging: LoggingConfig {
            level: log_level.to_string(),
        },
        metrics: MetricsConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 9100)),
        },
    };
    let decap_toml = toml::to_string(&config)?;
    edge.ns
        .spawn(async { tokio::fs::write("/tmp/decap.toml", decap_toml).await })
        .await??;
    let decap = edge
        .ns
        .spawn_process(EREZD_BIN, &["decap", "--config", "/tmp/decap.toml"])
        .await?;
    Ok(decap)
}
