use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};

use erez_lib::metrics;
use erezd::{
    bgp,
    bpf::{self},
    config::{self, DecapConfig, EncapConfig},
    interface::Interface,
    logging, rtt_aggregation, steering,
};
use prometheus_client::registry::Registry;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run the encapsulation daemon.
    Encap {
        /// Path to the config file.
        #[arg(long, default_value_t = String::from("config.toml"))]
        config: String,
    },
    /// Run the decapsulation daemon.
    Decap {
        /// Path to the config file.
        #[arg(long, default_value_t = String::from("config.toml"))]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Encap { config } => {
            let config: EncapConfig = config::from_path(&config).await?;
            logging::init(&config.logging.level)?;
            info!(?config, "loaded config");

            let token = CancellationToken::new();
            let mut registry = Registry::default();

            let mut speaker = bgp::Speaker::new(config.bgp, token.clone());
            let iface = Interface::lookup(&config.ebpf.interface)?;
            // Keep the sockops link alive until the daemon exits.
            let (_encap_links, encap_maps) =
                bpf::attach_encap(&iface, &mut registry).context("failed attaching erez_encap")?;
            let rtt_aggregator = rtt_aggregation::TcpRttAggregator::new(&mut registry);
            let controller = steering::Controller::new(
                speaker.subscribe(),
                encap_maps.fib,
                rtt_aggregator.clone(),
                token.clone(),
            );

            let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
            join_set.spawn(metrics::serve(
                config.metrics.listen_addr,
                registry,
                token.clone(),
            ));
            join_set.spawn(rtt_aggregator.run(encap_maps.tcp_rtt_events, token.clone()));
            join_set.spawn(speaker.run());
            join_set.spawn(controller.run());

            graceful_shutdown(&iface, join_set, token).await?;
        }
        Commands::Decap { config } => {
            let config: DecapConfig = config::from_path(&config).await?;
            logging::init(&config.logging.level)?;
            info!(?config, "loaded config");

            let token = CancellationToken::new();
            let mut registry = Registry::default();

            let iface = Interface::lookup(&config.ebpf.interface)?;
            bpf::attach_decap(&iface, &mut registry).context("failed attaching erez_decap")?;

            let mut join_set: JoinSet<anyhow::Result<()>> = JoinSet::new();
            join_set.spawn(metrics::serve(
                config.metrics.listen_addr,
                registry,
                token.clone(),
            ));

            graceful_shutdown(&iface, join_set, token).await?;
        }
    }

    Ok(())
}

async fn graceful_shutdown(
    iface: &Interface,
    mut join_set: JoinSet<anyhow::Result<()>>,
    token: CancellationToken,
) -> anyhow::Result<()> {
    tokio::select! {
        _ = erez_lib::signal::shutdown_signal() => {
            info!("received signal, shutting down");
        }
        Some(result) = join_set.join_next() => {
            if let Ok(Err(e)) = result {
                error!(error = %format!("{e:#}"), "task failed, shutting down");
            }
        }
    }

    bpf::detach(iface).context("failed to detach erez programs")?;
    info!("detached erez programs");

    token.cancel();
    info!("draining tasks");
    tokio::select! {
        _ = join_set.join_all() => {
            info!("all tasks finished");
        }
        () = tokio::time::sleep(Duration::from_secs(30)) => {
            warn!("shutdown timed out, some tasks did not finish");
        }
    }

    info!("shut down");
    Ok(())
}
