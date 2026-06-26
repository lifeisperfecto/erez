use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use anyhow::Context;
use ipnet::IpNet;
use netgauze_bgp_pkt::{
    capabilities::{
        AddPathAddressFamily, AddPathCapability, BgpCapability, MultiProtocolExtensionsCapability,
    },
    nlri::{Ipv4UnicastAddress, Ipv6UnicastAddress},
    path_attribute::{MpReach, MpUnreach, PathAttributeValue},
    update::BgpUpdateMessage,
};
use netgauze_bgp_speaker::{
    connection::TcpActiveConnect,
    events::{BgpEvent, UpdateTreatment},
    fsm::{FsmState, FsmStateError},
    listener::BgpListener,
    peer::{EchoCapabilitiesPolicy, PeerConfigBuilder, PeerProperties},
    supervisor::PeersSupervisor,
};
use netgauze_iana::address_family::AddressType;
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedReceiver},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{config::BgpConfig, interface::Interface};

/// This is a thin wrapper over `netgauze-bgp-speaker`.
pub struct Speaker {
    // Speaker configuration.
    config: BgpConfig,
    /// Send updates about NLRIs via these channels.
    subscribers: Vec<mpsc::Sender<Update>>,
    /// Manages the state of all known peers (including our own).
    supervisor: PeersSupervisor<IpAddr, SocketAddr, TcpStream>,
    /// Listener solely handles incoming BGP connections
    /// and hands these off to the supervisor to manage.
    listener: BgpListener<SocketAddr, TcpStream>,
    /// Cancellation token for graceful shutdown.
    token: CancellationToken,
}

impl Speaker {
    pub fn new(config: BgpConfig, token: CancellationToken) -> Self {
        let supervisor = PeersSupervisor::new(config.asn, config.bgp_id);
        let port = config.port;

        Self {
            config,
            supervisor,
            subscribers: vec![],
            listener: BgpListener::new(
                vec![SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    port,
                    0,
                    0,
                ))],
                false,
            ),
            token,
        }
    }

    // Subscribe to BGP updates.
    pub fn subscribe(&mut self) -> mpsc::Receiver<Update> {
        let (tx, rx) = mpsc::channel(32);
        self.subscribers.push(tx);
        rx
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        // Link-local addresses are scoped to an interface, so we need the
        // interface index to correctly address peers on the same link.
        let scope_id = if let Some(iface) = &self.config.interface {
            Interface::lookup(iface)?.index.cast_unsigned().get()
        } else {
            0
        };
        // Register all the peers so the listener peers with them and
        // receives BGP updates when we run it.
        let peer_ips = self.config.peer_ips.clone();
        let port = self.config.port;
        for ip in peer_ips {
            self.add_peer(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))?;
        }

        tokio::select! {
            () = self.token.cancelled() => {}
            result = self.listener.run(&mut self.supervisor) => {
                result.context("failed to run bgp listener")?;
            }
        }
        info!("bgp speaker finished running");
        Ok(())
    }

    fn add_peer(&mut self, addr: SocketAddr) -> anyhow::Result<()> {
        let config = PeerConfigBuilder::new()
            .open_delay_timer_duration(5)
            .build();
        // We are parroting the default config value which
        // is itself stored as u16, so no truncation is
        // possible.
        let hold_timer_duration = config.hold_timer_duration_large_value().as_secs() as u16;
        let policy = EchoCapabilitiesPolicy::new(
            self.config.asn,
            true,
            self.config.bgp_id,
            hold_timer_duration,
            vec![
                BgpCapability::AddPath(AddPathCapability::new(vec![
                    AddPathAddressFamily::new(AddressType::Ipv4Unicast, false, true),
                    AddPathAddressFamily::new(AddressType::Ipv6Unicast, false, true),
                ])),
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv4Unicast,
                )),
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv6Unicast,
                )),
            ],
            vec![],
        );
        let properties = PeerProperties::new(
            self.config.asn,
            self.config.asn,
            self.config.bgp_id,
            addr,
            true,
        );

        // A bunch of the netgauze errors don't actually implement
        // std::error::Error, so we construct errors manually.
        let (peer_states_rx, peer_handle) = self
            .supervisor
            .create_peer(addr.ip(), properties, config, TcpActiveConnect, policy)
            .map_err(|e| anyhow::anyhow!("failed to create peer {}: {e:?}", addr.ip()))?;
        peer_handle
            .start()
            .map_err(|e| anyhow::anyhow!("failed to start peer {}: {e:?}", addr.ip()))?;
        self.listener.reg_peer(addr.ip(), peer_handle);

        tokio::spawn({
            let subscribers = self.subscribers.clone();
            async move { process_bgp_updates(addr.ip(), peer_states_rx, subscribers).await }
        });

        Ok(())
    }
}

pub type Nexthop = IpAddr;

pub type Nlri = IpNet;

pub type PathId = Option<u32>;

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Route {
    pub path_id: PathId,
    pub nlri: Nlri,
}

impl From<&Ipv4UnicastAddress> for Route {
    fn from(nlri: &Ipv4UnicastAddress) -> Self {
        Self {
            path_id: nlri.path_id(),
            nlri: IpNet::V4(nlri.network().address()),
        }
    }
}

impl From<&Ipv6UnicastAddress> for Route {
    fn from(nlri: &Ipv6UnicastAddress) -> Self {
        Self {
            path_id: nlri.path_id(),
            nlri: IpNet::V6(nlri.network().address()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Announcement {
    pub routes: Vec<Route>,
    pub nexthop: Nexthop,
}

#[derive(Debug, Clone)]
pub struct Update {
    // We may have multiple NLRIs announced for different
    // nexthops (due to MP-BGP), but this isn't the case
    // for withdrawals, so we don't need a "nested" vec.
    pub announcements: Vec<Announcement>,
    pub withdrawals: Vec<Route>,
}

impl TryFrom<BgpUpdateMessage> for Update {
    type Error = anyhow::Error;

    fn try_from(msg: BgpUpdateMessage) -> std::result::Result<Self, Self::Error> {
        let mut announcements: Vec<Announcement> = vec![];
        let mut withdrawals: Vec<Route> = vec![];

        // Prefer globally scoped MP-BGP nexthops. Link-local nexthops require
        // interface scope, which is not communicated to encapsulation daemons.

        // IPv4 advertised using "legacy" BGP.
        if !msg.nlri().is_empty() {
            let nexthop = msg
                .path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::NextHop(nh) => Some(IpAddr::V4(nh.next_hop())),
                    _ => None,
                })
                .context("bgp update missing nexthop")?;
            announcements.push(Announcement {
                routes: msg.nlri().iter().map(Route::from).collect(),
                nexthop,
            });
        }

        // IPv4 withdrawn using "legacy" BGP.
        if !msg.withdraw_routes().is_empty() {
            withdrawals.extend(msg.withdraw_routes().iter().map(Route::from));
        }

        // IPv4 advertised using MP-BGP.
        if let Some(MpReach::Ipv4Unicast { next_hop, nlri, .. }) = msg
            .path_attributes()
            .iter()
            .find_map(|attr| match attr.value() {
                PathAttributeValue::MpReach(reach) => Some(reach),
                _ => None,
            })
        {
            announcements.push(Announcement {
                routes: nlri.iter().map(Route::from).collect(),
                nexthop: *next_hop,
            });
        }

        // IPv4 withdrawn using MP-BGP.
        if let Some(MpUnreach::Ipv4Unicast { nlri }) =
            msg.path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::MpUnreach(unreach) => Some(unreach),
                    _ => None,
                })
        {
            withdrawals.extend(nlri.iter().map(Route::from));
        }

        // IPv6 advertised using MP-BGP.
        if let Some(MpReach::Ipv6Unicast {
            next_hop_global,
            nlri,
            ..
        }) = msg
            .path_attributes()
            .iter()
            .find_map(|attr| match attr.value() {
                PathAttributeValue::MpReach(reach) => Some(reach),
                _ => None,
            })
        {
            announcements.push(Announcement {
                routes: nlri.iter().map(Route::from).collect(),
                nexthop: IpAddr::V6(*next_hop_global),
            });
        }

        // IPv6 withdrawn using MP-BGP.
        if let Some(MpUnreach::Ipv6Unicast { nlri }) =
            msg.path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::MpUnreach(unreach) => Some(unreach),
                    _ => None,
                })
        {
            withdrawals.extend(nlri.iter().map(Route::from));
        }

        Ok(Self {
            announcements,
            withdrawals,
        })
    }
}

// Filter out BGP updates for a specific peer and emit
// them from the speaker via an update channel.
#[allow(clippy::type_complexity)]
#[tracing::instrument(skip_all, fields(peer = %peer_address))]
async fn process_bgp_updates(
    peer_address: IpAddr,
    mut fsm_state_rx: UnboundedReceiver<
        std::result::Result<(FsmState, BgpEvent<SocketAddr>), FsmStateError<SocketAddr>>,
    >,
    subscribers: Vec<mpsc::Sender<Update>>,
) {
    use netgauze_bgp_speaker::events::BgpEvent as E;
    use netgauze_bgp_speaker::fsm::FsmState as S;

    while let Some(event) = fsm_state_rx.recv().await {
        match event {
            Ok((S::Established, E::UpdateMsg(msg, treatment))) => {
                if treatment != UpdateTreatment::Normal {
                    warn!(?treatment, "skipping bgp update message, invalid treatment");
                    continue;
                }

                let update = match Update::try_from(msg) {
                    Ok(update) => update,
                    Err(e) => {
                        warn!(error = %format!("{e:#}"), "failed parsing bgp update message");
                        continue;
                    }
                };
                debug!(?update, "bgp update");
                for tx in &subscribers {
                    let _ = tx.send(update.clone()).await;
                }
            }
            Ok(event) => {
                debug!(?event, "bgp event");
            }
            Err(e) => {
                // Explicitly drop before the scope ends so the
                // log definitely fires after all subscribers
                // are dropped.
                for tx in subscribers {
                    drop(tx)
                }
                error!(error = %format!("{e:#}"), "fsm failed, handling stopped");
                return;
            }
        }
    }
}
