use std::num::NonZeroI32;

use anyhow::Context;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: NonZeroI32,
}

impl Interface {
    pub fn lookup(name: &str) -> anyhow::Result<Self> {
        let ifaces = NetworkInterface::show().context("failed listing interfaces")?;
        let iface = ifaces
            .into_iter()
            .find(|iface| iface.name == name)
            .with_context(|| format!("interface not found: {name}"))?;

        // We parse to i32 because the libbpf function calls we
        // execute require the index as this type; it's easier
        // to force this failure here so we don't have to deal
        // with it later.
        let index = i32::try_from(iface.index)
            .with_context(|| format!("failed parsing interface index: {}", iface.index))?;
        let index =
            NonZeroI32::new(index).with_context(|| format!("interface {name} has zero index"))?;
        Ok(Interface {
            name: iface.name,
            index,
        })
    }
}
