//! isisd — the Rouster IS-IS daemon (Phase 5 opener, S10-a).
//!
//! Thin shell in the ospfd shape: config load, the one p2p circuit's
//! raw 0x00FE socket (Linux), the zapi edge when the config names a
//! socket, then the daemon run loop with SIGTERM/SIGINT shutdown.
//!
//! Usage: `isisd --config <PATH>`.

#[cfg(target_os = "linux")]
mod linux_main {
    use isisd::config::parse as parse_config;
    use isisd::daemon::{self, Daemon, Event};
    use isisd::pdu::Pdu;
    use isisd::transport::{IsisPacketSocket, Mac};
    use isisd::zedge;
    use tokio::sync::mpsc;
    use tracing::{error, info};

    pub fn main() {
        let mut config_path = None;
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--config" | "-f" => {
                    config_path = Some(
                        it.next()
                            .map(std::path::PathBuf::from)
                            .expect("--config requires a path"),
                    );
                }
                "--help" | "-h" => {
                    println!("usage: isisd --config <PATH>");
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument `{other}`");
                    std::process::exit(2);
                }
            }
        }
        let config_path = config_path.expect("missing --config <PATH>");
        let _ = tracing_subscriber::fmt().try_init();

        let text = match std::fs::read_to_string(&config_path) {
            Ok(text) => text,
            Err(e) => {
                eprintln!("isisd: cannot read {}: {e}", config_path.display());
                std::process::exit(1);
            }
        };
        let config = match parse_config(&text) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("isisd: {e}");
                std::process::exit(1);
            }
        };
        let iface = config.interface.name.clone();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async move {
        let mut core = match Daemon::new(config) {
            Ok(core) => core,
            Err(e) => {
                error!("isisd: {e}");
                std::process::exit(1);
            }
        };

        // The one circuit's raw socket (TX side lives in its own task
        // below; the handle is cloneable only by fd-dup plumbing, so
        // RX owns it and TX goes through the channel).
        let socket = match IsisPacketSocket::open(&iface) {
            Ok(socket) => socket,
            Err(e) => {
                error!(iface = %iface, error = %e, "isisd: cannot open raw 0x00FE socket");
                std::process::exit(1);
            }
        };
        info!(iface = %iface, mac = %socket.our_mac(), "isisd: raw 0x00FE socket open");

        // Events in (PDUs from the wire, redistribute pushes).
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // The zapi edge (optional).
        if let Some(socket_path) = core.config_ref().zapi_socket.clone() {
            let (pushed_tx, mut pushed_rx) = mpsc::unbounded_channel();
            let (withdrawn_tx, mut withdrawn_rx) = mpsc::unbounded_channel();
            match zedge::spawn(
                socket_path.into(),
                core.config_ref().redistribute_static,
                pushed_tx,
                withdrawn_tx,
            )
            .await
            {
                Ok(tx) => core.attach_zapi(tx),
                Err(e) => {
                    error!(error = %e, "isisd: zapi edge failed");
                    std::process::exit(1);
                }
            }
            let feed_tx = event_tx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        route = pushed_rx.recv() => match route {
                            Some(route) => { let _ = feed_tx.send(redistribute_event(&route, true)); }
                            None => break,
                        },
                        route = withdrawn_rx.recv() => match route {
                            Some(route) => { let _ = feed_tx.send(redistribute_event(&route, false)); }
                            None => break,
                        },
                    }
                }
            });
        }

        // The TX-side clone (taken before the RX pump owns the
        // original).
        let tx_socket = socket.clone();

        // The RX pump: frames -> PDUs -> events.
        let rx_tx = event_tx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 9000];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(n) => {
                        if let Some(frame) = isisd::transport::parse_frame(&buf[..n]) {
                            if let Ok(pdu) = Pdu::decode(frame.payload) {
                                let _ = rx_tx.send(Event::Pdu(pdu));
                            } else {
                                tracing::debug!("isisd: undecodable PDU on the wire (dropped)");
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "isisd: socket recv failed");
                        break;
                    }
                }
            }
        });

        // The TX pump: daemon outputs -> frames (level multicast
        // destinations; the p2p wire form) through a clone of the
        // circuit socket.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Pdu>();
        tokio::spawn(async move {
            while let Some(pdu) = out_rx.recv().await {
                let level2 = pdu.level().has_level2();
                let bytes = pdu.encode();
                if let Err(e) = tx_socket.send(Mac::for_level(level2), &bytes).await {
                    error!(error = %e, "isisd: socket send failed");
                }
            }
        });

        drop(event_tx);
        if let Err(e) = daemon::run(core, event_rx, move |pdu| {
            let _ = out_tx.send(pdu);
        })
        .await
        {
            error!(error = %e, "isisd: run loop exited");
            std::process::exit(1);
        }
        info!("isisd: stopped");
    });
    }

    fn redistribute_event(route: &zedge::RedistributedRoute, add: bool) -> Event {
        let prefix = match route.prefix {
            common::IpPrefix::V4(p) => (p.addr(), p.prefix_len()),
            common::IpPrefix::V6(_) => {
                // v4-only v1; v6 redistributions are not ours.
                return Event::Redistributed {
                    prefix: (std::net::Ipv4Addr::UNSPECIFIED, 255),
                    add: false,
                };
            }
        };
        Event::Redistributed { prefix, add }
    }
} // mod linux_main

#[cfg(target_os = "linux")]
fn main() {
    linux_main::main()
}

/// The raw 0x00FE transport is AF_PACKET (Linux); every other host
/// gets the honest refusal — the wire proof runs in the container
/// leg (the ospfd raw-socket precedent: cfg-gated, EPERM-skipping).
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "isisd: the raw ethertype-0x00FE transport is Linux-only (AF_PACKET); \
run the container interop leg (scripts/test-isis-frr-interop.sh)"
    );
    std::process::exit(1);
}
