//! ospfd — the Rouster OSPF daemon (Phase 3, W2-e).
//!
//! Thin shell in the bgpd/savd shape: config load, the interface
//! sockets (raw IP proto 89, §A.1), the zapi edge when the config
//! names a socket, then the daemon run loop with SIGTERM/SIGINT
//! shutdown.
//!
//! Usage: `ospfd --config <PATH>`.

use std::sync::Arc;

use ospfd::config::{parse as parse_config, AddressFamily};
use ospfd::daemon::{self, Ospfd};
use ospfd::daemon_v3::{self, OspfdV3};
use ospfd::transport::{OspfRawSocket, OspfV6RawSocket};
use ospfd::zedge;
use tracing::{error, info};

fn main() {
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
                println!("usage: ospfd --config <PATH>");
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
            eprintln!("ospfd: cannot read {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };
    let mut config = match parse_config(&text) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("ospfd: {e}");
            std::process::exit(1);
        }
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        // The zapi edge (optional): the interface dump FIRST — the
        // merged live addresses/link-state are the core's construction
        // input (ADD-C2) — then the resident edge on the same session.
        let (pushed_tx, pushed_rx) = tokio::sync::mpsc::unbounded_channel();
        let (withdrawn_tx, withdrawn_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut zapi_client = None;
        if let Some(socket) = &config.zapi_socket {
            let mut client = match zedge::connect(std::path::Path::new(socket)).await {
                Ok(client) => client,
                Err(e) => {
                    error!(error = %e, "ospfd: zapi edge failed");
                    std::process::exit(1);
                }
            };
            // The v4 interface dump (ADD-C2); the v6 runtime's
            // link-local source is the static `link-local` line (the
            // dump's v6 merge is §Deferred, see ospf.md).
            if config.family == AddressFamily::Ipv4 {
                let dump = match ospfd::ifdump::sync(&mut client).await {
                    Ok(dump) => dump,
                    Err(e) => {
                        error!(error = %e, "ospfd: zapi interface dump failed");
                        std::process::exit(1);
                    }
                };
                let report = dump.merge_into(&mut config);
                info!(
                    dynamic = report.dynamic_address,
                    fallback = report.static_fallback,
                    down = report.down,
                    "ospfd: interface config merged with the zapi dump"
                );
            }
            zapi_client = Some(client);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {}
                _ = sigint.recv() => {}
            }
            let _ = shutdown_tx.send(true);
        });

        // The family fork (S7-a): `address-family ipv6-unicast` runs
        // the OSPFv3 core over the v6 transport; the default is the
        // v2 daemon unchanged.
        if config.family == AddressFamily::Ipv6 {
            let mut core = match OspfdV3::new(&config) {
                Ok(core) => core,
                Err(e) => {
                    error!("ospfd(v3): {e}");
                    std::process::exit(1);
                }
            };
            let mut sockets = Vec::new();
            for iface in &core.interfaces {
                match OspfV6RawSocket::open(iface.link_local, iface.ifindex) {
                    Ok(sock) => {
                        info!(
                            iface = %iface.name,
                            link_local = %iface.link_local,
                            ifindex = iface.ifindex,
                            instance_id = iface.instance_id,
                            "ospfd(v3): raw v6 socket open"
                        );
                        sockets.push(Arc::new(sock));
                    }
                    Err(e) => {
                        error!(iface = %iface.name, error = %e, "ospfd(v3): cannot open raw v6 socket");
                        std::process::exit(1);
                    }
                }
            }
            if let Some(client) = zapi_client {
                match zedge::spawn_with_client(
                    client,
                    config.redistribute_static,
                    AddressFamily::Ipv6,
                    pushed_tx.clone(),
                    withdrawn_tx.clone(),
                )
                .await
                {
                    Ok(tx) => core.attach_zapi(tx),
                    Err(e) => {
                        error!(error = %e, "ospfd(v3): zapi edge failed");
                        std::process::exit(1);
                    }
                }
            }
            drop(pushed_tx);
            drop(withdrawn_tx);
            if let Err(e) =
                daemon_v3::run(core, sockets, pushed_rx, withdrawn_rx, shutdown_rx).await
            {
                error!(error = %e, "ospfd(v3): run loop exited");
                std::process::exit(1);
            }
            info!("ospfd(v3): stopped");
            return;
        }

        let mut core = match Ospfd::new(&config) {
            Ok(core) => core,
            Err(e) => {
                error!("ospfd: {e}");
                std::process::exit(1);
            }
        };

        // §A.1 sockets: one per configured interface, opened on the
        // (merged) interface address.
        let mut sockets = Vec::new();
        for iface in &core.interfaces {
            match OspfRawSocket::open(iface.addr) {
                Ok(sock) => {
                    info!(iface = %iface.name, addr = %iface.addr, "ospfd: raw socket open");
                    sockets.push(Arc::new(sock));
                }
                Err(e) => {
                    error!(iface = %iface.name, error = %e, "ospfd: cannot open raw socket");
                    std::process::exit(1);
                }
            }
        }

        // The resident edge on the dump's session (route export +
        // redistribute static pushes).
        if let Some(client) = zapi_client {
            match zedge::spawn_with_client(
                client,
                config.redistribute_static,
                AddressFamily::Ipv4,
                pushed_tx.clone(),
                withdrawn_tx.clone(),
            )
            .await
            {
                Ok(tx) => core.attach_zapi(tx),
                Err(e) => {
                    error!(error = %e, "ospfd: zapi edge failed");
                    std::process::exit(1);
                }
            }
        }
        drop(pushed_tx);
        drop(withdrawn_tx);

        if let Err(e) = daemon::run(core, sockets, pushed_rx, withdrawn_rx, shutdown_rx).await {
            error!(error = %e, "ospfd: run loop exited");
            std::process::exit(1);
        }
        info!("ospfd: stopped");
    });
}
