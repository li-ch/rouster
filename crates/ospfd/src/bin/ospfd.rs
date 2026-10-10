//! ospfd — the Rouster OSPF daemon (Phase 3, W2-e).
//!
//! Thin shell in the bgpd/savd shape: config load, the interface
//! sockets (raw IP proto 89, §A.1), the zapi edge when the config
//! names a socket, then the daemon run loop with SIGTERM/SIGINT
//! shutdown.
//!
//! Usage: `ospfd --config <PATH>`.

use std::sync::Arc;

use ospfd::config::parse as parse_config;
use ospfd::daemon::{self, Ospfd};
use ospfd::transport::OspfRawSocket;
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
    let config = match parse_config(&text) {
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
        let mut core = match Ospfd::new(&config) {
            Ok(core) => core,
            Err(e) => {
                error!("ospfd: {e}");
                std::process::exit(1);
            }
        };

        // §A.1 sockets: one per configured interface, opened on the
        // config-supplied address.
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

        // The zapi edge (optional): route export + redistribute
        // static pushes.
        let (pushed_tx, pushed_rx) = tokio::sync::mpsc::unbounded_channel();
        let (withdrawn_tx, withdrawn_rx) = tokio::sync::mpsc::unbounded_channel();
        if let Some(socket) = &config.zapi_socket {
            match zedge::spawn(
                socket.clone().into(),
                config.redistribute_static,
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

        if let Err(e) = daemon::run(core, sockets, pushed_rx, withdrawn_rx, shutdown_rx).await {
            error!(error = %e, "ospfd: run loop exited");
            std::process::exit(1);
        }
        info!("ospfd: stopped");
    });
}
