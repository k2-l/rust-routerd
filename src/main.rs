mod access;
mod api;
mod assets;
mod auth;
mod error;
mod openwrt;
mod state;
mod tls;
mod util;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Extension;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

use crate::state::{AppState, PeerAddr};

struct Args {
    http: String,
    https: String,
    no_tls: bool,
    sim: bool,
    data_dir: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        http: "0.0.0.0:80".into(),
        https: "0.0.0.0:443".into(),
        no_tls: false,
        sim: std::env::var("ROUTERD_SIM").map(|v| v == "1").unwrap_or(false),
        data_dir: "/etc/routerd".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--http" => args.http = it.next().unwrap_or_default(),
            "--https" => args.https = it.next().unwrap_or_default(),
            "--data-dir" => args.data_dir = it.next().unwrap_or_default(),
            "--no-tls" => args.no_tls = true,
            "--sim" => args.sim = true,
            "--version" | "-V" => {
                println!("routerd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "routerd {}\n\nUSAGE:\n  routerd [--http 0.0.0.0:80] [--https 0.0.0.0:443]\n          [--data-dir /etc/routerd] [--no-tls]",
                    env!("CARGO_PKG_VERSION")
                );
                std::process::exit(0);
            }
            other => eprintln!("routerd: unknown argument {other}"),
        }
    }
    args
}

async fn serve_plain(
    listener: TcpListener,
    app: Router,
    permits: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                let Ok(permit) = permits.clone().acquire_owned().await else { break };
                let app = app.clone().layer(Extension(PeerAddr(peer.ip())));
                tokio::spawn(async move {
                    let _permit = permit;
                    let io = TokioIo::new(stream);
                    let service = TowerToHyperService::new(app);
                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new());
                    builder.http1().header_read_timeout(Duration::from_secs(15));
                    let conn = builder.serve_connection_with_upgrades(io, service);
                    if let Err(e) = conn.await {
                        tracing::debug!("http connection error: {e}");
                    }
                });
            }
        }
    }
}

async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    permits: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else { continue };
                let Ok(permit) = permits.clone().acquire_owned().await else { break };
                let acceptor = acceptor.clone();
                let app = app.clone().layer(Extension(PeerAddr(peer.ip())));
                tokio::spawn(async move {
                    let _permit = permit;
                    let tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::debug!("tls handshake failed from {peer}: {e}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls);
                    let service = TowerToHyperService::new(app);
                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new());
                    builder.http1().header_read_timeout(Duration::from_secs(15));
                    let conn = builder.serve_connection_with_upgrades(io, service);
                    if let Err(e) = conn.await {
                        tracing::debug!("https connection error: {e}");
                    }
                });
            }
        }
    }
}

fn install_rustls() {
    // rustls 0.23 requires an explicit process-level crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let filter = EnvFilter::try_from_env("ROUTERD_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    install_rustls();
    let _ = std::fs::create_dir_all(&args.data_dir);

    // Bind before building the app so the TLS state is final in AppState.
    let http_listener = match TcpListener::bind(&args.http).await {
        Ok(l) => Some(l),
        Err(e) => {
            tracing::error!("cannot bind HTTP {}: {e}", args.http);
            None
        }
    };

    let mut https_listener = None;
    if !args.no_tls {
        match TcpListener::bind(&args.https).await {
            Ok(l) => https_listener = Some(l),
            Err(e) => tracing::error!("cannot bind HTTPS {}: {e}", args.https),
        }
    }

    let mut tls_acceptor = None;
    if https_listener.is_some() {
        match tls::load_or_generate(&args.data_dir, &openwrt::sys::hostname()) {
            Ok((cert, key)) => match tls::server_config(&cert, &key) {
                Ok(cfg) => tls_acceptor = Some(TlsAcceptor::from(cfg)),
                Err(e) => tracing::error!("TLS config failed: {e:#}"),
            },
            Err(e) => tracing::error!("certificate setup failed: {e:#}"),
        }
    }
    let tls_active = tls_acceptor.is_some();

    let state = AppState::new(args.data_dir.clone(), tls_active, args.sim);
    openwrt::sys::spawn_sampler(state.history.clone());
    {
        let sessions = state.sessions.clone();
        let attempts = state.attempts.clone();
        let agent_rate = state.agent_rate.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                auth::cleanup(&sessions);
                attempts.cleanup(Duration::from_secs(900));
                agent_rate.cleanup();
            }
        });
    }
    {
        let access = state.access.clone();
        let data_dir = state.data_dir.clone();
        let sim = state.sim;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let access = access.clone();
                let data_dir = data_dir.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let mut store = access.write().unwrap();
                    let changed = store.scan();
                    if changed {
                        let _ = store.save(&format!("{data_dir}/access.json"));
                        if store.enforcement && !sim {
                            if let Err(e) = access::nft::sync(&store, &data_dir, sim) {
                                tracing::warn!("access enforcement sync failed: {e:#}");
                            }
                        }
                    }
                })
                .await;
            }
        });
    }
    {
        let access = state.access.clone();
        let data_dir = state.data_dir.clone();
        let sim = state.sim;
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let store = access.read().unwrap();
                if let Err(e) = access::nft::bootstrap(&store, &data_dir, sim) {
                    tracing::error!("access enforcement bootstrap failed: {e:#}");
                }
            })
            .await;
        });
    }

    let app = api::router(state.clone());
    let (tx, rx) = watch::channel(false);

    tracing::info!(
        "routerd {} starting: http={} https={} tls={} sim={} ui=embedded",
        state.version,
        args.http,
        if tls_active { args.https.as_str() } else { "off" },
        tls_active,
        args.sim
    );

    let mut tasks = Vec::new();
    let permits = Arc::new(Semaphore::new(256));
    if let Some(listener) = http_listener {
        let http_app = if tls_active {
            api::redirect_router()
        } else {
            app.clone()
        };
        tasks.push(tokio::spawn(serve_plain(
            listener,
            http_app,
            permits.clone(),
            rx.clone(),
        )));
    }
    if let (Some(listener), Some(acceptor)) = (https_listener, tls_acceptor) {
        tasks.push(tokio::spawn(serve_tls(
            listener,
            acceptor,
            app,
            permits.clone(),
            rx.clone(),
        )));
    }
    if tasks.is_empty() {
        tracing::error!("no listening sockets available");
        std::process::exit(1);
    }

    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = async {
            if let Some(sig) = sigterm.as_mut() {
                sig.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {},
    }

    tracing::info!("shutting down");
    let _ = tx.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    for t in tasks {
        t.abort();
    }
}
