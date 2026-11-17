use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use skyward_core::common::{TrafficStats, VERSION};
use skyward_core::config::{Config, Overrides};
use skyward_core::tunnel::Engine;
use skyward_core::AppState;
use tokio::signal::unix::{signal, SignalKind};

#[derive(Default)]
struct Args {
    version: bool,
    test: bool,
    help: bool,
    config: Option<PathBuf>,
    home: Option<PathBuf>,
    overrides: Overrides,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut need = |flag: &str| -> anyhow::Result<String> {
            it.next().with_context(|| format!("{} requires a value", flag))
        };
        match arg.as_str() {
            "-v" | "--version" => args.version = true,
            "-t" | "--test" => args.test = true,
            "-h" | "--help" => args.help = true,
            "-c" | "--config" => args.config = Some(PathBuf::from(need(&arg)?)),
            "-d" | "--home" => args.home = Some(PathBuf::from(need(&arg)?)),
            "--socks-port" => args.overrides.socks_port = Some(need(&arg)?.parse()?),
            "--http-port" => args.overrides.http_port = Some(need(&arg)?.parse()?),
            "--mixed-port" => args.overrides.mixed_port = Some(need(&arg)?.parse()?),
            "--external-controller" => args.overrides.external_controller = Some(need(&arg)?),
            other => bail!("unknown argument '{}' (try --help)", other),
        }
    }
    Ok(args)
}

fn print_help() {
    println!("skyward-core (rust rewrite) {}\n", VERSION);
    println!("USAGE:\n  skyward-core [OPTIONS]\n");
    println!("OPTIONS:");
    println!("  -c, --config <FILE>            configuration file (YAML)");
    println!("  -d, --home <DIR>               configuration directory");
    println!("  -t, --test                     validate configuration and exit");
    println!("  -v, --version                  print version and exit");
    println!("  -h, --help                     print help and exit");
    println!("      --socks-port <PORT>        override socks-port");
    println!("      --http-port <PORT>         override port (HTTP proxy)");
    println!("      --mixed-port <PORT>        override mixed-port");
    println!("      --external-controller <A>  override external-controller");
    println!("\nENV:");
    println!("  RUST_LOG                       tracing filter (default: info)");
    println!("  SKYWARD_HOME                   default configuration directory");
}

fn default_config_path(args: &Args) -> PathBuf {
    if let Some(p) = &args.config {
        return p.clone();
    }
    let home = args.home.clone().or_else(|| {
        std::env::var_os("SKYWARD_HOME").map(PathBuf::from)
    });
    match home {
        Some(h) => h.join("config.yaml"),
        None => PathBuf::from("config.yaml"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    if args.help {
        print_help();
        return Ok(());
    }
    if args.version {
        println!("skyward-core (rust) {}", VERSION);
        return Ok(());
    }

    let config_path = default_config_path(&args);
    let mut config = Config::load(&config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    config.apply_overrides(&args.overrides);

    let level = config.log_level.clone();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if args.test {
        println!("configuration file {} test is successful", config_path.display());
        return Ok(());
    }

    // Snapshot everything needed to start listeners before moving the config
    // into the engine.
    let host = if config.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    let mut listeners: Vec<(&'static str, u16)> = Vec::new();
    if let Some(p) = config.socks_port { listeners.push(("socks5", p)); }
    if let Some(p) = config.port { listeners.push(("http", p)); }
    if let Some(p) = config.mixed_port { listeners.push(("mixed", p)); }
    if let Some(p) = config.redir_port { listeners.push(("redir", p)); }
    if let Some(p) = config.tproxy_port { listeners.push(("tproxy", p)); }
    let controller = config.external_controller.clone();

    let traffic = Arc::new(TrafficStats::default());
    let data_dir = config_path.parent().unwrap_or_else(|| std::path::Path::new(".")).to_path_buf();
    let engine = Engine::new(config, traffic.clone(), &data_dir).await;
    let state = Arc::new(AppState::new(engine, config_path.clone(), traffic));

    tracing::info!("skyward-core (rust) {} starting", VERSION);
    tracing::info!("mode={} rules={} proxies={}",
        *state.engine.read().await.mode.read().await,
        state.engine.read().await.rules.rules.len(),
        state.engine.read().await.outbounds.outbounds.len());

    for (kind, port) in &listeners {
        let transparent = *kind == "redir" || *kind == "tproxy";
        let addr = format!("{}:{}", if transparent { "0.0.0.0" } else { host }, port);
        let bound = if *kind == "redir" {
            skyward_core::inbound::transparent::bind_redir(*port).await
        } else if *kind == "tproxy" {
            skyward_core::inbound::transparent::bind_tproxy(*port).await
        } else {
            skyward_core::inbound::bind(&addr).await
        };
        match bound {
            Ok(listener) => {
                tracing::info!("{} inbound listening on {}", kind, addr);
                let st = state.clone();
                match *kind {
                    "socks5" => { tokio::spawn(skyward_core::inbound::serve_socks(listener, st)); }
                    "http" => { tokio::spawn(skyward_core::inbound::serve_http(listener, st)); }
                    "redir" => { tokio::spawn(skyward_core::inbound::transparent::serve_redir(listener, st)); }
                    "tproxy" => { tokio::spawn(skyward_core::inbound::transparent::serve_tproxy(listener, st)); }
                    _ => { tokio::spawn(skyward_core::inbound::serve_mixed(listener, st)); }
                }
            }
            Err(e) => tracing::error!("failed to bind {} on {}: {}", kind, addr, e),
        }
    }
    if listeners.is_empty() {
        tracing::warn!("no inbound ports configured; set socks-port, port, mixed-port, redir-port or tproxy-port");
    }

    if let Some(addr) = &controller {
        let addr = addr.clone();
        let st = state.clone();
        tracing::info!("REST controller listening on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = skyward_core::hub::serve(&addr, st).await {
                tracing::error!("REST controller on {} stopped: {}", addr, e);
            }
        });
    }

    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            _ = hup.recv() => {
                if let Err(e) = state.reload().await {
                    tracing::error!("reload failed: {}", e);
                }
            }
        }
    }
    Ok(())
}
