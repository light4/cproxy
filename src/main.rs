use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::Config;

mod config;
mod guards;
mod proxy;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Redirect traffic to specific local port. default 1080
    #[arg(short, long)]
    port: Option<u16>,
    /// redirect DNS traffic. This option only works with redirect mode
    #[arg(short, long)]
    redirect_dns: Option<bool>,
    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`,
    /// or `redirect`. default `redirect`
    #[arg(short, long)]
    mode: Option<String>,
    /// Override dns server address. This option only works with tproxy mode
    #[arg(long)]
    override_dns: Option<String>,
    /// Proxy an existing process.
    #[arg(long)]
    pid: Option<u32>,
    #[command(subcommand)]
    command: Option<ChildCommand>,
}

#[derive(Subcommand, Debug)]
enum ChildCommand {
    #[command(external_subcommand)]
    Command(Vec<String>),
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("LOG_LEVEL"))
        .init();
    let args: Cli = Cli::parse();
    let config = Config::init(&args)?;

    if let Some(pid) = args.pid {
        proxy::proxy_existing_pid(pid, &config)?;
    } else if let Some(ChildCommand::Command(child_command)) = &args.command.as_ref() {
        tracing::info!("subcommand {:?}", child_command);
        proxy::proxy_new_command(child_command, &config)?;
    } else {
        eprintln!("Error, must provide pid by --pid or command");
    }

    Ok(())
}
