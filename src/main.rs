use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_eyre::Result;
use config::Config;
use nix::sys::stat::Mode;

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

fn get_setuid_help() -> Result<String> {
    let bin_path = std::fs::read_link("/proc/self/exe")?;
    let filename = bin_path.to_string_lossy();
    let file_stat = nix::sys::stat::lstat(&bin_path)?;
    let file_mode = nix::sys::stat::Mode::from_bits_truncate(file_stat.st_mode.into());
    if !file_mode.contains(Mode::S_ISUID) {
        Ok(format!(
            "    please run these cmds to setup:
        sudo chown root:root {filename}
        sudo chmod +s {filename}
"
        ))
    } else {
        Ok(
            "    文件位于一个设置了 `nosuid` 选项的文件系统(用 findmnt 查看)或者没有 root 权限的 NFS 文件系统中吗？"
                .to_string(),
        )
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("LOG_LEVEL"))
        .init();
    let args: Cli = Cli::parse();
    let config = Config::init(&args)?;

    if let Err(e) = nix::unistd::seteuid(nix::unistd::Uid::from_raw(0)) {
        let msg = get_setuid_help()?;
        eprintln!("cproxy failed to seteuid:\n{msg}");
        return Err(e.into());
    }

    nix::unistd::setegid(nix::unistd::Gid::from_raw(0))?;

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
