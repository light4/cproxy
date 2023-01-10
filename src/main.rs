use clap::{Parser, Subcommand};

mod guards;
mod proxy;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Redirect traffic to specific local port.
    #[arg(long, env = "CPROXY_PORT", default_value = "1080")]
    port: u32,
    /// redirect DNS traffic. This option only works with redirect mode
    #[arg(long)]
    redirect_dns: bool,
    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`,
    /// or `redirect`.
    #[arg(long, default_value = "redirect")]
    mode: String,
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
    nix::unistd::seteuid(nix::unistd::Uid::from_raw(0)).expect(
        "cproxy failed to seteuid, please `chown root:root` and `chmod +s` on cproxy binary",
    );
    nix::unistd::setegid(nix::unistd::Gid::from_raw(0)).expect(
        "cproxy failed to seteuid, please `chown root:root` and `chmod +s` on cproxy binary",
    );
    let args: Cli = Cli::parse();

    if let Some(pid) = args.pid {
        proxy::proxy_existing_pid(pid, &args)?;
    } else {
        proxy::proxy_new_command(&args)?;
    }

    Ok(())
}
