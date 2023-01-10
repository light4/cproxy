use structopt::StructOpt;

mod guards;
mod proxy;

#[derive(StructOpt, Debug)]
pub struct Cli {
    /// Redirect traffic to specific local port.
    #[structopt(long, env = "CPROXY_PORT", default_value = "1080")]
    port: u32,
    /// redirect DNS traffic. This option only works with redirect mode
    #[structopt(long)]
    redirect_dns: bool,
    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`,
    /// or `redirect`.
    #[structopt(long, default_value = "redirect")]
    mode: String,
    /// Override dns server address. This option only works with tproxy mode
    #[structopt(long)]
    override_dns: Option<String>,
    /// Proxy an existing process.
    #[structopt(long)]
    pid: Option<u32>,
    #[structopt(subcommand)]
    command: Option<ChildCommand>,
}

#[derive(StructOpt, Debug)]
enum ChildCommand {
    #[structopt(external_subcommand)]
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
    let args: Cli = Cli::from_args();

    match args.pid {
        None => {
            proxy::proxy_new_command(&args)?;
        }
        Some(existing_pid) => {
            proxy::proxy_existing_pid(existing_pid, &args)?;
        }
    }

    Ok(())
}
