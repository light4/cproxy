use std::{
    os::unix::process::CommandExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use color_eyre::Result;

use crate::{
    config::{Config, ProxyMode},
    guards::{CGroupGuard, Guard, RedirectGuard, TProxyGuard, TraceGuard},
};

pub fn proxy_new_command(child_command: &[String], config: &Config) -> Result<()> {
    let prefix = &config.iptables_prefix;
    let pid = std::process::id();

    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match config.mode {
        ProxyMode::Redirect => {
            let output_chain = format!("{prefix}_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                config.port,
                &output_chain,
                cgroup_guard,
                config.redirect_dns,
                config.ip_stack,
            )?)
        }
        ProxyMode::TProxy => {
            let output_chain = format!("{prefix}_tproxy_out_{pid}");
            let prerouting_chain = format!("{prefix}_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                config.port,
                mark,
                &output_chain,
                &prerouting_chain,
                cgroup_guard,
                config.override_dns.clone(),
            )?)
        }
        ProxyMode::Trace => {
            let prerouting_chain = format!("{prefix}_trace_pre_{pid}");
            let output_chain = format!("{prefix}_trace_out_{pid}");
            Box::new(TraceGuard::new(
                &output_chain,
                &prerouting_chain,
                cgroup_guard,
            )?)
        }
    };

    let original_uid = nix::unistd::getuid();
    let original_gid = nix::unistd::getgid();
    let mut child = std::process::Command::new(&child_command[0])
        .uid(original_uid.as_raw())
        .gid(original_gid.as_raw())
        .args(&child_command[1..])
        .spawn()?;
    nix::unistd::seteuid(nix::unistd::Uid::from_raw(0))?;
    nix::unistd::setegid(nix::unistd::Gid::from_raw(0))?;

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
    })?;

    child.wait()?;

    Ok(())
}

pub fn proxy_existing_pid(pid: u32, config: &Config) -> Result<()> {
    let prefix = &config.iptables_prefix;
    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match config.mode {
        ProxyMode::Redirect => {
            let output_chain = format!("{prefix}_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                config.port,
                &output_chain,
                cgroup_guard,
                !config.redirect_dns,
                config.ip_stack,
            )?)
        }
        ProxyMode::TProxy => {
            let output_chain = format!("{prefix}_tproxy_out_{pid}");
            let prerouting_chain = format!("{prefix}_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                config.port,
                mark,
                &output_chain,
                &prerouting_chain,
                cgroup_guard,
                config.override_dns.clone(),
            )?)
        }
        ProxyMode::Trace => {
            let prerouting_chain = format!("{prefix}_trace_pre_{pid}");
            let output_chain = format!("{prefix}_trace_out_{pid}");
            Box::new(TraceGuard::new(
                &output_chain,
                &prerouting_chain,
                cgroup_guard,
            )?)
        }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
