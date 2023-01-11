use std::{
    os::unix::process::CommandExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    config::{Config, ProxyMode},
    guards::{CGroupGuard, Guard, RedirectGuard, TProxyGuard, TraceGuard},
};

pub fn proxy_new_command(child_command: &[String], config: &Config) -> anyhow::Result<()> {
    let pid = std::process::id();

    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match config.mode {
        ProxyMode::Redirect => {
            let output_chain_name = format!("nozomi_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                config.port,
                output_chain_name.as_str(),
                cgroup_guard,
                config.redirect_dns,
            )?)
        }
        ProxyMode::TProxy => {
            let output_chain_name = format!("nozomi_tproxy_out_{pid}");
            let prerouting_chain_name = format!("nozomi_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                config.port,
                mark,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
                config.override_dns.clone(),
            )?)
        }
        ProxyMode::Trace => {
            let prerouting_chain_name = format!("nozomi_trace_pre_{pid}");
            let output_chain_name = format!("nozomi_trace_out_{pid}");
            Box::new(TraceGuard::new(
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
            )?)
        }
    };

    let (uid, gid) = {
        if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
            let s_uid = sudo_uid.parse::<u32>().unwrap();
            let s_gid = std::env::var("SUDO_GID").unwrap().parse::<u32>().unwrap();
            (s_uid, s_gid)
        } else {
            let o_uid = nix::unistd::getuid().as_raw();
            let o_gid = nix::unistd::getgid().as_raw();
            (o_uid, o_gid)
        }
    };
    let mut child = std::process::Command::new(&child_command[0])
        .uid(uid)
        .gid(gid)
        .args(&child_command[1..])
        .spawn()?;

    ctrlc::set_handler(move || {
        println!("received ctrl-c, terminating...");
    })?;

    child.wait()?;

    Ok(())
}

pub fn proxy_existing_pid(pid: u32, config: &Config) -> anyhow::Result<()> {
    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match config.mode {
        ProxyMode::Redirect => {
            let output_chain_name = format!("nozomi_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                config.port,
                output_chain_name.as_str(),
                cgroup_guard,
                !config.redirect_dns,
            )?)
        }
        ProxyMode::TProxy => {
            let output_chain_name = format!("nozomi_tproxy_out_{pid}");
            let prerouting_chain_name = format!("nozomi_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                config.port,
                mark,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
                config.override_dns.clone(),
            )?)
        }
        ProxyMode::Trace => {
            let prerouting_chain_name = format!("nozomi_trace_pre_{pid}");
            let output_chain_name = format!("nozomi_trace_out_{pid}");
            Box::new(TraceGuard::new(
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
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
