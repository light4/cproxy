use std::{
    os::unix::process::CommandExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    guards::{CGroupGuard, Guard, RedirectGuard, TProxyGuard, TraceGuard},
    ChildCommand, Cli,
};

pub fn proxy_new_command(args: &Cli) -> anyhow::Result<()> {
    let pid = std::process::id();
    let ChildCommand::Command(child_command) = &args
        .command
        .as_ref()
        .expect("must have command specified if --pid not provided");
    tracing::info!("subcommand {:?}", child_command);

    let port = args.port;

    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match args.mode.as_str() {
        "redirect" => {
            let output_chain_name = format!("nozomi_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                port,
                output_chain_name.as_str(),
                cgroup_guard,
                args.redirect_dns,
            )?)
        }
        "tproxy" => {
            let output_chain_name = format!("nozomi_tproxy_out_{pid}");
            let prerouting_chain_name = format!("nozomi_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                port,
                mark,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
                args.override_dns.clone(),
            )?)
        }
        "trace" => {
            let prerouting_chain_name = format!("nozomi_trace_pre_{pid}");
            let output_chain_name = format!("nozomi_trace_out_{pid}");
            Box::new(TraceGuard::new(
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
            )?)
        }
        &_ => {
            unimplemented!()
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
        .env("CPROXY_ENV", format!("cproxy/{port}"))
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

pub fn proxy_existing_pid(pid: u32, args: &Cli) -> anyhow::Result<()> {
    let port = args.port;

    let cgroup_guard = CGroupGuard::new(pid)?;
    let _guard: Box<dyn Guard> = match args.mode.as_str() {
        "redirect" => {
            let output_chain_name = format!("nozomi_redirect_out_{pid}");
            Box::new(RedirectGuard::new(
                port,
                output_chain_name.as_str(),
                cgroup_guard,
                !args.redirect_dns,
            )?)
        }
        "tproxy" => {
            let output_chain_name = format!("nozomi_tproxy_out_{pid}");
            let prerouting_chain_name = format!("nozomi_tproxy_pre_{pid}");
            let mark = pid;
            Box::new(TProxyGuard::new(
                port,
                mark,
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
                args.override_dns.clone(),
            )?)
        }
        "trace" => {
            let prerouting_chain_name = format!("nozomi_trace_pre_{pid}");
            let output_chain_name = format!("nozomi_trace_out_{pid}");
            Box::new(TraceGuard::new(
                output_chain_name.as_str(),
                prerouting_chain_name.as_str(),
                cgroup_guard,
            )?)
        }
        _ => {
            unimplemented!()
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
