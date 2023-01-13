use std::time::Duration;

use cgroups_rs::{cgroup_builder::CgroupBuilder, Cgroup, CgroupPid};
use color_eyre::Result;

use crate::{
    iproute2::{IPRoute2Builder, Object},
    iptables::{IPTablesBuider, Table},
};

pub trait Guard {}
impl<T> Guard for T {}

#[allow(unused_variables)]
pub struct CGroupGuard {
    pub pid: u32,
    pub cg: Cgroup,
    pub cg_path: String,
    pub class_id: u32,
    pub hier_v2: bool,
}

impl CGroupGuard {
    pub fn new(pid: u32) -> Result<Self> {
        let hier = cgroups_rs::hierarchies::auto();
        let hier_v2 = hier.v2();
        let class_id = pid;
        let cg_path = format!("cproxy-{pid}");
        let cg: Cgroup = CgroupBuilder::new(cg_path.as_str())
            .network()
            .class_id(class_id as u64)
            .done()
            .build(hier)?;
        cg.add_task_by_tgid(CgroupPid::from(pid as u64)).unwrap();
        Ok(Self {
            pid,
            hier_v2,
            cg,
            cg_path,
            class_id,
        })
    }
}

impl Drop for CGroupGuard {
    fn drop(&mut self) {
        self.cg
            .remove_task_by_tgid(CgroupPid::from(self.pid as u64))
            .unwrap_or_else(|e| eprintln!("remove task error: {e:?}"));
        self.cg.delete().unwrap();
    }
}

#[allow(unused)]
pub struct RedirectGuard {
    port: u16,
    output_chain: String,
    cgroup_guard: CGroupGuard,
    redirect_dns: bool,
}

impl RedirectGuard {
    pub fn new(
        port: u16,
        output_chain: &str,
        cgroup_guard: CGroupGuard,
        redirect_dns: bool,
    ) -> Result<Self> {
        tracing::debug!(
            "creating redirect guard on port {}, with redirect_dns: {}",
            port,
            redirect_dns
        );
        let class_id = cgroup_guard.class_id;
        let cgroup_path = cgroup_guard.cg_path.as_str();

        let nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;

        nat.new_chain(output_chain)?;
        nat.append("OUTPUT", &format!("-j {output_chain}"))?;
        nat.append(output_chain, "-p udp -o lo -j RETURN")?;
        nat.append(output_chain, "-p tcp -o lo -j RETURN")?;

        if cgroup_guard.hier_v2 {
            nat.append(
                output_chain,
                &format!("-p tcp -m cgroup --path {cgroup_path} -j REDIRECT --to-ports {port}"),
            )?;
            if redirect_dns {
                nat.append(
                output_chain,
                &format!(
                    "-p udp -m cgroup --path {cgroup_path} --dport 53 -j REDIRECT --to-ports {port}"
                    ),
                )?;
            }
        } else {
            nat.append(
                output_chain,
                &format!("-p tcp -m cgroup --cgroup {class_id} -j REDIRECT --to-ports {port}"),
            )?;
            if redirect_dns {
                nat.append(
                    output_chain,
                    &format!("-p udp -m cgroup --cgroup {class_id} --dport 53 -j REDIRECT --to-ports {port}"),
                )?;
            }
        }

        Ok(Self {
            port,
            output_chain: output_chain.to_owned(),
            cgroup_guard,
            redirect_dns,
        })
    }
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        let output_chain = &self.output_chain;

        let nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()
            .expect("init iptables error");

        let msg = "drop iptables and cgroup failed";
        nat.delete("OUTPUT", &format!("-j {output_chain}"))
            .expect(msg);
        nat.flush_chain(output_chain).expect(msg);
        nat.delete_chain(output_chain).expect(msg);
    }
}

pub struct IpRuleGuardInner {
    fwmark: u32,
    table: u32,
    guard_thread: std::thread::JoinHandle<()>,
    stop_channel: flume::Sender<()>,
}

#[allow(unused)]
pub struct IpRuleGuard {
    inner: Box<dyn Guard>,
}

impl IpRuleGuard {
    pub fn new(fwmark: u32, table: u32) -> Self {
        let (sender, receiver) = flume::unbounded();
        let thread = std::thread::spawn(move || {
            let fwmark = fwmark.to_string();
            let table = table.to_string();
            let ip_cmd = IPRoute2Builder::new().cmd_uid(0).cmd_gid(0).build();
            ip_cmd
                .object(Object::rule)
                .add()
                .run(["fwmark", &fwmark, "table", &table])
                .expect("ip add rule failed");
            ip_cmd
                .object(Object::route)
                .add()
                .run(["local", "0.0.0.0/0", "dev", "lo", "table", &table])
                .expect("ip add route failed");
            loop {
                if ip_cmd
                    .object(Object::rule)
                    .list()
                    .run(["fwmark", &fwmark])
                    .expect("ip list rule failed")
                    .stdout
                    .is_empty()
                {
                    tracing::warn!(
                        "detected disappearing routing policy, possibly due to interruped network, resetting"
                    );
                    ip_cmd
                        .object(Object::rule)
                        .add()
                        .run(["fwmark", &fwmark, "table", &table])
                        .expect("ip add routing rules failed");
                }
                if receiver.recv_timeout(Duration::from_secs(1)).is_ok() {
                    break;
                }
            }
        });
        let inner = IpRuleGuardInner {
            fwmark,
            table,
            guard_thread: thread,
            stop_channel: sender,
        };
        let inner = with_drop::with_drop(inner, |x| {
            x.stop_channel.send(()).unwrap();
            x.guard_thread.join().unwrap();
            let mark = x.fwmark.to_string();
            let table = x.table.to_string();
            let ip_cmd = IPRoute2Builder::new().cmd_uid(0).cmd_gid(0).build();
            ip_cmd
                .object(Object::rule)
                .delete()
                .run(["fwmark", &mark, "table", &table])
                .expect("ip drop routing rules failed");
            ip_cmd
                .object(Object::route)
                .delete()
                .run(["local", "0.0.0.0/0", "dev", "lo", "table", &table])
                .expect("ip delete routing rules failed");
        });
        Self {
            inner: Box::new(inner),
        }
    }
}

#[allow(unused)]
pub struct TProxyGuard {
    port: u16,
    mark: u32,
    output_chain: String,
    prerouting_chain: String,
    iprule_guard: IpRuleGuard,
    cgroup_guard: CGroupGuard,
    override_dns: Option<String>,
}

impl TProxyGuard {
    pub fn new(
        port: u16,
        mark: u32,
        output_chain: &str,
        prerouting_chain: &str,
        cgroup_guard: CGroupGuard,
        override_dns: Option<String>,
    ) -> Result<Self> {
        let class_id = cgroup_guard.class_id;
        let cg_path = cgroup_guard.cg_path.as_str();
        tracing::debug!(
            "creating tproxy guard on port {}, with override_dns: {:?}",
            port,
            override_dns
        );
        let iprule_guard = IpRuleGuard::new(mark, mark);

        let mangle = IPTablesBuider::new(Table::Mangle)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;

        mangle.new_chain(prerouting_chain)?;
        mangle.append("PREROUTING", &format!("-j {prerouting_chain}"))?;
        mangle.append(prerouting_chain, "-p tcp -o lo -j RETURN")?;
        mangle.append(prerouting_chain, "-p udp -o lo -j RETURN")?;
        mangle.append(
            prerouting_chain,
            &format!("-p udp -m mark --mark {mark} -j TPROXY --on-ip 127.0.0.1 --on-port {port}"),
        )?;
        mangle.append(
            prerouting_chain,
            &format!("-p tcp -m mark --mark {mark} -j TPROXY --on-ip 127.0.0.1 --on-port {port}"),
        )?;

        mangle.new_chain(output_chain)?;
        mangle.append("OUTPUT", &format!("-j {output_chain}"))?;
        mangle.append(output_chain, "-p tcp -o lo -j RETURN")?;
        mangle.append(output_chain, "-p udp -o lo -j RETURN")?;

        let nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;
        if override_dns.is_some() {
            nat.new_chain(output_chain)?;
            nat.append("OUTPUT", &format!("-j {output_chain}"))?;
            nat.append(output_chain, "-p udp -o lo -j RETURN")?;
        }

        if cgroup_guard.hier_v2 {
            mangle.append(
                output_chain,
                &format!("-p tcp -m cgroup --path {cg_path} -j MARK --set-mark {mark}"),
            )?;
            mangle.append(
                output_chain,
                &format!("-p udp -m cgroup --path {cg_path} -j MARK --set-mark {mark}"),
            )?;
            if let Some(override_dns) = &override_dns {
                nat.append(output_chain, &format!("-p udp -m cgroup --path {cg_path} --dport 53 -j DNAT --to-destination {override_dns}"))?;
            }
        } else {
            mangle.append(
                output_chain,
                &format!("-p tcp -m cgroup --cgroup {class_id} -j MARK --set-mark {mark}"),
            )?;
            mangle.append(
                output_chain,
                &format!("-p udp -m cgroup --cgroup {class_id} -j MARK --set-mark {mark}"),
            )?;
            if let Some(override_dns) = &override_dns {
                nat.append(output_chain, &format!("-p udp -m cgroup --cgroup {class_id} --dport 53 -j DNAT --to-destination {override_dns}"))?;
            }
        }

        Ok(Self {
            port,
            mark,
            output_chain: output_chain.to_owned(),
            prerouting_chain: prerouting_chain.to_owned(),
            iprule_guard,
            cgroup_guard,
            override_dns,
        })
    }
}

impl Drop for TProxyGuard {
    fn drop(&mut self) {
        let output_chain = &self.output_chain;
        let prerouting_chain = &self.prerouting_chain;

        std::thread::sleep(Duration::from_millis(100));

        let mangle = IPTablesBuider::new(Table::Mangle)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()
            .expect("init iptables error");

        let msg = "drop iptables and cgroup failed";
        mangle
            .delete("PREROUTING", &format!("-j {prerouting_chain}"))
            .expect(msg);
        mangle.flush_chain(prerouting_chain).expect(msg);
        mangle.delete_chain(prerouting_chain).expect(msg);

        mangle
            .delete("OUTPUT", &format!("-j {output_chain}"))
            .expect(msg);
        mangle.flush_chain(output_chain).expect(msg);
        mangle.delete_chain(output_chain).expect(msg);

        if self.override_dns.is_some() {
            let nat = IPTablesBuider::new(Table::Nat)
                .cmd_uid(0)
                .cmd_gid(0)
                .build()
                .expect("init iptables error");

            let msg = format!("drop iptables nat: {output_chain}");
            nat.delete("OUTPUT", &format!("-j {output_chain}"))
                .expect(&msg);
            nat.flush_chain(output_chain).expect(&msg);
            nat.delete_chain(output_chain).expect(&msg);
        }
    }
}

#[allow(unused)]
pub struct TraceGuard {
    prerouting_chain: String,
    output_chain: String,
    cgroup_guard: CGroupGuard,
}

impl TraceGuard {
    pub fn new(
        output_chain: &str,
        prerouting_chain: &str,
        cgroup_guard: CGroupGuard,
    ) -> Result<Self> {
        let class_id = cgroup_guard.class_id;

        let raw = IPTablesBuider::new(Table::Raw)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()
            .expect("init iptables error");

        raw.new_chain(output_chain)?;
        raw.append("OUTPUT", &format!("-j {output_chain}"))?;
        raw.append(
            output_chain,
            &format!("-m cgroup --cgroup {class_id} -p tcp -j LOG"),
        )?;
        raw.append(
            output_chain,
            &format!("-m cgroup --cgroup {class_id} -p udp -j LOG"),
        )?;

        Ok(Self {
            output_chain: output_chain.to_owned(),
            prerouting_chain: prerouting_chain.to_owned(),
            cgroup_guard,
        })
    }
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        let output_chain = &self.output_chain;
        let _prerouting_chain = &self.prerouting_chain;

        std::thread::sleep(Duration::from_millis(100));

        let raw = IPTablesBuider::new(Table::Raw)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()
            .expect("init iptables error");

        let msg = "drop iptables and cgroup failed";

        raw.delete("OUTPUT", &format!("-j {output_chain}"))
            .expect(msg);
        raw.flush_chain(output_chain).expect(msg);
        raw.delete_chain(output_chain).expect(msg);
    }
}
