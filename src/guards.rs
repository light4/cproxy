use std::time::Duration;

use cgroups_rs::{cgroup_builder::CgroupBuilder, Cgroup, CgroupPid};
use color_eyre::Result;

use crate::{
    config::IPStack,
    iproute2::{Action, IPRoute2, IPRoute2Builder, Object},
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
            .expect("remove task error {self.pid}");
        std::thread::sleep(Duration::from_millis(50));
        self.cg.delete().expect("delete cgroup error");
    }
}

#[allow(unused)]
pub struct RedirectGuard {
    port: u16,
    output_chain: String,
    cgroup_guard: CGroupGuard,
    redirect_dns: bool,
    ip_stack: IPStack,
}

impl RedirectGuard {
    // for inner use with ipv4/ipv6 but not both
    fn _create_rules_with_ip_stack(&self, ip_stack: IPStack) -> Result<()> {
        let stack_str = match ip_stack {
            IPStack::V4 => "ipv4",
            IPStack::V6 => "ipv6",
            _ => unreachable!(),
        };

        let port = self.port;
        let output_chain = &self.output_chain;
        let redirect_dns = self.redirect_dns;
        let class_id = self.cgroup_guard.class_id;
        let cgroup_path = self.cgroup_guard.cg_path.as_str();

        tracing::debug!(
            "creating {stack_str} redirect guard on port {port}, with redirect_dns: {redirect_dns}",
        );

        let mut nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;
        if matches!(ip_stack, IPStack::V6) {
            nat.set_ipv6();
        }

        nat.new_chain(output_chain)?;
        nat.append("OUTPUT", &format!("-j {output_chain}"))?;
        nat.append(output_chain, "-p udp -o lo -j RETURN")?;
        nat.append(output_chain, "-p tcp -o lo -j RETURN")?;

        if self.cgroup_guard.hier_v2 {
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

        Ok(())
    }

    pub fn create_v4_rules(&self) -> Result<()> {
        self._create_rules_with_ip_stack(IPStack::V4)
    }

    pub fn create_v6_rules(&self) -> Result<()> {
        self._create_rules_with_ip_stack(IPStack::V6)
    }

    pub fn new(
        port: u16,
        output_chain: &str,
        cgroup_guard: CGroupGuard,
        redirect_dns: bool,
        ip_stack: IPStack,
    ) -> Result<Self> {
        let guard = Self {
            port,
            output_chain: output_chain.to_owned(),
            cgroup_guard,
            redirect_dns,
            ip_stack,
        };

        if ip_stack.has_v4() {
            guard.create_v4_rules()?;
        }
        if ip_stack.has_v6() {
            guard.create_v6_rules()?;
        }

        Ok(guard)
    }

    pub fn drop_v4_rules(&self) -> Result<()> {
        self._drop_rules_with_ip_stack(IPStack::V4)
    }

    pub fn drop_v6_rules(&self) -> Result<()> {
        self._drop_rules_with_ip_stack(IPStack::V6)
    }

    // for inner use with ipv4/ipv6 but not both
    fn _drop_rules_with_ip_stack(&self, ip_stack: IPStack) -> Result<()> {
        let output_chain = &self.output_chain;

        let mut nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;
        if matches!(ip_stack, IPStack::V6) {
            nat.set_ipv6();
        }
        nat.delete("OUTPUT", &format!("-j {output_chain}"))?;
        nat.flush_chain(output_chain)?;
        nat.delete_chain(output_chain)?;

        Ok(())
    }
}

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if self.ip_stack.has_v4() {
            let msg = "redirect drop ipv4 iptables and cgroup failed";
            self.drop_v4_rules().expect(msg);
        }

        if self.ip_stack.has_v6() {
            let msg = "redirect drop ipv6 iptables and cgroup failed";
            self.drop_v6_rules().expect(msg);
        }
    }
}

pub struct IpRuleGuardInner {
    fwmark: u32,
    table: u32,
    guard_thread: std::thread::JoinHandle<()>,
    stop_channel: flume::Sender<()>,
    ip_stack: IPStack,
}

#[allow(unused)]
pub struct IpRuleGuard {
    inner: Box<dyn Guard>,
}

impl IpRuleGuard {
    pub fn new(fwmark: u32, table: u32, ip_stack: IPStack) -> Self {
        let ipv4_cmd = IPRoute2Builder::new().cmd_uid(0).cmd_gid(0).build();
        let ipv6_cmd = IPRoute2Builder::new().ipv6().cmd_uid(0).cmd_gid(0).build();

        fn update_fwmark(ip_cmd: &IPRoute2, action: Action, fwmark: &str, table: &str) {
            ip_cmd
                .object(Object::rule)
                .action(action)
                .run(["fwmark", fwmark, "table", table])
                .expect("ip {action} rule failed");
        }

        fn update_local_ip_table(ip_cmd: &IPRoute2, action: Action, table: &str) {
            let local_ip = if ip_cmd.ipv6 { "::/0" } else { "0.0.0.0/0" };
            ip_cmd
                .object(Object::route)
                .action(action)
                .run(["local", local_ip, "dev", "lo", "table", table])
                .expect("ip {action} route failed");
        }

        let (sender, receiver) = flume::unbounded();
        let thread = std::thread::spawn(move || {
            let fwmark = fwmark.to_string();
            let table = table.to_string();
            if ip_stack.has_v4() {
                update_fwmark(&ipv4_cmd, Action::Add, &fwmark, &table);
                update_local_ip_table(&ipv4_cmd, Action::Add, &table);
            }
            if ip_stack.has_v6() {
                update_fwmark(&ipv6_cmd, Action::Add, &fwmark, &table);
                update_local_ip_table(&ipv6_cmd, Action::Add, &table);
            }

            loop {
                if ipv4_cmd
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
                    if ip_stack.has_v4() {
                        update_fwmark(&ipv4_cmd, Action::Add, &fwmark, &table);
                    }
                    if ip_stack.has_v6() {
                        update_fwmark(&ipv6_cmd, Action::Add, &fwmark, &table);
                    }
                }
                if receiver.recv_timeout(Duration::from_millis(500)).is_ok() {
                    break;
                }
            }
        });
        let inner = IpRuleGuardInner {
            fwmark,
            table,
            guard_thread: thread,
            stop_channel: sender,
            ip_stack,
        };
        let inner = with_drop::with_drop(inner, |x| {
            x.stop_channel.send(()).unwrap();
            x.guard_thread.join().unwrap();
            let mark = x.fwmark.to_string();
            let table = x.table.to_string();
            if x.ip_stack.has_v4() {
                let ipv4_cmd = IPRoute2Builder::new().cmd_uid(0).cmd_gid(0).build();
                update_fwmark(&ipv4_cmd, Action::Delete, &mark, &table);
                update_local_ip_table(&ipv4_cmd, Action::Delete, &table);
            }
            if x.ip_stack.has_v6() {
                let ipv6_cmd = IPRoute2Builder::new().ipv6().cmd_uid(0).cmd_gid(0).build();
                update_fwmark(&ipv6_cmd, Action::Delete, &mark, &table);
                update_local_ip_table(&ipv6_cmd, Action::Delete, &table);
            }
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
    ip_stack: IPStack,
}

impl TProxyGuard {
    // for inner use with ipv4/ipv6 but not both
    fn _create_rules_with_ip_stack(&self, ip_stack: IPStack) -> Result<()> {
        let port = self.port;
        let override_dns = self.override_dns.clone();
        let class_id = self.cgroup_guard.class_id;
        let cg_path = self.cgroup_guard.cg_path.as_str();
        let mark = self.mark;
        let prerouting_chain = &self.prerouting_chain;
        let output_chain = &self.output_chain;

        tracing::debug!(
            "creating tproxy guard on port {port}, with override_dns: {override_dns:?}",
        );

        let mut mangle = IPTablesBuider::new(Table::Mangle)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;
        if matches!(ip_stack, IPStack::V6) {
            mangle.set_ipv6();
        }
        let redir_ip = match ip_stack {
            IPStack::V4 => "127.0.0.1",
            IPStack::V6 => "::1",
            _ => unreachable!(),
        };

        mangle.new_chain(prerouting_chain)?;
        mangle.append("PREROUTING", &format!("-j {prerouting_chain}"))?;
        mangle.append(prerouting_chain, "-p tcp -o lo -j RETURN")?;
        mangle.append(prerouting_chain, "-p udp -o lo -j RETURN")?;
        mangle.append(
            prerouting_chain,
            &format!("-p udp -m mark --mark {mark} -j TPROXY --on-ip {redir_ip} --on-port {port}"),
        )?;
        mangle.append(
            prerouting_chain,
            &format!("-p tcp -m mark --mark {mark} -j TPROXY --on-ip {redir_ip} --on-port {port}"),
        )?;

        mangle.new_chain(output_chain)?;
        mangle.append("OUTPUT", &format!("-j {output_chain}"))?;
        mangle.append(output_chain, "-p tcp -o lo -j RETURN")?;
        mangle.append(output_chain, "-p udp -o lo -j RETURN")?;
        mangle.append(output_chain, "-j RETURN -m mark --mark 0xff")?;

        let nat = IPTablesBuider::new(Table::Nat)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()?;
        if override_dns.is_some() {
            nat.new_chain(output_chain)?;
            nat.append("OUTPUT", &format!("-j {output_chain}"))?;
            nat.append(output_chain, "-p udp -o lo -j RETURN")?;
        }

        if self.cgroup_guard.hier_v2 {
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

        Ok(())
    }

    pub fn create_v4_rules(&self) -> Result<()> {
        self._create_rules_with_ip_stack(IPStack::V4)
    }

    pub fn create_v6_rules(&self) -> Result<()> {
        self._create_rules_with_ip_stack(IPStack::V6)
    }

    pub fn new(
        port: u16,
        mark: u32,
        output_chain: &str,
        prerouting_chain: &str,
        cgroup_guard: CGroupGuard,
        override_dns: Option<String>,
        ip_stack: IPStack,
    ) -> Result<Self> {
        let iprule_guard = IpRuleGuard::new(mark, mark, ip_stack);
        let guard = Self {
            port,
            mark,
            output_chain: output_chain.to_owned(),
            prerouting_chain: prerouting_chain.to_owned(),
            iprule_guard,
            cgroup_guard,
            override_dns,
            ip_stack,
        };
        if ip_stack.has_v4() {
            guard.create_v4_rules()?;
        }
        if ip_stack.has_v6() {
            guard.create_v6_rules()?;
        }

        Ok(guard)
    }

    pub fn drop_v4_rules(&self) -> Result<()> {
        self._drop_rules_with_ip_stack(IPStack::V4)
    }

    pub fn drop_v6_rules(&self) -> Result<()> {
        self._drop_rules_with_ip_stack(IPStack::V6)
    }

    // for inner use with ipv4/ipv6 but not both
    fn _drop_rules_with_ip_stack(&self, ip_stack: IPStack) -> Result<()> {
        let output_chain = &self.output_chain;
        let prerouting_chain = &self.prerouting_chain;

        std::thread::sleep(Duration::from_millis(100));

        let mut mangle = IPTablesBuider::new(Table::Mangle)
            .cmd_uid(0)
            .cmd_gid(0)
            .build()
            .expect("init iptables error");
        if matches!(ip_stack, IPStack::V6) {
            mangle.set_ipv6();
        }

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
            let mut nat = IPTablesBuider::new(Table::Nat)
                .cmd_uid(0)
                .cmd_gid(0)
                .build()
                .expect("init iptables error");
            if matches!(ip_stack, IPStack::V6) {
                nat.set_ipv6();
            }

            let msg = format!("drop iptables nat: {output_chain}");
            nat.delete("OUTPUT", &format!("-j {output_chain}"))
                .expect(&msg);
            nat.flush_chain(output_chain).expect(&msg);
            nat.delete_chain(output_chain).expect(&msg);
        }
        Ok(())
    }
}

impl Drop for TProxyGuard {
    fn drop(&mut self) {
        if self.ip_stack.has_v4() {
            let msg = "redirect drop ipv4 iptables and cgroup failed";
            self.drop_v4_rules().expect(msg);
        }

        if self.ip_stack.has_v6() {
            let msg = "redirect drop ipv6 iptables and cgroup failed";
            self.drop_v6_rules().expect(msg);
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
