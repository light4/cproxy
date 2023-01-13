//! Provides bindings for [iptables](https://www.netfilter.org/projects/iptables/index.html) application in Linux.
//! This crate uses iptables binary to manipulate chains and tables.
//! This source code is licensed under MIT license that can be found in the LICENSE file.
//!
//! # Example
//! ```
//! let mut ipt = IPTablesBuilder::new(Table::Nat)
//!     .ipv6()
//!     .cmd_uid(0)
//!     .cmd_gid(0);
//! assert!(ipt.new_chain("nat", "NEWCHAINNAME").is_ok());
//! assert!(ipt.append("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
//! assert!(ipt.exists("nat", "NEWCHAINNAME", "-j ACCEPT").unwrap());
//! assert!(ipt.delete("nat", "NEWCHAINNAME", "-j ACCEPT").is_ok());
//! assert!(ipt.delete_chain("nat", "NEWCHAINNAME").is_ok());
//! ```

#![allow(dead_code)]

use std::{
    convert::From,
    ffi::OsStr,
    fs::File,
    os::unix::{io::AsRawFd, process::CommandExt},
    process::{Command, Output},
    vec::Vec,
};

use lazy_regex::regex;
use nix::fcntl::{flock, FlockArg};
use semver::Version;

use crate::errors::IptablesError;

// List of built-in chains taken from: man 8 iptables
const BUILTIN_CHAINS_FILTER: &[&str] = &["INPUT", "FORWARD", "OUTPUT"];
const BUILTIN_CHAINS_MANGLE: &[&str] = &["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"];
const BUILTIN_CHAINS_NAT: &[&str] = &["PREROUTING", "POSTROUTING", "OUTPUT"];
const BUILTIN_CHAINS_RAW: &[&str] = &["PREROUTING", "OUTPUT"];
const BUILTIN_CHAINS_SECURITY: &[&str] = &["INPUT", "OUTPUT", "FORWARD"];

#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Table {
    Nat,
    Filter,
    Mangle,
    Raw,
    Security,
}

impl Table {
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Nat => "nat",
            Self::Filter => "filter",
            Self::Mangle => "mangle",
            Self::Raw => "raw",
            Self::Security => "security",
        }
    }

    pub const fn builtin_chains(&self) -> &[&str] {
        match self {
            Self::Filter => BUILTIN_CHAINS_FILTER,
            Self::Mangle => BUILTIN_CHAINS_MANGLE,
            Self::Nat => BUILTIN_CHAINS_NAT,
            Self::Raw => BUILTIN_CHAINS_RAW,
            Self::Security => BUILTIN_CHAINS_SECURITY,
        }
    }
}

pub type Result<T, E = IptablesError> = core::result::Result<T, E>;

trait SplitQuoted {
    fn split_quoted(&self) -> Vec<&str>;
}

impl SplitQuoted for str {
    fn split_quoted(&self) -> Vec<&str> {
        let re = regex!(r#"["'].+?["']|[^ ]+"#);
        re
            // Iterate over matched segments
            .find_iter(self)
            // Get match as str
            .map(|m| m.as_str())
            // Remove any surrounding quotes (they will be reinserted by `Command`)
            .map(|s| s.trim_matches(|c| c == '"' || c == '\''))
            // Collect
            .collect::<Vec<_>>()
    }
}

fn output_to_result(output: Output) -> Result<()> {
    if !output.status.success() {
        return Err(IptablesError::from(output));
    }
    Ok(())
}

/// Contains the iptables command and shows if it supports -w and -C options.
/// Use `new` method to create a new instance of this struct.
#[derive(Debug, Clone)]
pub struct IPTablesBuider {
    /// iptables table
    table: Table,

    /// The utility command which must be 'iptables' or 'ip6tables'.
    binary: String,

    /// run command uid
    cmd_uid: Option<u32>,
    /// run command gid
    cmd_gid: Option<u32>,
}

impl IPTablesBuider {
    pub fn new(table: Table) -> Self {
        Self {
            table,
            binary: "iptables".to_string(),
            cmd_uid: None,
            cmd_gid: None,
        }
    }

    #[inline]
    pub fn table(mut self, table: Table) -> Self {
        self.table = table;
        self
    }

    #[inline]
    pub fn ipv6(mut self) -> Self {
        self.binary = "ip6tables".to_string();
        self
    }

    #[inline]
    pub fn binary(mut self, binary: &str) -> Self {
        self.binary = binary.to_string();
        self
    }

    #[inline]
    pub fn cmd_uid(mut self, uid: u32) -> Self {
        self.cmd_uid = Some(uid);
        self
    }

    #[inline]
    pub fn cmd_gid(mut self, gid: u32) -> Self {
        self.cmd_gid = Some(gid);
        self
    }

    pub fn build(&self) -> Result<IPTables> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--version");
        if let Some(uid) = self.cmd_uid {
            cmd.uid(uid);
        }
        if let Some(gid) = self.cmd_gid {
            cmd.gid(gid);
        }
        let version_output = cmd.output()?;

        let re = regex!(r"v(\d+\.\d+\.\d+)");
        let version_string = String::from_utf8_lossy(version_output.stdout.as_slice());
        let version_str = re
            .captures(&version_string)
            .ok_or(IptablesError::Version(format!(
                "invalid version number: {version_string}"
            )))?
            .get(1)
            .ok_or(IptablesError::Version(format!(
                "unable to get version number: {version_string}"
            )))?
            .as_str();

        let version = Version::parse(version_str)?;
        let has_check = version > Version::new(1, 4, 10);
        let has_wait = version > Version::new(1, 4, 19);

        Ok(IPTables {
            table: self.table,
            binary: self.binary.clone(),
            version,
            has_check,
            has_wait,
            is_numeric: false,
            cmd_uid: self.cmd_uid,
            cmd_gid: self.cmd_gid,
        })
    }
}

/// Contains the iptables command and shows if it supports -w and -C options.
/// Use `new` method to create a new instance of this struct.
#[derive(Debug, Clone)]
pub struct IPTables {
    pub table: Table,

    /// The utility command which must be 'iptables' or 'ip6tables'.
    pub binary: String,

    pub version: Version,

    /// Indicates if iptables has -C (--check) option
    pub has_check: bool,

    /// Indicates if iptables has -w (--wait) option
    pub has_wait: bool,

    /// Indicates if iptables will be run with -n (--numeric) option
    pub is_numeric: bool,

    /// run command uid
    pub cmd_uid: Option<u32>,
    /// run command gid
    pub cmd_gid: Option<u32>,
}

impl IPTables {
    #[inline]
    pub fn set_ipv6(&mut self) {
        self.binary = "ip6tables".to_string();
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        self.binary == "ip6tables"
    }

    #[inline]
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-t").arg(self.table.to_str());
        if let Some(uid) = self.cmd_uid {
            cmd.uid(uid);
        }
        if let Some(gid) = self.cmd_gid {
            cmd.gid(gid);
        }
        cmd
    }

    /// Get the default policy for a table/chain.
    pub fn get_policy(&self, chain: &str) -> Result<String> {
        let builtin_chains = self.table.builtin_chains();
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(
                "given chain is not a default chain in the given table, can't get policy".into(),
            );
        }

        let stdout = match self.is_numeric {
            false => self.run(&["-L", chain])?.stdout,
            true => self.run(&["-L", chain, "-n"])?.stdout,
        };
        let output = String::from_utf8_lossy(stdout.as_slice());
        for item in output.trim().split('\n') {
            let fields = item.split(' ').collect::<Vec<&str>>();
            if fields.len() > 1 && fields[0] == "Chain" && fields[1] == chain {
                return Ok(fields[3].replace(')', ""));
            }
        }
        Err("could not find the default policy for table and chain".into())
    }

    /// Set the default policy for a table/chain.
    pub fn set_policy(&self, chain: &str, policy: &str) -> Result<()> {
        let builtin_chains = self.table.builtin_chains();
        if !builtin_chains.iter().as_slice().contains(&chain) {
            return Err(
                "given chain is not a default chain in the given table, can't set policy".into(),
            );
        }

        self.run(&["-P", chain, policy]).and_then(output_to_result)
    }

    /// Executes a given `command` on the chain.
    /// Returns the command output if successful.
    pub fn execute(&self, command: &str) -> Result<Output> {
        self.run(command.split_quoted().as_slice())
    }

    /// Checks for the existence of the `rule` in the table/chain.
    /// Returns true if the rule exists.
    #[cfg(target_os = "linux")]
    pub fn exists(&self, chain: &str, rule: &str) -> Result<bool> {
        if !self.has_check {
            return self.exists_old_version(chain, rule);
        }

        self.run(&[&["-C", chain], rule.split_quoted().as_slice()].concat())
            .map(|output| output.status.success())
    }

    /// Checks for the existence of the `chain` in the table.
    /// Returns true if the chain exists.
    #[cfg(target_os = "linux")]
    pub fn chain_exists(&self, table: &str, chain: &str) -> Result<bool> {
        match self.is_numeric {
            false => self
                .run(&["-t", table, "-L", chain])
                .map(|output| output.status.success()),
            true => self
                .run(&["-t", table, "-L", chain, "-n"])
                .map(|output| output.status.success()),
        }
    }

    fn exists_old_version(&self, chain: &str, rule: &str) -> Result<bool> {
        match self.is_numeric {
            false => self.run(&["-S"]).map(|output| {
                String::from_utf8_lossy(&output.stdout).contains(&format!("-A {chain} {rule}"))
            }),
            true => self.run(&["-S", "-n"]).map(|output| {
                String::from_utf8_lossy(&output.stdout).contains(&format!("-A {chain} {rule}"))
            }),
        }
    }

    /// Inserts `rule` in the `position` to the table/chain.
    pub fn insert(&self, chain: &str, rule: &str, position: i32) -> Result<()> {
        self.run(
            &[
                &["-I", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        )
        .and_then(output_to_result)
    }

    /// Inserts `rule` in the `position` to the table/chain if it does not exist.
    pub fn insert_unique(&self, chain: &str, rule: &str, position: i32) -> Result<()> {
        if self.exists(chain, rule)? {
            return Err("the rule exists in the table/chain".into());
        }

        self.insert(chain, rule, position)
    }

    /// Replaces `rule` in the `position` to the table/chain.
    pub fn replace(&self, chain: &str, rule: &str, position: i32) -> Result<()> {
        self.run(
            &[
                &["-R", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        )
        .and_then(output_to_result)
    }

    /// Appends `rule` to the table/chain.
    pub fn append(&self, chain: &str, rule: &str) -> Result<()> {
        self.run(&[&["-A", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    /// Appends `rule` to the table/chain if it does not exist.
    pub fn append_unique(&self, chain: &str, rule: &str) -> Result<()> {
        if self.exists(chain, rule)? {
            return Err("the rule exists in the table/chain".into());
        }

        self.append(chain, rule)
    }

    /// Appends or replaces `rule` to the table/chain if it does not exist.
    pub fn append_replace(&self, chain: &str, rule: &str) -> Result<()> {
        if self.exists(chain, rule)? {
            self.delete(chain, rule)?;
        }

        self.append(chain, rule)
    }

    /// Deletes `rule` from the table/chain.
    pub fn delete(&self, chain: &str, rule: &str) -> Result<()> {
        self.run(&[&["-D", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    /// Deletes all repetition of the `rule` from the table/chain.
    pub fn delete_all(&self, chain: &str, rule: &str) -> Result<()> {
        while self.exists(chain, rule)? {
            self.delete(chain, rule)?;
        }

        Ok(())
    }

    /// Lists rules in the table/chain.
    pub fn list(&self, chain: &str) -> Result<Vec<String>> {
        match self.is_numeric {
            false => self.get_list(&["-S", chain]),
            true => self.get_list(&["-S", chain, "-n"]),
        }
    }

    /// Lists rules in the table.
    pub fn list_table(&self) -> Result<Vec<String>> {
        match self.is_numeric {
            false => self.get_list(&["-S"]),
            true => self.get_list(&["-S", "-n"]),
        }
    }

    /// Lists the name of each chain in the table.
    pub fn list_chains(&self) -> Result<Vec<String>> {
        let mut list = Vec::new();
        let stdout = self.run(&["-S"])?.stdout;
        let output = String::from_utf8_lossy(stdout.as_slice());
        for item in output.trim().split('\n') {
            let fields = item.split(' ').collect::<Vec<&str>>();
            if fields.len() > 1 && (fields[0] == "-P" || fields[0] == "-N") {
                list.push(fields[1].to_string());
            }
        }
        Ok(list)
    }

    /// Creates a new user-defined chain.
    pub fn new_chain(&self, chain: &str) -> Result<()> {
        self.run(&["-N", chain]).and_then(output_to_result)
    }

    /// Flushes (deletes all rules) a chain.
    pub fn flush_chain(&self, chain: &str) -> Result<()> {
        self.run(&["-F", chain]).and_then(output_to_result)
    }

    /// Renames a chain in the table.
    pub fn rename_chain(&self, old_chain: &str, new_chain: &str) -> Result<()> {
        self.run(&["-E", old_chain, new_chain])
            .and_then(output_to_result)
    }

    /// Deletes a user-defined chain in the table.
    pub fn delete_chain(&self, chain: &str) -> Result<()> {
        self.run(&["-X", chain]).and_then(output_to_result)
    }

    /// Flushes all chains in a table.
    pub fn flush_table(&self) -> Result<()> {
        self.run(&["-F"]).and_then(output_to_result)
    }

    fn get_list<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Vec<String>> {
        let stdout = self.run(args)?.stdout;
        Ok(String::from_utf8_lossy(stdout.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .collect())
    }

    /// Set whether iptables is called with the -n (--numeric) option,
    /// to avoid host name and port name lookups
    pub fn set_numeric(&mut self, numeric: bool) {
        self.is_numeric = numeric;
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output> {
        let mut output_cmd = self.command();
        output_cmd.args(args);
        self.run_cmd(&mut output_cmd)
    }

    fn run_cmd(&self, cmd: &mut Command) -> Result<Output> {
        let mut file_lock = None;

        let output;

        if self.has_wait {
            output = cmd.arg("--wait").output()?;
        } else {
            file_lock = Some(File::create("/var/run/xtables_old.lock")?);

            let mut need_retry = true;
            while need_retry {
                match flock(
                    file_lock.as_ref().unwrap().as_raw_fd(),
                    FlockArg::LockExclusiveNonblock,
                ) {
                    Ok(_) => need_retry = false,
                    Err(e) if e == nix::errno::Errno::EAGAIN => {
                        // FIXME: may cause infinite loop
                        need_retry = true;
                    }
                    Err(e) => {
                        return Err(IptablesError::Other(e.to_string()));
                    }
                }
            }
            output = cmd.output()?;
        }

        if let Some(f) = file_lock {
            drop(f)
        }
        Ok(output)
    }
}
