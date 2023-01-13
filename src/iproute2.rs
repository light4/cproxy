#![allow(dead_code)]

use std::{
    ffi::OsStr,
    os::unix::process::CommandExt,
    process::{Command, Output},
};

use strum_macros::{EnumString, IntoStaticStr};

use crate::errors::IPRoute2Error;

pub type Result<T, E = IPRoute2Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, Copy)]
pub struct IPRoute2 {
    binary: &'static str,
    object: Option<Object>,
    action: Option<Action>,
    cmd_uid: Option<u32>,
    cmd_gid: Option<u32>,
}

#[allow(non_camel_case_types)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, IntoStaticStr)]
pub enum Object {
    address,
    addrlabel,
    amt,
    fou,
    help,
    ila,
    ioam,
    l2tp,
    link,
    macsec,
    maddress,
    monitor,
    mptcp,
    mroute,
    mrule,
    neighbor,
    neighbour,
    netconf,
    netns,
    nexthop,
    ntable,
    ntbl,
    route,
    rule,
    sr,
    tap,
    tcpmetrics,
    token,
    tunnel,
    tuntap,
    vrf,
    xfrm,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    List,
    Delete,
}

impl Action {
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::List => "list",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct IPRoute2Builder {
    binary: &'static str,
    object: Option<Object>,
    action: Option<Action>,
    cmd_uid: Option<u32>,
    cmd_gid: Option<u32>,
}

impl IPRoute2Builder {
    pub fn new() -> Self {
        Self {
            binary: "ip",
            cmd_uid: None,
            cmd_gid: None,
            ..Default::default()
        }
    }

    #[inline]
    pub fn object(mut self, object: Object) -> Self {
        self.object = Some(object);
        self
    }

    #[inline]
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    #[inline]
    pub fn add(mut self) -> Self {
        self.action = Some(Action::Add);
        self
    }

    #[inline]
    pub fn list(mut self) -> Self {
        self.action = Some(Action::List);
        self
    }

    #[inline]
    pub fn delete(mut self) -> Self {
        self.action = Some(Action::Delete);
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

    pub fn build(&self) -> IPRoute2 {
        IPRoute2 {
            binary: self.binary,
            object: self.object,
            action: self.action,
            cmd_uid: self.cmd_uid,
            cmd_gid: self.cmd_gid,
        }
    }
}

impl IPRoute2 {
    #[inline]
    pub fn object(mut self, object: Object) -> Self {
        self.object = Some(object);
        self
    }

    #[inline]
    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    #[inline]
    pub fn add(mut self) -> Self {
        self.action = Some(Action::Add);
        self
    }

    #[inline]
    pub fn list(mut self) -> Self {
        self.action = Some(Action::List);
        self
    }

    #[inline]
    pub fn delete(mut self) -> Self {
        self.action = Some(Action::Delete);
        self
    }

    #[inline]
    pub fn command(&self) -> Result<Command> {
        let mut cmd = Command::new(self.binary);
        let object: &'static str = self
            .object
            .ok_or(IPRoute2Error::BuildCommand(
                "please provide correct object".to_string(),
            ))?
            .into();
        let action = self
            .action
            .ok_or(IPRoute2Error::BuildCommand(
                "please provide correct action".to_string(),
            ))?
            .to_str();
        cmd.arg(object);
        cmd.arg(action);
        if let Some(uid) = self.cmd_uid {
            cmd.uid(uid);
        }
        if let Some(gid) = self.cmd_gid {
            cmd.gid(gid);
        }
        Ok(cmd)
    }

    pub fn run<I, S>(&self, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self
            .command()?
            .args(args)
            .output()
            .expect("run ip command error");
        if !output.status.success() {
            return Err(IPRoute2Error::from(output));
        }

        Ok(output)
    }
}
