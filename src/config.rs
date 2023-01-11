//! app config

use std::{fmt::Display, fs::File, io::Read, str::FromStr};

use anyhow::{bail, Error, Result};
use kdl::KdlDocument;

use crate::Cli;

#[derive(Clone, Debug)]
pub struct Config {
    /// default 1080
    pub port: u16,
    /// redirect DNS traffic. This option only works with redirect mode
    pub redirect_dns: bool,
    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`,
    /// or `redirect`.
    pub mode: ProxyMode,
    /// Override dns server address. This option only works with tproxy mode
    pub override_dns: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    #[default]
    Redirect,
    Trace,
    TProxy,
}

impl Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Redirect => write!(f, "redirect"),
            ProxyMode::Trace => write!(f, "trace"),
            ProxyMode::TProxy => write!(f, "tproxy"),
        }
    }
}

impl FromStr for ProxyMode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "redirect" => Ok(Self::Redirect),
            "trace" => Ok(Self::Trace),
            "tproxy" => Ok(Self::TProxy),
            _ => bail!("parse mode error"),
        }
    }
}

impl Config {
    pub fn init(cli: &Cli) -> Result<Self> {
        let mut config_str = String::new();
        if let Some(config_path) = &cli.config {
            let mut file = File::open(config_path)?;
            file.read_to_string(&mut config_str)?;
        }
        let doc: KdlDocument = config_str.parse()?;

        let mode = cli
            .mode
            .to_owned()
            .unwrap_or_else(|| {
                doc.get_arg("mode")
                    .map(|i| i.as_string().unwrap())
                    .unwrap_or("redirect")
                    .to_string()
            })
            .parse()?;
        let override_dns = if matches!(mode, ProxyMode::TProxy) {
            if let Some(d) = &cli.override_dns {
                Some(d.to_string())
            } else {
                doc.get_arg("overide_dns")
                    .map(|i| i.as_string().unwrap().to_string())
            }
        } else {
            None
        };

        let r = Self {
            port: cli.port.unwrap_or_else(|| {
                doc.get_arg("port")
                    .map(|i| i.as_i64().unwrap() as u16)
                    .unwrap_or(1080)
            }),
            redirect_dns: cli.redirect_dns.unwrap_or_else(|| {
                doc.get_arg("redirect_dns")
                    .map(|i| i.as_bool().unwrap())
                    .unwrap_or_default()
            }),
            mode,
            override_dns,
        };
        Ok(r)
    }
}
