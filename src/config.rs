//! app config

use std::{fmt::Display, fs::File, io::Read, path::PathBuf, str::FromStr};

use color_eyre::{
    eyre::{eyre, Report},
    Result,
};
use directories::ProjectDirs;
use kdl::KdlDocument;
use tracing::debug;

use crate::{Cli, PKG_NAME};

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum IPStack {
    V4,
    V6,
    Both,
}

impl IPStack {
    pub const fn has_v4(&self) -> bool {
        match self {
            Self::V4 | Self::Both => true,
            Self::V6 => false,
        }
    }

    pub const fn has_v6(&self) -> bool {
        match self {
            Self::V6 | Self::Both => true,
            Self::V4 => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// default both(ipv4 and ipv6)
    pub ip_stack: IPStack,
    /// config path
    pub path: Option<PathBuf>,
    /// project directories, see https://github.com/dirs-dev/directories-rs
    pub project_dirs: ProjectDirs,
    /// default 1080
    pub port: u16,
    /// redirect DNS traffic. This option only works with redirect mode
    pub redirect_dns: bool,
    /// Proxy mode can be `trace` (use iptables TRACE target to debug program network), `tproxy`,
    /// or `redirect`.
    pub mode: ProxyMode,
    /// Override dns server address. This option only works with tproxy mode
    pub override_dns: Option<String>,
    /// iptables_prefix
    pub iptables_prefix: String,
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
    type Err = Report;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "redirect" => Ok(Self::Redirect),
            "trace" => Ok(Self::Trace),
            "tproxy" => Ok(Self::TProxy),
            _ => Err(eyre!("parse mode error")),
        }
    }
}

impl Config {
    pub fn init(cli: &Cli) -> Result<Self> {
        let project_dirs = ProjectDirs::from("io", "i01", PKG_NAME).unwrap();

        let default_config = project_dirs.config_dir().join("config.kdl");

        let mut config_str = String::new();
        let config_path = if let Some(p) = &cli.config {
            Some(p.to_owned())
        } else if default_config.exists() {
            Some(default_config)
        } else {
            None
        };

        if let Some(p) = &config_path {
            let mut file = File::open(p)?;
            file.read_to_string(&mut config_str)?;
        }

        let doc: KdlDocument = config_str.parse()?;

        let ip_stack = {
            let stack_str = if let Some(s) = &cli.ip_stack {
                s
            } else {
                doc.get_arg("ip_stack")
                    .map(|i| i.as_string().unwrap())
                    .unwrap_or("both")
            };
            match stack_str {
                "ipv4" | "v4" => IPStack::V4,
                "ipv6" | "v6" => IPStack::V6,
                "both" | "ipv4,ipv6" | "v4,v6" => IPStack::Both,
                _ => IPStack::V4,
            }
        };
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

        let iptables_prefix = doc
            .get_arg("iptables_prefix")
            .map(|i| i.as_string().unwrap())
            .unwrap_or(PKG_NAME)
            .to_string();

        let r = Self {
            ip_stack,
            path: config_path,
            project_dirs,
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
            iptables_prefix,
        };

        debug!("CProxy config: {r:#?}");
        Ok(r)
    }
}
