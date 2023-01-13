use std::{io, process::Output};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum IptablesError {
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("run command error: code {code} msg {msg}")]
    Command { code: i32, msg: String },
    #[error("version error: {0}")]
    Version(String),
    #[error("other error")]
    Other(String),
}

impl From<Output> for IptablesError {
    fn from(output: Output) -> Self {
        Self::Command {
            code: output.status.code().unwrap_or(-1),
            msg: String::from_utf8_lossy(output.stderr.as_slice()).into(),
        }
    }
}

impl From<semver::Error> for IptablesError {
    fn from(e: semver::Error) -> Self {
        Self::Version(e.to_string())
    }
}

impl From<&str> for IptablesError {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

impl From<String> for IptablesError {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

#[derive(Error, Debug)]
pub enum IPRoute2Error {
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("run command error: code {code} msg {msg}")]
    Command { code: i32, msg: String },
    #[error("init command error: {0}")]
    BuildCommand(String),
}

impl From<Output> for IPRoute2Error {
    fn from(output: Output) -> Self {
        Self::Command {
            code: output.status.code().unwrap_or(-1),
            msg: String::from_utf8_lossy(output.stderr.as_slice()).into(),
        }
    }
}
