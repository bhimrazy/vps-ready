//! Reading OpenSSH server configuration.
//!
//! - [`effective`] parses the output of `sshd -T`, the effective settings
//!   after sshd has applied its own rules.
//! - [`files`] reads `sshd_config` and its `Include` files, to explain where a
//!   setting comes from and whether a drop-in directory is read early enough.
//!
//! The file reader follows `sshd_config(5)` for the parts it needs and is not
//! a validator: unknown keywords are kept as they are.

pub mod effective;
pub mod files;

pub use effective::SshdConfig;
pub use files::{Config, Directive, Error, IncludeCheck, Os, Source};
