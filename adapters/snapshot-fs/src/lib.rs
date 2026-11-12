//! Descriptor-capability materialization of immutable semantic snapshots.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(target_os = "macos"))]
compile_error!("vellum-adapter-semantic-snapshot-fs-macos supports only macOS");
