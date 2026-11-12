//! One-attempt macOS XPC interpretation of semantic-helper frames.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(target_os = "macos"))]
compile_error!("vellum-adapter-semantic-helper-xpc-macos supports only macOS");
