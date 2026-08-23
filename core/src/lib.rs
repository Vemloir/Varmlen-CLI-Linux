//! Client-side logic shared by the Varmlen GUI and CLI.
//!
//! These modules were extracted from the Tauri application so that a headless
//! client can build the same xray configuration and speak the same daemon
//! protocol. They must stay free of GUI dependencies.

pub mod daemon_client;
pub mod endpoint;
pub mod fetch;
pub mod split;
pub mod subscription;
pub mod xray;
