//! Simvader — an ultra-low-latency MCP security gateway.
//!
//! The library exposes the deterministic taint-style engine (SPELLSMITH stages 1–3) and the
//! aggregating gateway so it can be embedded, benchmarked, and tested independently of the CLI.

pub mod audit;
pub mod augment;
pub mod canon;
pub mod conceal;
pub mod config;
pub mod gateway;
pub mod guard;
pub mod http;
pub mod install;
pub mod policy;
pub mod reflect;
pub mod risk;
