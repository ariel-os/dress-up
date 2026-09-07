//! Minimal logging helpers shared across this example binary.
//!
//! Every log line is tagged so the flow of manifest processing is easy to scan when
//! redirected to a file or grepped through.

/// Logs a high-level step in the manifest processing pipeline (parsing, authentication, ...).
macro_rules! log_step {
    ($($arg:tt)*) => { println!("[step] {}", format_args!($($arg)*)) };
}

/// Logs a value read out of the manifest (e.g. version, sequence number, section presence).
macro_rules! log_data {
    ($($arg:tt)*) => { println!("[data] {}", format_args!($($arg)*)) };
}

/// Logs an operating-system hook invoked while a command sequence executes.
macro_rules! log_hook {
    ($($arg:tt)*) => { println!("[hook] {}", format_args!($($arg)*)) };
}

/// Logs a testing-only shortcut taken by this example (e.g. skipped authentication).
macro_rules! log_warn {
    ($($arg:tt)*) => { println!("[warn] {}", format_args!($($arg)*)) };
}

pub(crate) use log_data;
pub(crate) use log_hook;
pub(crate) use log_step;
pub(crate) use log_warn;
