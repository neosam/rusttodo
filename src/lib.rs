//! Task management library to successfully complete tasks

//#![feature (log_syntax, trace_macros)]

#[macro_use]
pub mod hash;
#[macro_use]
pub mod io;
#[macro_use]
pub mod hashio_1;
#[macro_use]
pub mod hashio;
pub mod lazyio;
pub mod log;
pub mod iolog;
pub mod task;

pub mod tasklog;
