#![allow(unused)]

pub mod error;
pub mod server;
mod dns_thread;
mod custom_handler;
mod pending_queries;
mod dns_thread_async;
mod async_dns_socket;
mod pending_request;
mod async_custom_handler;
mod async_server;

pub use crate::error::{Error, Result};
pub use crate::server::{AnyDNS, Builder};
pub use crate::custom_handler::{CustomHandler};