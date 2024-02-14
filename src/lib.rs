#![allow(unused)]

mod custom_handler;
mod dns_socket;
mod pending_request;
mod query_id_manager;
mod server;

pub use crate::custom_handler::{CustomHandler, CustomHandlerError, EmptyHandler, HandlerHolder};
pub use crate::dns_socket::DnsSocket;
pub use crate::server::{AnyDNS, Builder};
