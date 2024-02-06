// #![allow(unused)]

mod dns_socket;
mod pending_request;
mod custom_handler;
mod server;
mod query_id_manager;

use std::{cmp::Ordering, error::Error, net::Ipv4Addr, sync::{atomic::AtomicBool, Arc}, thread::sleep, time::Duration};

use custom_handler::{CustomHandler, CustomHandlerError};
use dns_socket::{AsyncDnsSocket, RequestError};
use async_trait::async_trait;
use simple_dns::{Packet, PacketFlag, ResourceRecord, QTYPE};

use crate::server::Builder;

#[derive(Clone, Debug)]
struct MyHandler {}

#[async_trait]
impl CustomHandler for MyHandler {
    /**
     * Only resolve 1 custom domain any.dns.
     */
    async fn lookup(&mut self, query: &Vec<u8>, socket: AsyncDnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
        // Parse query with any dns library. Here, we use `simple_dns``.
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");
        if question.qname.to_string() != "any.dns" || question.qtype != simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) {
            // Fallback to ICANN if it is not `any.dns`
            return Err(CustomHandlerError::Unhandled("Not interested"));
        };

        // Construct DNS reply
        let mut reply = Packet::new_reply(packet.id());
        reply.questions.push(question.clone());
        let ip: Ipv4Addr = "37.27.13.182".parse().unwrap();
        let record = ResourceRecord::new(question.qname.clone(), simple_dns::CLASS::IN, 120, simple_dns::rdata::RData::A(ip.try_into().unwrap()));
        reply.answers.push(record);
        Ok(reply.build_bytes_vec().unwrap())
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    println!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");
    let handler = MyHandler{};
    let anydns = Builder::new().handler(handler).verbose(true).icann_resolver("8.8.8.8:53".parse().unwrap()).build().await?;

    anydns.wait_on_ctrl_c();
    println!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
