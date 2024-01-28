#![allow(unused)]

mod error;
mod server;
mod dns_thread;
mod pending_queries;
mod custom_handler;

use std::{cmp::Ordering, error::Error, net::Ipv4Addr, sync::{atomic::AtomicBool, Arc}, thread::sleep, time::Duration};

use any_dns::{CustomHandler, Builder};
use error::Result;
use server::AnyDNS;
use simple_dns::{Packet, PacketFlag, ResourceRecord, QTYPE};

#[derive(Clone, Debug)]
struct MyHandler {}

impl CustomHandler for MyHandler {
    /**
     * Only resolve 1 custom domain 7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy.
     */
    fn lookup(&mut self, query: &Vec<u8>) -> std::prelude::v1::Result<Vec<u8>, Box<dyn Error>> {
        // Parse query with any dns library. Here, we use `simple_dns``.
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");
        if question.qname.to_string() != "any.dns" || question.qtype != simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) {
            // Fallback to ICANN if it is not `7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy`
            return Err("Not Implemented".into());
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


fn main() -> Result<()> {



    println!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");
    let handler = MyHandler{};
    let anydns = Builder::new().handler(handler).verbose(true).build();

    anydns.wait_on_ctrl_c();
    println!("Got it! Exiting...");
    anydns.join();

    Ok(())
}
