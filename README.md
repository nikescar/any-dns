# any-dns

![Crates.io Version](https://img.shields.io/crates/v/any-dns)


Lightweight DNS server with Middleware support for non-ICANN domains made in Rust.

## Example

Build DNS server and resolve `any.dns` to `37.27.13.182`.


```rust
use std::{error::Error, net::Ipv4Addr};
use any_dns::{CustomHandler, Builder};
use simple_dns::{Packet, ResourceRecord};


#[derive(Clone, Debug)]
struct MyHandler {}

impl CustomHandler for MyHandler {
    fn lookup(&mut self, query: &Vec<u8>) -> std::prelude::v1::Result<Vec<u8>, Box<dyn Error>> {
        // Parse query with any dns library. Here, we use `simple_dns``.
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0)
        .expect("Valid query");
        if question.qname.to_string() != "any.dns" 
            || question.qtype != simple_dns::QTYPE::TYPE(simple_dns::TYPE::A) {
            // Fallback to ICANN
            return Err("Not Implemented".into());
        };

        // Construct DNS reply
        let mut reply = Packet::new_reply(packet.id());
        reply.questions.push(question.clone());
        let ip: Ipv4Addr = "37.27.13.182".parse().unwrap();
        let record = ResourceRecord::new(
            question.qname.clone(), 
            simple_dns::CLASS::IN, 
            120, 
            simple_dns::rdata::RData::A(ip.try_into().unwrap())
        );
        reply.answers.push(record);
        Ok(reply.build_bytes_vec().unwrap())
    }
}


fn main(){
    let anydns = Builder::new()
        .handler(MyHandler{}) // Add custom handler
        .build();
    println!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");
    anydns.wait_on_ctrl_c();

    println!("Got it! Exiting...");
    anydns.join(); // Stop server
}
```

Check it out: `nslookup any.dns 127.0.0.1`