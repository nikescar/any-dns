# any-dns

![Crates.io Version](https://img.shields.io/crates/v/any-dns)


Lightweight DNS server with Middleware support for non-ICANN domains made in Rust. Tokio Async only.

## Example

**Regular DNS** Build server listening on `0.0.0.0:53` and forward queries to `8.8.8.8:53`.


```rust
use std::error::Error;
use any_dns::Builder;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");

    let anydns = Builder::new()
        .icann_resolver("8.8.8.8:53".parse()?)
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    println!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}

```

Test: `nslookup example.com 127.0.0.1`


**Custom Handler** Resolve `any.dns` to an IP.


```rust
use any_dns::{DnsSocket, Builder, CustomHandler, CustomHandlerError};
use async_trait::async_trait;
use simple_dns::{Packet, ResourceRecord};


/**
 * Create Custom handler
*/
#[derive(Clone, Debug)]
struct MyHandler {}

#[async_trait] // <-- Don't forget
impl CustomHandler for MyHandler {
    // `lookup` is called for every dns query
    async fn lookup(&mut self, query: &Vec<u8>, socket: DnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
        // Parse query with any dns library
        let packet = Packet::parse(query).unwrap();
        let question = packet.questions.get(0).expect("Valid query");

        let is_any_dot_dns = question.qname.to_string() == "any.dns" && question.qtype == QTYPE::TYPE(TYPE::A);
        if is_any_dot_dns {
            Ok(self.construct_reply(query)) // Reply with A record IP
        } else {
            Err(CustomHandlerError::Unhandled) // Fallback to ICANN
        }        
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Listening on 0.0.0.0:53. Waiting for Ctrl-C...");
    let handler = MyHandler {};
    let anydns = Builder::new()
        .handler(handler) // Add the handler here.
        .icann_resolver("8.8.8.8:53".parse().unwrap())
        .build()
        .await?;

    anydns.wait_on_ctrl_c().await;
    println!("Got it! Exiting...");
    anydns.stop();

    Ok(())
}
```

Test: `nslookup any.dns 127.0.0.1`


## Logs

anydns uses the tracing crate for logs. Set the environment variable `RUST_LOG=any_dns=trace` to see them.


slides: https://docs.google.com/presentation/d/1gjaeRNerTHDqaGn1oc2ZrZz9wMXSImoT4g--55P8RYY/edit?usp=sharing