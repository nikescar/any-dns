//! Main server implementation

use simple_dns::{Packet, Name, Question};
use tokio::{net::unix::pipe::Receiver, sync::oneshot};
use std::{
    collections::HashMap,
    net::{SocketAddr, UdpSocket}, str::FromStr, thread::sleep, time::{Duration, Instant}, sync::{mpsc::channel, Arc, Mutex}, ops::Range,
};

use crate::{ dns_socket::AsyncDnsSocket, custom_handler::{HandlerHolder, EmptyHandler, CustomHandler}};



pub struct Builder {
    icann_resolver: SocketAddr,
    listen: SocketAddr,
    handler: HandlerHolder,
    verbose: bool
}

impl Builder {
    pub fn new() -> Self {
        Self {
            icann_resolver: SocketAddr::from(([192, 168, 1, 1], 53)),
            listen: SocketAddr::from(([0, 0, 0, 0], 53)),
            handler: HandlerHolder::new(EmptyHandler::new()),
            verbose: false
        }
    }

    /// Set the DNS resolver for normal ICANN domains. Defaults to 192.168.1.1:53
    pub fn icann_resolver(mut self, icann_resolver: SocketAddr) -> Self {
        self.icann_resolver = icann_resolver;
        self
    }

    /// Set socket the server should listen on. Defaults to 0.0.0.0:53
    pub fn listen(mut self, listen: SocketAddr) -> Self {
        self.listen = listen;
        self
    }

    /// Makes the server log verbosely.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /** Set handler to process the dns packet. `Ok()`` should include a dns packet with answers. `Err()` will fallback to ICANN. */
    pub fn handler(mut self, handler: impl CustomHandler + 'static) -> Self {
        self.handler = HandlerHolder::new(handler);
        self
    }

    // /** Build and start server. */
    pub async fn build(self) -> tokio::io::Result<AsyncAnyDNS> {
        AsyncAnyDNS::new(self.listen, self.icann_resolver, self.handler).await
    }

    /** Calculates the dns packet id range for each thread. */
    fn calculate_id_range(thread_count: u16, i: u16) -> Range<u16> {
        let bucket_size = u16::MAX / thread_count;
        Range{
            start: i * bucket_size,
            end: (i + 1) * bucket_size -1
        }
    }
}

#[derive(Debug)]
pub struct AsyncAnyDNS {
    socket: AsyncDnsSocket,
    join_handle: tokio::task::JoinHandle<()>
}

impl AsyncAnyDNS {

    pub async fn new(listener: SocketAddr, icann_fallback: SocketAddr, handler: HandlerHolder) -> tokio::io::Result<Self> {
        let socket = AsyncDnsSocket::new(listener, icann_fallback, handler).await?;
        let mut receive_socket = socket.clone();
        let join_handle = tokio::spawn(async move {
            receive_socket.receive_loop().await;
        });

        let server = Self {
            socket,
            join_handle
        };


        Ok(server)
    }

    /**
     * Stops the server and consumes the instance.
     */
    pub fn stop(self) {
        self.join_handle.abort();
    }

    /**
     * Waits on CTRL+C
     */
    pub fn wait_on_ctrl_c(&self) {
        let (tx, rx) = channel();
        ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");
        rx.recv().expect("Could not receive from channel.");
    }
}

// impl Default for AsyncAnyDNS {
//     fn default() -> Self {
//         let builder = Builder::new();
//         builder.build()
//     }
// }

#[cfg(test)]
mod tests {
    use std::{error::Error, net::SocketAddr, thread::sleep, time::Duration};
    use simple_dns::{Name, Packet, Question};

    use crate::{custom_handler::EmptyHandler, server::AsyncAnyDNS, server::Builder};


    #[tokio::test]
    async fn run() {
        let listening: SocketAddr = "0.0.0.0:34255".parse().unwrap();
        let dns = Builder::new().listen(listening).build().await.unwrap();
        println!("Started");
        sleep(Duration::from_secs(5));
        println!("Stop");
        dns.stop();
        println!("Stopped");

        // let mut query = Packet::new_query(0);
        // let qname = Name::new("google.ch").unwrap();
        // let qtype = simple_dns::QTYPE::TYPE(simple_dns::TYPE::A);
        // let qclass = simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN);
        // let question = Question::new(qname, qtype, qclass, false);
        // query.questions = vec![question];

        // let query = query.build_bytes_vec_compressed().unwrap();
        // let to: SocketAddr = "8.8.8.8:53".parse().unwrap();
        // let result = socket.request(&query, &to, Duration::from_secs(5)).await.unwrap();
        // let reply = Packet::parse(&result).unwrap();
        // dbg!(reply);

    }
}
