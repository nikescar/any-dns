use std::{ net::SocketAddr, sync::{atomic::AtomicBool, Arc}, time::{Duration, Instant}};

use simple_dns::{Packet, SimpleDnsError};
use tokio::{net::UdpSocket, sync::{broadcast, oneshot}};

use crate::{async_custom_handler::HandlerHolder, pending_request::{PendingRequest, PendingRequestStore}};

#[derive(Debug, Clone)]
struct DnsPacket {
    id: u16,
    data: Vec<u8>,
    from: SocketAddr
}


#[derive(thiserror::Error, Debug)]
pub enum RequestError {
    // Dns packet parse error
    #[error("Dns packet parse error: {0}")]
    Parse(#[from] SimpleDnsError),

    #[error(transparent)]
    IO(#[from] tokio::io::Error),

    #[error("No answer received within timeout. {0}")]
    NoAnswer(#[from] oneshot::error::RecvError),

    #[error("No answer received within timeout. {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

/**
 * DNS UDP socket
 */
#[derive(Debug, Clone)]
pub struct AsyncDnsSocket {
    socket: Arc<UdpSocket>,
    pending: PendingRequestStore,
    handler: HandlerHolder
}

impl AsyncDnsSocket {

    /**
     * Creates a new DNS socket
     */
    pub async fn new(listening: SocketAddr, handler: HandlerHolder)-> tokio::io::Result<Self> {
        let socket = UdpSocket::bind(listening).await?;
        Ok(Self {
            socket: Arc::new(socket),
            pending: PendingRequestStore::new(),
            handler
        })
    }

    /**
     * Send message to address
     */
    pub async fn send_to(&self, buffer: &[u8], target: &SocketAddr) -> tokio::io::Result<usize> {
        let res = self.socket.send_to(buffer, target).await;
        res
    }

    /**
     * Run receive loop
     */
    pub async fn receive_loop(&mut self) {
        loop {
            if let Err(err) = self.receive().await {
                eprintln!("Error while trying to receive {err}");
            }
        };
    }

    async fn receive(&mut self) -> Result<(), RequestError> {
        let mut buffer = [0; 1024];
        println!("Wait to receive data");
        let (size, from) = self.socket.recv_from(&mut buffer).await?;
        let mut data = buffer.to_vec();
        data.drain((size + 1)..data.len());
        let packet = Packet::parse(&data)?;
        
        let pending = self.pending.remove(&packet.id(), &from);
        if pending.is_some() {
            let query = pending.unwrap();
            query.tx.send(data).unwrap();
            return Ok(());
        };

        let is_reply = packet.questions.len() == 0;
        if is_reply {
            eprintln!("Reply with no associated request {:?}", packet);
            return Ok(());
        };

        // New query
        self.on_query(&data).await;

        Ok(())
    }

    /**
     * New query received.
     */
    async fn on_query(&mut self, query: &Vec<u8>) {
        self.handler.call(query, self.clone());
    }

    /**
     * Send dns request
     */
    pub async fn request(&mut self, query: &Vec<u8>, to: &SocketAddr, timeout: Duration) -> Result<Vec<u8>, RequestError> {
        let packet = Packet::parse(&query)?;
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        let request = PendingRequest {
            query_id: packet.id(),
            sent_at: Instant::now(),
            to: to.clone(),
            tx
        };

        self.pending.insert(request);
        self.send_to(query, to).await?;


        // Wait on response
        let reply = tokio::time::timeout(timeout, rx).await;
        if reply.is_err() {
            // Timeout, remove pending again
            self.pending.remove(&packet.id(), &to);
        };
        let reply = reply??;
        Ok(reply)
    }

}




#[cfg(test)]
mod tests {
    use std::{error::Error, net::SocketAddr, time::Duration};
    use simple_dns::{Name, Packet, Question};

    use crate::async_custom_handler::{EmptyHandler, HandlerHolder};

    use super::AsyncDnsSocket;

    #[tokio::test]
    async fn run_processor() {
        let listening: SocketAddr = "0.0.0.0:34254".parse().unwrap();
        let handler = HandlerHolder::new(EmptyHandler::new());
        let mut socket = AsyncDnsSocket::new(listening, handler).await.unwrap();

        let mut run_socket = socket.clone();
        tokio::spawn(async move {
            run_socket.receive_loop().await;
        });

        let mut query = Packet::new_query(0);
        let qname = Name::new("google.ch").unwrap();
        let qtype = simple_dns::QTYPE::TYPE(simple_dns::TYPE::A);
        let qclass = simple_dns::QCLASS::CLASS(simple_dns::CLASS::IN);
        let question = Question::new(qname, qtype, qclass, false);
        query.questions = vec![question];

        let query = query.build_bytes_vec_compressed().unwrap();
        let to: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = socket.request(&query, &to, Duration::from_secs(5)).await.unwrap();
        let reply = Packet::parse(&result).unwrap();
        dbg!(reply);

    }
}
