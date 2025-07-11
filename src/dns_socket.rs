#![allow(unused)]
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use simple_dns::{Packet, SimpleDnsError};
use tokio::{net::UdpSocket, sync::oneshot};
use tracing::Level;

use crate::{
    custom_handler::{CustomHandlerError, HandlerHolder},
    pending_request::{PendingRequest, PendingRequestStore},
    query_id_manager::QueryIdManager,
};

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum RequestError {
    #[error("Dns packet parse error: {0}")]
    Parse(#[from] SimpleDnsError),

    #[error(transparent)]
    IO(#[from] tokio::io::Error),

    #[error("Timeout. No answer received from forward server.")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

/**
 * DNS UDP socket
 */
#[derive(Debug, Clone)]
pub struct DnsSocket {
    socket: Arc<UdpSocket>,
    pending: PendingRequestStore,
    handler: HandlerHolder,
    icann_fallback: SocketAddr,
    id_manager: QueryIdManager,
}

impl DnsSocket {
    /**
     * Creates a new DNS socket
     */
    pub async fn new(
        listening: SocketAddr,
        icann_fallback: SocketAddr,
        handler: HandlerHolder,
    ) -> tokio::io::Result<Self> {
        let socket = UdpSocket::bind(listening).await?;
        Ok(Self {
            socket: Arc::new(socket),
            pending: PendingRequestStore::new(),
            handler,
            icann_fallback,
            id_manager: QueryIdManager::new(),
        })
    }

    /**
     * Send message to address
     */
    pub async fn send_to(&self, buffer: &[u8], target: &SocketAddr) -> tokio::io::Result<usize> {
        self.socket.send_to(buffer, target).await
    }

    /**
     * Run receive loop
     */
    pub async fn receive_loop(&mut self) {
        loop {
            if let Err(err) = self.receive_datagram().await {
                tracing::error!("Error while trying to receive {err}");
            }
        }
    }

    async fn receive_datagram(&mut self) -> Result<(), RequestError> {
        let mut buffer = [0; 1024];
        let (size, from) = self.socket.recv_from(&mut buffer).await?;
        let mut data = buffer.to_vec();
        if data.len() > size {
            data.drain((size + 1)..data.len());
        }
        let packet = Packet::parse(&data)?;

        let pending = self.pending.remove_by_forward_id(&packet.id(), &from);
        if pending.is_some() {
            tracing::trace!("Received response from forward server. Send back to client.");
            let query = pending.unwrap();
            query.tx.send(data).unwrap();
            return Ok(());
        };

        let is_reply = packet.questions.len() == 0;
        if is_reply {
            let span = tracing::span!(Level::DEBUG, "", forward_id = packet.id());
            let guard = span.enter();
            tracing::debug!(
                "Received reply without an associated query {:?}. Ignore.",
                packet
            );
            return Ok(());
        };

        // New query
        let mut socket = self.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            let query_packet = Packet::parse(&data).unwrap();
            let span = tracing::span!(Level::TRACE, "", query_id = query_packet.id());
            let guard = span.enter();

            let question = query_packet.questions.first();
            if question.is_none() {
                tracing::debug!(
                    "Query with no associated a question {:?}. Ignore.",
                    query_packet
                );
                return;
            };
            let question = question.unwrap();
            tracing::trace!(
                "Received new query {} {:?}",
                question.qname,
                question.qtype
            );
            let query_result = socket.on_query(&data, &from).await;
                // tracing::trace!("query packet: {:?}", query_packet);
                // tracing::trace!("query data: {:?}", data);
                // tracing::trace!("query result: {:?}", query_result);
                match query_result {
                    Ok(_) => {
                        tracing::debug!(
                            "Processed query {} {:?} within {}ms",
                            question.qname,
                            question.qtype,
                            start.elapsed().as_millis()
                        );
                    }
                    Err(err) => {
                        tracing::error!(
                            "Failed to respond to query {} {:?}: {}",
                            question.qname,
                            question.qtype,
                            err
                        );
                    }
                };
        });

        Ok(())
    }

    /**
     * New query received.
     */
    async fn on_query(&mut self, query: &Vec<u8>, from: &SocketAddr) -> Result<(), RequestError> {
        match self.query(query).await {
            Ok(reply) => {
                self.send_to(&reply, from).await?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /**
     * Query this dns for data
     */
    pub async fn query(&mut self, query: &Vec<u8>) -> Result<Vec<u8>, RequestError> {
        tracing::trace!("Try to resolve the query with the custom handler.");
        let result = self.handler.call(query, self.clone()).await;
        tracing::trace!("Custom handler result {:?}", result);  
        if let Ok(reply) = result {
            tracing::trace!("Custom handler resolved the query.");
            // All good. Handler handled the query
            return Ok(reply);
        };

        match result.unwrap_err() {
            CustomHandlerError::Unhandled => {
                // Fallback to ICANN
                tracing::debug!("Custom handler rejected the query.");
                let reply = self.forward_to_icann(query, Duration::from_secs(5)).await?;
                Ok(reply)
            }
            CustomHandlerError::IO(e) => Err(e),
        }
    }

    /**
     * Replaces the id of the dns packet.
     */
    fn replace_packet_id(&self, packet: &mut Vec<u8>, new_id: u16) {
        let id_bytes = new_id.to_be_bytes();
        std::mem::replace(&mut packet[0], id_bytes[0]);
        std::mem::replace(&mut packet[1], id_bytes[1]);
    }

    /**
     * Send dns request
     */
    pub async fn forward(
        &mut self,
        query: &Vec<u8>,
        to: &SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, RequestError> {
        let packet = Packet::parse(&query)?;
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        let forward_id = self.id_manager.get_next(to);
        let original_id = packet.id();
        let span = tracing::span!(Level::DEBUG, "", forward_id = forward_id);
        let guard = span.enter();
        tracing::trace!("Fallback to forward server {to:?}.");
        let request = PendingRequest {
            original_query_id: original_id,
            forward_query_id: forward_id,
            sent_at: Instant::now(),
            to: to.clone(),
            tx,
        };

        let mut query = packet.build_bytes_vec_compressed()?;
        self.replace_packet_id(&mut query, forward_id);

        self.pending.insert(request);
        self.send_to(&query, to).await?;

        // Wait on response
        let reply = tokio::time::timeout(timeout, rx).await;
        if reply.is_err() {
            // Timeout, remove pending again
            tracing::trace!(
                "Forwarded query original_id={original_id} forward_id={forward_id} timed out."
            );
            self.pending.remove_by_forward_id(&forward_id, &to);
        };
        let mut reply = reply?.unwrap();
        self.replace_packet_id(&mut reply, original_id);
        Ok(reply)
    }

    /**
     * Forward query to icann
     */
    pub async fn forward_to_icann(
        &mut self,
        query: &Vec<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>, RequestError> {
        self.forward(query, &self.icann_fallback.clone(), timeout)
            .await
    }
}

#[cfg(test)]
mod tests {
    use simple_dns::{Name, Packet, Question};
    use std::{net::SocketAddr, time::Duration};

    use crate::custom_handler::{EmptyHandler, HandlerHolder};

    use super::DnsSocket;

    #[tokio::test]
    async fn run_processor() {
        let listening: SocketAddr = "0.0.0.0:34254".parse().unwrap();
        let icann_fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let handler = HandlerHolder::new(EmptyHandler::new());
        let mut socket = DnsSocket::new(listening, icann_fallback, handler)
            .await
            .unwrap();

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
        let result = socket
            .forward(&query, &to, Duration::from_secs(5))
            .await
            .unwrap();
        let reply = Packet::parse(&result).unwrap();
        dbg!(reply);
    }
}
