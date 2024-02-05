use std::{net::SocketAddr, time::Instant, collections::HashMap, sync::{Mutex, Arc}};

use tokio::sync::oneshot;

#[derive(Debug)]
pub struct PendingRequest {
    pub to: SocketAddr,
    pub sent_at: Instant,
    pub query_id: u16,
    pub tx: oneshot::Sender<Vec<u8>>
}

#[derive(Debug, Clone, Hash, PartialEq)]
struct PendingRequestKey {
    to: SocketAddr,
    query_id: u16
}

impl Eq for PendingRequestKey {}


/**
 * Multi-threading safe store.
 * Use `.clone()` to give each thread one store struct.
 * The data will stay shared.
 */
#[derive(Debug, Clone)]
pub struct PendingRequestStore {
    pending: Arc<Mutex<HashMap<PendingRequestKey, PendingRequest>>>,
}

impl PendingRequestStore {
    pub fn insert(&mut self, request: PendingRequest) {
        let mut locked = self.pending.lock().expect("Lock success");
        let key = PendingRequestKey {
            query_id: request.query_id.clone(),
            to: request.to.clone()
        };
        locked.insert(key, request);
    }

    pub fn remove(&mut self, id: &u16, from: &SocketAddr) -> Option<PendingRequest> {
        let mut locked = self.pending.lock().expect("Lock success");
        let key = PendingRequestKey {
            query_id: id.clone(),
            to: from.clone()
        };
        locked.remove(&key)
    }

    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new()))
        }
    }
}

