use dyn_clone::DynClone;
use std::fmt::Debug;
use async_trait::async_trait;

use crate::dns_socket::AsyncDnsSocket;


#[derive(thiserror::Error, Debug)]
pub enum CustomHandlerError {
    #[error(transparent)]
    IO(#[from] crate::dns_socket::RequestError),

    #[error("Query is not processed by handler. Fallback to ICANN. {0}")]
    Unhandled(&'static str),
}



/**
 * Trait to implement to make AnyDns use a custom handler.
 * Important: Handler must be clonable so it can be used by multiple threads.
 */
#[async_trait]
pub trait CustomHandler: DynClone + Send + Sync {
    async fn lookup(&mut self, query: &Vec<u8>, socket: AsyncDnsSocket) -> Result<Vec<u8>, CustomHandlerError>;
}

/**
 * Clonable handler holder
 */
pub struct HandlerHolder {
    pub func: Box<dyn CustomHandler>,
}

impl Clone for HandlerHolder {
    fn clone(&self) -> Self {
        Self {
            func: dyn_clone::clone_box(&*self.func),
        }
    }
}

impl Debug for HandlerHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerHolder")
            .field("func", &"HandlerHolder")
            .finish()
    }
}

impl HandlerHolder {
    /**
     * Bootstrap a holder from a struct that implements the CustomHandler.
     */
    pub fn new(f: impl CustomHandler + 'static) -> Self {
        HandlerHolder { func: Box::new(f) }
    }

    pub async fn call(&mut self, query: &Vec<u8>, socket: AsyncDnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
        self.func.lookup(query, socket).await
    }
}

#[derive(Clone)]
pub struct EmptyHandler {}

impl EmptyHandler {
    pub fn new() -> Self {
        EmptyHandler {}
    }
}

#[async_trait]
impl CustomHandler for EmptyHandler {
    async fn lookup(&mut self, query: &Vec<u8>, socket: AsyncDnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
        Err(CustomHandlerError::Unhandled("Not implemented".into()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use async_trait::async_trait;
    use crate::dns_socket::AsyncDnsSocket;

    use super::{CustomHandler, CustomHandlerError, HandlerHolder};

    struct ClonableStruct {
        value: String,
    }

    impl Clone for ClonableStruct {
        fn clone(&self) -> Self {
            Self {
                value: format!("{} cloned", self.value.clone()),
            }
        }
    }

    #[derive(Clone)]
    pub struct TestHandler {
        value: ClonableStruct,
    }

    impl TestHandler {
        pub fn new(value: &str) -> Self {
            TestHandler {
                value: ClonableStruct {
                    value: value.to_string(),
                },
            }
        }
    }
    #[async_trait]
    impl CustomHandler for TestHandler {
        async fn lookup(&mut self, query: &Vec<u8>, socket: AsyncDnsSocket) -> Result<Vec<u8>, CustomHandlerError> {
            println!("value {}", self.value.value);
            Err(CustomHandlerError::Unhandled("Not implemented".into()))
        }
    }

    #[tokio::test]
    async fn run_processor() {
        let mut test1 = TestHandler::new("test1");
        let holder1 = HandlerHolder::new(test1);
        let mut cloned = holder1.clone();
        let icann_fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let socket = AsyncDnsSocket::new("0.0.0.0:18293".parse().unwrap(), icann_fallback, holder1.clone()).await.unwrap();
        let result = cloned.call(&vec![], socket).await;
        assert!(result.is_err());
    }
}
