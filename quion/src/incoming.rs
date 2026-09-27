use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{connection::Connection, error::ConnectionError};

/// Accepted inbound connection handshake.
#[derive(Debug)]
pub struct Incoming {
    connection: Option<Connection>,
}

impl Incoming {
    #[allow(dead_code)]
    pub(crate) fn new(connection: Connection) -> Self {
        Self {
            connection: Some(connection),
        }
    }
}

impl Future for Incoming {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.connection.take().ok_or(ConnectionError::LocallyClosed))
    }
}
