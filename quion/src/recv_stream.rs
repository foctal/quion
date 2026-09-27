use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use tokio::sync::Notify;

use quion_proto::{VarInt, streams::StreamId};
use smallvec::SmallVec;

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use crate::connection::EndpointRuntimeNotify;
use crate::{
    connection::{ClosedState, ProtocolMemoryTracker, StreamResetState, StreamWakers},
    error::ReadError,
    qlog::SharedQlogState,
};

/// Owned chunk returned by unordered or chunked stream reads.
pub type Chunk = quion_proto::streams::Chunk;

/// Receive half of a QUIC stream. Dropping it requests STOP_SENDING with code zero.
#[derive(Debug, Default)]
pub struct RecvStream {
    proto: Option<Arc<Mutex<quion_proto::connection::Connection>>>,
    closed_state: Option<Arc<Mutex<ClosedState>>>,
    qlog: SharedQlogState,
    stream_wakers: Option<Arc<Mutex<StreamWakers>>>,
    stream_reset_state: Option<Arc<Mutex<StreamResetState>>>,
    protocol_memory: Arc<ProtocolMemoryTracker>,
    stream_id: Option<StreamId>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    runtime_notify: Option<Arc<Notify>>,
    #[cfg(all(
        feature = "runtime-tokio",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    endpoint_runtime_notify: Arc<Mutex<Option<EndpointRuntimeNotify>>>,
    buffer: Vec<u8>,
    offset: usize,
    read_mode: ReadMode,
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        // A dropped receive half abandons unread data with application code zero.
        let _ = self.stop(VarInt::ZERO);
        let Some(stream_id) = self.stream_id else {
            return;
        };
        if let Some(stream_wakers) = &self.stream_wakers {
            stream_wakers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove_reader(stream_id);
        }
        if let Some(stream_reset_state) = &self.stream_reset_state {
            stream_reset_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove_handle(stream_id);
        }
    }
}

impl RecvStream {
    // Stream handles share independently synchronized connection services;
    // keeping these explicit avoids another allocation and indirection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proto: Arc<Mutex<quion_proto::connection::Connection>>,
        closed_state: Arc<Mutex<ClosedState>>,
        qlog: SharedQlogState,
        stream_wakers: Arc<Mutex<StreamWakers>>,
        stream_reset_state: Arc<Mutex<StreamResetState>>,
        protocol_memory: Arc<ProtocolMemoryTracker>,
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        runtime_notify: Arc<Notify>,
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        endpoint_runtime_notify: Arc<Mutex<Option<EndpointRuntimeNotify>>>,
        stream_id: StreamId,
    ) -> Self {
        stream_reset_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .register_handle(stream_id);
        Self {
            proto: Some(proto),
            closed_state: Some(closed_state),
            qlog,
            stream_wakers: Some(stream_wakers),
            stream_reset_state: Some(stream_reset_state),
            protocol_memory,
            stream_id: Some(stream_id),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            runtime_notify: Some(runtime_notify),
            #[cfg(all(
                feature = "runtime-tokio",
                any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
            ))]
            endpoint_runtime_notify,
            buffer: Vec::new(),
            offset: 0,
            read_mode: ReadMode::Unknown,
        }
    }

    /// Reads available ordered bytes, waiting when necessary.
    pub fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<Option<usize>, ReadError>> + 'a {
        Read { stream: self, buf }
    }

    /// Returns the QUIC stream identifier.
    pub const fn id(&self) -> Option<StreamId> {
        self.stream_id
    }

    /// Returns the stream's final size once FIN or a reset has been received.
    ///
    /// Includes bytes discarded by a reset and any application protocol prefix.
    /// The value is retained for this handle after reads or `stop`, allowing
    /// applications to account for discarded bytes. `None` means the
    /// peer has not supplied a final size yet. This does not consume data or
    /// imply that the reliable prefix has been delivered.
    pub fn final_size(&self) -> Option<u64> {
        let (Some(proto), Some(id), Some(state)) =
            (&self.proto, self.stream_id, &self.stream_reset_state)
        else {
            return None;
        };
        let proto = proto.lock().unwrap_or_else(|p| p.into_inner());
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(size) = proto.recv_stream_final_size(id) {
            state.set_final_size(id, size);
        }
        state.final_size(id)
    }

    /// Waits until the peer supplies the final size, without consuming data.
    ///
    /// This also works after `stop`, when an application needs to account for bytes
    /// discarded by cancellation. Returns a connection error if the connection
    /// closes before the peer supplies the size.
    pub fn received_final_size(&mut self) -> impl Future<Output = Result<u64, ReadError>> + '_ {
        ReceivedFinalSize { stream: self }
    }

    /// Reads exactly enough bytes to fill `buf`.
    pub fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<(), ReadError>> + 'a {
        ReadExact {
            stream: self,
            buf,
            filled: 0,
        }
    }

    /// Reads until FIN while enforcing `max_size`.
    pub fn read_to_end(
        &mut self,
        max_size: usize,
    ) -> impl Future<Output = Result<Vec<u8>, ReadError>> + '_ {
        ReadToEnd {
            stream: self,
            max_size,
            out: Vec::new(),
        }
    }

    /// Waits for a peer reset or graceful stream completion.
    ///
    /// For RESET_STREAM_AT, the reset is not returned until the application
    /// has read the complete reliable prefix.
    pub fn received_reset(
        &mut self,
    ) -> impl Future<Output = Result<Option<VarInt>, ReadError>> + '_ {
        ReceivedReset { stream: self }
    }

    /// Reads one ordered or unordered stream chunk.
    pub fn read_chunk(
        &mut self,
        max_size: usize,
        ordered: bool,
    ) -> impl Future<Output = Result<Option<Chunk>, ReadError>> + '_ {
        ReadChunk {
            stream: self,
            max_size,
            ordered,
        }
    }

    /// Requests that the peer stop sending this stream.
    pub fn stop(&mut self, error_code: VarInt) -> Result<(), ReadError> {
        self.check_closed()?;
        let _ = self.final_size();
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto
                .stop_recv_stream(stream_id, error_code)
                .map_err(map_read_error)?;
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
        }
        Ok(())
    }

    fn notify_runtime_activity(&self) {
        #[cfg(all(
            feature = "runtime-tokio",
            any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
        ))]
        if let Some(notify) = self
            .endpoint_runtime_notify
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .cloned()
        {
            notify.notify();
        } else if let Some(notify) = &self.runtime_notify {
            notify.notify_one();
        }
    }

    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_size: usize,
        ordered: bool,
    ) -> Poll<Result<Option<Chunk>, ReadError>> {
        match self.poll_read_chunks(cx, max_size, ordered, 1) {
            Poll::Ready(Ok(mut chunks)) => Poll::Ready(Ok(chunks.pop())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_read_chunks(
        &mut self,
        cx: &mut Context<'_>,
        max_size: usize,
        ordered: bool,
        max_chunks: usize,
    ) -> Poll<Result<SmallVec<[Chunk; 8]>, ReadError>> {
        if let Err(error) = self.ensure_read_mode(ordered) {
            return Poll::Ready(Err(error));
        }
        if let (
            Some(proto),
            Some(stream_id),
            Some(closed_state),
            Some(stream_wakers),
            Some(stream_reset_state),
        ) = (
            &self.proto,
            self.stream_id,
            &self.closed_state,
            &self.stream_wakers,
            &self.stream_reset_state,
        ) {
            if let Some(error) = closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
            {
                return Poll::Ready(Err(ReadError::ConnectionLost(error)));
            }

            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(size) = proto.recv_stream_final_size(stream_id) {
                stream_reset_state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .set_final_size(stream_id, size);
            }
            let mut chunks = SmallVec::<[Chunk; 8]>::new();
            let mut remaining = max_size;
            while chunks.len() < max_chunks {
                let Some(chunk) = proto.read_recv_stream(stream_id, remaining, ordered) else {
                    break;
                };
                let len = chunk.bytes.len();
                let fin = chunk.fin;
                chunks.push(chunk);
                remaining = remaining.saturating_sub(len);
                if fin || len == 0 || remaining == 0 {
                    break;
                }
            }
            if !chunks.is_empty() {
                let reset_deliverable = proto.recv_stream_reset_error(stream_id).is_some();
                // Read-driven credit updates must wake the driver, but a read
                // below the credit threshold creates no wire work. Check while
                // holding the protocol lock so a queued update cannot be missed.
                let needs_transmit = proto.has_pending_transmit();
                self.protocol_memory
                    .reconcile(proto.memory_stats().payload_bytes());
                let events = proto.drain_qlog_events();
                drop(proto);
                self.qlog.publish(events);
                if needs_transmit {
                    self.notify_runtime_activity();
                }
                if reset_deliverable
                    && let Some(waker) = stream_reset_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .wake_waiter(stream_id)
                {
                    waker.wake();
                }
                return Poll::Ready(Ok(chunks));
            }
            if let Some(error_code) = proto.recv_stream_reset_error(stream_id).or_else(|| {
                stream_reset_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .reset_reason(stream_id)
            }) {
                return Poll::Ready(Err(ReadError::Reset(error_code)));
            }
            let finished = proto.is_recv_stream_finished(stream_id);
            if !finished {
                stream_wakers
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .register_reader(stream_id, cx.waker());
                stream_reset_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .register_waiter(stream_id, cx.waker());
            }
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            if finished {
                return Poll::Ready(Ok(chunks));
            }
            return Poll::Pending;
        }

        if let Err(error) = self.check_closed() {
            return Poll::Ready(Err(error));
        }
        if self.offset >= self.buffer.len() {
            return Poll::Ready(Ok(SmallVec::new()));
        }
        let len = max_size.min(self.buffer.len() - self.offset);
        let offset = self.offset as u64;
        let bytes = self.buffer[self.offset..self.offset + len].to_vec();
        self.offset += len;
        let mut chunks = SmallVec::new();
        chunks.push(Chunk {
            offset,
            bytes: bytes.into(),
            fin: self.offset == self.buffer.len(),
        });
        Poll::Ready(Ok(chunks))
    }

    fn check_closed(&self) -> Result<(), ReadError> {
        if let Some(closed_state) = &self.closed_state
            && let Some(error) = closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
        {
            return Err(ReadError::ConnectionLost(error));
        }
        Ok(())
    }

    fn ensure_read_mode(&mut self, ordered: bool) -> Result<(), ReadError> {
        let requested = if ordered {
            ReadMode::Ordered
        } else {
            ReadMode::Unordered
        };
        match (self.read_mode, requested) {
            (ReadMode::Unknown, requested) => {
                self.read_mode = requested;
                Ok(())
            }
            (current, requested) if current == requested => Ok(()),
            _ => Err(ReadError::IllegalOrderedState),
        }
    }

    fn has_buffered_data(&self) -> bool {
        let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) else {
            return self.offset < self.buffer.len();
        };
        proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv_stream_has_buffered_data(stream_id)
    }
}

#[cfg(feature = "runtime-tokio")]
impl tokio::io::AsyncRead for RecvStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.poll_read_chunk(cx, buf.remaining(), true) {
            Poll::Ready(Ok(Some(chunk))) => {
                buf.put_slice(&chunk.bytes);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ReadMode {
    #[default]
    Unknown,
    Ordered,
    Unordered,
}

fn map_read_error(error: quion_proto::CodecError) -> ReadError {
    ReadError::ConnectionLost(crate::ConnectionError::TransportError(
        error.transport_code(),
    ))
}

struct Read<'a> {
    stream: &'a mut RecvStream,
    buf: &'a mut [u8],
}

struct ReceivedFinalSize<'a> {
    stream: &'a mut RecvStream,
}

impl Future for ReceivedFinalSize<'_> {
    type Output = Result<u64, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let stream = &mut self.get_mut().stream;
        let (Some(proto), Some(id), Some(state), Some(wakers)) = (
            &stream.proto,
            stream.stream_id,
            &stream.stream_reset_state,
            &stream.stream_wakers,
        ) else {
            return Poll::Ready(Err(ReadError::FinishedEarly));
        };
        // Register under the protocol lock, following the same lock order as reads.
        let proto = proto.lock().unwrap_or_else(|p| p.into_inner());
        let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(size) = proto.recv_stream_final_size(id) {
            state.set_final_size(id, size);
        }
        if let Some(size) = state.final_size(id) {
            return Poll::Ready(Ok(size));
        }
        if let Err(error) = stream.check_closed() {
            return Poll::Ready(Err(error));
        }
        wakers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .register_reader(id, cx.waker());
        state.register_waiter(id, cx.waker());
        Poll::Pending
    }
}

struct ReceivedReset<'a> {
    stream: &'a mut RecvStream,
}

impl Future for ReceivedReset<'_> {
    type Output = Result<Option<VarInt>, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let (
            Some(proto),
            Some(stream_id),
            Some(closed_state),
            Some(stream_wakers),
            Some(stream_reset_state),
        ) = (
            &this.stream.proto,
            this.stream.stream_id,
            &this.stream.closed_state,
            &this.stream.stream_wakers,
            &this.stream.stream_reset_state,
        )
        else {
            return Poll::Ready(Ok(None));
        };
        if let Some(error) = closed_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .error
            .clone()
        {
            return Poll::Ready(Err(ReadError::ConnectionLost(error)));
        }
        let proto = proto
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(error_code) = proto.recv_stream_reset_error(stream_id).or_else(|| {
            stream_reset_state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .reset_reason(stream_id)
        }) {
            return Poll::Ready(Ok(Some(error_code)));
        }
        if proto.is_recv_stream_finished(stream_id) {
            return Poll::Ready(Ok(None));
        }
        stream_wakers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .register_reader(stream_id, cx.waker());
        stream_reset_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .register_waiter(stream_id, cx.waker());
        drop(proto);
        Poll::Pending
    }
}

impl Future for Read<'_> {
    type Output = Result<Option<usize>, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.buf.is_empty() {
            return Poll::Ready(Ok(Some(0)));
        }
        match this.stream.poll_read_chunk(cx, this.buf.len(), true) {
            Poll::Ready(Ok(Some(chunk))) => {
                this.buf[..chunk.bytes.len()].copy_from_slice(&chunk.bytes);
                Poll::Ready(Ok(Some(chunk.bytes.len())))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct ReadExact<'a> {
    stream: &'a mut RecvStream,
    buf: &'a mut [u8],
    filled: usize,
}

impl Future for ReadExact<'_> {
    type Output = Result<(), ReadError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while self.filled < self.buf.len() {
            let remaining = self.buf.len() - self.filled;
            match self.stream.poll_read_chunk(cx, remaining, true) {
                Poll::Ready(Ok(Some(chunk))) => {
                    let end = self.filled + chunk.bytes.len();
                    let start = self.filled;
                    self.buf[start..end].copy_from_slice(&chunk.bytes);
                    self.filled = end;
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Err(ReadError::FinishedEarly)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

struct ReadToEnd<'a> {
    stream: &'a mut RecvStream,
    max_size: usize,
    out: Vec<u8>,
}

impl ReadToEnd<'_> {
    const BULK_RESERVE_THRESHOLD: usize = 256 * 1024;
    const MAX_BULK_RESERVE: usize = 64 * 1024 * 1024;

    fn reserve_for(&mut self, next_len: usize) {
        if next_len <= self.out.capacity() || next_len < Self::BULK_RESERVE_THRESHOLD {
            return;
        }
        let target = next_len
            .saturating_mul(8)
            .min(self.max_size)
            .min(Self::MAX_BULK_RESERVE)
            .max(next_len);
        self.out.reserve_exact(target - self.out.len());
    }
}

impl Future for ReadToEnd<'_> {
    type Output = Result<Vec<u8>, ReadError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let remaining = self.max_size.saturating_sub(self.out.len());
            if remaining == 0 {
                if self.stream.has_buffered_data() {
                    return Poll::Ready(Err(ReadError::TooLong(self.max_size)));
                }
                return match self.stream.poll_read_chunk(cx, 0, true) {
                    Poll::Ready(Ok(None)) => Poll::Ready(Ok(std::mem::take(&mut self.out))),
                    Poll::Ready(Ok(Some(chunk))) if chunk.bytes.is_empty() && chunk.fin => {
                        Poll::Ready(Ok(std::mem::take(&mut self.out)))
                    }
                    Poll::Ready(Ok(Some(_))) => Poll::Ready(Err(ReadError::TooLong(self.max_size))),
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                };
            }

            match self.stream.poll_read_chunks(cx, remaining, true, 32) {
                Poll::Ready(Ok(chunks)) if !chunks.is_empty() => {
                    for chunk in chunks {
                        let next_len = self.out.len().saturating_add(chunk.bytes.len());
                        if next_len > self.max_size {
                            return Poll::Ready(Err(ReadError::TooLong(self.max_size)));
                        }
                        self.reserve_for(next_len);
                        self.out.extend_from_slice(&chunk.bytes);
                        if chunk.fin {
                            return Poll::Ready(Ok(std::mem::take(&mut self.out)));
                        }
                    }
                }
                Poll::Ready(Ok(_)) => return Poll::Ready(Ok(std::mem::take(&mut self.out))),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct ReadChunk<'a> {
    stream: &'a mut RecvStream,
    max_size: usize,
    ordered: bool,
}

impl Future for ReadChunk<'_> {
    type Output = Result<Option<Chunk>, ReadError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.stream.poll_read_chunk(cx, this.max_size, this.ordered)
    }
}
