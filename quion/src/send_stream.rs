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

#[cfg(all(
    feature = "runtime-tokio",
    any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
))]
use crate::connection::EndpointRuntimeNotify;
use crate::{
    connection::{ClosedState, ProtocolMemoryTracker, StreamStopState, StreamWriteState},
    error::{ConnectionError, WriteError},
    qlog::SharedQlogState,
};

/// Lower values receive scheduling preference over higher values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamPriority(pub u16);

/// Send half of a QUIC stream. Dropping it queues FIN after buffered data.
#[derive(Debug, Default)]
pub struct SendStream {
    proto: Option<Arc<Mutex<quion_proto::connection::Connection>>>,
    closed_state: Option<Arc<Mutex<ClosedState>>>,
    qlog: SharedQlogState,
    write_state: Option<Arc<Mutex<StreamWriteState>>>,
    stop_state: Option<Arc<Mutex<StreamStopState>>>,
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
    finished: bool,
    priority: StreamPriority,
}

impl Drop for SendStream {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
        if let Some(id) = self.stream_id {
            if let Some(state) = &self.write_state {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .wake_writer(id);
            }
            if let Some(state) = &self.stop_state {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove_handle(id);
            }
        }
    }
}

impl SendStream {
    // Stream handles share independently synchronized connection services;
    // keeping these explicit avoids another allocation and indirection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proto: Arc<Mutex<quion_proto::connection::Connection>>,
        closed_state: Arc<Mutex<ClosedState>>,
        qlog: SharedQlogState,
        write_state: Arc<Mutex<StreamWriteState>>,
        stop_state: Arc<Mutex<StreamStopState>>,
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
        stop_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .register_handle(stream_id);
        Self {
            proto: Some(proto),
            closed_state: Some(closed_state),
            qlog,
            write_state: Some(write_state),
            stop_state: Some(stop_state),
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
            finished: false,
            priority: StreamPriority::default(),
        }
    }

    /// Writes as many bytes as current flow-control and buffer credit allows.
    pub fn write<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<usize, WriteError>> + 'a {
        Write {
            stream: self,
            buf,
            written: false,
        }
    }

    /// Returns the QUIC stream identifier.
    pub const fn id(&self) -> Option<StreamId> {
        self.stream_id
    }

    /// Writes the complete buffer, waiting for credit when necessary.
    pub fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = Result<(), WriteError>> + 'a {
        WriteAll {
            stream: self,
            buf,
            offset: 0,
        }
    }

    /// Queues FIN after all buffered stream data.
    pub fn finish(&mut self) -> Result<(), WriteError> {
        self.check_stopped_or_closed()?;
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.finish_stream(stream_id).map_err(map_write_error)?;
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
        }
        self.finished = true;
        Ok(())
    }

    /// Resets the stream with an application error code.
    pub fn reset(&mut self, _error_code: VarInt) -> Result<(), WriteError> {
        self.check_stopped_or_closed()?;
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto
                .reset_stream(stream_id, _error_code)
                .map_err(map_write_error)?;
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
        }
        self.finished = true;
        Ok(())
    }

    /// Resets the stream while guaranteeing delivery through `reliable_size`.
    ///
    /// The reliable size is an absolute byte offset and cannot exceed the
    /// amount written before this call. The extension must have been enabled
    /// locally and negotiated by the peer.
    pub fn reset_at(
        &mut self,
        error_code: VarInt,
        reliable_size: VarInt,
    ) -> Result<(), WriteError> {
        self.check_stopped_or_closed()?;
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !proto.reset_stream_at_enabled() {
                return Err(WriteError::ResetStreamAtUnsupported);
            }
            proto
                .reset_stream_at(stream_id, error_code, reliable_size)
                .map_err(map_write_error)?;
            self.protocol_memory
                .reconcile(proto.memory_stats().payload_bytes());
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
        }
        self.finished = true;
        Ok(())
    }

    /// Waits until the peer requests that this stream stop sending.
    pub fn stopped(&mut self) -> impl Future<Output = Result<Option<VarInt>, WriteError>> + '_ {
        Stopped { stream: self }
    }

    /// Sets strict stream scheduling priority. Lower values are sent first;
    /// equal-priority streams are served round-robin. A continuously writable
    /// higher-priority stream can delay lower-priority streams.
    pub fn set_priority(&mut self, priority: StreamPriority) {
        self.priority = priority;
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proto.set_stream_priority(stream_id, priority.0);
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
        }
    }

    fn try_queue_data(
        &mut self,
        buf: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, WriteError>> {
        if let Err(error) = self.check_stopped_or_closed() {
            return Poll::Ready(Err(error));
        }
        if let (Some(proto), Some(stream_id)) = (&self.proto, self.stream_id) {
            let mut proto = proto
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let available =
                usize::try_from(proto.available_send_credit(stream_id)).unwrap_or(usize::MAX);
            if available == 0 {
                drop(proto);
                if let Some(write_state) = &self.write_state {
                    write_state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .register_writer(stream_id, cx.waker());
                    // Flow-control updates run on the connection driver and
                    // can arrive after the credit check but before the waker
                    // is registered. Recheck after registration so that
                    // transition cannot strand a blocked writer.
                    let credit_available = self.proto.as_ref().is_some_and(|proto| {
                        proto
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .available_send_credit(stream_id)
                            != 0
                    });
                    if credit_available
                        && let Some(waker) = write_state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .wake_writer(stream_id)
                    {
                        waker.wake();
                    }
                }
                if let Err(error) = self.check_stopped_or_closed() {
                    return Poll::Ready(Err(error));
                }
                return Poll::Pending;
            }
            let to_queue = available.min(buf.len());
            let Some(memory_growth) = self.protocol_memory.try_reserve_growth(to_queue) else {
                return Poll::Ready(Err(WriteError::EndpointMemoryLimitReached));
            };
            proto
                .queue_stream_data(stream_id, &buf[..to_queue])
                .map_err(map_write_error)?;
            if !memory_growth.commit(proto.memory_stats().payload_bytes()) {
                return Poll::Ready(Err(WriteError::EndpointMemoryLimitReached));
            }
            let events = proto.drain_qlog_events();
            drop(proto);
            self.qlog.publish(events);
            self.notify_runtime_activity();
            return Poll::Ready(Ok(to_queue));
        }
        self.buffer.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
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

    fn check_stopped_or_closed(&self) -> Result<(), WriteError> {
        if let (Some(stop_state), Some(stream_id)) = (&self.stop_state, self.stream_id)
            && let Some(error_code) = stop_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .stopped_reason(stream_id)
        {
            return Err(WriteError::Stopped(error_code));
        }
        if let (Some(proto), Some(id)) = (&self.proto, self.stream_id)
            && let Some(code) = proto
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .stopped_stream_error(id)
        {
            return Err(WriteError::Stopped(code));
        }
        if let Some(closed_state) = &self.closed_state
            && let Some(error) = closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
        {
            return Err(WriteError::ConnectionLost(error));
        }
        Ok(())
    }
}

#[cfg(feature = "runtime-tokio")]
impl tokio::io::AsyncWrite for SendStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.try_queue_data(buf, cx) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.finish().map_err(std::io::Error::other))
    }
}

struct Write<'a> {
    stream: &'a mut SendStream,
    buf: &'a [u8],
    written: bool,
}

impl Future for Write<'_> {
    type Output = Result<usize, WriteError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        if this.written {
            return Poll::Ready(Ok(0));
        }
        let buf = this.buf;
        match this.stream.try_queue_data(buf, cx) {
            Poll::Ready(Ok(written)) => {
                this.written = true;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct WriteAll<'a> {
    stream: &'a mut SendStream,
    buf: &'a [u8],
    offset: usize,
}

impl Future for WriteAll<'_> {
    type Output = Result<(), WriteError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while self.offset < self.buf.len() {
            let chunk = &self.buf[self.offset..];
            match self.stream.try_queue_data(chunk, cx) {
                Poll::Ready(Ok(written)) => {
                    self.offset += written;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

struct Stopped<'a> {
    stream: &'a mut SendStream,
}

impl Future for Stopped<'_> {
    type Output = Result<Option<VarInt>, WriteError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Err(error) = this.stream.check_stopped_or_closed() {
            return Poll::Ready(match error {
                WriteError::Stopped(code) => Ok(Some(code)),
                other => Err(other),
            });
        }
        if let (Some(stop_state), Some(stream_id)) =
            (&this.stream.stop_state, this.stream.stream_id)
        {
            let mut stop_state = stop_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(error_code) = stop_state.stopped_reason(stream_id) {
                return Poll::Ready(Ok(Some(error_code)));
            }
            stop_state.register_waiter(stream_id, cx.waker());
            drop(stop_state);
            if this.stream.proto.as_ref().is_some_and(|proto| {
                proto
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_send_stream_finished(stream_id)
            }) {
                this.stream
                    .stop_state
                    .as_ref()
                    .expect("stop state was present")
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove_waiter(stream_id);
                return Poll::Ready(Ok(None));
            }
        }
        if let Some(closed_state) = &this.stream.closed_state
            && let Some(error) = closed_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .error
                .clone()
        {
            return Poll::Ready(Err(WriteError::ConnectionLost(error)));
        }
        Poll::Pending
    }
}

fn map_write_error(error: quion_proto::CodecError) -> WriteError {
    match error {
        quion_proto::CodecError::BufferLimitExceeded => WriteError::BufferTooLarge,
        error => {
            WriteError::ConnectionLost(ConnectionError::TransportError(error.transport_code()))
        }
    }
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self(128)
    }
}
