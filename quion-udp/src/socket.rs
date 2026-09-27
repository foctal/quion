//! Nonblocking UDP socket operations and the portable batch fallback.

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
use std::io;

use socket2::SockRef;

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
use crate::UdpError;
use crate::{BatchRecv, BatchSend, EcnCapabilities, RecvMeta, Result, Transmit, cmsg};

#[derive(Debug)]
pub struct UdpSocket {
    inner: StdUdpSocket,
    local_addr: SocketAddr,
    capabilities: cmsg::Capabilities,
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let inner = StdUdpSocket::bind(addr)?;
        inner.set_nonblocking(true)?;
        let local_addr = inner.local_addr()?;
        let capabilities = cmsg::configure(&inner);
        Ok(Self {
            inner,
            local_addr,
            capabilities,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Returns a cloned standard UDP socket for runtime integrations that
    /// need native readiness registration without changing the fallback API.
    pub fn try_clone_std(&self) -> Result<StdUdpSocket> {
        Ok(self.inner.try_clone()?)
    }

    /// Checks kernel receive readiness without consuming a datagram.
    ///
    /// Runtime adapters may clear cached readiness only on `WouldBlock`.
    /// Other errors (including truncation on Windows) must be handled by
    /// their normal receive path, rather than interpreted as an empty socket.
    pub fn peek_for_readiness(&self) -> std::io::Result<()> {
        self.inner.peek_from(&mut [0; 1]).map(|_| ())
    }

    /// Requests the operating-system receive buffer size in bytes.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        Ok(SockRef::from(&self.inner).set_recv_buffer_size(size)?)
    }

    /// Returns the effective operating-system receive buffer size in bytes.
    pub fn recv_buffer_size(&self) -> Result<usize> {
        Ok(SockRef::from(&self.inner).recv_buffer_size()?)
    }

    /// Requests the operating-system send buffer size in bytes.
    pub fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        Ok(SockRef::from(&self.inner).set_send_buffer_size(size)?)
    }

    /// Returns the effective operating-system send buffer size in bytes.
    pub fn send_buffer_size(&self) -> Result<usize> {
        Ok(SockRef::from(&self.inner).send_buffer_size()?)
    }

    pub const fn ecn_capabilities(&self) -> EcnCapabilities {
        self.capabilities.ecn
    }

    /// Returns whether received datagrams include their destination address.
    pub const fn destination_ip_supported(&self) -> bool {
        self.capabilities.destination_ip
    }

    /// Returns whether received datagrams include a local interface index.
    pub const fn interface_discovery_supported(&self) -> bool {
        self.capabilities.interface
    }

    /// Returns whether this socket can send UDP GSO payloads.
    pub const fn gso_supported(&self) -> bool {
        self.capabilities.gso
    }

    /// Returns whether this socket can receive UDP GRO payloads.
    pub const fn gro_supported(&self) -> bool {
        self.capabilities.gro
    }

    pub fn recv(&self, buffer: &mut [u8]) -> Result<Option<RecvMeta>> {
        #[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
        {
            Ok(cmsg::recv(&self.inner, self.local_addr, buffer)?)
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        {
            match self.inner.recv_from(buffer) {
                Ok((len, remote)) => Ok(Some(RecvMeta {
                    local: Some(self.local_addr),
                    remote,
                    interface: None,
                    ecn: None,
                    segment_size: None,
                    len,
                })),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error.into()),
            }
        }
    }

    pub fn recv_batch(
        &self,
        batch: &mut BatchRecv,
        max_datagrams: usize,
        buffer_size: usize,
    ) -> Result<usize> {
        let receive_capacity = batch.adaptive_receive_capacity(max_datagrams);
        #[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
        {
            let received = cmsg::recv_batch(
                &self.inner,
                self.local_addr,
                batch,
                receive_capacity,
                buffer_size,
            )?;
            batch.record_receive_batch(receive_capacity, received);
            Ok(received)
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        {
            let mut received = 0;
            for _ in 0..receive_capacity {
                let mut buffer = batch.take_buffer(buffer_size);
                match self.recv(&mut buffer)? {
                    Some(meta) => {
                        received += batch.push_received(buffer, meta);
                    }
                    None => {
                        batch.recycle_buffer(buffer);
                        break;
                    }
                }
            }
            batch.record_receive_batch(receive_capacity, received);
            Ok(received)
        }
    }

    pub fn send(&self, transmit: &Transmit) -> Result<usize> {
        #[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
        {
            Ok(cmsg::send(&self.inner, self.local_addr, transmit)?)
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        {
            Ok(self
                .inner
                .send_to(&transmit.contents, transmit.destination)?)
        }
    }

    pub fn send_batch(&self, batch: &BatchSend) -> Result<usize> {
        #[cfg(any(target_os = "linux", target_vendor = "apple", windows))]
        {
            Ok(cmsg::send_batch(&self.inner, self.local_addr, batch)?)
        }
        #[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
        {
            let mut sent = 0;
            for transmit in batch.iter() {
                match self.send(transmit) {
                    Ok(_) => sent += 1,
                    Err(UdpError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(sent)
        }
    }
}
