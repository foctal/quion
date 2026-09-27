//! Platform control-message support.
//!
//! Linux and Apple targets use `recvmsg`/`sendmsg`, and Windows uses
//! `WSARecvMsg`/`WSASendMsg`, for ECN, destination address, interface, and
//! optional segmentation metadata. Other platforms retain the portable
//! `recv_from`/`send_to` fallback.

#[cfg(not(windows))]
use std::net::UdpSocket;

use crate::EcnCapabilities;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Capabilities {
    pub ecn: EcnCapabilities,
    pub destination_ip: bool,
    pub interface: bool,
    pub gso: bool,
    pub gro: bool,
}

#[cfg(windows)]
#[path = "cmsg/windows.rs"]
mod windows;

impl Capabilities {
    pub(crate) const PORTABLE: Self = Self {
        ecn: EcnCapabilities::NONE,
        destination_ip: false,
        interface: false,
        gso: false,
        gro: false,
    };
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
mod platform {
    #![allow(unsafe_code)]

    use smallvec::SmallVec;
    use std::{
        io,
        mem::{self, MaybeUninit},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::fd::AsRawFd,
        ptr,
    };

    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    use crate::BatchRecv;
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    use crate::BatchSend;
    use crate::{EcnCodepoint, RecvMeta, Transmit};

    use super::*;

    const CONTROL_WORDS: usize = 64;

    #[cfg(target_vendor = "apple")]
    #[repr(C)]
    struct MessageHeader {
        msg_name: *mut libc::c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_iovlen: libc::c_int,
        msg_control: *mut libc::c_void,
        msg_controllen: libc::socklen_t,
        msg_flags: libc::c_int,
        msg_datalen: usize,
    }

    #[cfg(target_vendor = "apple")]
    unsafe extern "C" {
        fn recvmsg_x(
            socket: libc::c_int,
            messages: *mut MessageHeader,
            count: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;

        fn sendmsg_x(
            socket: libc::c_int,
            messages: *const MessageHeader,
            count: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

    pub(crate) fn configure(socket: &UdpSocket) -> Capabilities {
        let Ok(local) = socket.local_addr() else {
            return Capabilities::PORTABLE;
        };
        let fd = socket.as_raw_fd();
        let mut capabilities = Capabilities::PORTABLE;
        match local {
            SocketAddr::V4(_) => {
                capabilities.ecn =
                    EcnCapabilities::new(set_flag(fd, libc::IPPROTO_IP, libc::IP_RECVTOS), true);
                #[cfg(target_os = "linux")]
                {
                    let packet_info = set_flag(fd, libc::IPPROTO_IP, libc::IP_PKTINFO);
                    capabilities.destination_ip = packet_info;
                    capabilities.interface = packet_info;
                }
                #[cfg(target_vendor = "apple")]
                {
                    capabilities.destination_ip =
                        set_flag(fd, libc::IPPROTO_IP, libc::IP_RECVDSTADDR);
                    capabilities.interface = set_flag(fd, libc::IPPROTO_IP, libc::IP_RECVIF);
                }
            }
            SocketAddr::V6(_) => {
                capabilities.ecn = EcnCapabilities::new(
                    set_flag(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS),
                    true,
                );
                let packet_info = set_flag(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO);
                capabilities.destination_ip = packet_info;
                capabilities.interface = packet_info;
            }
        }
        #[cfg(all(target_os = "linux", feature = "gso"))]
        {
            capabilities.gso = true;
        }
        #[cfg(all(target_os = "linux", feature = "gro"))]
        {
            capabilities.gro = set_flag(fd, libc::IPPROTO_UDP, libc::UDP_GRO);
        }
        capabilities
    }

    fn set_flag(fd: libc::c_int, level: libc::c_int, name: libc::c_int) -> bool {
        let enabled: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                ptr::from_ref(&enabled).cast(),
                mem::size_of_val(&enabled) as libc::socklen_t,
            ) == 0
        }
    }

    pub(crate) fn recv(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        buffer: &mut [u8],
    ) -> io::Result<Option<RecvMeta>> {
        let fd = socket.as_raw_fd();
        let mut remote = MaybeUninit::<libc::sockaddr_storage>::zeroed();
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut control = [0usize; CONTROL_WORDS];
        let mut message = libc::msghdr {
            msg_name: remote.as_mut_ptr().cast(),
            msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: ptr::from_mut(&mut iov),
            msg_iovlen: 1,
            msg_control: control.as_mut_ptr().cast(),
            msg_controllen: mem::size_of_val(&control) as _,
            msg_flags: 0,
        };

        let len = unsafe { libc::recvmsg(fd, &mut message, 0) };
        if len < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }

        let remote_storage = unsafe { remote.assume_init() };
        Ok(Some(recv_meta(
            bound_local,
            &message,
            &remote_storage,
            len as usize,
        )?))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recv_batch(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        batch: &mut BatchRecv,
        max_datagrams: usize,
        buffer_size: usize,
    ) -> io::Result<usize> {
        let count = max_datagrams.min(libc::c_uint::MAX as usize);
        if count == 0 {
            return Ok(0);
        }

        let mut buffers = (0..count)
            .map(|_| batch.take_buffer(buffer_size))
            .collect::<SmallVec<[Vec<u8>; 32]>>();
        let mut remotes = (0..count)
            .map(|_| MaybeUninit::<libc::sockaddr_storage>::zeroed())
            .collect::<SmallVec<[MaybeUninit<libc::sockaddr_storage>; 32]>>();
        // Ancillary storage is an output buffer. The kernel initializes the
        // bytes described by msg_controllen before recv_meta reads them.
        let mut controls = (0..count)
            .map(|_| MaybeUninit::<[usize; CONTROL_WORDS]>::uninit())
            .collect::<SmallVec<[MaybeUninit<[usize; CONTROL_WORDS]>; 32]>>();
        let mut iovecs = buffers
            .iter_mut()
            .map(|buffer| libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            })
            .collect::<SmallVec<[libc::iovec; 32]>>();
        let mut messages = (0..count)
            .map(|index| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: remotes[index].as_mut_ptr().cast(),
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                    msg_iov: ptr::from_mut(&mut iovecs[index]),
                    msg_iovlen: 1,
                    msg_control: controls[index].as_mut_ptr().cast(),
                    msg_controllen: mem::size_of::<[usize; CONTROL_WORDS]>() as _,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect::<SmallVec<[libc::mmsghdr; 32]>>();

        let received = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
                ptr::null_mut(),
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            for buffer in buffers {
                batch.recycle_buffer(buffer);
            }
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(error)
            };
        }

        let received = received as usize;
        let mut datagrams = 0;
        for index in 0..received {
            let remote = unsafe { remotes[index].assume_init_read() };
            let len = (messages[index].msg_len as usize).min(buffers[index].len());
            let meta = recv_meta(bound_local, &messages[index].msg_hdr, &remote, len)?;
            let buffer = mem::take(&mut buffers[index]);
            datagrams += batch.push_received(buffer, meta);
        }
        for buffer in buffers.into_iter().skip(received) {
            batch.recycle_buffer(buffer);
        }
        Ok(datagrams)
    }

    #[cfg(target_vendor = "apple")]
    pub(crate) fn recv_batch(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        batch: &mut BatchRecv,
        max_datagrams: usize,
        buffer_size: usize,
    ) -> io::Result<usize> {
        let count = max_datagrams.min(libc::c_uint::MAX as usize);
        if count == 0 {
            return Ok(0);
        }

        let mut buffers = (0..count)
            .map(|_| batch.take_buffer(buffer_size))
            .collect::<SmallVec<[Vec<u8>; 32]>>();
        let mut remotes = (0..count)
            .map(|_| MaybeUninit::<libc::sockaddr_storage>::zeroed())
            .collect::<SmallVec<[MaybeUninit<libc::sockaddr_storage>; 32]>>();
        // Ancillary storage is an output buffer. The kernel initializes the
        // bytes described by msg_controllen before recv_meta reads them.
        let mut controls = (0..count)
            .map(|_| MaybeUninit::<[usize; CONTROL_WORDS]>::uninit())
            .collect::<SmallVec<[MaybeUninit<[usize; CONTROL_WORDS]>; 32]>>();
        let mut iovecs = buffers
            .iter_mut()
            .map(|buffer| libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            })
            .collect::<SmallVec<[libc::iovec; 32]>>();
        let mut messages = (0..count)
            .map(|index| MessageHeader {
                msg_name: remotes[index].as_mut_ptr().cast(),
                msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                msg_iov: ptr::from_mut(&mut iovecs[index]),
                msg_iovlen: 1,
                msg_control: controls[index].as_mut_ptr().cast(),
                msg_controllen: mem::size_of::<[usize; CONTROL_WORDS]>() as libc::socklen_t,
                msg_flags: 0,
                msg_datalen: 0,
            })
            .collect::<SmallVec<[MessageHeader; 32]>>();

        let received = unsafe {
            recvmsg_x(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            for buffer in buffers {
                batch.recycle_buffer(buffer);
            }
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(error)
            };
        }

        let received = received as usize;
        let mut datagrams = 0;
        for index in 0..received {
            let remote = unsafe { remotes[index].assume_init_read() };
            let message = libc::msghdr {
                msg_name: messages[index].msg_name,
                msg_namelen: messages[index].msg_namelen,
                msg_iov: messages[index].msg_iov,
                msg_iovlen: messages[index].msg_iovlen,
                msg_control: messages[index].msg_control,
                msg_controllen: messages[index].msg_controllen,
                msg_flags: messages[index].msg_flags,
            };
            let len = messages[index].msg_datalen.min(buffers[index].len());
            let meta = recv_meta(bound_local, &message, &remote, len)?;
            let buffer = mem::take(&mut buffers[index]);
            datagrams += batch.push_received(buffer, meta);
        }
        for buffer in buffers.into_iter().skip(received) {
            batch.recycle_buffer(buffer);
        }
        Ok(datagrams)
    }

    fn recv_meta(
        bound_local: SocketAddr,
        message: &libc::msghdr,
        remote_storage: &libc::sockaddr_storage,
        len: usize,
    ) -> io::Result<RecvMeta> {
        let remote = sockaddr_to_std(remote_storage)?;
        let mut local_ip = None;
        let mut interface = None;
        let mut ecn = None;
        #[cfg(all(target_os = "linux", feature = "gro"))]
        let mut segment_size = None;
        #[cfg(not(all(target_os = "linux", feature = "gro")))]
        let segment_size = None;

        let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
        while !header.is_null() {
            let level = unsafe { (*header).cmsg_level };
            let kind = unsafe { (*header).cmsg_type };
            let data = unsafe { libc::CMSG_DATA(header) };

            if level == libc::IPPROTO_IP && (kind == libc::IP_TOS || kind == libc::IP_RECVTOS) {
                let value = unsafe { ptr::read_unaligned(data.cast::<u8>()) };
                ecn = EcnCodepoint::from_bits(value);
            } else if level == libc::IPPROTO_IPV6 && kind == libc::IPV6_TCLASS {
                let value = unsafe { ptr::read_unaligned(data.cast::<libc::c_int>()) };
                ecn = EcnCodepoint::from_bits(value as u8);
            }

            #[cfg(target_os = "linux")]
            if level == libc::IPPROTO_IP && kind == libc::IP_PKTINFO {
                let info = unsafe { ptr::read_unaligned(data.cast::<libc::in_pktinfo>()) };
                local_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))));
                interface = u32::try_from(info.ipi_ifindex).ok();
            }
            #[cfg(target_vendor = "apple")]
            if level == libc::IPPROTO_IP && kind == libc::IP_RECVDSTADDR {
                let address = unsafe { ptr::read_unaligned(data.cast::<libc::in_addr>()) };
                local_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(address.s_addr))));
            }
            #[cfg(target_vendor = "apple")]
            if level == libc::IPPROTO_IP && kind == libc::IP_RECVIF {
                let link = unsafe { ptr::read_unaligned(data.cast::<libc::sockaddr_dl>()) };
                interface = Some(u32::from(link.sdl_index));
            }
            if level == libc::IPPROTO_IPV6 && kind == libc::IPV6_PKTINFO {
                let info = unsafe { ptr::read_unaligned(data.cast::<libc::in6_pktinfo>()) };
                local_ip = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                interface = Some(info.ipi6_ifindex);
            }
            #[cfg(all(target_os = "linux", feature = "gro"))]
            if level == libc::IPPROTO_UDP && kind == libc::UDP_GRO {
                let value = unsafe { ptr::read_unaligned(data.cast::<u16>()) };
                segment_size = Some(usize::from(value));
            }

            header = unsafe { libc::CMSG_NXTHDR(message, header) };
        }

        let local = local_ip
            .map(|ip| SocketAddr::new(ip, bound_local.port()))
            .or(Some(bound_local));
        tracing::trace!(
            remote = %remote,
            local = ?local,
            interface = ?interface,
            ecn = ?ecn,
            segment_size = ?segment_size,
            bytes = len,
            "received UDP datagram with control metadata"
        );
        Ok(RecvMeta {
            local,
            remote,
            interface,
            ecn,
            segment_size,
            len,
        })
    }

    pub(crate) fn send(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        transmit: &Transmit,
    ) -> io::Result<usize> {
        let destination = socket2::SockAddr::from(transmit.destination);
        let mut iov = libc::iovec {
            iov_base: transmit.contents.as_ptr().cast_mut().cast(),
            iov_len: transmit.contents.len(),
        };
        let mut control = [0usize; CONTROL_WORDS];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_name = destination.as_ptr().cast_mut().cast();
        message.msg_namelen = destination.len();
        message.msg_iov = ptr::from_mut(&mut iov);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();

        add_send_controls(&mut message, &mut control, bound_local, transmit)?;

        if message.msg_controllen == 0 {
            message.msg_control = ptr::null_mut();
        }
        let len = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            tracing::trace!(
                destination = %transmit.destination,
                source = ?transmit.source,
                ecn = ?transmit.ecn,
                segment_size = ?transmit.segment_size,
                bytes = len,
                "sent UDP datagram with control metadata"
            );
            Ok(len as usize)
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn send_batch(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        batch: &BatchSend,
    ) -> io::Result<usize> {
        let count = batch.len().min(libc::c_uint::MAX as usize);
        if count == 0 {
            return Ok(0);
        }

        let transmits = batch
            .iter()
            .take(count)
            .collect::<SmallVec<[&Transmit; 32]>>();
        let destinations = transmits
            .iter()
            .map(|transmit| socket2::SockAddr::from(transmit.destination))
            .collect::<SmallVec<[socket2::SockAddr; 32]>>();
        let mut iovecs = transmits
            .iter()
            .map(|transmit| libc::iovec {
                iov_base: transmit.contents.as_ptr().cast_mut().cast(),
                iov_len: transmit.contents.len(),
            })
            .collect::<SmallVec<[libc::iovec; 32]>>();
        let mut controls = (0..count)
            .map(|_| [0usize; CONTROL_WORDS])
            .collect::<SmallVec<[[usize; CONTROL_WORDS]; 32]>>();
        let mut messages = (0..count)
            .map(|index| libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: destinations[index].as_ptr().cast_mut().cast(),
                    msg_namelen: destinations[index].len(),
                    msg_iov: ptr::from_mut(&mut iovecs[index]),
                    msg_iovlen: 1,
                    msg_control: controls[index].as_mut_ptr().cast(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            })
            .collect::<SmallVec<[libc::mmsghdr; 32]>>();

        for (index, transmit) in transmits.iter().enumerate() {
            add_send_controls(
                &mut messages[index].msg_hdr,
                &mut controls[index],
                bound_local,
                transmit,
            )?;
            if messages[index].msg_hdr.msg_controllen == 0 {
                messages[index].msg_hdr.msg_control = ptr::null_mut();
            }
        }

        let sent = unsafe {
            libc::sendmmsg(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(error)
            }
        } else {
            tracing::trace!(datagrams = sent, "sent UDP datagram batch");
            Ok(sent as usize)
        }
    }

    #[cfg(target_vendor = "apple")]
    pub(crate) fn send_batch(
        socket: &UdpSocket,
        bound_local: SocketAddr,
        batch: &BatchSend,
    ) -> io::Result<usize> {
        let count = batch.len().min(libc::c_uint::MAX as usize);
        if count == 0 {
            return Ok(0);
        }

        let transmits = batch
            .iter()
            .take(count)
            .collect::<SmallVec<[&Transmit; 32]>>();
        let destinations = transmits
            .iter()
            .map(|transmit| socket2::SockAddr::from(transmit.destination))
            .collect::<SmallVec<[socket2::SockAddr; 32]>>();
        let mut iovecs = transmits
            .iter()
            .map(|transmit| libc::iovec {
                iov_base: transmit.contents.as_ptr().cast_mut().cast(),
                iov_len: transmit.contents.len(),
            })
            .collect::<SmallVec<[libc::iovec; 32]>>();
        let mut controls = (0..count)
            .map(|_| [0usize; CONTROL_WORDS])
            .collect::<SmallVec<[[usize; CONTROL_WORDS]; 32]>>();
        let mut messages = SmallVec::<[MessageHeader; 32]>::new();
        for index in 0..count {
            let mut standard: libc::msghdr = unsafe { mem::zeroed() };
            standard.msg_name = destinations[index].as_ptr().cast_mut().cast();
            standard.msg_namelen = destinations[index].len();
            standard.msg_iov = ptr::from_mut(&mut iovecs[index]);
            standard.msg_iovlen = 1;
            standard.msg_control = controls[index].as_mut_ptr().cast();
            add_send_controls(
                &mut standard,
                &mut controls[index],
                bound_local,
                transmits[index],
            )?;
            if standard.msg_controllen == 0 {
                standard.msg_control = ptr::null_mut();
            }
            messages.push(MessageHeader {
                msg_name: standard.msg_name,
                msg_namelen: standard.msg_namelen,
                msg_iov: standard.msg_iov,
                msg_iovlen: 1,
                msg_control: standard.msg_control,
                msg_controllen: standard.msg_controllen as libc::socklen_t,
                msg_flags: 0,
                msg_datalen: transmits[index].contents.len(),
            });
        }

        loop {
            let sent = unsafe {
                sendmsg_x(
                    socket.as_raw_fd(),
                    messages.as_ptr(),
                    count as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };
            if sent >= 0 {
                tracing::trace!(datagrams = sent, "sent Apple UDP datagram batch");
                return Ok(sent as usize);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock => return Ok(0),
                _ => return Err(error),
            }
        }
    }

    fn add_send_controls(
        message: &mut libc::msghdr,
        control: &mut [usize; CONTROL_WORDS],
        bound_local: SocketAddr,
        transmit: &Transmit,
    ) -> io::Result<()> {
        if let Some(ecn) = transmit.ecn {
            match transmit.destination {
                SocketAddr::V4(_) => {
                    let value = libc::c_int::from(ecn.bits());
                    push_control(message, control, libc::IPPROTO_IP, libc::IP_TOS, &value)?;
                }
                SocketAddr::V6(_) => {
                    let value = libc::c_int::from(ecn.bits());
                    push_control(
                        message,
                        control,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_TCLASS,
                        &value,
                    )?;
                }
            }
        }

        if let Some(source) = transmit
            .source
            .filter(|source| bound_local.ip().is_unspecified() || source.ip() != bound_local.ip())
        {
            push_source_control(message, control, source)?;
        }

        #[cfg(all(target_os = "linux", feature = "gso"))]
        if let Some(segment_size) = transmit.segment_size {
            let segment_size = u16::try_from(segment_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "GSO segment size exceeds u16")
            })?;
            push_control(
                message,
                control,
                libc::IPPROTO_UDP,
                libc::UDP_SEGMENT,
                &segment_size,
            )?;
        }
        Ok(())
    }

    fn push_source_control(
        message: &mut libc::msghdr,
        control: &mut [usize; CONTROL_WORDS],
        source: SocketAddr,
    ) -> io::Result<()> {
        match source.ip() {
            IpAddr::V4(address) => {
                let address = libc::in_addr {
                    s_addr: u32::from(address).to_be(),
                };
                #[cfg(target_os = "linux")]
                {
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: address,
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    push_control(message, control, libc::IPPROTO_IP, libc::IP_PKTINFO, &info)
                }
                #[cfg(target_vendor = "apple")]
                {
                    push_control(
                        message,
                        control,
                        libc::IPPROTO_IP,
                        libc::IP_RECVDSTADDR,
                        &address,
                    )
                }
            }
            IpAddr::V6(address) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: address.octets(),
                    },
                    ipi6_ifindex: 0,
                };
                push_control(
                    message,
                    control,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    &info,
                )
            }
        }
    }

    fn push_control<T>(
        message: &mut libc::msghdr,
        control: &mut [usize; CONTROL_WORDS],
        level: libc::c_int,
        kind: libc::c_int,
        value: &T,
    ) -> io::Result<()> {
        let value_len = mem::size_of::<T>();
        let space = unsafe { libc::CMSG_SPACE(value_len as libc::c_uint) as usize };
        #[cfg(target_os = "linux")]
        let used = message.msg_controllen;
        // Apple uses socklen_t here, whereas Linux uses size_t.
        #[cfg(target_vendor = "apple")]
        let used = message.msg_controllen as usize;
        if used.saturating_add(space) > mem::size_of_val(control) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP control metadata exceeds buffer",
            ));
        }

        let header = unsafe {
            message
                .msg_control
                .cast::<u8>()
                .add(used)
                .cast::<libc::cmsghdr>()
        };
        unsafe {
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(value_len as libc::c_uint) as _;
            ptr::copy_nonoverlapping(
                ptr::from_ref(value).cast::<u8>(),
                libc::CMSG_DATA(header),
                value_len,
            );
        }
        message.msg_controllen = used.saturating_add(space) as _;
        Ok(())
    }

    fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
        match libc::c_int::from(storage.ss_family) {
            libc::AF_INET => {
                let address = unsafe {
                    ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in>())
                };
                Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))),
                    u16::from_be(address.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let address = unsafe {
                    ptr::read_unaligned(ptr::from_ref(storage).cast::<libc::sockaddr_in6>())
                };
                Ok(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                    u16::from_be(address.sin6_port),
                ))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP peer address family",
            )),
        }
    }
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(crate) use platform::recv_batch;
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(crate) use platform::send_batch;
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
pub(crate) use platform::{configure, recv, send};

#[cfg(windows)]
pub(crate) use windows::{configure, recv, recv_batch, send, send_batch};

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
pub(crate) fn configure(_socket: &UdpSocket) -> Capabilities {
    Capabilities::PORTABLE
}
