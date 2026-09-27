//! Windows UDP control-message support.

#![allow(unsafe_code)]

use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::windows::io::AsRawSocket,
    ptr,
    sync::OnceLock,
};

use windows_sys::Win32::Networking::WinSock;

use crate::{BatchRecv, BatchSend, EcnCapabilities, EcnCodepoint, RecvMeta, Transmit};

use super::Capabilities;

const CONTROL_BYTES: usize = 128;
const CONTROL_WORDS: usize = CONTROL_BYTES / mem::size_of::<usize>();
const OPTION_ON: u32 = 1;

type ReceiveMessageFn = WinSock::LPFN_WSARECVMSG;

static RECEIVE_MESSAGE: OnceLock<ReceiveMessageFn> = OnceLock::new();

pub(crate) fn configure(socket: &UdpSocket) -> Capabilities {
    if receive_message_function(socket).is_none() {
        return Capabilities::PORTABLE;
    }

    let Ok(local) = socket.local_addr() else {
        return Capabilities::PORTABLE;
    };
    let raw = socket.as_raw_socket() as WinSock::SOCKET;
    let (ecn_read, destination_ip, interface) = match local {
        SocketAddr::V4(_) => {
            let packet_info = set_flag(raw, WinSock::IPPROTO_IP, WinSock::IP_PKTINFO);
            let ecn = set_flag(raw, WinSock::IPPROTO_IP, WinSock::IP_RECVECN);
            (ecn, packet_info, packet_info)
        }
        SocketAddr::V6(_) => {
            let ipv6_packet_info = set_flag(raw, WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO);
            let ipv6_ecn = set_flag(raw, WinSock::IPPROTO_IPV6, WinSock::IPV6_RECVECN);
            let ipv6_only = is_ipv6_only(raw).unwrap_or(true);
            let ipv4_packet_info =
                ipv6_only || set_flag(raw, WinSock::IPPROTO_IP, WinSock::IP_PKTINFO);
            let ipv4_ecn = ipv6_only || set_flag(raw, WinSock::IPPROTO_IP, WinSock::IP_RECVECN);
            let packet_info = ipv6_packet_info && ipv4_packet_info;
            let ecn = ipv6_ecn && ipv4_ecn;
            (ecn, packet_info, packet_info)
        }
    };

    Capabilities {
        ecn: EcnCapabilities::new(ecn_read, true),
        destination_ip,
        interface,
        gso: false,
        gro: false,
    }
}

pub(crate) fn recv(
    socket: &UdpSocket,
    bound_local: SocketAddr,
    buffer: &mut [u8],
) -> io::Result<Option<RecvMeta>> {
    let Some(receive_message) = receive_message_function(socket) else {
        return portable_recv(socket, bound_local, buffer);
    };

    let mut source = MaybeUninit::<WinSock::SOCKADDR_INET>::zeroed();
    let mut data = WinSock::WSABUF {
        len: u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        buf: buffer.as_mut_ptr(),
    };
    let mut control = MaybeUninit::<[usize; CONTROL_WORDS]>::uninit();
    let mut message = WinSock::WSAMSG {
        name: source.as_mut_ptr().cast(),
        namelen: mem::size_of::<WinSock::SOCKADDR_INET>() as i32,
        lpBuffers: ptr::from_mut(&mut data),
        dwBufferCount: 1,
        Control: WinSock::WSABUF {
            len: CONTROL_BYTES as u32,
            buf: control.as_mut_ptr().cast(),
        },
        dwFlags: 0,
    };
    let mut received = 0;
    let result = unsafe {
        receive_message(
            socket.as_raw_socket() as WinSock::SOCKET,
            &mut message,
            &mut received,
            ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        };
    }

    let source = unsafe { source.assume_init() };
    let remote = sockaddr_to_std(&source)?;
    let (local_ip, interface, ecn) = decode_controls(&message);
    let local = local_ip
        .map(|ip| SocketAddr::new(ip, bound_local.port()))
        .or(Some(bound_local));
    let len = (received as usize).min(buffer.len());
    tracing::trace!(
        remote = %remote,
        local = ?local,
        interface = ?interface,
        ecn = ?ecn,
        bytes = len,
        "received Windows UDP datagram with control metadata"
    );
    Ok(Some(RecvMeta {
        local,
        remote,
        interface,
        ecn,
        segment_size: None,
        len,
    }))
}

pub(crate) fn recv_batch(
    socket: &UdpSocket,
    bound_local: SocketAddr,
    batch: &mut BatchRecv,
    max_datagrams: usize,
    buffer_size: usize,
) -> io::Result<usize> {
    let mut datagrams = 0;
    for _ in 0..max_datagrams {
        let mut buffer = batch.take_buffer(buffer_size);
        match recv(socket, bound_local, &mut buffer)? {
            Some(meta) => datagrams += batch.push_received(buffer, meta),
            None => {
                batch.recycle_buffer(buffer);
                break;
            }
        }
    }
    Ok(datagrams)
}

pub(crate) fn send(
    socket: &UdpSocket,
    bound_local: SocketAddr,
    transmit: &Transmit,
) -> io::Result<usize> {
    if receive_message_function(socket).is_none() {
        return socket.send_to(&transmit.contents, transmit.destination);
    }

    let destination = socket2::SockAddr::from(transmit.destination);
    let mut data = WinSock::WSABUF {
        len: u32::try_from(transmit.contents.len()).unwrap_or(u32::MAX),
        buf: transmit.contents.as_ptr().cast_mut(),
    };
    let mut control = [0usize; CONTROL_WORDS];
    let mut message = WinSock::WSAMSG {
        name: destination.as_ptr().cast_mut().cast(),
        namelen: destination.len(),
        lpBuffers: ptr::from_mut(&mut data),
        dwBufferCount: 1,
        Control: WinSock::WSABUF {
            len: CONTROL_BYTES as u32,
            buf: control.as_mut_ptr().cast(),
        },
        dwFlags: 0,
    };
    let mut control_len = 0;
    if let Some(ecn) = transmit.ecn {
        let value = i32::from(ecn.bits());
        let (level, kind) = if destination_is_ipv4(transmit.destination) {
            (WinSock::IPPROTO_IP, WinSock::IP_ECN)
        } else {
            (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN)
        };
        push_control(&mut message, &mut control_len, level, kind, value)?;
    }
    if let Some(source) = transmit
        .source
        .filter(|source| bound_local.ip().is_unspecified() || source.ip() != bound_local.ip())
    {
        push_source_control(&mut message, &mut control_len, source)?;
    }
    message.Control.len = control_len as u32;
    if control_len == 0 {
        message.Control.buf = ptr::null_mut();
    }

    let mut sent = 0;
    let result = unsafe {
        WinSock::WSASendMsg(
            socket.as_raw_socket() as WinSock::SOCKET,
            &message,
            0,
            &mut sent,
            ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    tracing::trace!(
        destination = %transmit.destination,
        source = ?transmit.source,
        ecn = ?transmit.ecn,
        bytes = sent,
        "sent Windows UDP datagram with control metadata"
    );
    Ok(sent as usize)
}

pub(crate) fn send_batch(
    socket: &UdpSocket,
    bound_local: SocketAddr,
    batch: &BatchSend,
) -> io::Result<usize> {
    let mut sent = 0;
    for transmit in batch.iter() {
        match send(socket, bound_local, transmit) {
            Ok(_) => sent += 1,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(sent)
}

fn portable_recv(
    socket: &UdpSocket,
    bound_local: SocketAddr,
    buffer: &mut [u8],
) -> io::Result<Option<RecvMeta>> {
    match socket.recv_from(buffer) {
        Ok((len, remote)) => Ok(Some(RecvMeta {
            local: Some(bound_local),
            remote,
            interface: None,
            ecn: None,
            segment_size: None,
            len,
        })),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

fn set_flag(socket: WinSock::SOCKET, level: i32, name: i32) -> bool {
    unsafe {
        WinSock::setsockopt(
            socket,
            level,
            name,
            ptr::from_ref(&OPTION_ON).cast(),
            mem::size_of_val(&OPTION_ON) as i32,
        ) == 0
    }
}

fn is_ipv6_only(socket: WinSock::SOCKET) -> io::Result<bool> {
    let mut value = 0u32;
    let mut length = mem::size_of_val(&value) as i32;
    let result = unsafe {
        WinSock::getsockopt(
            socket,
            WinSock::IPPROTO_IPV6,
            WinSock::IPV6_V6ONLY,
            ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(value != 0)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn receive_message_function(socket: &UdpSocket) -> ReceiveMessageFn {
    *RECEIVE_MESSAGE.get_or_init(|| {
        let guid = WinSock::WSAID_WSARECVMSG;
        let mut function: ReceiveMessageFn = None;
        let mut returned = 0;
        let result = unsafe {
            WinSock::WSAIoctl(
                socket.as_raw_socket() as WinSock::SOCKET,
                WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                ptr::from_ref(&guid).cast_mut().cast(),
                mem::size_of_val(&guid) as u32,
                ptr::from_mut(&mut function).cast(),
                mem::size_of_val(&function) as u32,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if result == 0 && returned as usize == mem::size_of_val(&function) {
            function
        } else {
            None
        }
    })
}

fn destination_is_ipv4(destination: SocketAddr) -> bool {
    destination.is_ipv4()
        || matches!(destination.ip(), IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

fn push_source_control(
    message: &mut WinSock::WSAMSG,
    used: &mut usize,
    source: SocketAddr,
) -> io::Result<()> {
    let address = socket2::SockAddr::from(SocketAddr::new(source.ip(), 0));
    match source.ip() {
        IpAddr::V4(_) => {
            let address = unsafe { ptr::read(address.as_ptr().cast::<WinSock::SOCKADDR_IN>()) };
            let info = WinSock::IN_PKTINFO {
                ipi_addr: address.sin_addr,
                ipi_ifindex: 0,
            };
            push_control(
                message,
                used,
                WinSock::IPPROTO_IP,
                WinSock::IP_PKTINFO,
                info,
            )
        }
        IpAddr::V6(_) => {
            let address = unsafe { ptr::read(address.as_ptr().cast::<WinSock::SOCKADDR_IN6>()) };
            let info = WinSock::IN6_PKTINFO {
                ipi6_addr: address.sin6_addr,
                ipi6_ifindex: unsafe { address.Anonymous.sin6_scope_id },
            };
            push_control(
                message,
                used,
                WinSock::IPPROTO_IPV6,
                WinSock::IPV6_PKTINFO,
                info,
            )
        }
    }
}

fn push_control<T: Copy>(
    message: &mut WinSock::WSAMSG,
    used: &mut usize,
    level: i32,
    kind: i32,
    value: T,
) -> io::Result<()> {
    let space = control_space(mem::size_of::<T>());
    if used.saturating_add(space) > message.Control.len as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP control metadata exceeds buffer",
        ));
    }
    let header = unsafe { message.Control.buf.add(*used).cast::<WinSock::CMSGHDR>() };
    unsafe {
        ptr::write(
            header,
            WinSock::CMSGHDR {
                cmsg_len: control_len(mem::size_of::<T>()),
                cmsg_level: level,
                cmsg_type: kind,
            },
        );
        ptr::write_unaligned(control_data(header).cast::<T>(), value);
    }
    *used += space;
    Ok(())
}

fn decode_controls(
    message: &WinSock::WSAMSG,
) -> (Option<IpAddr>, Option<u32>, Option<EcnCodepoint>) {
    let mut local_ip = None;
    let mut interface = None;
    let mut ecn = None;
    for_each_control(message, |header, data_len| {
        let data = control_data(header);
        match (header.cmsg_level, header.cmsg_type) {
            (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO)
                if data_len >= mem::size_of::<WinSock::IN_PKTINFO>() =>
            {
                let info = unsafe { ptr::read_unaligned(data.cast::<WinSock::IN_PKTINFO>()) };
                let address = unsafe { info.ipi_addr.S_un.S_addr };
                local_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(address))));
                interface = Some(info.ipi_ifindex);
            }
            (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO)
                if data_len >= mem::size_of::<WinSock::IN6_PKTINFO>() =>
            {
                let info = unsafe { ptr::read_unaligned(data.cast::<WinSock::IN6_PKTINFO>()) };
                local_ip = Some(IpAddr::V6(Ipv6Addr::from(unsafe { info.ipi6_addr.u.Byte })));
                interface = Some(info.ipi6_ifindex);
            }
            (WinSock::IPPROTO_IP, WinSock::IP_ECN) | (WinSock::IPPROTO_IPV6, WinSock::IPV6_ECN)
                if data_len >= mem::size_of::<i32>() =>
            {
                let bits = unsafe { ptr::read_unaligned(data.cast::<i32>()) };
                ecn = EcnCodepoint::from_bits(bits as u8);
            }
            _ => {}
        }
    });
    (local_ip, interface, ecn)
}

fn for_each_control(message: &WinSock::WSAMSG, mut visit: impl FnMut(&WinSock::CMSGHDR, usize)) {
    let total = message.Control.len as usize;
    let mut offset = 0usize;
    while offset.saturating_add(mem::size_of::<WinSock::CMSGHDR>()) <= total {
        let header = unsafe { &*message.Control.buf.add(offset).cast::<WinSock::CMSGHDR>() };
        let minimum = control_len(0);
        if header.cmsg_len < minimum || header.cmsg_len > total - offset {
            break;
        }
        visit(header, header.cmsg_len - minimum);
        let next = control_align(header.cmsg_len);
        if next == 0 {
            break;
        }
        offset += next;
    }
}

fn sockaddr_to_std(source: &WinSock::SOCKADDR_INET) -> io::Result<SocketAddr> {
    let (_, address) = unsafe {
        socket2::SockAddr::try_init(|storage, length| {
            *length = mem::size_of_val(source) as i32;
            ptr::copy_nonoverlapping(
                ptr::from_ref(source).cast::<u8>(),
                storage.cast::<u8>(),
                mem::size_of_val(source),
            );
            Ok(())
        })?
    };
    address.as_socket().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows UDP peer address",
        )
    })
}

fn control_data(header: *const WinSock::CMSGHDR) -> *mut u8 {
    unsafe {
        header
            .cast::<u8>()
            .add(control_align(mem::size_of::<WinSock::CMSGHDR>()))
            .cast_mut()
    }
}

fn control_len(payload: usize) -> usize {
    control_align(mem::size_of::<WinSock::CMSGHDR>()) + payload
}

fn control_space(payload: usize) -> usize {
    control_align(control_len(payload))
}

fn control_align(length: usize) -> usize {
    let alignment = mem::align_of::<usize>();
    (length + alignment - 1) & !(alignment - 1)
}
