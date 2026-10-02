//! UDP support layer for quion.
//!
//! The portable fallback keeps socket I/O separate from packet metadata and
//! batching. Platform control-message, GSO, and GRO implementations can be
//! enabled without changing the public transport API.

mod batch;
mod cmsg;
mod ecn;
#[cfg(feature = "gro")]
mod gro;
#[cfg(feature = "gso")]
mod gso;
mod recv;
mod socket;
mod transmit;

use std::io;

use thiserror::Error;

pub use batch::{BatchRecv, BatchSend};
pub use ecn::{EcnCapabilities, EcnCodepoint};
pub use recv::RecvMeta;
pub use socket::UdpSocket;
pub use transmit::Transmit;

#[derive(Debug, Error)]
pub enum UdpError {
    #[error("udp socket error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, UdpError>;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn ecn_codepoints_roundtrip_bits() {
        for codepoint in [EcnCodepoint::Ect0, EcnCodepoint::Ect1, EcnCodepoint::Ce] {
            assert_eq!(EcnCodepoint::from_bits(codepoint.bits()), Some(codepoint));
        }
        assert_eq!(EcnCodepoint::from_bits(0), None);
    }

    #[test]
    fn batch_send_and_recv_over_loopback() {
        let a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        // Preserve CE receive coverage on platforms that permit injecting it.
        // Winsock rejects application-originated CE, so use ECT(1) there.
        let second_ecn = if cfg!(windows) {
            EcnCodepoint::Ect1
        } else {
            EcnCodepoint::Ce
        };
        let mut send = BatchSend::default();
        send.push(Transmit {
            destination: b.local_addr().unwrap(),
            source: None,
            ecn: Some(EcnCodepoint::Ect0),
            contents: b"one".to_vec(),
            segment_size: None,
            send_at: None,
        });
        send.push(Transmit {
            destination: b.local_addr().unwrap(),
            source: None,
            ecn: Some(second_ecn),
            contents: b"two".to_vec(),
            segment_size: None,
            send_at: None,
        });
        send.push(Transmit {
            destination: b.local_addr().unwrap(),
            source: None,
            ecn: None,
            contents: b"plain".to_vec(),
            segment_size: None,
            send_at: None,
        });

        assert_eq!(a.send_batch(&send).unwrap(), 3);

        let mut recv = BatchRecv::default();
        for _ in 0..100 {
            if b.recv_batch(&mut recv, 8, 64).unwrap() == 3 {
                break;
            }
            std::thread::yield_now();
        }

        assert_eq!(recv.len(), 3);
        let packets = recv.iter().map(|(bytes, _)| bytes).collect::<Vec<_>>();
        assert_eq!(packets, vec![&b"one"[..], &b"two"[..], &b"plain"[..]]);
        if b.ecn_capabilities().read {
            let marks = recv.iter().map(|(_, meta)| meta.ecn).collect::<Vec<_>>();
            assert_eq!(
                marks,
                vec![Some(EcnCodepoint::Ect0), Some(second_ecn), None]
            );
        }
        if b.destination_ip_supported() {
            assert!(
                recv.iter()
                    .all(|(_, meta)| meta.local == Some(b.local_addr().unwrap()))
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dual_stack_sender_reaches_ipv4_with_source_and_ecn() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use std::time::{Duration, Instant};

        let sender = UdpSocket::bind("[::]:0".parse().unwrap()).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let destination = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            receiver.local_addr().unwrap().port(),
        );
        let sources = [
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            None,
            Some(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        for source in sources {
            for ecn in [None, Some(EcnCodepoint::Ect0), Some(EcnCodepoint::Ect1)] {
                for batch in [false, true] {
                    let transmit = Transmit {
                        destination,
                        source: source
                            .map(|ip| SocketAddr::new(ip, sender.local_addr().unwrap().port())),
                        ecn,
                        contents: b"dual-stack".to_vec(),
                        segment_size: None,
                        send_at: None,
                    };
                    if batch {
                        let mut send = BatchSend::default();
                        send.push(transmit);
                        assert_eq!(sender.send_batch(&send).unwrap(), 1);
                    } else {
                        sender.send(&transmit).unwrap();
                    }
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let mut buffer = [0; 64];
                    let meta = loop {
                        if let Some(meta) = receiver.recv(&mut buffer).unwrap() {
                            break meta;
                        }
                        assert!(Instant::now() < deadline, "dual-stack datagram timed out");
                        std::thread::yield_now();
                    };
                    assert_eq!(&buffer[..meta.len], b"dual-stack");
                    assert_eq!(meta.remote.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                    if receiver.ecn_capabilities().read {
                        assert_eq!(meta.ecn, ecn);
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_sender_congestion_marking_without_sending_a_packet() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let sender = UdpSocket::bind(address.parse().unwrap()).unwrap();
            let receiver = UdpSocket::bind(address.parse().unwrap()).unwrap();
            let transmit = Transmit {
                destination: receiver.local_addr().unwrap(),
                source: None,
                ecn: Some(EcnCodepoint::Ce),
                contents: b"invalid sender marking".to_vec(),
                segment_size: None,
                send_at: None,
            };
            let UdpError::Io(error) = sender.send(&transmit).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            let mut buffer = [0; 64];
            assert!(receiver.recv(&mut buffer).unwrap().is_none());
        }
    }

    #[cfg(all(target_os = "linux", feature = "gso", feature = "gro"))]
    #[test]
    fn linux_gso_send_and_gro_receive_roundtrip_segments() {
        let sender = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut send = BatchSend::default();
        send.push(Transmit {
            destination: receiver.local_addr().unwrap(),
            source: None,
            ecn: None,
            contents: b"aaaabbbbcccc".to_vec(),
            segment_size: Some(4),
            send_at: None,
        });

        assert_eq!(sender.send_batch(&send).unwrap(), 1);

        let mut recv = BatchRecv::default();
        for _ in 0..100 {
            if receiver.recv_batch(&mut recv, 8, 64).unwrap() == 3 {
                break;
            }
            std::thread::yield_now();
        }

        assert_eq!(recv.len(), 3);
        assert_eq!(
            recv.iter().map(|(bytes, _)| bytes).collect::<Vec<_>>(),
            vec![&b"aaaa"[..], &b"bbbb"[..], &b"cccc"[..]]
        );
    }

    #[test]
    fn socket_buffer_sizes_can_be_configured_and_inspected() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();

        socket.set_recv_buffer_size(64 * 1024).unwrap();
        socket.set_send_buffer_size(64 * 1024).unwrap();

        assert!(socket.recv_buffer_size().unwrap() > 0);
        assert!(socket.send_buffer_size().unwrap() > 0);
    }

    #[test]
    fn wildcard_receive_preserves_the_destination_ip() {
        let sender = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let receiver = UdpSocket::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 1], receiver.local_addr().unwrap().port()));
        let transmit = Transmit {
            destination,
            source: Some(sender.local_addr().unwrap()),
            ecn: None,
            contents: b"destination".to_vec(),
            segment_size: None,
            send_at: None,
        };

        sender.send(&transmit).unwrap();
        let mut buffer = [0; 64];
        let meta = (0..100)
            .find_map(|_| {
                let received = receiver.recv(&mut buffer).unwrap();
                if received.is_none() {
                    std::thread::yield_now();
                }
                received
            })
            .expect("loopback datagram was not received");

        assert_eq!(&buffer[..meta.len], b"destination");
        if receiver.destination_ip_supported() {
            assert_eq!(meta.local, Some(destination));
        }
    }

    #[test]
    fn wildcard_ipv6_receive_preserves_the_destination_ip() {
        let Ok(sender) = UdpSocket::bind("[::1]:0".parse().unwrap()) else {
            return;
        };
        let Ok(receiver) = UdpSocket::bind("[::]:0".parse().unwrap()) else {
            return;
        };
        let destination = SocketAddr::from((
            [0, 0, 0, 0, 0, 0, 0, 1],
            receiver.local_addr().unwrap().port(),
        ));
        let transmit = Transmit {
            destination,
            source: Some(sender.local_addr().unwrap()),
            ecn: Some(EcnCodepoint::Ect1),
            contents: b"ipv6-destination".to_vec(),
            segment_size: None,
            send_at: None,
        };

        sender.send(&transmit).unwrap();
        let mut buffer = [0; 64];
        let meta = (0..100)
            .find_map(|_| {
                let received = receiver.recv(&mut buffer).unwrap();
                if received.is_none() {
                    std::thread::yield_now();
                }
                received
            })
            .expect("IPv6 loopback datagram was not received");

        assert_eq!(&buffer[..meta.len], b"ipv6-destination");
        if receiver.destination_ip_supported() {
            assert_eq!(meta.local, Some(destination));
        }
        if receiver.ecn_capabilities().read {
            assert_eq!(meta.ecn, Some(EcnCodepoint::Ect1));
        }
    }

    #[test]
    fn wildcard_ipv4_source_send_over_loopback() {
        wildcard_source_over_loopback("0.0.0.0:0", "127.0.0.1:0", false);
    }

    #[test]
    fn wildcard_ipv4_source_batch_send_over_loopback() {
        wildcard_source_over_loopback("0.0.0.0:0", "127.0.0.1:0", true);
    }

    #[test]
    fn wildcard_ipv6_source_send_over_loopback() {
        wildcard_source_over_loopback("[::]:0", "[::1]:0", false);
    }

    #[test]
    fn wildcard_ipv6_source_batch_send_over_loopback() {
        wildcard_source_over_loopback("[::]:0", "[::1]:0", true);
    }

    fn wildcard_source_over_loopback(bind: &str, loopback: &str, batch: bool) {
        use std::time::{Duration, Instant};

        let sender = UdpSocket::bind(bind.parse().unwrap()).unwrap();
        let receiver = UdpSocket::bind(loopback.parse().unwrap()).unwrap();
        let source = sender.local_addr().unwrap();
        let destination = receiver.local_addr().unwrap();
        assert!(source.ip().is_unspecified());

        for ecn in [None, Some(EcnCodepoint::Ect0), Some(EcnCodepoint::Ect1)] {
            let transmit = Transmit {
                destination,
                source: Some(source),
                ecn,
                contents: b"wildcard-source".to_vec(),
                segment_size: None,
                send_at: None,
            };
            if batch {
                let mut send = BatchSend::default();
                send.push(transmit);
                assert_eq!(sender.send_batch(&send).unwrap(), 1);
            } else {
                assert_eq!(sender.send(&transmit).unwrap(), transmit.contents.len());
            }

            let deadline = Instant::now() + Duration::from_secs(2);
            let mut buffer = [0; 64];
            let meta = loop {
                if let Some(meta) = receiver.recv(&mut buffer).unwrap() {
                    break meta;
                }
                assert!(
                    Instant::now() < deadline,
                    "wildcard-source datagram timed out"
                );
                std::thread::yield_now();
            };
            assert_eq!(&buffer[..meta.len], b"wildcard-source");
            assert_eq!(
                meta.remote,
                SocketAddr::new(destination.ip(), source.port())
            );
            if receiver.ecn_capabilities().read {
                assert_eq!(meta.ecn, ecn);
            }
        }
    }

    #[test]
    fn wildcard_sender_selects_an_explicit_source_address() {
        let sender = UdpSocket::bind("0.0.0.0:0".parse().unwrap()).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source = SocketAddr::from(([127, 0, 0, 1], sender.local_addr().unwrap().port()));
        let transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            source: Some(source),
            ecn: Some(EcnCodepoint::Ect0),
            contents: b"explicit-source".to_vec(),
            segment_size: None,
            send_at: None,
        };

        sender.send(&transmit).unwrap();
        let mut buffer = [0; 64];
        let meta = (0..100)
            .find_map(|_| {
                let received = receiver.recv(&mut buffer).unwrap();
                if received.is_none() {
                    std::thread::yield_now();
                }
                received
            })
            .expect("explicit-source loopback datagram was not received");

        assert_eq!(&buffer[..meta.len], b"explicit-source");
        assert_eq!(meta.remote.ip(), source.ip());
        if receiver.ecn_capabilities().read {
            assert_eq!(meta.ecn, Some(EcnCodepoint::Ect0));
        }
    }
}
