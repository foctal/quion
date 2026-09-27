use std::sync::{Arc, Mutex, MutexGuard};

use rustls::{
    pki_types::ServerName,
    quic::{self, KeyChange},
};

use crate::{
    crypto::{CryptoProvider, CryptoSession},
    error::{CodecError, Result},
    packet::{
        Header, LongHeader, PacketType, ShortHeader, decode_packet_number, encode_packet_number,
    },
    varint::VarInt,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct RustlsProvider;

impl RustlsProvider {
    pub fn start_client_with_transport_parameters(
        &self,
        config: Arc<rustls::ClientConfig>,
        server_name: ServerName<'static>,
        transport_parameters: Vec<u8>,
    ) -> Result<RustlsSession> {
        let conn = quic::ClientConnection::new(
            config,
            quic::Version::V1,
            server_name,
            transport_parameters,
        )
        .map_err(map_rustls_error)?;
        Ok(RustlsSession::new(quic::Connection::Client(conn)))
    }

    pub fn start_server_with_transport_parameters(
        &self,
        config: Arc<rustls::ServerConfig>,
        transport_parameters: Vec<u8>,
    ) -> Result<RustlsSession> {
        let conn = quic::ServerConnection::new(config, quic::Version::V1, transport_parameters)
            .map_err(map_rustls_error)?;
        Ok(RustlsSession::new(quic::Connection::Server(conn)))
    }
}

impl CryptoProvider for RustlsProvider {
    type ClientConfig = rustls::ClientConfig;
    type ServerConfig = rustls::ServerConfig;
    type Session = RustlsSession;

    fn start_client(
        &self,
        config: Arc<Self::ClientConfig>,
        server_name: &str,
    ) -> Result<Self::Session> {
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|err| CodecError::Crypto(err.to_string()))?;
        self.start_client_with_transport_parameters(config, name, Vec::new())
    }

    fn start_server(&self, config: Arc<Self::ServerConfig>) -> Result<Self::Session> {
        self.start_server_with_transport_parameters(config, Vec::new())
    }
}

/// A TLS session whose exporter can be shared with an established connection.
#[derive(Debug)]
pub struct RustlsSession {
    connection: Arc<Mutex<quic::Connection>>,
}

/// Access to the TLS exporter without exposing mutable handshake state.
#[derive(Debug, Clone)]
pub struct RustlsExporter {
    connection: Arc<Mutex<quic::Connection>>,
}

impl RustlsExporter {
    /// Derives TLS 1.3 keying material after handshake completion.
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<()> {
        self.connection
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .export_keying_material(output, label, Some(context))
            .map(|_| ())
            .map_err(map_rustls_error)
    }
}

impl RustlsSession {
    fn new(connection: quic::Connection) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, quic::Connection> {
        self.connection.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Returns a handle to this session's TLS exporter.
    pub fn exporter(&self) -> RustlsExporter {
        RustlsExporter {
            connection: self.connection.clone(),
        }
    }

    #[cfg(feature = "zero-rtt")]
    pub fn install_zero_rtt_keys(&self, keys: &mut RustlsKeyStore) -> bool {
        match &*self.lock() {
            quic::Connection::Client(conn) => conn
                .zero_rtt_keys()
                .map(|zero_rtt| keys.install_zero_rtt_local(zero_rtt)),
            quic::Connection::Server(conn) => conn
                .zero_rtt_keys()
                .map(|zero_rtt| keys.install_zero_rtt_remote(zero_rtt)),
        }
        .is_some()
    }

    /// Returns the server's resolved 0-RTT decision for a client session.
    ///
    /// `None` means this is a server session or the handshake is still in progress.
    #[cfg(feature = "zero-rtt")]
    pub fn client_zero_rtt_accepted(&self) -> Option<bool> {
        match &*self.lock() {
            quic::Connection::Client(conn) if !conn.is_handshaking() => {
                Some(conn.is_early_data_accepted())
            }
            _ => None,
        }
    }

    pub fn read_handshake(&mut self, plaintext: &[u8]) -> Result<()> {
        self.lock().read_hs(plaintext).map_err(map_rustls_error)
    }

    pub fn write_handshake(&mut self, out: &mut Vec<u8>) -> Option<RustlsKeyChange> {
        self.lock().write_hs(out).map(RustlsKeyChange::from)
    }

    /// Returns an owned copy of the peer's encoded QUIC transport parameters,
    /// or `None` if they have not been received yet.
    pub fn peer_transport_parameters(&self) -> Option<Vec<u8>> {
        self.lock()
            .quic_transport_parameters()
            .map(ToOwned::to_owned)
    }

    pub fn alert(&self) -> Option<rustls::AlertDescription> {
        self.lock().alert()
    }

    pub fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        self.lock()
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
    }

    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.lock().alpn_protocol().map(ToOwned::to_owned)
    }
}

impl CryptoSession for RustlsSession {
    fn write_tls(&mut self, out: &mut Vec<u8>) -> Result<()> {
        let _ = self.write_handshake(out);
        Ok(())
    }

    fn read_tls(&mut self, input: &[u8]) -> Result<()> {
        self.read_handshake(input)
    }

    fn is_handshaking(&self) -> bool {
        self.lock().is_handshaking()
    }
}

pub enum RustlsKeyChange {
    Handshake {
        keys: quic::Keys,
    },
    OneRtt {
        keys: quic::Keys,
        next: quic::Secrets,
    },
}

/// Bit in the short-header first byte that carries the current key phase.
const KEY_PHASE_BIT: u8 = 0x04;

#[derive(Default)]
pub struct RustlsKeyStore {
    handshake: Option<RustlsPacketKeys>,
    #[cfg(feature = "zero-rtt")]
    zero_rtt: Option<RustlsPacketKeys>,
    one_rtt: Option<RustlsPacketKeys>,
    one_rtt_key_phase: bool,
    next_one_rtt: Option<quic::Secrets>,
    /// Remote packet key for the previous key phase, retained after a key
    /// update so reordered packets protected with the old keys can still be
    /// decrypted (RFC 9001 §6.3).
    previous_remote_packet: Option<Box<dyn quic::PacketKey>>,
    /// Lowest packet number observed in the current key phase. Used to tell a
    /// reordered previous-phase packet apart from a peer-initiated update when
    /// the key-phase bit differs from the current phase.
    current_phase_first_pn: Option<u64>,
    /// Number of failed 1-RTT decryptions since the last successful one. Used to
    /// surface the RFC 9001 §6.6 integrity limit to higher layers.
    one_rtt_integrity_failures: u64,
}

impl core::fmt::Debug for RustlsKeyStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = f.debug_struct("RustlsKeyStore");
        debug.field("has_handshake", &self.has_handshake());
        #[cfg(feature = "zero-rtt")]
        debug.field("has_zero_rtt", &self.has_zero_rtt());
        debug
            .field("has_one_rtt", &self.has_one_rtt())
            .field("has_next_one_rtt", &self.has_next_one_rtt())
            .field("one_rtt_key_phase", &self.one_rtt_key_phase)
            .field(
                "has_previous_one_rtt",
                &self.previous_remote_packet.is_some(),
            )
            .finish()
    }
}

impl RustlsKeyStore {
    #[cfg(feature = "zero-rtt")]
    fn install_zero_rtt_local(&mut self, keys: quic::DirectionalKeys) {
        self.zero_rtt = Some(RustlsPacketKeys::new_local(keys));
    }

    #[cfg(feature = "zero-rtt")]
    fn install_zero_rtt_remote(&mut self, keys: quic::DirectionalKeys) {
        self.zero_rtt = Some(RustlsPacketKeys::new_remote(keys));
    }

    pub fn install(&mut self, change: RustlsKeyChange) -> crate::crypto::EncryptionLevel {
        match change {
            RustlsKeyChange::Handshake { keys } => {
                self.handshake = Some(RustlsPacketKeys::new(keys));
                crate::crypto::EncryptionLevel::Handshake
            }
            RustlsKeyChange::OneRtt { keys, next } => {
                self.one_rtt = Some(RustlsPacketKeys::new(keys));
                self.one_rtt_key_phase = false;
                self.next_one_rtt = Some(next);
                self.previous_remote_packet = None;
                self.current_phase_first_pn = None;
                self.one_rtt_integrity_failures = 0;
                crate::crypto::EncryptionLevel::OneRtt
            }
        }
    }

    pub fn get(&self, level: crate::crypto::EncryptionLevel) -> Option<&RustlsPacketKeys> {
        match level {
            crate::crypto::EncryptionLevel::Handshake => self.handshake.as_ref(),
            #[cfg(feature = "zero-rtt")]
            crate::crypto::EncryptionLevel::ZeroRtt => self.zero_rtt.as_ref(),
            crate::crypto::EncryptionLevel::OneRtt => self.one_rtt.as_ref(),
            crate::crypto::EncryptionLevel::Initial => None,
            #[cfg(not(feature = "zero-rtt"))]
            crate::crypto::EncryptionLevel::ZeroRtt => None,
        }
    }

    pub const fn has_handshake(&self) -> bool {
        self.handshake.is_some()
    }

    #[cfg(feature = "zero-rtt")]
    pub const fn has_zero_rtt(&self) -> bool {
        self.zero_rtt.is_some()
    }

    #[cfg(feature = "zero-rtt")]
    pub fn discard_zero_rtt(&mut self) {
        self.zero_rtt = None;
    }

    pub const fn has_one_rtt(&self) -> bool {
        self.one_rtt.is_some()
    }

    pub const fn has_next_one_rtt(&self) -> bool {
        self.next_one_rtt.is_some()
    }

    pub fn current_one_rtt_key_phase(&self) -> Option<bool> {
        self.one_rtt.as_ref().map(|_| self.one_rtt_key_phase)
    }

    pub fn discard_handshake(&mut self) {
        self.handshake = None;
    }

    pub fn initiate_one_rtt_key_update(&mut self) -> Result<bool> {
        self.promote_next_one_rtt()
    }

    /// Discards the remote packet key from the previous key phase.
    ///
    /// The caller must only do this after receiving an acknowledgement for a
    /// packet sent with the current keys, as required by RFC 9001 Section 6.3.
    pub fn discard_previous_one_rtt_key(&mut self) {
        self.previous_remote_packet = None;
    }

    /// Returns whether a remote packet key from the previous phase is retained.
    pub const fn has_previous_one_rtt_key(&self) -> bool {
        self.previous_remote_packet.is_some()
    }

    /// Returns the lowest packet number successfully opened in the current
    /// 1-RTT key phase.
    pub const fn current_one_rtt_phase_first_packet_number(&self) -> Option<u64> {
        self.current_phase_first_pn
    }

    pub fn protect_one_rtt_short_packet(
        &self,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.protect_one_rtt_short_packet_in(Vec::new(), header, packet_number, plaintext_payload)
    }

    /// Protects a 1-RTT short-header packet using the supplied allocation.
    ///
    /// The buffer is cleared before use, allowing callers to recycle packet
    /// storage between transmissions.
    pub fn protect_one_rtt_short_packet_in(
        &self,
        packet: Vec<u8>,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        let keys = self
            .one_rtt
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?;
        keys.protect_short_packet_in(packet, header, packet_number, plaintext_payload)
    }

    pub(crate) fn protect_one_rtt_short_packet_with_payload_in(
        &self,
        packet: Vec<u8>,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload_len: usize,
        append_plaintext_payload: impl FnOnce(&mut Vec<u8>),
    ) -> Result<Vec<u8>> {
        let keys = self
            .one_rtt
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?;
        keys.protect_short_packet_with_payload_in(
            packet,
            header,
            packet_number,
            plaintext_payload_len,
            append_plaintext_payload,
        )
    }

    pub fn open_one_rtt_short_packet<'a>(
        &mut self,
        packet: &'a mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
    ) -> Result<OpenedRustlsPacket<'a>> {
        self.open_one_rtt_short_packet_with_key_update_permission(
            packet,
            expected_dst_cid_len,
            largest_received,
            true,
        )
    }

    pub fn open_one_rtt_short_packet_with_key_update_permission<'a>(
        &mut self,
        packet: &'a mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
        key_update_permitted: bool,
    ) -> Result<OpenedRustlsPacket<'a>> {
        if self.one_rtt.is_none() {
            return Err(CodecError::Crypto("missing 1-RTT keys".into()));
        }

        // Header protection keys never rotate on a key update, so the current
        // remote header key always recovers the key-phase bit and packet number.
        let packet_number_offset = 1 + expected_dst_cid_len;
        {
            let keys = self
                .one_rtt
                .as_ref()
                .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?;
            let sample = header_protection_sample(packet, packet_number_offset)?;
            unprotect_header_with_key(
                keys.remote
                    .as_ref()
                    .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?
                    .header
                    .as_ref(),
                packet,
                packet_number_offset,
                &sample,
            )?;
        }

        let first_byte = *packet.first().ok_or(CodecError::UnexpectedEnd)?;
        let key_phase = first_byte & KEY_PHASE_BIT != 0;
        let packet_number_len = usize::from(first_byte & 0x03) + 1;
        let packet_number_end = packet_number_offset + packet_number_len;
        let truncated_packet_number = packet
            .get(packet_number_offset..packet_number_end)
            .ok_or(CodecError::UnexpectedEnd)?
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        let packet_number =
            decode_packet_number(truncated_packet_number, packet_number_len, largest_received);

        let (header, consumed) = Header::decode(packet, expected_dst_cid_len)?;
        if consumed != packet_number_offset {
            return Err(CodecError::MalformedPacket);
        }

        let choice = if key_phase == self.one_rtt_key_phase {
            KeyChoice::Current
        } else if self.previous_remote_packet.is_some()
            && self
                .current_phase_first_pn
                .is_none_or(|first| packet_number < first)
        {
            // The phase bit differs and either we have not yet received a packet
            // in the current phase or this packet precedes it: a reordered or
            // lagging packet from the previous key phase.
            KeyChoice::Previous
        } else {
            // Phase bit differs and the packet number is at or beyond the start
            // of the current phase: a peer-initiated key update.
            KeyChoice::Update
        };

        let datagram_len = packet.len();
        let (header_bytes, payload) = packet.split_at_mut(packet_number_end);
        let result = match choice {
            KeyChoice::Current => {
                let keys = self
                    .one_rtt
                    .as_ref()
                    .ok_or_else(|| CodecError::Crypto("missing 1-RTT keys".into()))?;
                keys.remote
                    .as_ref()
                    .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?
                    .packet
                    .decrypt_in_place(packet_number, header_bytes, payload)
            }
            KeyChoice::Previous => {
                let previous = self
                    .previous_remote_packet
                    .as_ref()
                    .ok_or_else(|| CodecError::Crypto("missing previous 1-RTT keys".into()))?;
                previous.decrypt_in_place(packet_number, header_bytes, payload)
            }
            KeyChoice::Update => {
                if !key_update_permitted {
                    return Err(CodecError::Transport(
                        crate::transport_error::TransportErrorCode::KeyUpdateError,
                    ));
                }
                let next_keys = self
                    .derived_next_one_rtt_packet_keys()
                    .ok_or_else(|| CodecError::Crypto("missing next 1-RTT keys".into()))?;
                next_keys
                    .remote
                    .decrypt_in_place(packet_number, header_bytes, payload)
            }
        };

        let Ok(payload) = result else {
            self.one_rtt_integrity_failures = self.one_rtt_integrity_failures.saturating_add(1);
            if self
                .one_rtt_integrity_limit()
                .is_some_and(|limit| self.one_rtt_integrity_failures >= limit)
            {
                return Err(CodecError::Transport(
                    crate::transport_error::TransportErrorCode::AeadLimitReached,
                ));
            }
            return Err(CodecError::PacketDiscard);
        };

        match choice {
            KeyChoice::Current => self.note_current_phase_packet(packet_number),
            KeyChoice::Previous => {}
            KeyChoice::Update => {
                // The update is confirmed: rotate keys, retire the old remote
                // key for reorder handling, and anchor the new phase.
                self.promote_next_one_rtt()?;
                self.current_phase_first_pn = Some(packet_number);
            }
        }

        Ok(OpenedRustlsPacket {
            header,
            packet_number,
            payload,
            consumed: datagram_len,
        })
    }

    fn note_current_phase_packet(&mut self, packet_number: u64) {
        self.current_phase_first_pn = Some(match self.current_phase_first_pn {
            Some(first) => first.min(packet_number),
            None => packet_number,
        });
    }

    /// Number of consecutive failed 1-RTT decryptions since the last success.
    ///
    /// RFC 9001 §6.6 requires closing the connection once this reaches the AEAD
    /// integrity limit for the negotiated cipher.
    pub const fn one_rtt_integrity_failures(&self) -> u64 {
        self.one_rtt_integrity_failures
    }

    /// AEAD confidentiality limit for the local 1-RTT packet protection key, if
    /// 1-RTT keys are installed. A key update must be initiated before this many
    /// packets are protected with the current key (RFC 9001 §6.6).
    pub fn one_rtt_confidentiality_limit(&self) -> Option<u64> {
        self.one_rtt
            .as_ref()
            .and_then(|keys| keys.local.as_ref())
            .map(|keys| keys.packet.confidentiality_limit())
    }

    pub(crate) fn one_rtt_tag_len(&self) -> Option<usize> {
        self.one_rtt
            .as_ref()
            .and_then(|keys| keys.local.as_ref())
            .map(|keys| keys.packet.tag_len())
    }

    /// AEAD integrity limit for the remote 1-RTT packet protection key, if
    /// 1-RTT keys are installed.
    pub fn one_rtt_integrity_limit(&self) -> Option<u64> {
        self.one_rtt
            .as_ref()
            .and_then(|keys| keys.remote.as_ref())
            .map(|keys| keys.packet.integrity_limit())
    }

    fn promote_next_one_rtt(&mut self) -> Result<bool> {
        let Some(next_keys) = self
            .next_one_rtt
            .as_mut()
            .map(quic::Secrets::next_packet_keys)
        else {
            return Ok(false);
        };
        let current = self
            .one_rtt
            .as_mut()
            .ok_or_else(|| CodecError::Crypto("missing current 1-RTT keys".into()))?;
        current
            .local
            .as_mut()
            .ok_or_else(|| CodecError::Crypto("missing local packet keys".into()))?
            .packet = next_keys.local;
        self.previous_remote_packet = Some(core::mem::replace(
            &mut current
                .remote
                .as_mut()
                .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?
                .packet,
            next_keys.remote,
        ));
        self.one_rtt_key_phase = !self.one_rtt_key_phase;
        // The new phase starts empty until a packet is observed in it.
        self.current_phase_first_pn = None;
        Ok(true)
    }

    fn derived_next_one_rtt_packet_keys(&self) -> Option<quic::PacketKeySet> {
        let mut secrets = self.next_one_rtt.clone()?;
        Some(secrets.next_packet_keys())
    }
}

#[derive(Clone, Copy)]
enum KeyChoice {
    Current,
    Previous,
    Update,
}

pub struct RustlsPacketKeys {
    local: Option<quic::DirectionalKeys>,
    remote: Option<quic::DirectionalKeys>,
}

impl RustlsPacketKeys {
    pub fn new(keys: quic::Keys) -> Self {
        Self {
            local: Some(keys.local),
            remote: Some(keys.remote),
        }
    }

    #[cfg(feature = "zero-rtt")]
    fn new_local(keys: quic::DirectionalKeys) -> Self {
        Self {
            local: Some(keys),
            remote: None,
        }
    }

    #[cfg(feature = "zero-rtt")]
    fn new_remote(keys: quic::DirectionalKeys) -> Self {
        Self {
            local: None,
            remote: Some(keys),
        }
    }

    pub fn protect_long_packet(
        &self,
        mut header: LongHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        if !matches!(header.ty, PacketType::Handshake | PacketType::ZeroRtt) {
            return Err(CodecError::MalformedPacket);
        }

        let packet_number_len = header.packet_number_len;
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing local packet keys".into()))?;
        let minimum_payload_len =
            20usize.saturating_sub(packet_number_len + local.packet.tag_len());
        let payload_len = plaintext_payload.len().max(minimum_payload_len);
        let ciphertext_len = payload_len + local.packet.tag_len();
        header.length = Some(VarInt::new((packet_number_len + ciphertext_len) as u64)?);

        let mut packet = Header::Long(header).encode();
        let packet_number_offset = packet.len();
        encode_packet_number(packet_number, packet_number_len, &mut packet)?;
        let header_len = packet.len();

        packet.reserve(payload_len.saturating_add(local.packet.tag_len()));
        packet.extend_from_slice(plaintext_payload);
        packet.resize(header_len.saturating_add(payload_len), 0);
        let (header_bytes, payload) = packet.split_at_mut(header_len);
        let tag = local
            .packet
            .encrypt_in_place(packet_number, header_bytes, payload)
            .map_err(map_rustls_error)?;
        packet.extend_from_slice(tag.as_ref());

        let sample = header_protection_sample(&packet, packet_number_offset)?;
        protect_header_with_key(
            local.header.as_ref(),
            &mut packet[..header_len],
            packet_number_offset,
            packet_number_len,
            &sample,
        )?;

        Ok(packet)
    }

    pub fn protect_short_packet(
        &self,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.protect_short_packet_in(Vec::new(), header, packet_number, plaintext_payload)
    }

    pub fn protect_short_packet_in(
        &self,
        packet: Vec<u8>,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.protect_short_packet_with_payload_in(
            packet,
            header,
            packet_number,
            plaintext_payload.len(),
            |packet| packet.extend_from_slice(plaintext_payload),
        )
    }

    fn protect_short_packet_with_payload_in(
        &self,
        mut packet: Vec<u8>,
        header: ShortHeader,
        packet_number: u64,
        plaintext_payload_len: usize,
        append_plaintext_payload: impl FnOnce(&mut Vec<u8>),
    ) -> Result<Vec<u8>> {
        let packet_number_len = header.packet_number_len;
        packet.clear();
        Header::Short(header).append_encoded_to(&mut packet);
        let packet_number_offset = packet.len();
        encode_packet_number(packet_number, packet_number_len, &mut packet)?;
        let header_len = packet.len();

        let local = self
            .local
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing local packet keys".into()))?;
        let minimum_payload_len =
            20usize.saturating_sub(packet_number_len + local.packet.tag_len());
        let payload_len = plaintext_payload_len.max(minimum_payload_len);
        packet.reserve(payload_len.saturating_add(local.packet.tag_len()));
        append_plaintext_payload(&mut packet);
        if packet.len() != header_len.saturating_add(plaintext_payload_len) {
            return Err(CodecError::ValueOutOfBounds);
        }
        packet.resize(header_len.saturating_add(payload_len), 0);
        let (header_bytes, payload) = packet.split_at_mut(header_len);
        let tag = local
            .packet
            .encrypt_in_place(packet_number, header_bytes, payload)
            .map_err(map_rustls_error)?;
        packet.extend_from_slice(tag.as_ref());

        let sample = header_protection_sample(&packet, packet_number_offset)?;
        protect_header_with_key(
            local.header.as_ref(),
            &mut packet[..header_len],
            packet_number_offset,
            packet_number_len,
            &sample,
        )?;

        Ok(packet)
    }

    pub fn open_long_packet<'a>(
        &self,
        packet: &'a mut [u8],
        largest_received: Option<u64>,
    ) -> Result<OpenedRustlsPacket<'a>> {
        let packet_number_offset = long_header_packet_number_offset(packet)?;
        let sample = header_protection_sample(packet, packet_number_offset)?;

        let remote = self
            .remote
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?;
        unprotect_header_with_key(
            remote.header.as_ref(),
            packet,
            packet_number_offset,
            &sample,
        )?;

        let packet_number_len = usize::from(packet[0] & 0x03) + 1;
        let packet_number_end = packet_number_offset + packet_number_len;
        let truncated_packet_number = packet[packet_number_offset..packet_number_end]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        let packet_number =
            decode_packet_number(truncated_packet_number, packet_number_len, largest_received);

        let (header, consumed) = Header::decode(packet, 0)?;
        if consumed != packet_number_offset {
            return Err(CodecError::MalformedPacket);
        }

        // Bound the ciphertext by the long-header Length field so coalesced
        // trailing packets are not fed into this packet's AEAD (RFC 9000 §12.2).
        let Header::Long(ref long) = header else {
            return Err(CodecError::MalformedPacket);
        };
        let length = long.length.ok_or(CodecError::MalformedPacket)?.into_inner() as usize;
        if length < packet_number_len {
            return Err(CodecError::MalformedPacket);
        }
        let packet_end = packet_number_offset
            .checked_add(length)
            .ok_or(CodecError::MalformedPacket)?;
        if packet_end > packet.len() {
            return Err(CodecError::UnexpectedEnd);
        }

        let (header_bytes, rest) = packet.split_at_mut(packet_number_end);
        let ciphertext = rest
            .get_mut(..packet_end - packet_number_end)
            .ok_or(CodecError::UnexpectedEnd)?;
        let payload = self
            .remote
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?
            .packet
            .decrypt_in_place(packet_number, header_bytes, ciphertext)
            .map_err(map_rustls_error)?;

        Ok(OpenedRustlsPacket {
            header,
            packet_number,
            payload,
            consumed: packet_end,
        })
    }

    pub fn open_short_packet<'a>(
        &self,
        packet: &'a mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
    ) -> Result<OpenedRustlsPacket<'a>> {
        self.open_short_packet_with_packet_keys(
            self.remote
                .as_ref()
                .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?
                .packet
                .as_ref(),
            packet,
            expected_dst_cid_len,
            largest_received,
        )
    }

    fn open_short_packet_with_packet_keys<'a>(
        &self,
        packet_key: &dyn quic::PacketKey,
        packet: &'a mut [u8],
        expected_dst_cid_len: usize,
        largest_received: Option<u64>,
    ) -> Result<OpenedRustlsPacket<'a>> {
        let packet_number_offset = 1 + expected_dst_cid_len;
        let sample = header_protection_sample(packet, packet_number_offset)?;

        let remote = self
            .remote
            .as_ref()
            .ok_or_else(|| CodecError::Crypto("missing remote packet keys".into()))?;
        unprotect_header_with_key(
            remote.header.as_ref(),
            packet,
            packet_number_offset,
            &sample,
        )?;

        let packet_number_len = usize::from(packet[0] & 0x03) + 1;
        let packet_number_end = packet_number_offset + packet_number_len;
        let truncated_packet_number = packet[packet_number_offset..packet_number_end]
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
        let packet_number =
            decode_packet_number(truncated_packet_number, packet_number_len, largest_received);

        let (header, consumed) = Header::decode(packet, expected_dst_cid_len)?;
        if consumed != packet_number_offset {
            return Err(CodecError::MalformedPacket);
        }

        let datagram_len = packet.len();
        let (header_bytes, payload) = packet.split_at_mut(packet_number_end);
        let payload = packet_key
            .decrypt_in_place(packet_number, header_bytes, payload)
            .map_err(map_rustls_error)?;

        Ok(OpenedRustlsPacket {
            header,
            packet_number,
            payload,
            consumed: datagram_len,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpenedRustlsPacket<'a> {
    pub header: Header,
    pub packet_number: u64,
    pub payload: &'a [u8],
    /// Total length of this packet within the datagram, i.e. the offset at which
    /// a coalesced following packet would begin. Short-header packets always run
    /// to the end of the datagram.
    pub consumed: usize,
}

impl From<KeyChange> for RustlsKeyChange {
    fn from(value: KeyChange) -> Self {
        match value {
            KeyChange::Handshake { keys } => Self::Handshake { keys },
            KeyChange::OneRtt { keys, next } => Self::OneRtt { keys, next },
        }
    }
}

fn map_rustls_error(error: rustls::Error) -> CodecError {
    CodecError::Crypto(error.to_string())
}

fn header_protection_sample(packet: &[u8], packet_number_offset: usize) -> Result<[u8; 16]> {
    let sample_offset = packet_number_offset
        .checked_add(4)
        .ok_or(CodecError::ValueOutOfBounds)?;
    packet
        .get(sample_offset..sample_offset.saturating_add(16))
        .ok_or(CodecError::UnexpectedEnd)?
        .try_into()
        .map_err(|_| CodecError::UnexpectedEnd)
}

fn protect_header_with_key(
    key: &dyn quic::HeaderProtectionKey,
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
    sample: &[u8],
) -> Result<()> {
    let (first, packet_number) = header_parts(header, packet_number_offset, packet_number_len)?;
    key.encrypt_in_place(sample, first, packet_number)
        .map_err(map_rustls_error)
}

fn unprotect_header_with_key(
    key: &dyn quic::HeaderProtectionKey,
    packet: &mut [u8],
    packet_number_offset: usize,
    sample: &[u8],
) -> Result<()> {
    let (first, packet_number) = header_parts(packet, packet_number_offset, 4)?;
    key.decrypt_in_place(sample, first, packet_number)
        .map_err(map_rustls_error)
}

fn header_parts(
    header: &mut [u8],
    packet_number_offset: usize,
    packet_number_len: usize,
) -> Result<(&mut u8, &mut [u8])> {
    if !(1..=4).contains(&packet_number_len) {
        return Err(CodecError::ValueOutOfBounds);
    }
    if header.is_empty() {
        return Err(CodecError::UnexpectedEnd);
    }
    let packet_number_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(CodecError::ValueOutOfBounds)?;
    if packet_number_end > header.len() || packet_number_offset == 0 {
        return Err(CodecError::UnexpectedEnd);
    }
    let (first, rest) = header.split_at_mut(1);
    let pn_start = packet_number_offset - 1;
    Ok((
        &mut first[0],
        &mut rest[pn_start..pn_start + packet_number_len],
    ))
}

fn long_header_packet_number_offset(packet: &[u8]) -> Result<usize> {
    let (header, consumed) = Header::decode(packet, 0)?;
    match header {
        Header::Long(LongHeader {
            ty: PacketType::Handshake | PacketType::ZeroRtt,
            ..
        }) => Ok(consumed),
        _ => Err(CodecError::MalformedPacket),
    }
}

#[cfg(test)]
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub(crate) mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    #[cfg(feature = "rustls-ring")]
    use rustls::crypto::ring;
    use rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    };

    use super::*;
    use crate::{
        cid::ConnectionId,
        connection::Connection,
        crypto::{
            EncryptionLevel, Side,
            initial::{InitialKeys, InitialPacketProtector},
            packet::{CryptoPacketBuilder, CryptoPacketOpener},
            stream::CryptoFrame,
        },
        frame::Frame,
        packet::QUIC_VERSION_1,
    };

    #[test]
    fn simulated_rustls_quic_handshake_exchanges_protected_crypto_packets() {
        let (client_tls, server_tls, client_keys, server_keys, io) = simulated_handshake();

        assert!(!client_tls.is_handshaking());
        assert!(!server_tls.is_handshaking());
        assert_eq!(
            client_tls.peer_transport_parameters().as_deref(),
            Some(&b"server transport parameters"[..])
        );
        assert_eq!(
            server_tls.peer_transport_parameters().as_deref(),
            Some(&b"client transport parameters"[..])
        );
        assert!(client_keys.has_handshake());
        assert!(server_keys.has_handshake());
        assert!(client_keys.has_one_rtt());
        assert!(server_keys.has_one_rtt());
        assert!(io.clock.now() > 0);
        assert_eq!(io.delivered_packets, io.sent_packets);

        let frames = vec![CryptoFrame {
            level: EncryptionLevel::Handshake,
            offset: 0,
            bytes: b"protected handshake bytes".to_vec(),
        }];
        let mut builder = CryptoPacketBuilder::new(
            crate::cid::ConnectionId::from_slice(b"server-dcid").unwrap(),
            crate::cid::ConnectionId::from_slice(b"client-scid").unwrap(),
        );
        let mut packet = builder.build_handshake(&client_keys, &frames).unwrap();
        let opened = CryptoPacketOpener::open_handshake(&server_keys, &mut packet, None).unwrap();

        assert_eq!(opened.level, EncryptionLevel::Handshake);
        assert_eq!(opened.packet_number, 0);
        assert_eq!(
            opened.frames.as_slice(),
            &[Frame::Crypto {
                offset: crate::VarInt::ZERO,
                data: b"protected handshake bytes".to_vec(),
            }]
        );
    }

    #[test]
    fn key_update_rotates_one_rtt_key_phase_and_opening_keys() {
        use crate::crypto::packet::{FramePacketBuilder, FramePacketOpener};

        let (mut client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let expected_dst_cid_len = dst.len();
        let mut builder = FramePacketBuilder::new(dst);

        let first_frames = [Frame::Datagram {
            data: b"first-1rtt-packet".to_vec().into(),
        }];
        let mut first = builder.build_one_rtt(&client_keys, &first_frames).unwrap();
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut first,
            expected_dst_cid_len,
            None,
        )
        .unwrap();
        let Header::Short(first_header) = opened.header else {
            panic!("expected short header");
        };
        assert!(!first_header.key_phase);
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(false));

        assert!(client_keys.initiate_one_rtt_key_update().unwrap());
        let second_frames = [Frame::Datagram {
            data: b"second-1rtt-packet".to_vec().into(),
        }];
        let mut second = builder.build_one_rtt(&client_keys, &second_frames).unwrap();
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut second,
            expected_dst_cid_len,
            Some(0),
        )
        .unwrap();
        let Header::Short(second_header) = opened.header else {
            panic!("expected short header");
        };
        assert!(second_header.key_phase);
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(true));
    }

    #[test]
    fn reordered_previous_phase_packet_decrypts_after_key_update() {
        use crate::crypto::packet::{FramePacketBuilder, FramePacketOpener};

        let (mut client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let expected_dst_cid_len = dst.len();
        let mut builder = FramePacketBuilder::new(dst);

        // Build an old-phase packet (packet number 0) but hold it back.
        let old_phase_frames = [Frame::Datagram {
            data: b"old-phase-packet".to_vec().into(),
        }];
        let mut reordered = builder
            .build_one_rtt(&client_keys, &old_phase_frames)
            .unwrap();

        // Client updates keys and sends packet number 1 in the new phase first.
        assert!(client_keys.initiate_one_rtt_key_update().unwrap());
        let new_phase_frames = [Frame::Datagram {
            data: b"new-phase-packet".to_vec().into(),
        }];
        let mut new_phase = builder
            .build_one_rtt(&client_keys, &new_phase_frames)
            .unwrap();

        // Server receives the new-phase packet first, triggering the update.
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut new_phase,
            expected_dst_cid_len,
            None,
        )
        .unwrap();
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(true));
        assert_eq!(
            opened.frames.as_slice(),
            &[Frame::Datagram {
                data: b"new-phase-packet".to_vec().into(),
            }]
        );

        // The reordered old-phase packet (lower packet number, old phase bit)
        // must still decrypt using the retained previous keys.
        let opened = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut reordered,
            expected_dst_cid_len,
            Some(1),
        )
        .unwrap();
        let Header::Short(header) = &opened.header else {
            panic!("expected short header");
        };
        assert!(!header.key_phase);
        assert_eq!(opened.packet_number, 0);
        assert_eq!(
            opened.frames.as_slice(),
            &[Frame::Datagram {
                data: b"old-phase-packet".to_vec().into(),
            }]
        );
        // The key phase must not flip back when handling a reordered packet.
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(true));
    }

    #[test]
    fn consecutive_peer_key_update_is_rejected_before_key_promotion() {
        use crate::crypto::packet::{FramePacketBuilder, FramePacketOpener};

        let (mut client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let expected_dst_cid_len = dst.len();
        let mut builder = FramePacketBuilder::new(dst);
        let frames = [Frame::Datagram {
            data: b"invalid-second-update".to_vec().into(),
        }];

        client_keys.initiate_one_rtt_key_update().unwrap();
        let mut first_update = builder.build_one_rtt(&client_keys, &frames).unwrap();
        FramePacketOpener::open_one_rtt_with_key_update_permission(
            &mut server_keys,
            &mut first_update,
            expected_dst_cid_len,
            None,
            true,
        )
        .unwrap();
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(true));
        assert_eq!(
            server_keys.current_one_rtt_phase_first_packet_number(),
            Some(0)
        );

        client_keys.initiate_one_rtt_key_update().unwrap();
        let mut second_update = builder.build_one_rtt(&client_keys, &frames).unwrap();
        let error = FramePacketOpener::open_one_rtt_with_key_update_permission(
            &mut server_keys,
            &mut second_update,
            expected_dst_cid_len,
            Some(0),
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            CodecError::Transport(crate::transport_error::TransportErrorCode::KeyUpdateError)
        );
        assert_eq!(server_keys.current_one_rtt_key_phase(), Some(true));
        assert_eq!(
            server_keys.current_one_rtt_phase_first_packet_number(),
            Some(0)
        );
        assert_eq!(server_keys.one_rtt_integrity_failures(), 0);
    }

    #[test]
    fn corrupt_one_rtt_packet_is_discarded_and_counts_toward_the_integrity_limit() {
        use crate::crypto::packet::{FramePacketBuilder, FramePacketOpener};

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let expected_dst_cid_len = dst.len();
        let mut builder = FramePacketBuilder::new(dst);
        let frames = [Frame::Datagram {
            data: b"integrity-check-payload".to_vec().into(),
        }];
        let mut packet = builder.build_one_rtt(&client_keys, &frames).unwrap();
        // Flip a byte in the authenticated tag region.
        let last = packet.len() - 1;
        packet[last] ^= 0xff;

        assert_eq!(server_keys.one_rtt_integrity_failures(), 0);
        let result = FramePacketOpener::open_one_rtt(
            &mut server_keys,
            &mut packet,
            expected_dst_cid_len,
            None,
        );
        assert_eq!(result.unwrap_err(), CodecError::PacketDiscard);
        assert_eq!(server_keys.one_rtt_integrity_failures(), 1);
        // RFC 9001 Section 6.6 counts failures per packet-protection key.
        // Successfully authenticated packets do not erase earlier failures.
        let mut good = builder.build_one_rtt(&client_keys, &frames).unwrap();
        FramePacketOpener::open_one_rtt(&mut server_keys, &mut good, expected_dst_cid_len, Some(0))
            .unwrap();
        assert_eq!(server_keys.one_rtt_integrity_failures(), 1);
    }

    #[test]
    fn malformed_unauthenticated_one_rtt_header_is_a_silent_discard() {
        use crate::crypto::packet::FramePacketOpener;

        let (_client_keys, mut server_keys) = one_rtt_test_keys();
        let mut packet = vec![0x40; 8];

        let error =
            FramePacketOpener::open_one_rtt(&mut server_keys, &mut packet, 8, None).unwrap_err();

        assert_eq!(error, CodecError::PacketDiscard);
        assert_eq!(server_keys.one_rtt_integrity_failures(), 0);
    }

    #[test]
    fn malformed_authenticated_one_rtt_frame_is_not_a_silent_discard() {
        use crate::crypto::packet::FramePacketOpener;

        let (client_keys, mut server_keys) = one_rtt_test_keys();
        let dst = ConnectionId::from_slice(b"server-dcid").unwrap();
        let header = ShortHeader {
            spin: false,
            key_phase: false,
            dst_cid: dst.clone(),
            packet_number_len: 2,
        };
        let malformed_close = [0x1d, 0x2a, 0x04, b'b', b'a'];
        let mut packet = client_keys
            .protect_one_rtt_short_packet(header, 0, &malformed_close)
            .unwrap();

        let error = FramePacketOpener::open_one_rtt(&mut server_keys, &mut packet, dst.len(), None)
            .unwrap_err();

        assert_ne!(error, CodecError::PacketDiscard);
        assert_eq!(
            error.transport_code(),
            crate::transport_error::TransportErrorCode::FrameEncodingError
        );
        assert_eq!(server_keys.one_rtt_integrity_failures(), 0);
    }

    #[test]
    fn aead_limits_are_exposed_when_one_rtt_keys_are_installed() {
        let (client_keys, _server_keys) = one_rtt_test_keys();
        assert!(client_keys.one_rtt_confidentiality_limit().is_some());
        assert!(client_keys.one_rtt_integrity_limit().is_some());
        assert!(client_keys.one_rtt_confidentiality_limit().unwrap() > 0);

        let empty = RustlsKeyStore::default();
        assert!(empty.one_rtt_confidentiality_limit().is_none());
        assert!(empty.one_rtt_integrity_limit().is_none());
    }

    #[test]
    #[cfg(feature = "rustls-ring")]
    fn negotiated_aead_limits_match_each_supported_ring_cipher() {
        let cases = [
            (
                ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
                1 << 23,
                1 << 52,
            ),
            (
                ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                1 << 23,
                1 << 52,
            ),
            (
                ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                u64::MAX,
                1 << 36,
            ),
        ];

        for (suite, confidentiality_limit, integrity_limit) in cases {
            let mut provider = ring::default_provider();
            provider.cipher_suites = vec![suite];
            let (_, _, client_keys, server_keys, _) = simulated_handshake_with_provider(provider);
            for keys in [&client_keys, &server_keys] {
                assert_eq!(
                    keys.one_rtt_confidentiality_limit(),
                    Some(confidentiality_limit)
                );
                assert_eq!(keys.one_rtt_integrity_limit(), Some(integrity_limit));
            }
        }
    }

    #[test]
    fn discard_handshake_removes_handshake_keys() {
        let (mut client_keys, _server_keys) = one_rtt_test_keys();
        assert!(client_keys.has_handshake());
        client_keys.discard_handshake();
        assert!(!client_keys.has_handshake());
        assert!(client_keys.has_one_rtt());
    }

    #[cfg(feature = "zero-rtt")]
    #[test]
    fn zero_rtt_long_packet_round_trips_with_directional_keys() {
        use crate::crypto::packet::{CryptoPacketBuilder, CryptoPacketOpener};

        let provider = default_test_crypto_provider();
        let suite = provider.cipher_suites[0]
            .tls13()
            .and_then(rustls::Tls13CipherSuite::quic_suite)
            .unwrap();
        let dcid = ConnectionId::from_slice(b"zero-rtt-dcid").unwrap();
        let client = suite.keys(dcid.as_bytes(), rustls::Side::Client, quic::Version::V1);
        let server = suite.keys(dcid.as_bytes(), rustls::Side::Server, quic::Version::V1);
        let mut client_keys = RustlsKeyStore::default();
        client_keys.install_zero_rtt_local(client.local);
        let mut server_keys = RustlsKeyStore::default();
        server_keys.install_zero_rtt_remote(server.remote);

        let mut builder = CryptoPacketBuilder::new(dcid, ConnectionId::EMPTY);
        let frames = [Frame::Stream {
            stream_id: crate::VarInt::ZERO,
            offset: crate::VarInt::ZERO,
            fin: false,
            data: b"early application data".to_vec().into(),
        }];
        let mut packet = builder
            .build_zero_rtt_frames(&client_keys, &frames)
            .unwrap();
        let opened = CryptoPacketOpener::open_zero_rtt(&server_keys, &mut packet, None).unwrap();

        assert_eq!(opened.level, EncryptionLevel::ZeroRtt);
        assert_eq!(opened.packet_number, 0);
        assert_eq!(opened.frames.as_slice(), frames.as_slice());
        assert!(matches!(
            opened.header,
            Header::Long(LongHeader {
                ty: PacketType::ZeroRtt,
                ..
            })
        ));
    }

    #[cfg(feature = "zero-rtt")]
    #[test]
    fn resumed_handshake_reports_zero_rtt_acceptance_and_rejection() {
        let (accepted_client_config, accepted_server_config) =
            configs_with_resumption_ticket(default_test_crypto_provider());
        let (accepted_client, _, accepted_client_keys, accepted_server_keys, _) =
            simulated_handshake_with_configs(accepted_client_config, accepted_server_config, false);
        assert!(accepted_client_keys.has_zero_rtt());
        assert!(accepted_server_keys.has_zero_rtt());
        assert_eq!(accepted_client.client_zero_rtt_accepted(), Some(true));

        let (rejected_client_config, accepted_server_config) =
            configs_with_resumption_ticket(default_test_crypto_provider());
        let mut rejected_server_config = (*accepted_server_config).clone();
        rejected_server_config.max_early_data_size = 0;
        let (rejected_client, _, rejected_client_keys, rejected_server_keys, _) =
            simulated_handshake_with_configs(
                rejected_client_config,
                Arc::new(rejected_server_config),
                false,
            );
        assert!(rejected_client_keys.has_zero_rtt());
        assert!(!rejected_server_keys.has_zero_rtt());
        assert_eq!(rejected_client.client_zero_rtt_accepted(), Some(false));
    }

    pub(crate) fn one_rtt_test_keys() -> (RustlsKeyStore, RustlsKeyStore) {
        let (_, _, client_keys, server_keys, _) = simulated_handshake();
        (client_keys, server_keys)
    }

    #[cfg(feature = "zero-rtt")]
    pub(crate) fn zero_rtt_test_keys() -> (RustlsKeyStore, RustlsKeyStore) {
        let (client_config, server_config) =
            configs_with_resumption_ticket(default_test_crypto_provider());
        let (_, _, client_keys, server_keys, _) =
            simulated_handshake_with_configs(client_config, server_config, false);
        (client_keys, server_keys)
    }

    fn simulated_handshake() -> (
        RustlsSession,
        RustlsSession,
        RustlsKeyStore,
        RustlsKeyStore,
        SimulatedIo,
    ) {
        simulated_handshake_with_provider(default_test_crypto_provider())
    }

    #[cfg(feature = "rustls-ring")]
    fn default_test_crypto_provider() -> rustls::crypto::CryptoProvider {
        ring::default_provider()
    }

    #[cfg(all(not(feature = "rustls-ring"), feature = "rustls-aws-lc-rs"))]
    fn default_test_crypto_provider() -> rustls::crypto::CryptoProvider {
        rustls::crypto::aws_lc_rs::default_provider()
    }

    fn simulated_handshake_with_provider(
        crypto_provider: rustls::crypto::CryptoProvider,
    ) -> (
        RustlsSession,
        RustlsSession,
        RustlsKeyStore,
        RustlsKeyStore,
        SimulatedIo,
    ) {
        let (client_config, server_config) = configs_with_provider(crypto_provider);
        simulated_handshake_with_configs(Arc::new(client_config), Arc::new(server_config), false)
    }

    fn simulated_handshake_with_configs(
        client_config: Arc<rustls::ClientConfig>,
        server_config: Arc<rustls::ServerConfig>,
        wait_for_ticket: bool,
    ) -> (
        RustlsSession,
        RustlsSession,
        RustlsKeyStore,
        RustlsKeyStore,
        SimulatedIo,
    ) {
        let provider = RustlsProvider;
        let mut client_tls = provider
            .start_client_with_transport_parameters(
                client_config,
                ServerName::try_from("localhost").unwrap(),
                b"client transport parameters".to_vec(),
            )
            .unwrap();
        let mut server_tls = provider
            .start_server_with_transport_parameters(
                server_config,
                b"server transport parameters".to_vec(),
            )
            .unwrap();
        let mut client_conn = Connection::new();
        let mut server_conn = Connection::new();
        let mut client_keys = RustlsKeyStore::default();
        let mut server_keys = RustlsKeyStore::default();
        let mut client_level = EncryptionLevel::Initial;
        let mut server_level = EncryptionLevel::Initial;
        let client_dcid = ConnectionId::from_slice(b"client-dcid").unwrap();
        let server_scid = ConnectionId::from_slice(b"server-scid").unwrap();
        let initial_keys = InitialKeys::derive(QUIC_VERSION_1, &client_dcid).unwrap();
        let client_initial = InitialPacketProtector::new(&initial_keys, Side::Client).unwrap();
        let server_initial = InitialPacketProtector::new(&initial_keys, Side::Server).unwrap();
        let mut client_builder = CryptoPacketBuilder::new(client_dcid.clone(), ConnectionId::EMPTY);
        let mut server_builder = CryptoPacketBuilder::new(ConnectionId::EMPTY, server_scid.clone());
        let mut io = SimulatedIo::default();

        #[cfg(feature = "zero-rtt")]
        client_tls.install_zero_rtt_keys(&mut client_keys);

        for _ in 0..32 {
            emit_crypto_packets(
                SenderPeer {
                    conn: &mut client_conn,
                    tls: &mut client_tls,
                    keys: &mut client_keys,
                    level: &mut client_level,
                    builder: &mut client_builder,
                    initial: &client_initial,
                },
                ReceiverPeer {
                    keys: &mut server_keys,
                    initial: &server_initial,
                },
                Direction::ClientToServer,
                &mut io,
            );
            io.deliver_to_server(&mut server_conn, &mut server_tls);
            #[cfg(feature = "zero-rtt")]
            server_tls.install_zero_rtt_keys(&mut server_keys);
            emit_crypto_packets(
                SenderPeer {
                    conn: &mut server_conn,
                    tls: &mut server_tls,
                    keys: &mut server_keys,
                    level: &mut server_level,
                    builder: &mut server_builder,
                    initial: &server_initial,
                },
                ReceiverPeer {
                    keys: &mut client_keys,
                    initial: &client_initial,
                },
                Direction::ServerToClient,
                &mut io,
            );
            io.deliver_to_client(&mut client_conn, &mut client_tls);

            let ticket_ready = match &*client_tls.lock() {
                quic::Connection::Client(conn) => conn.tls13_tickets_received() > 0,
                quic::Connection::Server(_) => false,
            };
            if !client_tls.is_handshaking()
                && !server_tls.is_handshaking()
                && (!wait_for_ticket || ticket_ready)
            {
                break;
            }
        }

        assert_eq!(client_conn.stats().packets_received, 0);
        (client_tls, server_tls, client_keys, server_keys, io)
    }

    struct SenderPeer<'a> {
        conn: &'a mut Connection,
        tls: &'a mut RustlsSession,
        keys: &'a mut RustlsKeyStore,
        level: &'a mut EncryptionLevel,
        builder: &'a mut CryptoPacketBuilder,
        initial: &'a InitialPacketProtector,
    }

    struct ReceiverPeer<'a> {
        keys: &'a mut RustlsKeyStore,
        initial: &'a InitialPacketProtector,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Direction {
        ClientToServer,
        ServerToClient,
    }

    #[derive(Debug)]
    struct SimulatedPacket {
        direction: Direction,
        opened: crate::crypto::packet::OpenedCryptoPacket,
        sent_at: u64,
    }

    #[derive(Debug, Default)]
    struct ManualClock {
        now: u64,
    }

    impl ManualClock {
        const fn now(&self) -> u64 {
            self.now
        }

        fn advance(&mut self, delta: u64) {
            self.now += delta;
        }
    }

    #[derive(Debug, Default)]
    struct SimulatedIo {
        clock: ManualClock,
        packets: VecDeque<SimulatedPacket>,
        sent_packets: u64,
        delivered_packets: u64,
        last_delivery_time: u64,
    }

    impl SimulatedIo {
        fn push(
            &mut self,
            direction: Direction,
            opened: crate::crypto::packet::OpenedCryptoPacket,
        ) {
            self.clock.advance(1);
            self.sent_packets += 1;
            self.packets.push_back(SimulatedPacket {
                direction,
                opened,
                sent_at: self.clock.now(),
            });
        }

        fn deliver_to_server(&mut self, conn: &mut Connection, tls: &mut RustlsSession) {
            self.deliver(Direction::ClientToServer, conn, tls);
        }

        fn deliver_to_client(&mut self, conn: &mut Connection, tls: &mut RustlsSession) {
            self.deliver(Direction::ServerToClient, conn, tls);
        }

        fn deliver(
            &mut self,
            direction: Direction,
            conn: &mut Connection,
            tls: &mut RustlsSession,
        ) {
            let mut retained = VecDeque::new();
            while let Some(packet) = self.packets.pop_front() {
                if packet.direction == direction {
                    assert!(packet.sent_at >= self.last_delivery_time);
                    self.last_delivery_time = packet.sent_at;
                    conn.handle_opened_crypto_packet(tls, packet.opened)
                        .unwrap();
                    self.delivered_packets += 1;
                } else {
                    retained.push_back(packet);
                }
            }
            self.packets = retained;
        }
    }

    fn emit_crypto_packets(
        sender: SenderPeer<'_>,
        receiver: ReceiverPeer<'_>,
        direction: Direction,
        io: &mut SimulatedIo,
    ) {
        let mut out = Vec::new();
        let key_change = sender.tls.write_handshake(&mut out);
        let effects = sender
            .conn
            .queue_crypto_bytes(*sender.level, &out, 1200)
            .unwrap();

        for frame in effects.crypto_frames {
            let opened = match frame.level {
                EncryptionLevel::Initial => {
                    let mut packet = sender
                        .builder
                        .build_initial(sender.initial, &[frame])
                        .unwrap();
                    CryptoPacketOpener::open_initial(receiver.initial, &mut packet, None).unwrap()
                }
                EncryptionLevel::Handshake => {
                    let mut packet = sender
                        .builder
                        .build_handshake(sender.keys, &[frame])
                        .unwrap();
                    CryptoPacketOpener::open_handshake(receiver.keys, &mut packet, None).unwrap()
                }
                EncryptionLevel::OneRtt => {
                    let expected_dst_cid_len = sender.builder.dst_cid_len();
                    let mut packet = sender.builder.build_one_rtt(sender.keys, &[frame]).unwrap();
                    CryptoPacketOpener::open_one_rtt(
                        receiver.keys,
                        &mut packet,
                        expected_dst_cid_len,
                        None,
                    )
                    .unwrap()
                }
                EncryptionLevel::ZeroRtt => {
                    panic!("handshake transfer emitted unexpected 0-RTT crypto")
                }
            };
            io.push(direction, opened);
        }

        if let Some(change) = key_change {
            *sender.level = sender.keys.install(change);
        }
    }

    fn configs_with_provider(
        provider: rustls::crypto::CryptoProvider,
    ) -> (rustls::ClientConfig, rustls::ServerConfig) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der: CertificateDer<'static> = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();

        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"hq-29".to_vec()];

        let mut server = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server.alpn_protocols = vec![b"hq-29".to_vec()];

        (client, server)
    }

    #[cfg(feature = "zero-rtt")]
    fn configs_with_resumption_ticket(
        provider: rustls::crypto::CryptoProvider,
    ) -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
        let (mut client, mut server) = configs_with_provider(provider);
        client.enable_early_data = true;
        server.max_early_data_size = u32::MAX;
        let client = Arc::new(client);
        let server = Arc::new(server);
        let (first_client, _, _, _, _) =
            simulated_handshake_with_configs(client.clone(), server.clone(), true);
        assert!(matches!(
            &*first_client.lock(),
            quic::Connection::Client(conn) if conn.tls13_tickets_received() > 0
        ));
        (client, server)
    }
}
