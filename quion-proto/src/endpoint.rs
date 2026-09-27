use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use web_time::Duration;

use crate::{
    cid::ConnectionId,
    error::Result,
    packet::{Header, LongHeader, PacketType, QUIC_VERSION_1, encode_retry_packet},
    stats::EndpointStats,
    token::{RetryToken, RetryTokenKey, RetryTokenManager, TokenReplayCache},
};

const MAX_ANTI_AMPLIFICATION_FACTOR: u64 = 3;
const DEFAULT_MAX_TRACKED_PATHS: usize = 4096;
const MIN_RETRY_SOURCE_CID_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    ExistingConnection {
        connection: usize,
    },
    NewConnection {
        original_dcid: ConnectionId,
        retry: Option<RetryToken>,
    },
    RetryRequired {
        packet: Vec<u8>,
    },
    VersionNegotiationRequired {
        packet: Vec<u8>,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionNegotiationResult {
    Negotiated(u32),
    NoSupportedVersion,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathBudget {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub validated: bool,
}

impl PathBudget {
    pub const fn new() -> Self {
        Self {
            bytes_received: 0,
            bytes_sent: 0,
            validated: false,
        }
    }

    pub const fn available(&self) -> u64 {
        if self.validated {
            return u64::MAX;
        }
        self.bytes_received
            .saturating_mul(MAX_ANTI_AMPLIFICATION_FACTOR)
            .saturating_sub(self.bytes_sent)
    }

    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
    }

    pub fn record_sent(&mut self, bytes: u64) -> bool {
        if bytes > self.available() {
            return false;
        }
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        true
    }

    pub fn refund_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_sub(bytes);
    }

    pub fn validate(&mut self) {
        self.validated = true;
    }
}

impl Default for PathBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Endpoint {
    stats: EndpointStats,
    routes: BTreeMap<ConnectionId, ConnectionRoute>,
    paths: BTreeMap<SocketAddr, RetainedPath>,
    path_recency: BTreeSet<(u64, SocketAddr)>,
    next_path_generation: u64,
    max_tracked_paths: usize,
    retry: RetryTokenManager,
    replay: TokenReplayCache,
    retry_source_cid: ConnectionId,
    retry_cid_key: [u8; 32],
    next_retry_cid_sequence: u64,
    retry_enabled: bool,
}

#[derive(Debug)]
struct RetainedPath {
    budget: PathBudget,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRouteKind {
    InitialDestination,
    OriginalDestination,
    Active,
    Migration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRoute {
    pub connection: usize,
    pub kind: ConnectionRouteKind,
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_retry(retry: RetryTokenManager, retry_source_cid: ConnectionId) -> Self {
        let retry_source_cid = if retry_source_cid.len() < MIN_RETRY_SOURCE_CID_LEN {
            let bytes: [u8; MIN_RETRY_SOURCE_CID_LEN] = rand::random();
            ConnectionId::from_slice(&bytes).expect("minimum Retry CID length is valid")
        } else {
            retry_source_cid
        };
        Self {
            stats: EndpointStats::default(),
            routes: BTreeMap::new(),
            paths: BTreeMap::new(),
            path_recency: BTreeSet::new(),
            next_path_generation: 0,
            max_tracked_paths: DEFAULT_MAX_TRACKED_PATHS,
            retry,
            replay: TokenReplayCache::default(),
            retry_source_cid,
            retry_cid_key: rand::random(),
            next_retry_cid_sequence: 0,
            retry_enabled: true,
        }
    }

    pub fn set_max_tracked_paths(&mut self, max_tracked_paths: usize) {
        self.max_tracked_paths = max_tracked_paths.max(1);
        self.evict_paths_to_limit();
    }

    pub fn set_max_retry_replay_entries(&mut self, max_entries: usize) {
        self.replay = TokenReplayCache::with_capacity(max_entries);
    }

    pub fn set_retry_enabled(&mut self, enabled: bool) {
        self.retry_enabled = enabled;
    }

    pub fn tracked_paths(&self) -> usize {
        self.paths.len()
    }

    pub fn path_budget(&self, remote: SocketAddr) -> Option<&PathBudget> {
        self.paths.get(&remote).map(|retained| &retained.budget)
    }

    pub fn insert_route(&mut self, cid: ConnectionId, connection: usize) {
        self.insert_connection_route(cid, connection, ConnectionRouteKind::InitialDestination);
    }

    pub fn insert_connection_route(
        &mut self,
        cid: ConnectionId,
        connection: usize,
        kind: ConnectionRouteKind,
    ) {
        self.routes
            .insert(cid, ConnectionRoute { connection, kind });
    }

    pub fn remove_route(&mut self, cid: &ConnectionId) -> Option<usize> {
        self.routes.remove(cid).map(|route| route.connection)
    }

    pub fn retire_connection_route(&mut self, cid: &ConnectionId, connection: usize) -> bool {
        let Some(route) = self.routes.get(cid) else {
            return false;
        };
        if route.connection != connection
            || !matches!(
                route.kind,
                ConnectionRouteKind::InitialDestination | ConnectionRouteKind::Active
            )
        {
            return false;
        }
        self.routes.remove(cid);
        true
    }

    pub fn route(&self, dst_cid: &ConnectionId) -> Option<usize> {
        self.route_entry(dst_cid).map(|route| route.connection)
    }

    pub fn route_entry(&self, dst_cid: &ConnectionId) -> Option<ConnectionRoute> {
        self.routes.get(dst_cid).copied()
    }

    pub fn admit_initial(
        &mut self,
        remote: SocketAddr,
        header: &LongHeader,
        packet_len: usize,
        now_ms: u64,
    ) -> Result<Admission> {
        self.path(remote).record_received(packet_len as u64);
        self.admit_initial_on_recorded_path(remote, header, now_ms)
    }

    /// Applies Initial admission after the containing UDP datagram has already
    /// been recorded against the path's anti-amplification budget.
    ///
    /// A coalesced datagram can contain multiple QUIC packets, but its bytes
    /// contribute to the server's amplification allowance exactly once.
    pub fn admit_initial_on_recorded_path(
        &mut self,
        remote: SocketAddr,
        header: &LongHeader,
        now_ms: u64,
    ) -> Result<Admission> {
        if let Some(connection) = self.route(&header.dst_cid) {
            return Ok(Admission::ExistingConnection { connection });
        }
        if header.ty != PacketType::Initial {
            return Ok(Admission::Drop);
        }
        if header.version != QUIC_VERSION_1 {
            let packet = Header::VersionNegotiation {
                dst_cid: header.src_cid.clone(),
                src_cid: header.dst_cid.clone(),
                versions: vec![QUIC_VERSION_1],
            }
            .encode();
            return Ok(Admission::VersionNegotiationRequired { packet });
        }

        if header.token.is_empty() && self.retry_enabled {
            let retry_source_cid = self.next_retry_source_cid();
            let token = self.retry.encode_with_retry_source_cid(
                remote,
                &header.dst_cid,
                &retry_source_cid,
                now_ms,
            )?;
            let packet = encode_retry_packet(
                header.version,
                header.src_cid.clone(),
                retry_source_cid,
                token,
                &header.dst_cid,
            )?;
            return Ok(Admission::RetryRequired { packet });
        }

        if header.token.is_empty() {
            return Ok(Admission::NewConnection {
                original_dcid: header.dst_cid.clone(),
                retry: None,
            });
        }

        let retry = self.retry.validate(&header.token, remote, now_ms)?;
        if !retry.retry_source_cid.is_empty() && retry.retry_source_cid != header.dst_cid {
            return Err(crate::error::CodecError::Transport(
                crate::transport_error::TransportErrorCode::InvalidToken,
            ));
        }
        if !self
            .replay
            .insert(&header.token, now_ms, retry_lifetime_ms())
        {
            return Ok(Admission::Drop);
        }
        self.path(remote).validate();
        Ok(Admission::NewConnection {
            original_dcid: retry.original_dcid.clone(),
            retry: Some(retry),
        })
    }

    pub fn path(&mut self, remote: SocketAddr) -> &mut PathBudget {
        self.touch_path(remote)
    }

    pub fn can_send_to(&mut self, remote: SocketAddr, bytes: u64) -> bool {
        self.path(remote).record_sent(bytes)
    }

    pub fn refund_send_to(&mut self, remote: SocketAddr, bytes: u64) {
        self.path(remote).refund_sent(bytes);
    }

    pub const fn stats(&self) -> &EndpointStats {
        &self.stats
    }

    fn next_retry_source_cid(&mut self) -> ConnectionId {
        let sequence = self.next_retry_cid_sequence;
        self.next_retry_cid_sequence = self.next_retry_cid_sequence.wrapping_add(1);
        if sequence == 0 {
            return self.retry_source_cid.clone();
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.retry_cid_key)
            .expect("fixed Retry CID key length is valid");
        mac.update(b"quion retry source cid");
        mac.update(self.retry_source_cid.as_bytes());
        mac.update(&sequence.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        ConnectionId::from_slice(&digest[..self.retry_source_cid.len()])
            .unwrap_or(ConnectionId::EMPTY)
    }

    fn touch_path(&mut self, remote: SocketAddr) -> &mut PathBudget {
        if let Some(retained) = self.paths.get(&remote) {
            self.path_recency.remove(&(retained.generation, remote));
        } else {
            self.evict_paths_for_insert();
        }
        let generation = self.next_path_generation;
        self.next_path_generation = self.next_path_generation.wrapping_add(1);
        self.path_recency.insert((generation, remote));
        let retained = self.paths.entry(remote).or_insert_with(|| RetainedPath {
            budget: PathBudget::default(),
            generation,
        });
        retained.generation = generation;
        &mut retained.budget
    }

    fn evict_paths_for_insert(&mut self) {
        while self.paths.len() >= self.max_tracked_paths {
            let Some((generation, remote)) = self.path_recency.pop_first() else {
                break;
            };
            if self
                .paths
                .get(&remote)
                .is_some_and(|retained| retained.generation == generation)
            {
                self.paths.remove(&remote);
            }
        }
    }

    fn evict_paths_to_limit(&mut self) {
        while self.paths.len() > self.max_tracked_paths {
            let Some((generation, remote)) = self.path_recency.pop_first() else {
                break;
            };
            if self
                .paths
                .get(&remote)
                .is_some_and(|retained| retained.generation == generation)
            {
                self.paths.remove(&remote);
            }
        }
    }

    pub fn validate_version_negotiation(
        header: &Header,
        original_dst_cid: &ConnectionId,
        original_src_cid: &ConnectionId,
        attempted_version: u32,
        supported_versions: &[u32],
    ) -> VersionNegotiationResult {
        let Header::VersionNegotiation {
            dst_cid,
            src_cid,
            versions,
        } = header
        else {
            return VersionNegotiationResult::Invalid;
        };
        if dst_cid != original_src_cid || src_cid != original_dst_cid {
            return VersionNegotiationResult::Invalid;
        }
        if versions.contains(&attempted_version) {
            return VersionNegotiationResult::Invalid;
        }
        supported_versions
            .iter()
            .copied()
            .find(|version| versions.contains(version))
            .map_or(
                VersionNegotiationResult::NoSupportedVersion,
                VersionNegotiationResult::Negotiated,
            )
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        let retry_source_cid_bytes: [u8; 8] = rand::random();
        Self::with_retry(
            RetryTokenManager::new(
                RetryTokenKey::new(rand::random(), rand::random()),
                Duration::from_secs(30),
            ),
            ConnectionId::from_slice(&retry_source_cid_bytes).unwrap_or(ConnectionId::EMPTY),
        )
    }
}

const fn retry_lifetime_ms() -> u64 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::VarInt;

    fn initial_header(token: Vec<u8>) -> LongHeader {
        LongHeader {
            ty: PacketType::Initial,
            version: QUIC_VERSION_1,
            dst_cid: ConnectionId::from_slice(b"client-dcid").unwrap(),
            src_cid: ConnectionId::from_slice(b"client-scid").unwrap(),
            token,
            length: Some(VarInt::from_u32(1200)),
            packet_number_len: 2,
        }
    }

    #[test]
    fn routes_existing_connection_by_destination_cid() {
        let mut endpoint = Endpoint::new();
        let cid = ConnectionId::from_slice(b"route").unwrap();
        endpoint.insert_route(cid.clone(), 42);

        assert_eq!(endpoint.route(&cid), Some(42));
        assert_eq!(
            endpoint.route_entry(&cid),
            Some(ConnectionRoute {
                connection: 42,
                kind: ConnectionRouteKind::InitialDestination,
            })
        );
        assert_eq!(endpoint.remove_route(&cid), Some(42));
        assert_eq!(endpoint.route(&cid), None);
    }

    #[test]
    fn routes_multiple_connection_id_kinds_and_retires_issued_cids() {
        let mut endpoint = Endpoint::new();
        let initial = ConnectionId::from_slice(b"initial").unwrap();
        let original = ConnectionId::from_slice(b"original").unwrap();
        let active = ConnectionId::from_slice(b"active").unwrap();
        let migration = ConnectionId::from_slice(b"migration").unwrap();

        endpoint.insert_connection_route(
            initial.clone(),
            7,
            ConnectionRouteKind::InitialDestination,
        );
        endpoint.insert_connection_route(
            original.clone(),
            7,
            ConnectionRouteKind::OriginalDestination,
        );
        endpoint.insert_connection_route(active.clone(), 7, ConnectionRouteKind::Active);
        endpoint.insert_connection_route(migration.clone(), 7, ConnectionRouteKind::Migration);

        assert_eq!(endpoint.route(&initial), Some(7));
        assert_eq!(endpoint.route(&original), Some(7));
        assert_eq!(endpoint.route(&active), Some(7));
        assert_eq!(endpoint.route(&migration), Some(7));
        assert!(!endpoint.retire_connection_route(&original, 7));
        assert!(endpoint.retire_connection_route(&initial, 7));
        assert!(endpoint.retire_connection_route(&active, 7));
        assert_eq!(endpoint.route(&initial), None);
        assert_eq!(endpoint.route(&original), Some(7));
        assert_eq!(endpoint.route(&active), None);
        assert_eq!(endpoint.route(&migration), Some(7));
    }

    #[test]
    fn initial_without_token_generates_retry_packet() {
        let mut endpoint = Endpoint::with_retry(
            RetryTokenManager::new(RetryTokenKey::new(1, [3; 32]), Duration::from_secs(30)),
            ConnectionId::from_slice(b"retry-scid").unwrap(),
        );
        let remote = "127.0.0.1:4433".parse().unwrap();

        let admission = endpoint
            .admit_initial(remote, &initial_header(Vec::new()), 1200, 10)
            .unwrap();

        let Admission::RetryRequired { packet } = admission else {
            panic!("expected retry");
        };
        let (decoded, consumed) = Header::decode(&packet, 0).unwrap();
        assert_eq!(consumed, packet.len());
        match decoded {
            Header::Long(header) => {
                assert_eq!(header.ty, PacketType::Retry);
                assert_eq!(
                    header.dst_cid,
                    ConnectionId::from_slice(b"client-scid").unwrap()
                );
                assert_eq!(
                    header.src_cid,
                    ConnectionId::from_slice(b"retry-scid").unwrap()
                );
                assert!(!header.token.is_empty());
            }
            _ => panic!("expected retry long header"),
        }
    }

    #[test]
    fn default_endpoints_do_not_share_retry_secrets() {
        let mut first = Endpoint::new();
        let mut second = Endpoint::new();
        let remote = "127.0.0.1:4433".parse().unwrap();
        let first_packet = first
            .admit_initial(remote, &initial_header(Vec::new()), 1200, 10)
            .unwrap();
        let second_packet = second
            .admit_initial(remote, &initial_header(Vec::new()), 1200, 10)
            .unwrap();
        let Admission::RetryRequired {
            packet: first_packet,
        } = first_packet
        else {
            panic!("expected first Retry");
        };
        let Admission::RetryRequired {
            packet: second_packet,
        } = second_packet
        else {
            panic!("expected second Retry");
        };

        assert_ne!(first_packet, second_packet);
    }

    #[test]
    fn retry_source_connection_ids_are_unique_and_token_bound() {
        let mut endpoint = Endpoint::with_retry(
            RetryTokenManager::new(RetryTokenKey::new(1, [4; 32]), Duration::from_secs(30)),
            ConnectionId::from_slice(b"retry000").unwrap(),
        );
        let first_remote = "127.0.0.1:4433".parse().unwrap();
        let second_remote = "127.0.0.1:4434".parse().unwrap();
        let Admission::RetryRequired {
            packet: first_packet,
        } = endpoint
            .admit_initial(first_remote, &initial_header(Vec::new()), 1200, 10)
            .unwrap()
        else {
            panic!("expected first Retry");
        };
        let Admission::RetryRequired {
            packet: second_packet,
        } = endpoint
            .admit_initial(second_remote, &initial_header(Vec::new()), 1200, 11)
            .unwrap()
        else {
            panic!("expected second Retry");
        };
        let (Header::Long(first_retry), _) = Header::decode(&first_packet, 0).unwrap() else {
            panic!("expected first Retry header");
        };
        let (Header::Long(second_retry), _) = Header::decode(&second_packet, 0).unwrap() else {
            panic!("expected second Retry header");
        };
        assert_ne!(first_retry.src_cid, second_retry.src_cid);

        let mut retried = initial_header(first_retry.token);
        retried.dst_cid = second_retry.src_cid;
        assert_eq!(
            endpoint
                .admit_initial(first_remote, &retried, 1200, 12)
                .unwrap_err()
                .transport_code(),
            crate::transport_error::TransportErrorCode::InvalidToken
        );
    }

    #[test]
    fn tracked_paths_evict_least_recently_used_remote() {
        let mut endpoint = Endpoint::new();
        endpoint.set_max_tracked_paths(2);
        let first = "127.0.0.1:1001".parse().unwrap();
        let second = "127.0.0.1:1002".parse().unwrap();
        let third = "127.0.0.1:1003".parse().unwrap();

        endpoint.path(first).record_received(10);
        endpoint.path(second).record_received(20);
        endpoint.path(first).record_received(5);
        endpoint.path(third).record_received(30);

        assert_eq!(endpoint.tracked_paths(), 2);
        assert_eq!(
            endpoint
                .path_budget(first)
                .map(|budget| budget.bytes_received),
            Some(15)
        );
        assert!(endpoint.path_budget(second).is_none());
        assert_eq!(
            endpoint
                .path_budget(third)
                .map(|budget| budget.bytes_received),
            Some(30)
        );
    }

    #[test]
    fn tracked_path_limit_clamps_to_one_and_evicts_immediately() {
        let mut endpoint = Endpoint::new();
        let first = "127.0.0.1:1001".parse().unwrap();
        let second = "127.0.0.1:1002".parse().unwrap();
        endpoint.path(first).record_received(10);
        endpoint.path(second).record_received(20);

        endpoint.set_max_tracked_paths(0);

        assert_eq!(endpoint.tracked_paths(), 1);
        assert!(endpoint.path_budget(first).is_none());
        assert!(endpoint.path_budget(second).is_some());
    }

    #[test]
    fn retry_token_admits_new_connection_and_validates_path() {
        let manager =
            RetryTokenManager::new(RetryTokenKey::new(1, [4; 32]), Duration::from_secs(30));
        let mut endpoint =
            Endpoint::with_retry(manager.clone(), ConnectionId::from_slice(b"retry").unwrap());
        let remote = "127.0.0.1:4433".parse().unwrap();
        let token = manager
            .encode(remote, &ConnectionId::from_slice(b"original").unwrap(), 100)
            .unwrap();

        let admission = endpoint
            .admit_initial(remote, &initial_header(token.clone()), 1200, 200)
            .unwrap();

        assert_eq!(
            admission,
            Admission::NewConnection {
                original_dcid: ConnectionId::from_slice(b"original").unwrap(),
                retry: Some(RetryToken {
                    issued_at_ms: 100,
                    original_dcid: ConnectionId::from_slice(b"original").unwrap(),
                    retry_source_cid: ConnectionId::EMPTY,
                }),
            }
        );
        assert_eq!(endpoint.path(remote).available(), u64::MAX);

        assert_eq!(
            endpoint
                .admit_initial(remote, &initial_header(token), 1200, 201)
                .unwrap(),
            Admission::Drop
        );
    }

    #[test]
    fn retry_enabled_and_disabled_initial_floods_keep_path_state_bounded() {
        for retry_enabled in [true, false] {
            let mut endpoint = Endpoint::default();
            endpoint.set_max_tracked_paths(8);
            endpoint.set_retry_enabled(retry_enabled);

            for index in 0..2_000u16 {
                let remote = SocketAddr::from(([127, 0, 0, 1], index.saturating_add(1)));
                let admission = endpoint
                    .admit_initial(remote, &initial_header(Vec::new()), 1_200, 1_000)
                    .unwrap();
                if retry_enabled {
                    assert!(matches!(admission, Admission::RetryRequired { .. }));
                } else {
                    assert!(matches!(
                        admission,
                        Admission::NewConnection { retry: None, .. }
                    ));
                }
                assert!(endpoint.tracked_paths() <= 8);
            }
        }
    }

    #[test]
    fn anti_amplification_budget_limits_unvalidated_path() {
        let mut budget = PathBudget::new();
        budget.record_received(100);
        assert!(budget.record_sent(250));
        assert!(!budget.record_sent(51));
        budget.validate();
        assert!(budget.record_sent(1_000_000));
    }

    #[test]
    fn anti_amplification_budget_refunds_failed_send_reservation() {
        let mut endpoint = Endpoint::new();
        let remote = "127.0.0.1:4433".parse().unwrap();
        endpoint.path(remote).record_received(100);

        assert!(endpoint.can_send_to(remote, 300));
        assert!(!endpoint.can_send_to(remote, 1));

        endpoint.refund_send_to(remote, 300);

        assert!(endpoint.can_send_to(remote, 300));
    }

    #[test]
    fn admission_on_recorded_path_does_not_double_count_datagram_bytes() {
        let mut endpoint = Endpoint::new();
        endpoint.set_retry_enabled(false);
        let remote = "127.0.0.1:4433".parse().unwrap();
        endpoint.path(remote).record_received(1_200);

        let admission = endpoint
            .admit_initial_on_recorded_path(remote, &initial_header(Vec::new()), 10)
            .unwrap();

        assert!(matches!(
            admission,
            Admission::NewConnection { retry: None, .. }
        ));
        assert_eq!(
            endpoint
                .path_budget(remote)
                .map(|budget| budget.bytes_received),
            Some(1_200)
        );
    }

    #[test]
    fn unsupported_initial_version_generates_version_negotiation_packet() {
        let mut endpoint = Endpoint::new();
        let remote = "127.0.0.1:4433".parse().unwrap();
        let mut header = initial_header(Vec::new());
        header.version = 0x0a0a_0a0a;

        let admission = endpoint.admit_initial(remote, &header, 1200, 10).unwrap();

        let Admission::VersionNegotiationRequired { packet } = admission else {
            panic!("expected version negotiation");
        };
        let (decoded, consumed) = Header::decode(&packet, 0).unwrap();
        assert_eq!(consumed, packet.len());
        assert_eq!(
            decoded,
            Header::VersionNegotiation {
                dst_cid: header.src_cid,
                src_cid: header.dst_cid,
                versions: vec![QUIC_VERSION_1],
            }
        );
    }

    #[test]
    fn validates_version_negotiation_against_original_cids() {
        let original_dst = ConnectionId::from_slice(b"server").unwrap();
        let original_src = ConnectionId::from_slice(b"client").unwrap();
        let header = Header::VersionNegotiation {
            dst_cid: original_src.clone(),
            src_cid: original_dst.clone(),
            versions: vec![QUIC_VERSION_1],
        };

        assert_eq!(
            Endpoint::validate_version_negotiation(
                &header,
                &original_dst,
                &original_src,
                0x0a0a_0a0a,
                &[QUIC_VERSION_1],
            ),
            VersionNegotiationResult::Negotiated(QUIC_VERSION_1)
        );
    }

    #[test]
    fn rejects_invalid_version_negotiation() {
        let original_dst = ConnectionId::from_slice(b"server").unwrap();
        let original_src = ConnectionId::from_slice(b"client").unwrap();

        let wrong_cid = Header::VersionNegotiation {
            dst_cid: ConnectionId::from_slice(b"other").unwrap(),
            src_cid: original_dst.clone(),
            versions: vec![QUIC_VERSION_1],
        };
        assert_eq!(
            Endpoint::validate_version_negotiation(
                &wrong_cid,
                &original_dst,
                &original_src,
                0x0a0a_0a0a,
                &[QUIC_VERSION_1],
            ),
            VersionNegotiationResult::Invalid
        );

        let includes_attempted = Header::VersionNegotiation {
            dst_cid: original_src.clone(),
            src_cid: original_dst.clone(),
            versions: vec![QUIC_VERSION_1],
        };
        assert_eq!(
            Endpoint::validate_version_negotiation(
                &includes_attempted,
                &original_dst,
                &original_src,
                QUIC_VERSION_1,
                &[QUIC_VERSION_1],
            ),
            VersionNegotiationResult::Invalid
        );

        let no_supported = Header::VersionNegotiation {
            dst_cid: original_src,
            src_cid: original_dst,
            versions: vec![0x0a0a_0a0a],
        };
        assert_eq!(
            Endpoint::validate_version_negotiation(
                &no_supported,
                &ConnectionId::from_slice(b"server").unwrap(),
                &ConnectionId::from_slice(b"client").unwrap(),
                QUIC_VERSION_1,
                &[QUIC_VERSION_1],
            ),
            VersionNegotiationResult::NoSupportedVersion
        );
    }
}
