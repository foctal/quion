use std::{collections::BTreeMap, net::SocketAddr};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use web_time::{Duration, Instant};

use crate::{
    cid::ConnectionId,
    coding::{Reader, Writer},
    error::{CodecError, Result},
    transport_error::TransportErrorCode,
};

type HmacSha256 = Hmac<Sha256>;

const TOKEN_MAGIC: &[u8; 4] = b"qion";
const TOKEN_VERSION: u8 = 1;
const MAC_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressToken {
    pub issued_at: Instant,
    pub lifetime: Duration,
    pub payload: Vec<u8>,
}

impl AddressToken {
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.issued_at) > self.lifetime
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryTokenKey {
    pub id: u8,
    secret: [u8; 32],
}

impl RetryTokenKey {
    pub const fn new(id: u8, secret: [u8; 32]) -> Self {
        Self { id, secret }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryToken {
    pub issued_at_ms: u64,
    pub original_dcid: ConnectionId,
    pub retry_source_cid: ConnectionId,
}

#[derive(Debug, Clone)]
pub struct RetryTokenManager {
    current: RetryTokenKey,
    previous: Vec<RetryTokenKey>,
    lifetime_ms: u64,
}

impl RetryTokenManager {
    pub fn new(current: RetryTokenKey, lifetime: Duration) -> Self {
        Self {
            current,
            previous: Vec::new(),
            lifetime_ms: duration_millis(lifetime),
        }
    }

    pub fn with_previous_keys(mut self, previous: Vec<RetryTokenKey>) -> Self {
        self.previous = previous;
        self
    }

    pub fn encode(
        &self,
        remote: SocketAddr,
        original_dcid: &ConnectionId,
        issued_at_ms: u64,
    ) -> Result<Vec<u8>> {
        self.encode_with_retry_source_cid(remote, original_dcid, &ConnectionId::EMPTY, issued_at_ms)
    }

    pub fn encode_with_retry_source_cid(
        &self,
        remote: SocketAddr,
        original_dcid: &ConnectionId,
        retry_source_cid: &ConnectionId,
        issued_at_ms: u64,
    ) -> Result<Vec<u8>> {
        let mut body = Writer::with_capacity(96);
        body.put_bytes(TOKEN_MAGIC);
        body.put_u8(TOKEN_VERSION);
        body.put_u8(self.current.id);
        body.put_u64(issued_at_ms);
        body.put_u8(original_dcid.len() as u8);
        body.put_bytes(original_dcid.as_bytes());
        body.put_u8(retry_source_cid.len() as u8);
        body.put_bytes(retry_source_cid.as_bytes());
        let remote = remote.to_string();
        body.put_u8(remote.len() as u8);
        body.put_bytes(remote.as_bytes());

        let mut token = body.into_vec();
        token.extend_from_slice(&sign(&self.current, &token)?);
        Ok(token)
    }

    pub fn validate(&self, token: &[u8], remote: SocketAddr, now_ms: u64) -> Result<RetryToken> {
        if token.len() < MAC_LEN {
            return Err(invalid_token());
        }
        let body_len = token.len() - MAC_LEN;
        let (body, mac) = token.split_at(body_len);
        let key_id = *body.get(5).ok_or_else(invalid_token)?;
        let key = self.key(key_id).ok_or_else(invalid_token)?;
        verify(key, body, mac)?;

        let mut r = Reader::new(body);
        if r.get_bytes(TOKEN_MAGIC.len())? != TOKEN_MAGIC {
            return Err(invalid_token());
        }
        if r.get_u8()? != TOKEN_VERSION {
            return Err(invalid_token());
        }
        let _key_id = r.get_u8()?;
        let issued_at_ms = r.get_u64()?;
        if now_ms.saturating_sub(issued_at_ms) > self.lifetime_ms {
            return Err(invalid_token());
        }
        let dcid_len = usize::from(r.get_u8()?);
        let original_dcid = ConnectionId::decode_fixed(r.get_bytes(dcid_len)?)?;
        let retry_source_cid_len = usize::from(r.get_u8()?);
        let retry_source_cid = ConnectionId::decode_fixed(r.get_bytes(retry_source_cid_len)?)?;
        let remote_len = usize::from(r.get_u8()?);
        let encoded_remote = r.get_bytes(remote_len)?;
        if encoded_remote != remote.to_string().as_bytes() || !r.is_empty() {
            return Err(invalid_token());
        }

        Ok(RetryToken {
            issued_at_ms,
            original_dcid,
            retry_source_cid,
        })
    }

    fn key(&self, id: u8) -> Option<&RetryTokenKey> {
        if self.current.id == id {
            return Some(&self.current);
        }
        self.previous.iter().find(|key| key.id == id)
    }
}

/// Maximum number of distinct token MACs retained for replay detection.
///
/// Time-based eviction alone does not bound peak memory: an attacker spoofing
/// many source addresses can harvest distinct server-signed tokens and replay
/// each once within the token lifetime window, so the cache also enforces a
/// hard entry cap and evicts the oldest entry when full. Bounded at roughly
/// `DEFAULT_MAX_REPLAY_ENTRIES * (MAC_LEN + overhead)` bytes.
pub const DEFAULT_MAX_REPLAY_ENTRIES: usize = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReplayCache {
    seen: BTreeMap<[u8; MAC_LEN], u64>,
    max_entries: usize,
}

impl Default for TokenReplayCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_REPLAY_ENTRIES)
    }
}

impl TokenReplayCache {
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            seen: BTreeMap::new(),
            max_entries,
        }
    }

    pub fn insert(&mut self, token: &[u8], now_ms: u64, lifetime_ms: u64) -> bool {
        self.retain(now_ms, lifetime_ms);
        if self.max_entries == 0 {
            return true;
        }
        let Some(mac) = token.get(token.len().saturating_sub(MAC_LEN)..) else {
            return false;
        };
        let Ok(mac) = <[u8; MAC_LEN]>::try_from(mac) else {
            return false;
        };
        if self.seen.contains_key(&mac) {
            return false;
        }
        // Enforce the hard cap before inserting. Evicting the oldest entry
        // trades a small, single replay opportunity for that token against
        // bounded memory under a token-harvesting flood (RFC 9000 §8.1.4).
        while self.seen.len() >= self.max_entries {
            let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_, seen_at)| **seen_at)
                .map(|(mac, _)| *mac)
            else {
                break;
            };
            self.seen.remove(&oldest);
        }
        self.seen.insert(mac, now_ms);
        true
    }

    pub fn retain(&mut self, now_ms: u64, lifetime_ms: u64) {
        self.seen
            .retain(|_, seen_at| now_ms.saturating_sub(*seen_at) <= lifetime_ms);
    }

    /// Number of token MACs currently retained.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

fn sign(key: &RetryTokenKey, body: &[u8]) -> Result<[u8; MAC_LEN]> {
    let mut mac = HmacSha256::new_from_slice(&key.secret).map_err(|_| invalid_token())?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn verify(key: &RetryTokenKey, body: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(&key.secret).map_err(|_| invalid_token())?;
    mac.update(body);
    mac.verify_slice(expected).map_err(|_| invalid_token())
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn invalid_token() -> CodecError {
    CodecError::Transport(TransportErrorCode::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_token_roundtrips_and_binds_remote_address() {
        let manager =
            RetryTokenManager::new(RetryTokenKey::new(7, [42; 32]), Duration::from_secs(30));
        let remote = "127.0.0.1:4433".parse().unwrap();
        let dcid = ConnectionId::from_slice(b"original").unwrap();

        let token = manager.encode(remote, &dcid, 1_000).unwrap();
        let decoded = manager.validate(&token, remote, 20_000).unwrap();

        assert_eq!(decoded.issued_at_ms, 1_000);
        assert_eq!(decoded.original_dcid, dcid);
        assert!(decoded.retry_source_cid.is_empty());
        assert_eq!(
            manager
                .validate(&token, "127.0.0.1:4434".parse().unwrap(), 20_000)
                .unwrap_err(),
            invalid_token()
        );
    }

    #[test]
    fn retry_token_rejects_tampering_and_expiration() {
        let manager =
            RetryTokenManager::new(RetryTokenKey::new(1, [9; 32]), Duration::from_secs(10));
        let remote = "[::1]:4433".parse().unwrap();
        let dcid = ConnectionId::from_slice(b"dcid").unwrap();
        let mut token = manager.encode(remote, &dcid, 5_000).unwrap();

        token[8] ^= 0x55;
        assert_eq!(
            manager.validate(&token, remote, 6_000).unwrap_err(),
            invalid_token()
        );

        let token = manager.encode(remote, &dcid, 5_000).unwrap();
        assert_eq!(
            manager.validate(&token, remote, 16_001).unwrap_err(),
            invalid_token()
        );
    }

    #[test]
    fn retry_token_accepts_previous_key_and_replay_cache_deduplicates() {
        let old = RetryTokenKey::new(1, [1; 32]);
        let new = RetryTokenKey::new(2, [2; 32]);
        let old_manager = RetryTokenManager::new(old, Duration::from_secs(60));
        let manager =
            RetryTokenManager::new(new, Duration::from_secs(60)).with_previous_keys(vec![old]);
        let remote = "127.0.0.1:4433".parse().unwrap();
        let dcid = ConnectionId::from_slice(b"dcid").unwrap();
        let token = old_manager.encode(remote, &dcid, 100).unwrap();

        assert!(manager.validate(&token, remote, 200).is_ok());

        let mut replay = TokenReplayCache::default();
        assert!(replay.insert(&token, 200, 60_000));
        assert!(!replay.insert(&token, 201, 60_000));
        replay.retain(60_000, 60_000);
        assert!(!replay.insert(&token, 60_001, 60_000));
        replay.retain(60_002, 1);
        assert!(replay.insert(&token, 60_003, 60_000));
    }

    #[test]
    fn replay_cache_enforces_hard_capacity_with_oldest_eviction() {
        let mut replay = TokenReplayCache::with_capacity(2);
        // Distinct token MACs are produced by distinct trailing bytes.
        let token = |mac_byte: u8| {
            let mut t = vec![0u8; MAC_LEN];
            t[MAC_LEN - 1] = mac_byte;
            t
        };

        // Fill to capacity at increasing timestamps; no eviction yet.
        assert!(replay.insert(&token(1), 100, 60_000));
        assert!(replay.insert(&token(2), 200, 60_000));
        assert_eq!(replay.len(), 2);

        // Inserting a third (still within lifetime) evicts the oldest (token 1)
        // and keeps the cache bounded.
        assert!(replay.insert(&token(3), 300, 60_000));
        assert_eq!(replay.len(), 2);

        // Token 1 was evicted, so it is no longer detected as a replay; tokens
        // 2 and 3 remain and are still rejected as replays.
        assert!(!replay.insert(&token(2), 400, 60_000));
        assert!(!replay.insert(&token(3), 400, 60_000));
        // Re-inserting token 1 succeeds (treated as new) but stays bounded.
        assert!(replay.insert(&token(1), 500, 60_000));
        assert_eq!(replay.len(), 2);
    }

    #[test]
    fn zero_capacity_replay_cache_retains_nothing() {
        let mut cache = TokenReplayCache::with_capacity(0);
        let token = vec![0x5a; MAC_LEN];

        assert!(cache.insert(&token, 1, 30));
        assert!(cache.insert(&token, 2, 30));
        assert!(cache.is_empty());
    }
}
