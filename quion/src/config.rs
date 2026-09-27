use std::{path::Path, sync::Arc};

use crate::{ConfigError, QlogHandler, qlog::DEFAULT_MAX_BUFFERED_QLOG_EVENTS};

type ConfigResult<T> = std::result::Result<T, ConfigError>;

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
use rustls::{
    DigitallySignedStruct, Error as TlsError, KeyLogFile, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};

/// Endpoint-level configuration shared by runtime constructors.
#[derive(Debug, Clone, Default)]
pub struct EndpointConfig {
    /// Transport defaults applied to new connections.
    pub transport: TransportConfig,
}

/// QUIC transport limits, features, queue budgets, and diagnostics settings.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    inner: quion_proto::config::TransportConfig,
    qlog: QlogConfig,
    max_connections: usize,
    max_pending_handshakes: usize,
    max_established_connections: usize,
    max_endpoint_memory_bytes: usize,
    max_endpoint_routed_datagram_bytes: usize,
    max_tracked_endpoint_paths: usize,
    max_retry_replay_entries: usize,
    retry_enabled: bool,
    max_runtime_driver_work_per_tick: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            inner: quion_proto::config::TransportConfig::default(),
            qlog: QlogConfig::default(),
            max_connections: 1024,
            max_pending_handshakes: 1024,
            max_established_connections: 1024,
            max_endpoint_memory_bytes: 512 * 1024 * 1024,
            max_endpoint_routed_datagram_bytes: 64 * 1024 * 1024,
            max_tracked_endpoint_paths: 4096,
            max_retry_replay_entries: 1 << 16,
            retry_enabled: true,
            max_runtime_driver_work_per_tick: 32,
        }
    }
}

#[derive(Clone)]
struct QlogConfig {
    handler: Option<QlogHandler>,
    max_buffered_events: usize,
}

impl Default for QlogConfig {
    fn default() -> Self {
        Self {
            handler: None,
            max_buffered_events: DEFAULT_MAX_BUFFERED_QLOG_EVENTS,
        }
    }
}

impl core::fmt::Debug for QlogConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QlogConfig")
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

impl TransportConfig {
    /// Returns the underlying sans-I/O transport configuration.
    pub const fn proto(&self) -> &quion_proto::config::TransportConfig {
        &self.inner
    }

    pub(crate) fn into_proto(self) -> quion_proto::config::TransportConfig {
        self.inner
    }

    pub(crate) fn qlog_handler(&self) -> Option<QlogHandler> {
        self.qlog.handler.clone()
    }

    pub(crate) const fn max_buffered_qlog_events(&self) -> usize {
        self.qlog.max_buffered_events
    }

    /// Sets connection-level receive flow-control credit.
    pub fn set_initial_max_data(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.initial_max_data = value;
        self
    }

    /// Sets receive credit for locally initiated bidirectional streams.
    pub fn set_initial_max_stream_data_bidi_local(
        &mut self,
        value: quion_proto::VarInt,
    ) -> &mut Self {
        self.inner.initial_max_stream_data_bidi_local = value;
        self
    }

    /// Sets receive credit for peer-initiated bidirectional streams.
    pub fn set_initial_max_stream_data_bidi_remote(
        &mut self,
        value: quion_proto::VarInt,
    ) -> &mut Self {
        self.inner.initial_max_stream_data_bidi_remote = value;
        self
    }

    /// Sets receive credit for peer-initiated unidirectional streams.
    pub fn set_initial_max_stream_data_uni(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.initial_max_stream_data_uni = value;
        self
    }

    /// Sets the initial peer-initiated bidirectional stream limit.
    pub fn set_initial_max_streams_bidi(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.initial_max_streams_bidi = value;
        self
    }

    /// Sets the initial peer-initiated unidirectional stream limit.
    pub fn set_initial_max_streams_uni(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.initial_max_streams_uni = value;
        self
    }

    /// Sets the advertised idle timeout in milliseconds; zero disables it.
    pub fn set_max_idle_timeout(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.max_idle_timeout_ms = value;
        self
    }

    /// Sends PINGs while an established connection is otherwise idle.
    /// Disabled by default; `None` or zero disables it. The effective interval
    /// is capped at half the effective idle timeout (including its three-PTO
    /// minimum), with a one-millisecond minimum interval. This can preserve NAT
    /// mappings but does not guarantee that an unreachable peer remains alive.
    pub fn set_keep_alive_interval(&mut self, interval: Option<std::time::Duration>) -> &mut Self {
        self.inner.keep_alive_interval = interval.filter(|value| !value.is_zero());
        self
    }

    /// Advertises support for ACK_FREQUENCY with the minimum ACK delay, in
    /// microseconds, that this endpoint can honor.
    ///
    /// Passing `None` disables ACK_FREQUENCY negotiation. Values above the
    /// locally advertised maximum ACK delay are rejected during transport
    /// parameter validation.
    pub fn set_min_ack_delay(&mut self, value: Option<quion_proto::VarInt>) -> &mut Self {
        self.inner.min_ack_delay = value;
        self
    }

    /// Sets the ACK_FREQUENCY policy requested from peers that advertise the
    /// extension. Passing `None` disables outgoing requests.
    pub fn set_ack_frequency_config(
        &mut self,
        value: Option<quion_proto::config::AckFrequencyConfig>,
    ) -> &mut Self {
        self.inner.ack_frequency_config = value;
        self
    }

    /// Selects the congestion controller for connections created from this
    /// transport configuration. NewReno remains the conservative default;
    /// CUBIC is available for deployments that validate it against their own
    /// traffic and loss profiles.
    pub fn set_congestion_algorithm(
        &mut self,
        algorithm: quion_proto::congestion::CongestionAlgorithm,
    ) -> &mut Self {
        self.inner.congestion_algorithm = algorithm;
        self
    }

    /// Sets the initial maximum UDP payload size.
    ///
    /// Values below QUIC's required minimum are clamped to 1,200 bytes. PMTU
    /// discovery can raise this value up to its configured upper bound and
    /// black-hole recovery can restore it to 1,200 bytes.
    pub fn set_initial_mtu(&mut self, value: u16) -> &mut Self {
        self.inner.initial_mtu = value.clamp(1200, 65_527);
        self
    }

    /// Returns the configured initial maximum UDP payload size.
    pub const fn initial_mtu(&self) -> u16 {
        self.inner.initial_mtu
    }

    /// Configures Datagram Packetization Layer PMTU discovery.
    ///
    /// Passing `None` fixes the path UDP payload size to [`Self::initial_mtu`].
    pub fn set_mtu_discovery_config(
        &mut self,
        value: Option<quion_proto::mtud::MtuDiscoveryConfig>,
    ) -> &mut Self {
        self.inner.mtu_discovery = value;
        self
    }

    /// Returns the Datagram Packetization Layer PMTU discovery configuration.
    pub const fn mtu_discovery_config(&self) -> Option<&quion_proto::mtud::MtuDiscoveryConfig> {
        self.inner.mtu_discovery.as_ref()
    }

    /// Sets the maximum number of peer-issued active connection IDs retained
    /// by this endpoint. Values below QUIC's required minimum of two are
    /// clamped to two so this endpoint never advertises an invalid transport
    /// parameter.
    pub fn set_active_connection_id_limit(&mut self, value: quion_proto::VarInt) -> &mut Self {
        self.inner.active_connection_id_limit = value.max(quion_proto::VarInt::from_u32(2));
        self
    }

    /// Sets the maximum DATAGRAM frame size advertised to the peer.
    pub fn set_max_datagram_frame_size(&mut self, value: Option<quion_proto::VarInt>) -> &mut Self {
        self.inner.max_datagram_frame_size = value;
        self
    }

    /// Enables the RESET_STREAM_AT extension for reliable stream prefixes.
    ///
    /// Both peers must enable the extension before
    /// [`crate::SendStream::reset_at`] can be used.
    pub fn set_reset_stream_at(&mut self, enabled: bool) -> &mut Self {
        self.inner.reset_stream_at = enabled;
        self
    }

    /// Limits the number of DATAGRAM payloads queued in either direction per
    /// connection. A value of zero disables DATAGRAM queueing.
    pub fn set_max_queued_datagrams(&mut self, value: usize) -> &mut Self {
        self.inner.max_queued_datagrams = value;
        self
    }

    /// Limits DATAGRAM payload bytes queued in either direction per
    /// connection. A value of zero disables non-empty DATAGRAM queueing.
    pub fn set_max_queued_datagram_bytes(&mut self, value: usize) -> &mut Self {
        self.inner.max_queued_datagram_bytes = value;
        self
    }

    /// Limits pending control frames per connection.
    ///
    /// The protocol layer coalesces superseded flow-control updates and
    /// duplicate idempotent frames before enforcing this limit. A value of
    /// zero rejects all non-closing control frames.
    pub fn set_max_queued_control_frames(&mut self, value: usize) -> &mut Self {
        self.inner.max_queued_control_frames = value;
        self
    }

    /// Limits disjoint received packet ranges retained for ACK generation in
    /// each packet number space.
    ///
    /// Values below one are clamped to one to preserve acknowledgment progress.
    /// Generated ACK frames also have an independent wire-size limit.
    pub fn set_max_ack_ranges_per_space(&mut self, value: usize) -> &mut Self {
        self.inner.max_ack_ranges_per_space = value.max(1);
        self
    }

    /// Limits CRYPTO bytes buffered ahead of the TLS read offset in each
    /// packet number space.
    pub fn set_max_crypto_buffered_data(&mut self, value: u64) -> &mut Self {
        self.inner.max_crypto_buffered_data = value;
        self
    }

    /// Bounds stream metadata independently of payload flow control.
    pub fn set_max_stream_metadata_entries(&mut self, value: usize) -> &mut Self {
        self.inner.max_stream_metadata_entries = value;
        self
    }

    /// Limits queued stream send data per connection.
    ///
    /// This is independent of QUIC flow-control credit and prevents an
    /// application from buffering unbounded stream data after a peer advertises
    /// large send windows.
    pub fn set_max_send_buffered_stream_data(&mut self, value: usize) -> &mut Self {
        self.inner.max_send_buffered_stream_data = value;
        self
    }

    /// Limits received stream data buffered per stream before the application
    /// reads it.
    ///
    /// This is independent of QUIC flow-control credit and bounds memory used
    /// by out-of-order or unread stream data.
    pub fn set_max_recv_buffered_stream_data(&mut self, value: usize) -> &mut Self {
        self.inner.max_recv_buffered_stream_data = value;
        self
    }

    /// Limits received stream data buffered across all streams in one
    /// connection before the application reads it.
    ///
    /// This aggregate budget prevents a peer from multiplying the per-stream
    /// limit by opening many streams. A value of zero permits only empty
    /// STREAM frames until buffered data is consumed or the limit is raised.
    pub fn set_max_recv_buffered_stream_data_per_connection(&mut self, value: usize) -> &mut Self {
        self.inner.max_recv_buffered_stream_data_per_connection = value;
        self
    }

    /// Configures whether local transport parameters disable active migration.
    ///
    /// Migration stays disabled by default until endpoint-owned path migration
    /// policy and interop coverage are production-complete.
    pub fn set_disable_active_migration(&mut self, value: bool) -> &mut Self {
        self.inner.disable_active_migration = value;
        self
    }

    /// Sets the length of newly generated connection IDs.
    ///
    /// A value of zero preserves the endpoint default of eight bytes. Values
    /// larger than QUIC's 20-byte connection-ID limit are clamped on use.
    pub fn set_connection_id_length(&mut self, value: u8) -> &mut Self {
        self.inner.connection_id_length = value;
        self
    }

    /// Limits the number of server connections in handshake or established
    /// state that an endpoint will admit. A value of zero rejects all new
    /// server connections. Existing connections continue to be routed.
    pub fn set_max_connections(&mut self, value: usize) -> &mut Self {
        self.max_connections = value;
        self
    }

    pub(crate) const fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Limits the number of server handshakes that may be in progress.
    ///
    /// A value of zero rejects new server handshakes while preserving routing
    /// for existing connections.
    pub fn set_max_pending_handshakes(&mut self, value: usize) -> &mut Self {
        self.max_pending_handshakes = value;
        self
    }

    pub(crate) const fn max_pending_handshakes(&self) -> usize {
        self.max_pending_handshakes
    }

    /// Limits the number of established server connections an endpoint admits.
    ///
    /// A value of zero rejects newly validated server connections while
    /// preserving routing for existing connections.
    pub fn set_max_established_connections(&mut self, value: usize) -> &mut Self {
        self.max_established_connections = value;
        self
    }

    pub(crate) const fn max_established_connections(&self) -> usize {
        self.max_established_connections
    }

    /// Limits payload memory retained across all connections owned by one
    /// endpoint.
    ///
    /// This shared ceiling is enforced in addition to per-connection stream,
    /// CRYPTO, DATAGRAM, and routed-packet limits. Exhausting it applies
    /// backpressure to application writes and drops unretained network input.
    pub fn set_max_endpoint_memory_bytes(&mut self, value: usize) -> &mut Self {
        self.max_endpoint_memory_bytes = value;
        self
    }

    pub(crate) const fn max_endpoint_memory_bytes(&self) -> usize {
        self.max_endpoint_memory_bytes
    }

    /// Limits endpoint-wide memory reserved by routed UDP datagrams.
    ///
    /// This budget covers datagrams that have been routed by the endpoint but
    /// are still waiting for connection-level packet processing.
    pub fn set_max_endpoint_routed_datagram_bytes(&mut self, value: usize) -> &mut Self {
        self.max_endpoint_routed_datagram_bytes = value;
        self
    }

    pub(crate) const fn max_endpoint_routed_datagram_bytes(&self) -> usize {
        self.max_endpoint_routed_datagram_bytes
    }

    /// Limits retained anti-amplification and validation state for remote
    /// socket addresses.
    ///
    /// When the limit is reached, the least recently used path is evicted.
    /// Values below one are clamped to one.
    pub fn set_max_tracked_endpoint_paths(&mut self, value: usize) -> &mut Self {
        self.max_tracked_endpoint_paths = value.max(1);
        self
    }

    pub(crate) const fn max_tracked_endpoint_paths(&self) -> usize {
        self.max_tracked_endpoint_paths
    }

    /// Limits Retry token MACs retained for replay detection.
    ///
    /// When full, the oldest entry is evicted. A value of zero disables
    /// replay-cache retention while still validating token authenticity.
    pub fn set_max_retry_replay_entries(&mut self, value: usize) -> &mut Self {
        self.max_retry_replay_entries = value;
        self
    }

    pub(crate) const fn max_retry_replay_entries(&self) -> usize {
        self.max_retry_replay_entries
    }

    /// Enables address validation with Retry before admitting new server
    /// connections. Enabled by default.
    pub fn set_retry_enabled(&mut self, enabled: bool) -> &mut Self {
        self.retry_enabled = enabled;
        self
    }

    pub(crate) const fn retry_enabled(&self) -> bool {
        self.retry_enabled
    }

    /// Limits consecutive units of runtime driver work before yielding.
    ///
    /// This prevents endpoint-owned runtime tasks from monopolizing an
    /// executor under sustained packet bursts. A value of zero is treated as
    /// one unit of work.
    pub fn set_max_runtime_driver_work_per_tick(&mut self, value: usize) -> &mut Self {
        self.max_runtime_driver_work_per_tick = value;
        self
    }

    pub(crate) const fn max_runtime_driver_work_per_tick(&self) -> usize {
        self.max_runtime_driver_work_per_tick
    }

    /// Installs a synchronous handler for structured qlog events.
    pub fn set_qlog_handler<F>(&mut self, handler: F) -> &mut Self
    where
        F: Fn(&crate::QlogEvent) + Send + Sync + 'static,
    {
        self.qlog.handler = Some(Arc::new(handler));
        self
    }

    /// Removes the configured qlog event handler.
    pub fn clear_qlog_handler(&mut self) -> &mut Self {
        self.qlog.handler = None;
        self
    }

    /// Limits qlog events retained for later `Connection::drain_qlog_events`
    /// calls.
    ///
    /// Event handlers still receive every event synchronously. This limit only
    /// bounds the in-memory backlog kept for applications that drain qlog
    /// events manually. A value of zero disables retained qlog buffering.
    pub fn set_max_buffered_qlog_events(&mut self, value: usize) -> &mut Self {
        self.qlog.max_buffered_events = value;
        self
    }
}

/// Client TLS, ALPN, and transport configuration.
#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    /// ALPN protocol identifiers offered to the server.
    pub alpn_protocols: Arc<Vec<Vec<u8>>>,
    /// Transport settings used for new client connections.
    pub transport: TransportConfig,
    version_negotiation_probe: bool,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) rustls: Option<Arc<rustls::ClientConfig>>,
}

impl ClientConfig {
    /// Starts a client configuration builder.
    pub fn builder() -> ClientConfigBuilder {
        ClientConfigBuilder::default()
    }

    /// Returns whether new connections start with a reserved-version probe.
    pub const fn version_negotiation_probe_enabled(&self) -> bool {
        self.version_negotiation_probe
    }

    /// Returns whether TLS session resumption may derive 0-RTT write keys.
    ///
    /// This does not make arbitrary application operations replay-safe.
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub fn zero_rtt_enabled(&self) -> bool {
        self.rustls
            .as_ref()
            .is_some_and(|config| config.enable_early_data)
    }
}

/// Builder for [`ClientConfig`].
#[derive(Debug, Default)]
pub struct ClientConfigBuilder {
    alpn_protocols: Vec<Vec<u8>>,
    transport: TransportConfig,
    version_negotiation_probe: bool,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    rustls: Option<Arc<rustls::ClientConfig>>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    enable_key_logging: bool,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    insecure_no_certificate_verification: bool,
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    enable_zero_rtt: bool,
}

impl ClientConfigBuilder {
    /// Loads the operating system's native root certificate store.
    pub fn with_native_roots(mut self) -> ConfigResult<Self> {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            let roots = load_native_roots()?;
            self = self.with_root_certificates(roots)?;
            Ok(self)
        }

        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        {
            Err(ConfigError::Unsupported)
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Uses an application-provided rustls client configuration.
    pub fn with_rustls_config(mut self, config: rustls::ClientConfig) -> Self {
        self.rustls = Some(Arc::new(config));
        self
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Uses an application-provided root certificate store.
    pub fn with_root_certificates(mut self, roots: rustls::RootCertStore) -> ConfigResult<Self> {
        let provider = default_crypto_provider();
        let config = rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(map_rustls_config_error)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        self.rustls = Some(Arc::new(config));
        Ok(self)
    }

    /// Loads trusted root certificates from a PEM file.
    pub fn with_root_certificates_from_pem_file(
        mut self,
        certs: impl AsRef<Path>,
    ) -> ConfigResult<Self> {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            let roots = load_root_certificates(certs.as_ref())?;
            self = self.with_root_certificates(roots)?;
            Ok(self)
        }

        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        {
            let _ = certs;
            Err(ConfigError::Unsupported)
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Enables rustls key logging through `SSLKEYLOGFILE`.
    pub fn with_key_logging(mut self) -> Self {
        self.enable_key_logging = true;
        self
    }

    /// Disables certificate verification and must only be used in local tests
    /// or controlled development environments.
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub fn with_insecure_no_certificate_verification(mut self) -> Self {
        self.insecure_no_certificate_verification = true;
        self
    }

    /// Enables TLS session resumption to derive 0-RTT write keys.
    ///
    /// 0-RTT data can be replayed. Applications must restrict early writes to
    /// replay-safe operations and handle server rejection. Enabling this does
    /// not by itself send application data before handshake completion.
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub fn with_zero_rtt(mut self) -> Self {
        self.enable_zero_rtt = true;
        self
    }

    /// Sets ALPN protocol identifiers in preference order.
    pub fn with_alpn_protocols<I>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.alpn_protocols = protocols.into_iter().collect();
        self
    }

    /// Sets transport options for new connections.
    pub fn with_transport_config(mut self, transport: TransportConfig) -> Self {
        self.transport = transport;
        self
    }

    /// Starts new connections with a reserved QUIC version to exercise
    /// Version Negotiation before restarting with QUIC v1.
    ///
    /// This is disabled by default and adds one network round trip. The probe
    /// version can never be selected for the connection; it is used only to
    /// request the peer's supported-version list.
    pub fn with_version_negotiation_probe(mut self) -> Self {
        self.version_negotiation_probe = true;
        self
    }

    /// Builds the client configuration.
    pub fn build(self) -> ClientConfig {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let rustls = {
            let mut config = if self.insecure_no_certificate_verification {
                insecure_client_rustls_config()
            } else {
                self.rustls.as_deref().cloned()
            };
            if let Some(mut config) = config.take() {
                if self.enable_key_logging {
                    set_key_logging(&mut config);
                }
                config.enable_early_data = {
                    #[cfg(feature = "zero-rtt")]
                    {
                        self.enable_zero_rtt
                    }
                    #[cfg(not(feature = "zero-rtt"))]
                    {
                        false
                    }
                };
                let config = with_client_alpn(config, &self.alpn_protocols);
                Some(Arc::new(config))
            } else {
                None
            }
        };

        ClientConfig {
            alpn_protocols: Arc::new(self.alpn_protocols),
            transport: self.transport,
            version_negotiation_probe: self.version_negotiation_probe,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            rustls,
        }
    }
}

/// Server TLS, ALPN, and transport configuration.
#[derive(Debug, Clone, Default)]
pub struct ServerConfig {
    /// ALPN protocol identifiers offered to clients.
    pub alpn_protocols: Arc<Vec<Vec<u8>>>,
    /// Transport settings used for accepted connections.
    pub transport: TransportConfig,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    pub(crate) rustls: Option<Arc<rustls::ServerConfig>>,
}

impl ServerConfig {
    /// Starts a server configuration builder.
    pub fn builder() -> ServerConfigBuilder {
        ServerConfigBuilder::default()
    }

    /// Returns whether this configuration explicitly accepts TLS 0-RTT.
    ///
    /// Applications must still apply replay-safe request policy.
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub fn zero_rtt_enabled(&self) -> bool {
        self.rustls
            .as_ref()
            .is_some_and(|config| config.max_early_data_size == u32::MAX)
    }
}

/// Builder for [`ServerConfig`].
#[derive(Debug, Default)]
pub struct ServerConfigBuilder {
    alpn_protocols: Vec<Vec<u8>>,
    transport: TransportConfig,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    rustls: Option<Arc<rustls::ServerConfig>>,
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    enable_key_logging: bool,
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    accept_zero_rtt: bool,
}

impl ServerConfigBuilder {
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Installs an in-memory certificate chain and private key.
    pub fn with_single_cert(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> ConfigResult<Self> {
        let provider = default_crypto_provider();
        let config = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(map_rustls_config_error)?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(map_rustls_config_error)?;
        self.rustls = Some(Arc::new(config));
        Ok(self)
    }

    /// Loads a certificate chain and private key from PEM files.
    pub fn with_single_cert_from_pem_files(
        mut self,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> ConfigResult<Self> {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        {
            let certs = load_cert_chain(cert.as_ref())?;
            let key = load_private_key(key.as_ref())?;
            self = self.with_single_cert(certs, key)?;
            Ok(self)
        }

        #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
        {
            let _ = cert;
            let _ = key;
            Err(ConfigError::Unsupported)
        }
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Uses an application-provided rustls server configuration.
    pub fn with_rustls_config(mut self, config: rustls::ServerConfig) -> Self {
        self.rustls = Some(Arc::new(config));
        self
    }

    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    /// Enables rustls key logging through `SSLKEYLOGFILE`.
    pub fn with_key_logging(mut self) -> Self {
        self.enable_key_logging = true;
        self
    }

    /// Explicitly allows TLS to accept 0-RTT on resumed connections.
    ///
    /// QUIC requires the TLS early-data limit to be either zero or
    /// `u32::MAX`; this method selects `u32::MAX`. Early requests can be
    /// replayed, so applications must process only replay-safe operations.
    #[cfg(all(
        feature = "zero-rtt",
        any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")
    ))]
    pub fn with_zero_rtt(mut self) -> Self {
        self.accept_zero_rtt = true;
        self
    }

    /// Sets ALPN protocol identifiers in preference order.
    pub fn with_alpn_protocols<I>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.alpn_protocols = protocols.into_iter().collect();
        self
    }

    /// Sets transport options for accepted connections.
    pub fn with_transport_config(mut self, transport: TransportConfig) -> Self {
        self.transport = transport;
        self
    }

    /// Validates and builds the server configuration.
    pub fn build(self) -> ConfigResult<ServerConfig> {
        #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
        let rustls = self.rustls.map(|config| {
            let mut config = (*config).clone();
            if self.enable_key_logging {
                set_key_logging(&mut config);
            }
            config.max_early_data_size = {
                #[cfg(feature = "zero-rtt")]
                {
                    if self.accept_zero_rtt { u32::MAX } else { 0 }
                }
                #[cfg(not(feature = "zero-rtt"))]
                {
                    0
                }
            };
            Arc::new(with_server_alpn(config, &self.alpn_protocols))
        });

        Ok(ServerConfig {
            alpn_protocols: Arc::new(self.alpn_protocols),
            transport: self.transport,
            #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
            rustls,
        })
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn load_native_roots() -> ConfigResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let mut loaded = 0usize;
    for cert in native.certs {
        roots.add(cert).map_err(map_rustls_config_error)?;
        loaded += 1;
    }
    if loaded == 0 {
        return Err(ConfigError::NoNativeRoots);
    }
    Ok(roots)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn load_pem_certs(path: &Path) -> ConfigResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|error| ConfigError::Io {
        path: path.to_path_buf(),
        kind: error.kind(),
    })?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::InvalidCertificate {
            path: path.to_path_buf(),
        })?;
    if certs.is_empty() {
        return Err(ConfigError::InvalidCertificate {
            path: path.to_path_buf(),
        });
    }
    Ok(certs)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn load_root_certificates(path: &Path) -> ConfigResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in load_pem_certs(path)? {
        roots
            .add(cert)
            .map_err(|_| ConfigError::InvalidCertificate {
                path: path.to_path_buf(),
            })?;
    }
    Ok(roots)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn load_cert_chain(path: &Path) -> ConfigResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    load_pem_certs(path)
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn load_private_key(path: &Path) -> ConfigResult<rustls::pki_types::PrivateKeyDer<'static>> {
    let pem = std::fs::read(path).map_err(|error| ConfigError::Io {
        path: path.to_path_buf(),
        kind: error.kind(),
    })?;
    PrivateKeyDer::from_pem_slice(&pem).map_err(|_| ConfigError::InvalidPrivateKey {
        path: path.to_path_buf(),
    })
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn insecure_client_rustls_config() -> Option<rustls::ClientConfig> {
    let provider = default_crypto_provider();
    rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(map_rustls_config_error)
        .ok()
        .map(|builder| {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth()
        })
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn with_client_alpn(
    mut config: rustls::ClientConfig,
    protocols: &[Vec<u8>],
) -> rustls::ClientConfig {
    if !protocols.is_empty() {
        config.alpn_protocols = protocols.to_vec();
    }
    config
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn with_server_alpn(
    mut config: rustls::ServerConfig,
    protocols: &[Vec<u8>],
) -> rustls::ServerConfig {
    if !protocols.is_empty() {
        config.alpn_protocols = protocols.to_vec();
    }
    config
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn map_rustls_config_error(error: impl core::fmt::Display) -> ConfigError {
    ConfigError::TlsConfiguration(error.to_string())
}

#[cfg(feature = "rustls-ring")]
pub(crate) fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(all(not(feature = "rustls-ring"), feature = "rustls-aws-lc-rs"))]
pub(crate) fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
fn set_key_logging(config: &mut impl HasKeyLog) {
    config.set_key_log(Arc::new(KeyLogFile::new()));
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
trait HasKeyLog {
    fn set_key_log(&mut self, key_log: Arc<dyn rustls::KeyLog>);
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl HasKeyLog for rustls::ClientConfig {
    fn set_key_log(&mut self, key_log: Arc<dyn rustls::KeyLog>) {
        self.key_log = key_log;
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl HasKeyLog for rustls::ServerConfig {
    fn set_key_log(&mut self, key_log: Arc<dyn rustls::KeyLog>) {
        self.key_log = key_log;
    }
}

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
#[derive(Debug)]
struct NoCertificateVerification;

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(all(test, any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
mod tests {
    use super::*;

    fn self_signed_materials() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        rustls::RootCertStore,
    ) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        (vec![cert_der], key, roots)
    }

    #[test]
    fn client_builder_supports_custom_roots_key_logging_and_insecure_override() {
        let (_certs, _key, roots) = self_signed_materials();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .unwrap()
            .with_alpn_protocols([b"quion-test".to_vec()])
            .with_key_logging()
            .with_insecure_no_certificate_verification()
            .build();

        assert_eq!(config.alpn_protocols.as_ref(), &[b"quion-test".to_vec()]);
        let rustls = config.rustls.expect("client rustls config should be built");
        assert_eq!(rustls.alpn_protocols, vec![b"quion-test".to_vec()]);
        assert!(format!("{:?}", rustls.key_log).contains("KeyLogFile"));
    }

    #[test]
    fn version_negotiation_probe_requires_explicit_opt_in() {
        let default = ClientConfig::builder().build();
        let enabled = ClientConfig::builder()
            .with_version_negotiation_probe()
            .build();

        assert!(!default.version_negotiation_probe_enabled());
        assert!(enabled.version_negotiation_probe_enabled());
    }

    #[test]
    fn server_builder_supports_in_memory_cert_chain_and_key_logging() {
        let (certs, key, _roots) = self_signed_materials();
        let config = ServerConfig::builder()
            .with_single_cert(certs, key)
            .unwrap()
            .with_alpn_protocols([b"quion-test".to_vec()])
            .with_key_logging()
            .build()
            .unwrap();

        assert_eq!(config.alpn_protocols.as_ref(), &[b"quion-test".to_vec()]);
        let rustls = config.rustls.expect("server rustls config should be built");
        assert_eq!(rustls.alpn_protocols, vec![b"quion-test".to_vec()]);
        assert!(format!("{:?}", rustls.key_log).contains("KeyLogFile"));
    }

    #[cfg(feature = "zero-rtt")]
    #[test]
    fn zero_rtt_requires_explicit_client_and_server_opt_in() {
        let (certs, key, roots) = self_signed_materials();
        let provider = default_crypto_provider();
        let mut client_crypto =
            rustls::ClientConfig::builder_with_provider(provider.clone().into())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_crypto.enable_early_data = true;

        let client_disabled = ClientConfig::builder()
            .with_rustls_config(client_crypto.clone())
            .build();
        assert!(!client_disabled.zero_rtt_enabled());
        assert!(!client_disabled.rustls.as_ref().unwrap().enable_early_data);

        let client_enabled = ClientConfig::builder()
            .with_rustls_config(client_crypto)
            .with_zero_rtt()
            .build();
        assert!(client_enabled.zero_rtt_enabled());
        assert!(client_enabled.rustls.as_ref().unwrap().enable_early_data);

        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone_key())
            .unwrap();
        server_crypto.max_early_data_size = u32::MAX;

        let server_disabled = ServerConfig::builder()
            .with_rustls_config(server_crypto.clone())
            .build()
            .unwrap();
        assert!(!server_disabled.zero_rtt_enabled());
        assert_eq!(
            server_disabled.rustls.as_ref().unwrap().max_early_data_size,
            0
        );

        let server_enabled = ServerConfig::builder()
            .with_single_cert(certs, key)
            .unwrap()
            .with_zero_rtt()
            .build()
            .unwrap();
        assert!(server_enabled.zero_rtt_enabled());
        assert_eq!(
            server_enabled.rustls.as_ref().unwrap().max_early_data_size,
            u32::MAX
        );
    }

    #[test]
    fn pem_configuration_reports_stable_io_error() {
        let path = std::env::temp_dir().join(format!(
            "quion-missing-certificate-{}.pem",
            std::process::id()
        ));
        let error = ClientConfig::builder()
            .with_root_certificates_from_pem_file(&path)
            .unwrap_err();

        assert_eq!(
            error,
            ConfigError::Io {
                path,
                kind: std::io::ErrorKind::NotFound,
            }
        );
    }

    #[test]
    fn transport_config_exposes_server_connection_limit() {
        let mut transport = TransportConfig::default();
        assert_eq!(transport.max_connections(), 1024);
        assert_eq!(transport.max_pending_handshakes(), 1024);
        assert_eq!(transport.max_established_connections(), 1024);
        assert_eq!(
            transport.max_endpoint_routed_datagram_bytes(),
            64 * 1024 * 1024
        );
        assert_eq!(transport.max_retry_replay_entries(), 1 << 16);
        assert!(transport.retry_enabled());
        assert_eq!(transport.max_tracked_endpoint_paths(), 4096);
        assert_eq!(transport.max_runtime_driver_work_per_tick(), 32);
        assert_eq!(transport.max_buffered_qlog_events(), 0);
        assert_eq!(
            transport.proto().max_send_buffered_stream_data,
            16 * 1024 * 1024
        );
        assert_eq!(
            transport.proto().max_recv_buffered_stream_data,
            16 * 1024 * 1024
        );
        assert_eq!(
            transport
                .proto()
                .max_recv_buffered_stream_data_per_connection,
            16 * 1024 * 1024
        );
        assert_eq!(transport.proto().max_queued_datagrams, 1024);
        assert_eq!(transport.proto().max_queued_datagram_bytes, 4 * 1024 * 1024);
        assert_eq!(transport.proto().max_queued_control_frames, 4096);
        assert_eq!(transport.proto().max_ack_ranges_per_space, 256);
        assert_eq!(
            transport.proto().min_ack_delay,
            Some(quion_proto::VarInt::from_u32(1_000))
        );
        assert!(transport.proto().ack_frequency_config.is_none());
        assert_eq!(transport.proto().max_crypto_buffered_data, 64 * 1024);
        assert!(transport.proto().disable_active_migration);
        assert_eq!(
            transport.proto().congestion_algorithm,
            quion_proto::congestion::CongestionAlgorithm::NewReno
        );
        assert_eq!(transport.initial_mtu(), 1200);
        assert_eq!(
            transport
                .mtu_discovery_config()
                .map(quion_proto::mtud::MtuDiscoveryConfig::upper_bound),
            Some(1452)
        );

        transport.set_max_connections(7);
        assert_eq!(transport.max_connections(), 7);
        transport.set_max_pending_handshakes(3);
        assert_eq!(transport.max_pending_handshakes(), 3);
        transport.set_max_established_connections(5);
        assert_eq!(transport.max_established_connections(), 5);
        transport.set_max_endpoint_routed_datagram_bytes(4096);
        assert_eq!(transport.max_endpoint_routed_datagram_bytes(), 4096);
        transport.set_max_endpoint_memory_bytes(8192);
        assert_eq!(transport.max_endpoint_memory_bytes(), 8192);
        transport.set_max_retry_replay_entries(23);
        assert_eq!(transport.max_retry_replay_entries(), 23);
        transport.set_retry_enabled(false);
        assert!(!transport.retry_enabled());
        transport.set_max_tracked_endpoint_paths(3);
        assert_eq!(transport.max_tracked_endpoint_paths(), 3);
        transport.set_max_tracked_endpoint_paths(0);
        assert_eq!(transport.max_tracked_endpoint_paths(), 1);
        transport.set_max_runtime_driver_work_per_tick(2);
        assert_eq!(transport.max_runtime_driver_work_per_tick(), 2);
        transport.set_min_ack_delay(None);
        assert_eq!(transport.proto().min_ack_delay, None);
        let ack_frequency = quion_proto::config::AckFrequencyConfig {
            ack_eliciting_threshold: quion_proto::VarInt::from_u32(9),
            max_ack_delay: None,
            reordering_threshold: quion_proto::VarInt::from_u32(2),
        };
        transport.set_ack_frequency_config(Some(ack_frequency.clone()));
        assert_eq!(transport.proto().ack_frequency_config, Some(ack_frequency));
        transport.set_max_send_buffered_stream_data(8192);
        assert_eq!(transport.proto().max_send_buffered_stream_data, 8192);
        transport.set_max_recv_buffered_stream_data(4096);
        assert_eq!(transport.proto().max_recv_buffered_stream_data, 4096);
        transport.set_max_recv_buffered_stream_data_per_connection(6144);
        assert_eq!(
            transport
                .proto()
                .max_recv_buffered_stream_data_per_connection,
            6144
        );
        transport.set_max_queued_datagrams(7);
        assert_eq!(transport.proto().max_queued_datagrams, 7);
        transport.set_max_queued_datagram_bytes(2048);
        assert_eq!(transport.proto().max_queued_datagram_bytes, 2048);
        transport.set_max_queued_control_frames(17);
        assert_eq!(transport.proto().max_queued_control_frames, 17);
        transport.set_max_ack_ranges_per_space(19);
        assert_eq!(transport.proto().max_ack_ranges_per_space, 19);
        transport.set_max_ack_ranges_per_space(0);
        assert_eq!(transport.proto().max_ack_ranges_per_space, 1);
        transport.set_max_crypto_buffered_data(3072);
        assert_eq!(transport.proto().max_crypto_buffered_data, 3072);
        transport.set_congestion_algorithm(quion_proto::congestion::CongestionAlgorithm::Cubic);
        assert_eq!(
            transport.proto().congestion_algorithm,
            quion_proto::congestion::CongestionAlgorithm::Cubic
        );
        transport.set_initial_mtu(1452);
        assert_eq!(transport.initial_mtu(), 1452);
        transport.set_initial_mtu(1000);
        assert_eq!(transport.initial_mtu(), 1200);
        transport.set_mtu_discovery_config(None);
        assert!(transport.mtu_discovery_config().is_none());
        transport.set_active_connection_id_limit(quion_proto::VarInt::from_u32(9));
        assert_eq!(
            transport.proto().active_connection_id_limit,
            quion_proto::VarInt::from_u32(9)
        );
        transport.set_active_connection_id_limit(quion_proto::VarInt::ZERO);
        assert_eq!(
            transport.proto().active_connection_id_limit,
            quion_proto::VarInt::from_u32(2)
        );
        transport.set_disable_active_migration(false);
        assert!(!transport.proto().disable_active_migration);
        transport.set_max_buffered_qlog_events(11);
        assert_eq!(transport.max_buffered_qlog_events(), 11);
    }
}
