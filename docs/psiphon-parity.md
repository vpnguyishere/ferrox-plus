# Ferrox vs psiphon-tunnel-core config map

Pinned reference: `upstream/psiphon-tunnel-core` @ `2956a96` (`upstream/pins.toml`). This lane: `crates/ferrox-app/src/psiphon.rs`.

`KNOWN_SETTINGS` is the config surface the native lane accepts without an
`ignores …` warning. It is deliberately wider than the JSON tags of
`psiphon.Config`: the Aether config dialect, the Android fork and the
reference's older aliases each have their own spelling. Every JSON field of the
pinned `psiphon.Config` is therefore either in `KNOWN_SETTINGS` or in the gap
table below.

The checker is `python3 scripts/check-psiphon-parity.py` (also in
`scripts/check.sh` and the live workflow). It fails when a pinned field is
neither accepted nor classified, when a classified field is accepted or is not
in the pin, when a field is listed twice, when a class or state is outside its
vocabulary, or when the alias list drifts. A new pin therefore cannot add a
field silently.

`client-*` rows are the work list: client behaviour the lane does not read yet.
`not-a-client-lane` rows are the reference's relay, proxy, diagnostics,
migration, host-callback and disabled-transport surface; they are recorded so
the gap count is complete, not so a client lane should implement them.

## Remaining config fields

<!-- parity:begin -->
| class | state | fields |
| --- | --- | --- |
| `client-inproxy` | `missing` | `InproxyAllowClient`, `InproxyBrokerSpecs`, `InproxyClientBrokerSpecs`, `InproxyClientDialRateLimitIntervalMilliseconds`, `InproxyClientDialRateLimitQuantity`, `InproxyClientDisableIPv6ICECandidates`, `InproxyClientDisableInboundForMobileNetworks`, `InproxyClientDisablePortMapping`, `InproxyClientDisableSTUN`, `InproxyClientDisableWaitToShareSession`, `InproxyClientDiscoverNATProbability`, `InproxyClientDiscoverNATTimeoutMilliseconds`, `InproxyClientIncompatibleNetworkTypes`, `InproxyClientNoMatchFailoverPersonalProbability`, `InproxyClientNoMatchFailoverProbability`, `InproxyClientOfferRequestPersonalTimeoutMilliseconds`, `InproxyClientOfferRequestTimeoutMilliseconds`, `InproxyClientOfferRetryDelayMilliseconds`, `InproxyClientOfferRetryJitter`, `InproxyClientPersonalPairingBrokerSpecs`, `InproxyClientRelayedPacketRequestTimeoutMilliseconds`, `InproxyClientSTUNServerAddresses`, `InproxyClientSTUNServerAddressesRFC5780`, `InproxyClientWebRTCAwaitReadyToProxyTimeoutMilliseconds`, `InproxyCommonCompartmentIDs`, `InproxyDTLSRandomizationProbability`, `InproxyDisableIPv6ICECandidates`, `InproxyDisableInboundForMobileNetworks`, `InproxyDisablePortMapping`, `InproxyDisableSTUN`, `InproxyEnableWebRTCDebugLogging`, `InproxyFrontingProviderClientMaxRequestTimeouts`, `InproxyPersonalPairingBrokerSpecs`, `InproxyPersonalPairingMaxBrokerSpecCount`, `InproxyPsiphonAPIRequestTimeoutMilliseconds`, `InproxySTUNServerAddresses`, `InproxySTUNServerAddressesRFC5780`, `InproxySkipAwaitFullyConnected`, `InproxyTunnelProtocolForceSelectionCount`, `InproxyTunnelProtocolPreferProbability`, `InproxyTunnelProtocolSelectionProbability`, `InproxyWebRTCAnswerTimeoutMilliseconds`, `InproxyWebRTCDataChannelTrafficShapingParameters`, `InproxyWebRTCDataChannelTrafficShapingProbability`, `InproxyWebRTCMediaStreamsProbability`, `InproxyWebRTCMediaStreamsTrafficShapingParameters`, `InproxyWebRTCMediaStreamsTrafficShapingProbability` |
| `relay-inproxy` | `not-a-client-lane` | `EmitInproxyProxyActivity`, `InproxyAllowProxy`, `InproxyEnableProxy`, `InproxyLimitDownstreamBytesPerSecond`, `InproxyLimitUpstreamBytesPerSecond`, `InproxyMaxClients`, `InproxyMaxCommonClients`, `InproxyMaxCompartmentIDListLength`, `InproxyMaxPersonalClients`, `InproxyPersonalPairingConnectionWorkerPoolSize`, `InproxyProxyAnnounceDelayJitter`, `InproxyProxyAnnounceDelayMilliseconds`, `InproxyProxyAnnounceMaxBackoffDelayMilliseconds`, `InproxyProxyAnnounceRequestTimeoutMilliseconds`, `InproxyProxyAnswerRequestTimeoutMilliseconds`, `InproxyProxyBrokerSpecs`, `InproxyProxyDestinationDialTimeoutMilliseconds`, `InproxyProxyDisableIPv6ICECandidates`, `InproxyProxyDisableInboundForMobileNetworks`, `InproxyProxyDisablePortMapping`, `InproxyProxyDisableSTUN`, `InproxyProxyDisableWaitToShareSession`, `InproxyProxyDiscoverNATTimeoutMilliseconds`, `InproxyProxyIncompatibleNetworkTypes`, `InproxyProxyOnBrokerClientFailedRetryPeriodMilliseconds`, `InproxyProxyPersonalCompartmentID`, `InproxyProxyPersonalPairingBrokerSpecs`, `InproxyProxySTUNServerAddresses`, `InproxyProxySTUNServerAddressesRFC5780`, `InproxyProxySessionPrivateKey`, `InproxyProxySplitDownstreamInterfaceName`, `InproxyProxySplitUpstreamInterfaceName`, `InproxyProxyTotalActivityNoticePeriodMilliseconds`, `InproxyProxyWebRTCAwaitReadyToProxyTimeoutMilliseconds`, `InproxyReducedEndTime`, `InproxyReducedLimitDownstreamBytesPerSecond`, `InproxyReducedLimitUpstreamBytesPerSecond`, `InproxyReducedMaxClients`, `InproxyReducedMaxCommonClients`, `InproxyReducedStartTime` |
| `relay-server` | `not-a-client-lane` | `EnableProxyProtocolHeaders`, `PushPayloadObfuscationKey`, `PushPayloadSignaturePublicKey` |
| `diagnostics` | `not-a-client-lane` | `DisableServerEntriesReporter`, `EmitBytesTransferred`, `EmitClientAddress`, `EmitDiagnosticNetworkParameters`, `EmitDiagnosticNotices`, `EmitRefractionNetworkingLogs`, `IgnoreHandshakeStatsRegexps`, `ShutdownGoroutineProfileDeadlineSeconds`, `UseNoticeFiles` |
| `migration` | `not-a-client-lane` | `DataStoreDirectory`, `MigrateDataStoreDirectory`, `MigrateHomepageNoticesFilename`, `MigrateObfuscatedServerListDownloadDirectory`, `MigrateRemoteServerListDownloadFilename`, `MigrateRotatingNoticesFilename`, `MigrateUpgradeDownloadFilename`, `ObfuscatedServerListDownloadDirectory`, `RemoteServerListDownloadFilename`, `UpgradeDownloadFilename` |
| `host-hook` | `not-a-client-lane` | `AllowDefaultDNSResolverWithBindToDevice`, `DNSServerGetter`, `DeviceBinder`, `HasIPv6RouteGetter`, `IPv6Synthesizer`, `NetworkConnectivityChecker`, `NetworkID`, `NetworkIDCacheTTLMilliseconds`, `NetworkIDGetter` |
| `upstream-disabled` | `not-a-client-lane` | `ConjureAPIRegistrarBidirectionalURL`, `ConjureAPIRegistrarFrontingSpecs`, `ConjureAPIRegistrarMaxDelayMilliseconds`, `ConjureAPIRegistrarMinDelayMilliseconds`, `ConjureCachedRegistrationTTLSeconds`, `ConjureDTLSEmptyInitialPacketProbability`, `ConjureDecoyRegistrarMaxDelayMilliseconds`, `ConjureDecoyRegistrarMinDelayMilliseconds`, `ConjureDecoyRegistrarProbability`, `ConjureDecoyRegistrarWidth`, `ConjureEnableIPv6Dials`, `ConjureEnablePortRandomization`, `ConjureEnableRegistrationOverrides`, `ConjureLimitTransports`, `ConjureSTUNServerAddresses` |
<!-- parity:end -->

## Fork and alias spellings

`KNOWN_SETTINGS` also holds the Aether config dialect, the Android fork and the
reference's older names. They are accepted without an `ignores …` warning and
are checked against `KNOWN_SETTINGS`, so a spelling that is dropped from the
code fails here.

<!-- aliases:begin -->
`AdditionalCustomHeaders`, `CONDUIT_TUNNEL_PROTOCOLS`, `ClientBuildRev`, `QUICDisableClientPathMTUDiscoveryProbability`, `ConduitTunnelProtocols`, `DisableKeepAlive`, `DisableTimeouts`, `FeedbackUploadMaxAttempts`, `FeedbackUploadRetryMaxDelaySeconds`, `FeedbackUploadRetryMinDelaySeconds`, `InitialLimitTunnelProtocolsProbability`, `LightProxyDialTimeout`, `LightProxyDisable`, `LightProxyTunnelInactiveThreshold`, `LimitTunnelDialPortNumbersProbability`, `LimitTunnelProtocolsProbability`, `NetworkType`, `OSSHPrefixSplitMaxDelay`, `OSSHPrefixSplitMinDelay`, `PrioritizeTunnelProtocols`, `PrioritizeTunnelProtocolsCandidateCount`, `PrioritizeTunnelProtocolsProbability`, `SponsorID`, `TLSOSSHSNIServerName`, `TLSOSSHSNIServerNames`, `TLSProfile`, `UpstreamProxyUrl`, `additionalParameters`, `aggressiveEstablishment`, `beastMode`, `cdnIps`, `cdnProfile`, `cdnSets`, `cdnSni`, `conduitMode`, `conduitTimeout`, `conduitTunnelProtocols`, `conduit_mode`, `conduit_timeout`, `customHeaders`, `dataDirectory`, `dataRootDirectory`, `deviceLocation`, `deviceRegion`, `disableTunnels`, `egressRegion`, `frontedMeekCDNScanSpec`, `inproxyClientPersonalCompartmentID`, `inproxyCompartment`, `limitTunnelDialPortNumbers`, `limitTunnelProtocols`, `listen`, `localProxyPassword`, `localProxyUsername`, `obfuscatedServerListRootURLs`, `protocolSelection`, `protocol_selection`, `readySeconds`, `region`, `rejectCensoredCountryProxies`, `rejectProxyCountryCodes`, `remoteServerListSignaturePublicKey`, `remoteServerListURLs`, `remoteServerListUrl`, `serverEntries`, `serverList`, `serverListSignaturePublicKey`, `serverListURL`, `serverListURLs`, `serverListUrls`, `shareProxyOnNetwork`, `shareProxyOnNetworkHttpPort`, `shareProxyOnNetworkPassword`, `shareProxyOnNetworkSocksPort`, `shareProxyOnNetworkUsername`, `sponsorId`, `state`, `tunnelPoolSize`, `tunnelProtocol`, `tunnelProtocols`, `upstream`, `upstreamProxy`
<!-- aliases:end -->

## Working the list

The map is a config surface, not a behaviour report; `carrier-psiphon.md` owns
the handshake, tunnel, relay and measurement claims. To close a gap, implement
the field (or name it as explicitly accepted), add its spelling to
`KNOWN_SETTINGS`, move it out of the table, and run the checker. A class row
that empties disappears; the remaining rows are the next slices.
