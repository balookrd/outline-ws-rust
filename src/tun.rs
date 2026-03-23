use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::config::TunConfig;
use crate::memory::maybe_shrink_hash_map;
use crate::metrics;
use crate::transport::{UdpWsTransport, is_dropped_oversized_udp_error};
use crate::tun_tcp::TunTcpEngine;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

const UDP_HEADER_LEN: usize = 8;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    version: IpVersion,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone)]
struct UdpFlowState {
    id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    uplink_name: String,
    created_at: Instant,
    last_seen: Instant,
}

#[derive(Clone)]
pub(crate) struct SharedTunWriter {
    inner: Arc<Mutex<File>>,
}

#[derive(Debug, Clone)]
struct ParsedUdpPacket {
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketDisposition {
    Udp,
    Tcp,
    IcmpEchoRequest,
    Unsupported(&'static str),
}

type FlowTable = Arc<Mutex<HashMap<UdpFlowKey, UdpFlowState>>>;

pub async fn spawn_tun_loop(config: TunConfig, uplinks: UplinkManager) -> Result<()> {
    let tun_path = config.path.clone();
    let tun_name = config.name.clone();
    let tun_mtu = config.mtu;
    let tun_path_for_task = tun_path.clone();
    let device = open_tun_device(&config)
        .with_context(|| format!("failed to open TUN device {}", config.path.display()))?;
    let reader = File::from_std(
        device
            .try_clone()
            .context("failed to clone TUN file descriptor")?,
    );
    let writer = SharedTunWriter {
        inner: Arc::new(Mutex::new(File::from_std(device))),
    };

    let flows = Arc::new(Mutex::new(HashMap::new()));
    let flow_ids = Arc::new(AtomicU64::new(1));
    let idle_timeout = config.idle_timeout;
    let max_flows = config.max_flows;
    let tcp_engine = TunTcpEngine::new(
        writer.clone(),
        uplinks.clone(),
        max_flows,
        idle_timeout,
        tun_mtu,
        config.tcp.clone(),
    );
    metrics::set_tun_config(max_flows, idle_timeout);
    spawn_flow_cleanup_loop(&flows, idle_timeout);

    tokio::spawn(async move {
        if let Err(error) = tun_read_loop(
            reader, writer, tcp_engine, uplinks, flows, flow_ids, tun_mtu, max_flows,
        )
        .await
        {
            warn!(path = %tun_path_for_task.display(), error = %format!("{error:#}"), "TUN loop stopped");
        }
    });

    info!(
        path = %tun_path.display(),
        name = tun_name.as_deref().unwrap_or("n/a"),
        mtu = tun_mtu,
        max_flows,
        idle_timeout_secs = idle_timeout.as_secs(),
        "TUN loop started"
    );
    Ok(())
}

async fn tun_read_loop(
    mut reader: File,
    writer: SharedTunWriter,
    tcp_engine: TunTcpEngine,
    uplinks: UplinkManager,
    flows: FlowTable,
    flow_ids: Arc<AtomicU64>,
    mtu: usize,
    max_flows: usize,
) -> Result<()> {
    let mut buf = vec![0u8; mtu + 256];
    loop {
        let read = reader
            .read(&mut buf)
            .await
            .context("failed to read TUN packet")?;
        if read == 0 {
            bail!("TUN device returned EOF");
        }
        let packet = &buf[..read];
        let version_nibble = packet[0] >> 4;
        let disposition = match classify_packet(packet) {
            Ok(disposition) => disposition,
            Err(error) => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "error",
                );
                debug!(error = %format!("{error:#}"), packet_len = read, "dropping malformed TUN packet");
                continue;
            }
        };
        match disposition {
            PacketDisposition::Udp => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "accepted",
                );
                let parsed = match parse_udp_packet(packet) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        metrics::record_tun_packet(
                            "tun_to_upstream",
                            ip_family_name(version_nibble),
                            "error",
                        );
                        debug!(error = %format!("{error:#}"), packet_len = read, "dropping malformed UDP packet from TUN");
                        continue;
                    }
                };
                if let Err(error) =
                    forward_udp_packet(parsed, &writer, &uplinks, &flows, &flow_ids, max_flows)
                        .await
                {
                    metrics::record_tun_udp_forward_error(classify_tun_udp_forward_error(&error));
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "udp_error",
                    );
                    warn!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "failed to forward UDP packet from TUN"
                    );
                    continue;
                }
            }
            PacketDisposition::Tcp => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "tcp_observed",
                );
                if let Err(error) = tcp_engine.handle_packet(packet).await {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "tcp_error",
                    );
                    debug!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "dropping malformed TCP packet from TUN"
                    );
                }
            }
            PacketDisposition::IcmpEchoRequest => match build_icmp_echo_reply(packet) {
                Ok(reply) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "icmp_local_reply",
                    );
                    if let Err(error) = writer.write_packet(&reply).await {
                        metrics::record_tun_packet(
                            "upstream_to_tun",
                            ip_family_name(version_nibble),
                            "error",
                        );
                        warn!(
                            error = %format!("{error:#}"),
                            packet_len = read,
                            "failed to write local ICMP echo reply to TUN"
                        );
                    } else {
                        metrics::record_tun_icmp_local_reply(ip_family_name(version_nibble));
                        metrics::record_tun_packet(
                            "upstream_to_tun",
                            ip_family_name(version_nibble),
                            "icmp_local_reply",
                        );
                    }
                }
                Err(error) => {
                    metrics::record_tun_packet(
                        "tun_to_upstream",
                        ip_family_name(version_nibble),
                        "error",
                    );
                    debug!(
                        error = %format!("{error:#}"),
                        packet_len = read,
                        "dropping malformed ICMP packet from TUN"
                    );
                }
            },
            PacketDisposition::Unsupported(reason) => {
                metrics::record_tun_packet(
                    "tun_to_upstream",
                    ip_family_name(version_nibble),
                    "unsupported",
                );
                let packet_summary = summarize_unsupported_packet(packet);
                debug!(
                    reason,
                    packet_len = read,
                    packet = %packet_summary,
                    "ignoring unsupported TUN packet"
                );
            }
        }
    }
}

async fn forward_udp_packet(
    packet: ParsedUdpPacket,
    writer: &SharedTunWriter,
    uplinks: &UplinkManager,
    flows: &FlowTable,
    flow_ids: &Arc<AtomicU64>,
    max_flows: usize,
) -> Result<()> {
    let remote_target = ip_to_target(packet.destination_ip, packet.destination_port);
    let key = UdpFlowKey {
        version: packet.version,
        local_ip: packet.source_ip,
        local_port: packet.source_port,
        remote_ip: packet.destination_ip,
        remote_port: packet.destination_port,
    };

    let active_uplink = if uplinks.strict_active_uplink_for(TransportKind::Udp) {
        uplinks
            .active_uplink_index_for_transport(TransportKind::Udp)
            .await
    } else {
        None
    };

    let (existing, stale_flow) = {
        let mut guard = flows.lock().await;
        match guard.get(&key) {
            Some(flow) if active_uplink.is_some_and(|active| active != flow.uplink_index) => {
                let stale = guard.remove(&key).expect("stale TUN UDP flow must exist");
                (None, Some(stale))
            }
            Some(_) => {
                let flow = guard.get_mut(&key).expect("TUN UDP flow must still exist");
                flow.last_seen = Instant::now();
                (
                    Some((
                        flow.id,
                        Arc::clone(&flow.transport),
                        flow.uplink_index,
                        flow.uplink_name.clone(),
                    )),
                    None,
                )
            }
            None => (None, None),
        }
    };

    if let Some(stale_flow) = stale_flow {
        metrics::record_tun_flow_closed(
            &stale_flow.uplink_name,
            "global_switch",
            Instant::now().saturating_duration_since(stale_flow.created_at),
        );
        if let Err(error) = stale_flow.transport.close().await {
            debug!(
                flow_id = stale_flow.id,
                error = %format!("{error:#}"),
                "failed to close stale TUN UDP transport after global switch"
            );
        }
    }

    let (flow_id, transport, uplink_index, uplink_name) = match existing {
        Some(existing) => existing,
        None => {
            create_udp_flow(
                key.clone(),
                writer.clone(),
                uplinks,
                flows,
                flow_ids,
                max_flows,
            )
            .await?
        }
    };

    let payload = build_udp_payload(&remote_target, &packet.payload)?;
    if let Err(error) = transport.send_packet(&payload).await {
        if is_dropped_oversized_udp_error(&error) {
            return Ok(());
        }
        uplinks
            .report_runtime_failure(uplink_index, TransportKind::Udp, &error)
            .await;
        close_flow_if_current(flows, &key, flow_id, "send_error").await;
        let (replacement_flow_id, replacement_transport, replacement_index, replacement_name) =
            create_udp_flow(
                key.clone(),
                writer.clone(),
                uplinks,
                flows,
                flow_ids,
                max_flows,
            )
            .await?;
        metrics::record_failover("udp", &uplink_name, &replacement_name);
        if let Err(error) = replacement_transport.send_packet(&payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            return Err(error);
        }
        metrics::add_udp_datagram("client_to_upstream", &replacement_name);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            &replacement_name,
            payload.len(),
        );
        debug!(
            flow_id = replacement_flow_id,
            uplink = %replacement_name,
            "recreated TUN UDP flow after send failure"
        );
        let _ = replacement_index;
    } else {
        metrics::add_udp_datagram("client_to_upstream", &uplink_name);
        metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
    }

    Ok(())
}

fn classify_tun_udp_forward_error(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}");
    let lower = text.to_ascii_lowercase();
    if lower.contains("all udp uplinks failed") {
        "all_uplinks_failed"
    } else if lower.contains("failed to send udp websocket frame")
        || lower.contains("websocket read failed")
    {
        "transport_error"
    } else if lower.contains("failed to connect to") {
        "connect_failed"
    } else {
        "other"
    }
}

async fn create_udp_flow(
    key: UdpFlowKey,
    writer: SharedTunWriter,
    uplinks: &UplinkManager,
    flows: &FlowTable,
    flow_ids: &Arc<AtomicU64>,
    max_flows: usize,
) -> Result<(u64, Arc<UdpWsTransport>, usize, String)> {
    let (candidate, transport) =
        select_udp_candidate_and_connect(uplinks, &ip_to_target(key.remote_ip, key.remote_port))
            .await?;
    uplinks
        .confirm_selected_uplink(
            TransportKind::Udp,
            Some(&ip_to_target(key.remote_ip, key.remote_port)),
            candidate.index,
        )
        .await;
    let transport = Arc::new(transport);
    let now = Instant::now();
    let flow_id = flow_ids.fetch_add(1, Ordering::Relaxed);
    let state = UdpFlowState {
        id: flow_id,
        transport: Arc::clone(&transport),
        uplink_index: candidate.index,
        uplink_name: candidate.uplink.name.clone(),
        created_at: now,
        last_seen: now,
    };

    let mut evicted_transport = None;
    {
        let mut guard = flows.lock().await;
        if let Some(existing) = guard.get_mut(&key) {
            existing.last_seen = now;
            return Ok((
                existing.id,
                Arc::clone(&existing.transport),
                existing.uplink_index,
                existing.uplink_name.clone(),
            ));
        }
        if guard.len() >= max_flows {
            if let Some(evicted_key) = oldest_flow_key(&guard) {
                if let Some(evicted) = guard.remove(&evicted_key) {
                    metrics::record_tun_flow_closed(
                        &evicted.uplink_name,
                        "evicted",
                        now.saturating_duration_since(evicted.created_at),
                    );
                    warn!(
                        evicted_flow_id = evicted.id,
                        evicted_uplink = %evicted.uplink_name,
                        max_flows,
                        "evicted oldest TUN UDP flow due to flow table limit"
                    );
                    evicted_transport = Some(evicted.transport);
                }
            } else {
                bail!("TUN flow table limit reached and no flow could be evicted");
            }
        }
        guard.insert(key.clone(), state);
    }

    if let Some(transport) = evicted_transport {
        if let Err(error) = transport.close().await {
            debug!(
                error = %format!("{error:#}"),
                "failed to close evicted TUN UDP transport"
            );
        }
    }

    metrics::record_uplink_selected("udp", &candidate.uplink.name);
    metrics::record_tun_flow_created(&candidate.uplink.name);
    debug!(
        flow_id,
        uplink = %candidate.uplink.name,
        local = %format!("{}:{}", key.local_ip, key.local_port),
        remote = %format!("{}:{}", key.remote_ip, key.remote_port),
        "created TUN UDP flow"
    );
    spawn_udp_flow_reader(
        key,
        flow_id,
        Arc::clone(&transport),
        candidate.index,
        writer,
        uplinks.clone(),
        Arc::clone(flows),
    );

    Ok((
        flow_id,
        transport,
        candidate.index,
        candidate.uplink.name.clone(),
    ))
}

async fn select_udp_candidate_and_connect(
    uplinks: &UplinkManager,
    remote_target: &TargetAddr,
) -> Result<(UplinkCandidate, UdpWsTransport)> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Udp);
    let mut tried_indexes = std::collections::HashSet::new();

    loop {
        let candidates = uplinks.udp_candidates(Some(remote_target)).await;
        let iter = if strict_transport {
            candidates.into_iter().take(1).collect::<Vec<_>>()
        } else {
            candidates
        };
        if iter.is_empty() {
            break;
        }
        let mut progressed = false;
        for candidate in iter {
            if strict_transport && !tried_indexes.insert(candidate.index) {
                continue;
            }
            progressed = true;
            match uplinks
                .acquire_udp_standby_or_connect(&candidate, "tun_udp")
                .await
            {
                Ok(transport) => {
                    return Ok((candidate, transport));
                }
                Err(error) => {
                    uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                        .await;
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                }
            }
        }
        if !strict_transport || !progressed {
            break;
        }
    }
    Err(anyhow!(
        "all UDP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

fn spawn_udp_flow_reader(
    key: UdpFlowKey,
    flow_id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: FlowTable,
) {
    tokio::spawn(async move {
        let result = async {
            loop {
                if uplinks.strict_active_uplink_for(TransportKind::Udp)
                    && uplinks
                        .active_uplink_index_for_transport(TransportKind::Udp)
                        .await
                        .is_some_and(|active| active != uplink_index)
                {
                    close_flow_if_current(&flows, &key, flow_id, "global_switch").await;
                    return Ok(());
                }
                let payload = transport.read_packet().await?;
                let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                let packet = build_response_packet(
                    key.version,
                    &target,
                    key.local_ip,
                    key.local_port,
                    &payload[consumed..],
                )?;
                let uplink_name = {
                    let guard = flows.lock().await;
                    guard
                        .get(&key)
                        .filter(|flow| flow.id == flow_id)
                        .map(|flow| flow.uplink_name.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                };
                metrics::add_udp_datagram("upstream_to_client", &uplink_name);
                metrics::add_bytes("udp", "upstream_to_client", &uplink_name, payload.len());
                writer.write_packet(&packet).await?;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(key.version),
                    "accepted",
                );
                let mut guard = flows.lock().await;
                if let Some(flow) = guard.get_mut(&key) {
                    if flow.id == flow_id {
                        flow.last_seen = Instant::now();
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let close_reason = if result.is_ok() {
            "closed"
        } else {
            "read_error"
        };

        if let Err(ref error) = result {
            // Only report a runtime failure if this flow is still the current flow.
            // If it was already removed (e.g. by idle-timeout cleanup), the WS close
            // we received was from our own intentional transport.close() — not a real failure.
            let is_current = flows
                .lock()
                .await
                .get(&key)
                .map_or(false, |f| f.id == flow_id);
            if is_current {
                uplinks
                    .report_runtime_failure(uplink_index, TransportKind::Udp, &error)
                    .await;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(key.version),
                    "error",
                );
                warn!(
                    flow_id,
                    error = %format!("{error:#}"),
                    "TUN UDP flow reader stopped"
                );
            }
        }
        close_flow_if_current(&flows, &key, flow_id, close_reason).await;
    });
}

fn spawn_flow_cleanup_loop(flows: &FlowTable, idle_timeout: Duration) {
    let flows = Arc::downgrade(flows);
    tokio::spawn(async move {
        loop {
            sleep(TUN_FLOW_CLEANUP_INTERVAL).await;
            let Some(flows) = flows.upgrade() else {
                break;
            };
            cleanup_idle_flows(&flows, idle_timeout).await;
        }
    });
}

impl SharedTunWriter {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new(file: File) -> Self {
        Self {
            inner: Arc::new(Mutex::new(file)),
        }
    }

    pub(crate) async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let mut writer = self.inner.lock().await;
        writer
            .write_all(packet)
            .await
            .context("failed to write packet to TUN")?;
        writer.flush().await.context("failed to flush TUN packet")?;
        Ok(())
    }
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn build_response_packet(
    version: IpVersion,
    target: &TargetAddr,
    local_ip: IpAddr,
    local_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (version, target, local_ip) {
        (IpVersion::V4, TargetAddr::IpV4(remote_ip, remote_port), IpAddr::V4(local_ip)) => {
            build_ipv4_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        }
        (IpVersion::V6, TargetAddr::IpV6(remote_ip, remote_port), IpAddr::V6(local_ip)) => {
            build_ipv6_udp_packet(*remote_ip, local_ip, *remote_port, local_port, payload)
        }
        _ => bail!("unexpected response address family for TUN UDP flow"),
    }
}

fn classify_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => classify_ipv4_packet(packet),
        6 => classify_ipv6_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn classify_ipv4_packet(packet: &[u8]) -> Result<PacketDisposition> {
    if packet.len() < IPV4_HEADER_LEN {
        bail!("short IPv4 packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN || packet.len() < header_len {
        bail!("invalid IPv4 header length");
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        return Ok(PacketDisposition::Unsupported(
            "IPv4 fragments are not supported on TUN",
        ));
    }
    Ok(match packet[9] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        1 => classify_ipv4_icmp_packet(packet, header_len)?,
        _ => PacketDisposition::Unsupported("unsupported IPv4 protocol on TUN"),
    })
}

fn classify_ipv6_packet(packet: &[u8]) -> Result<PacketDisposition> {
    if packet.len() < IPV6_HEADER_LEN {
        bail!("short IPv6 packet");
    }
    Ok(match packet[6] {
        17 => PacketDisposition::Udp,
        6 => PacketDisposition::Tcp,
        58 => classify_ipv6_icmp_packet(packet)?,
        _ => PacketDisposition::Unsupported(
            "unsupported IPv6 payload protocol or extension header path on TUN",
        ),
    })
}

fn classify_ipv4_icmp_packet(packet: &[u8], header_len: usize) -> Result<PacketDisposition> {
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        bail!("truncated IPv4 ICMP packet");
    }
    Ok(match packet[header_len] {
        8 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMP is not supported on TUN"),
    })
}

fn classify_ipv6_icmp_packet(packet: &[u8]) -> Result<PacketDisposition> {
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if payload_len < 8 || packet.len() < total_len {
        bail!("truncated IPv6 ICMP packet");
    }
    Ok(match packet[IPV6_HEADER_LEN] {
        128 => PacketDisposition::IcmpEchoRequest,
        _ => PacketDisposition::Unsupported("non-echo ICMPv6 is not supported on TUN"),
    })
}

fn summarize_unsupported_packet(packet: &[u8]) -> String {
    let version = match packet.first() {
        Some(first) => first >> 4,
        None => return "empty".to_string(),
    };
    match version {
        4 => summarize_unsupported_ipv4_packet(packet),
        6 => summarize_unsupported_ipv6_packet(packet),
        other => format!("ipv{other}"),
    }
}

fn summarize_unsupported_ipv4_packet(packet: &[u8]) -> String {
    if packet.len() < IPV4_HEADER_LEN {
        return "ipv4 short".to_string();
    }
    let protocol = packet[9];
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    format!("ipv4 proto={protocol} src={src} dst={dst}")
}

fn summarize_unsupported_ipv6_packet(packet: &[u8]) -> String {
    if packet.len() < IPV6_HEADER_LEN {
        return "ipv6 short".to_string();
    }
    let next_header = packet[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).expect("slice length checked"));
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).expect("slice length checked"));
    format!("ipv6 next_header={next_header} src={src} dst={dst}")
}

fn parse_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        other => bail!("unsupported IP version in TUN packet: {other}"),
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv4 UDP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + UDP_HEADER_LEN {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 packet");
    }
    if packet[9] != 17 {
        bail!("expected IPv4 UDP packet");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V4,
        source_ip: IpAddr::V4(src),
        destination_ip: IpAddr::V4(dst),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Result<ParsedUdpPacket> {
    if packet.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN {
        bail!("short IPv6 UDP packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() < total_len {
        bail!("truncated IPv6 packet");
    }
    if packet[6] != 17 {
        bail!("expected IPv6 UDP packet");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    let udp = &packet[IPV6_HEADER_LEN..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp.len() < udp_len {
        bail!("truncated IPv6 UDP payload");
    }
    Ok(ParsedUdpPacket {
        version: IpVersion::V6,
        source_ip: IpAddr::V6(Ipv6Addr::from(src)),
        destination_ip: IpAddr::V6(Ipv6Addr::from(dst)),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

fn build_ipv4_udp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV4_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = udp_checksum_ipv4(
        source_ip,
        destination_ip,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_udp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV6_HEADER_LEN + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let udp_offset = IPV6_HEADER_LEN;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[udp_offset + UDP_HEADER_LEN..].copy_from_slice(payload);

    let udp_checksum = udp_checksum_ipv6(
        source_ip,
        destination_ip,
        &packet[udp_offset..udp_offset + udp_len],
    );
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn build_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    let version = packet.first().ok_or_else(|| anyhow!("empty TUN packet"))? >> 4;
    match version {
        4 => build_ipv4_icmp_echo_reply(packet),
        6 => build_ipv6_icmp_echo_reply(packet),
        other => bail!("unsupported IP version in ICMP packet: {other}"),
    }
}

fn build_ipv4_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < IPV4_HEADER_LEN + 8 {
        bail!("short IPv4 ICMP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + 8 || packet.len() < total_len {
        bail!("invalid IPv4 ICMP packet lengths");
    }
    if packet[9] != 1 {
        bail!("expected IPv4 ICMP packet");
    }
    if packet[header_len] != 8 {
        bail!("expected IPv4 ICMP echo request");
    }

    let mut reply = packet[..total_len].to_vec();
    let source = [packet[12], packet[13], packet[14], packet[15]];
    let destination = [packet[16], packet[17], packet[18], packet[19]];
    reply[8] = 64;
    reply[12..16].copy_from_slice(&destination);
    reply[16..20].copy_from_slice(&source);
    reply[header_len] = 0;
    reply[header_len + 2] = 0;
    reply[header_len + 3] = 0;
    let icmp_checksum = checksum16(&reply[header_len..total_len]);
    reply[header_len + 2..header_len + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    reply[10] = 0;
    reply[11] = 0;
    let header_checksum = checksum16(&reply[..header_len]);
    reply[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(reply)
}

fn build_ipv6_icmp_echo_reply(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() < IPV6_HEADER_LEN + 8 {
        bail!("short IPv6 ICMP packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if payload_len < 8 || packet.len() < total_len {
        bail!("invalid IPv6 ICMP packet lengths");
    }
    if packet[6] != 58 {
        bail!("expected IPv6 ICMP packet");
    }
    if packet[IPV6_HEADER_LEN] != 128 {
        bail!("expected IPv6 ICMP echo request");
    }

    let mut reply = packet[..total_len].to_vec();
    let mut source = [0u8; 16];
    source.copy_from_slice(&packet[8..24]);
    let mut destination = [0u8; 16];
    destination.copy_from_slice(&packet[24..40]);
    reply[7] = 64;
    reply[8..24].copy_from_slice(&destination);
    reply[24..40].copy_from_slice(&source);
    reply[IPV6_HEADER_LEN] = 129;
    reply[IPV6_HEADER_LEN + 2] = 0;
    reply[IPV6_HEADER_LEN + 3] = 0;
    let icmp_checksum = icmpv6_checksum(
        Ipv6Addr::from(destination),
        Ipv6Addr::from(source),
        &reply[IPV6_HEADER_LEN..total_len],
    );
    reply[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(reply)
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            u16::from_be_bytes([chunk[0], 0]) as u32
        };
        sum = sum.wrapping_add(value);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn udp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    checksum16(&pseudo)
}

fn udp_checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(udp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(udp_segment);
    checksum16(&pseudo)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, icmp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp_packet.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(icmp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp_packet);
    checksum16(&pseudo)
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

fn ip_family_name(version: u8) -> &'static str {
    match version {
        4 => "ipv4",
        6 => "ipv6",
        _ => "unknown",
    }
}

fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

fn oldest_flow_key(flows: &HashMap<UdpFlowKey, UdpFlowState>) -> Option<UdpFlowKey> {
    flows
        .iter()
        .min_by_key(|(_, flow)| flow.last_seen)
        .map(|(key, _)| key.clone())
}

async fn close_flow_if_current(
    flows: &FlowTable,
    key: &UdpFlowKey,
    flow_id: u64,
    reason: &'static str,
) {
    let removed = {
        let mut guard = flows.lock().await;
        if guard.get(key).map(|flow| flow.id) == Some(flow_id) {
            guard.remove(key)
        } else {
            None
        }
    };

    if let Some(flow) = removed {
        metrics::record_tun_flow_closed(
            &flow.uplink_name,
            reason,
            Instant::now().saturating_duration_since(flow.created_at),
        );
        if let Err(error) = flow.transport.close().await {
            debug!(
                flow_id,
                reason,
                error = %format!("{error:#}"),
                "failed to close TUN UDP transport"
            );
        }
    }
}

async fn cleanup_idle_flows(flows: &FlowTable, idle_timeout: Duration) {
    let now = Instant::now();
    let expired = {
        let mut guard = flows.lock().await;
        let expired_keys: Vec<UdpFlowKey> = guard
            .iter()
            .filter_map(|(key, flow)| {
                (now.saturating_duration_since(flow.last_seen) >= idle_timeout).then(|| key.clone())
            })
            .collect();

        let mut removed = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(flow) = guard.remove(&key) {
                removed.push(flow);
            }
        }
        maybe_shrink_hash_map(&mut guard);
        removed
    };

    for flow in expired {
        metrics::record_tun_flow_closed(
            &flow.uplink_name,
            "idle_timeout",
            now.saturating_duration_since(flow.created_at),
        );
        if let Err(error) = flow.transport.close().await {
            debug!(
                flow_id = flow.id,
                error = %format!("{error:#}"),
                "failed to close idle TUN UDP transport"
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    let name = config
        .name
        .as_ref()
        .ok_or_else(|| anyhow!("missing tun.name for Linux TUN attach"))?;
    if name.len() >= libc::IFNAMSIZ {
        bail!("tun.name is too long for Linux ifreq: {}", name);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))?;

    let mut ifreq = IfReq {
        name: [0; libc::IFNAMSIZ],
        data: [0; 24],
    };
    for (index, byte) in name.as_bytes().iter().enumerate() {
        ifreq.name[index] = *byte as libc::c_char;
    }
    unsafe {
        std::ptr::write_unaligned(
            ifreq.data.as_mut_ptr() as *mut libc::c_short,
            IFF_TUN | IFF_NO_PI,
        );
    }

    let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &ifreq) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF failed");
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
    use url::Url;

    use crate::config::{
        LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
        WsProbeConfig,
    };
    use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};
    use crate::metrics;
    use crate::types::{CipherKind, TargetAddr, UplinkTransport, WsTransportMode};
    use crate::uplink::UplinkManager;

    #[test]
    fn ipv4_udp_roundtrip() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello",
        )
        .unwrap();

        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V4);
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 40000);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let packet = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            5353,
            41000,
            b"world",
        )
        .unwrap();

        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Udp);
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V6);
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 5353);
        assert_eq!(parsed.destination_port, 41000);
        assert_eq!(parsed.payload, b"world");
    }

    #[test]
    fn tcp_packets_are_classified_for_tun_tcp_path() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(classify_packet(&packet).unwrap(), PacketDisposition::Tcp);
    }

    #[test]
    fn ipv4_icmp_echo_request_gets_local_reply() {
        let packet = build_ipv4_icmp_echo_request(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            0x1234,
            0x0007,
            b"ping",
        );

        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::IcmpEchoRequest
        );
        let reply = build_icmp_echo_reply(&packet).unwrap();

        assert_eq!(reply[9], 1);
        assert_eq!(reply[12..16], [8, 8, 8, 8]);
        assert_eq!(reply[16..20], [10, 0, 0, 2]);
        assert_eq!(reply[IPV4_HEADER_LEN], 0);
        assert_eq!(
            reply[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 8],
            [0x12, 0x34, 0x00, 0x07]
        );
        assert_eq!(&reply[IPV4_HEADER_LEN + 8..], b"ping");
        assert_eq!(
            checksum16(
                &reply[IPV4_HEADER_LEN..usize::from(u16::from_be_bytes([reply[2], reply[3]]))]
            ),
            0
        );
    }

    #[test]
    fn ipv6_icmp_echo_request_gets_local_reply() {
        let source = Ipv6Addr::LOCALHOST;
        let destination = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let packet = build_ipv6_icmp_echo_request(source, destination, 0xabcd, 0x0002, b"pong");

        assert_eq!(
            classify_packet(&packet).unwrap(),
            PacketDisposition::IcmpEchoRequest
        );
        let reply = build_icmp_echo_reply(&packet).unwrap();

        assert_eq!(reply[6], 58);
        assert_eq!(reply[8..24], destination.octets());
        assert_eq!(reply[24..40], source.octets());
        assert_eq!(reply[IPV6_HEADER_LEN], 129);
        assert_eq!(
            reply[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 8],
            [0xab, 0xcd, 0x00, 0x02]
        );
        assert_eq!(&reply[IPV6_HEADER_LEN + 8..], b"pong");
        let checksum = icmpv6_checksum(destination, source, &reply[IPV6_HEADER_LEN..]);
        assert_eq!(checksum, 0);
    }

    fn build_ipv4_icmp_echo_request(
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total_len = IPV4_HEADER_LEN + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&destination_ip.octets());
        let icmp_offset = IPV4_HEADER_LEN;
        packet[icmp_offset] = 8;
        packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
        packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[icmp_offset + 8..].copy_from_slice(payload);
        let icmp_checksum = checksum16(&packet[icmp_offset..]);
        packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
        let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn build_ipv6_icmp_echo_request(
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp_len = 8 + payload.len();
        let total_len = IPV6_HEADER_LEN + icmp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source_ip.octets());
        packet[24..40].copy_from_slice(&destination_ip.octets());
        let icmp_offset = IPV6_HEADER_LEN;
        packet[icmp_offset] = 128;
        packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&identifier.to_be_bytes());
        packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[icmp_offset + 8..].copy_from_slice(payload);
        let checksum = icmpv6_checksum(source_ip, destination_ip, &packet[icmp_offset..]);
        packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn udp_flow_routes_burst_responses_to_same_client_port() {
        metrics::init();

        let cipher = CipherKind::Chacha20IetfPoly1305;
        let password = "Secret0";
        let server = UdpBurstWsServer::start(cipher, password, 5).await;
        let uplinks = test_udp_uplink_manager(server.url(), cipher, password);

        let tun_path = temp_test_path("tun-udp-burst");
        let tun_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&tun_path)
            .expect("open test TUN output");
        let writer = SharedTunWriter::new(File::from_std(tun_file));
        let flows: FlowTable = Arc::new(Mutex::new(HashMap::new()));
        let flow_ids = Arc::new(AtomicU64::new(1));

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(203, 0, 113, 10);
        let client_port = 40123;
        let remote_port = 5300;
        forward_udp_packet(
            ParsedUdpPacket {
                version: IpVersion::V4,
                source_ip: IpAddr::V4(client_ip),
                destination_ip: IpAddr::V4(remote_ip),
                source_port: client_port,
                destination_port: remote_port,
                payload: b"probe-payload".to_vec(),
            },
            &writer,
            &uplinks,
            &flows,
            &flow_ids,
            16,
        )
        .await
        .expect("forward initial UDP packet through TUN NAT");

        let responses = wait_for_udp_packets(&tun_path, 5, Duration::from_secs(5)).await;
        assert_eq!(responses.len(), 5, "expected exactly five UDP responses");

        for (index, packet) in responses.iter().enumerate() {
            assert_eq!(packet.version, IpVersion::V4);
            assert_eq!(packet.source_ip, IpAddr::V4(remote_ip));
            assert_eq!(packet.destination_ip, IpAddr::V4(client_ip));
            assert_eq!(packet.source_port, remote_port);
            assert_eq!(
                packet.destination_port, client_port,
                "reply #{index} was not mapped back to the original client port"
            );
            assert_eq!(
                packet.payload,
                format!("reply-{index}").into_bytes(),
                "unexpected payload in reply #{index}"
            );
        }

        assert_eq!(
            server.accepted_connections(),
            1,
            "one outgoing UDP packet should create exactly one upstream flow"
        );
        assert_eq!(
            server.received_requests(),
            1,
            "test server should observe exactly one upstream UDP request"
        );

        wait_for_flow_count(&flows, 0, Duration::from_secs(5)).await;
        let _ = fs::remove_file(&tun_path);
    }

    fn test_udp_uplink_manager(url: Url, cipher: CipherKind, password: &str) -> UplinkManager {
        UplinkManager::new(
            vec![UplinkConfig {
                name: "test".to_string(),
                transport: UplinkTransport::Websocket,
                tcp_ws_url: None,
                tcp_ws_mode: WsTransportMode::Http1,
                udp_ws_url: Some(url),
                udp_ws_mode: WsTransportMode::Http1,
                tcp_addr: None,
                udp_addr: None,
                cipher,
                password: password.to_string(),
                weight: 1.0,
                fwmark: None,
                ipv6_first: false,
            }],
            ProbeConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                max_concurrent: 1,
                max_dials: 1,
                min_failures: 1,
                attempts: 1,
                ws: WsProbeConfig { enabled: false },
                http: None,
                dns: None,
            },
            LoadBalancingConfig {
                mode: LoadBalancingMode::ActiveActive,
                routing_scope: RoutingScope::PerFlow,
                sticky_ttl: Duration::from_secs(60),
                hysteresis: Duration::from_millis(0),
                failure_cooldown: Duration::from_secs(5),
                warm_standby_tcp: 0,
                warm_standby_udp: 0,
                rtt_ewma_alpha: 0.5,
                failure_penalty: Duration::from_millis(0),
                failure_penalty_max: Duration::from_millis(0),
                failure_penalty_halflife: Duration::from_secs(60),
                h3_downgrade_duration: Duration::from_secs(60),
                udp_ws_keepalive_interval: None,
                tcp_ws_standby_keepalive_interval: None,
                auto_failback: false,
            },
        )
        .expect("build test uplink manager")
    }

    fn temp_test_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}.bin",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time after epoch")
                .as_nanos()
        ))
    }

    async fn wait_for_udp_packets(
        path: &std::path::Path,
        expected: usize,
        timeout: Duration,
    ) -> Vec<ParsedUdpPacket> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(bytes) = fs::read(path)
                && let Ok(packets) = split_tun_packets(&bytes)
                && packets.len() >= expected
            {
                return packets
                    .into_iter()
                    .map(|packet| parse_udp_packet(&packet).expect("valid UDP response packet"))
                    .collect();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected} UDP packets in {}",
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_for_flow_count(flows: &FlowTable, expected: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if flows.lock().await.len() == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for flow count {expected}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn split_tun_packets(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let version = bytes
                .get(offset)
                .ok_or_else(|| anyhow!("missing IP version nibble"))?
                >> 4;
            let packet_len = match version {
                4 => {
                    if bytes.len() < offset + IPV4_HEADER_LEN {
                        bail!("short IPv4 packet in TUN capture");
                    }
                    usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]))
                }
                6 => {
                    if bytes.len() < offset + IPV6_HEADER_LEN {
                        bail!("short IPv6 packet in TUN capture");
                    }
                    IPV6_HEADER_LEN
                        + usize::from(u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]))
                }
                other => bail!("unexpected IP version in TUN capture: {other}"),
            };
            if packet_len == 0 || bytes.len() < offset + packet_len {
                bail!("truncated TUN packet capture");
            }
            packets.push(bytes[offset..offset + packet_len].to_vec());
            offset += packet_len;
        }
        Ok(packets)
    }

    struct UdpBurstWsServer {
        addr: SocketAddr,
        accepted_connections: Arc<AtomicUsize>,
        received_requests: Arc<AtomicUsize>,
    }

    impl UdpBurstWsServer {
        async fn start(cipher: CipherKind, password: &str, burst_size: usize) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("bind UDP burst WS server");
            let addr = listener.local_addr().expect("UDP burst WS server address");
            let accepted_connections = Arc::new(AtomicUsize::new(0));
            let received_requests = Arc::new(AtomicUsize::new(0));
            let master_key = cipher
                .derive_master_key(password)
                .expect("derive test UDP master key");

            let accepted_connections_task = Arc::clone(&accepted_connections);
            let received_requests_task = Arc::clone(&received_requests);
            tokio::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    accepted_connections_task.fetch_add(1, Ordering::SeqCst);
                    let master_key = master_key.clone();
                    let received_requests = Arc::clone(&received_requests_task);
                    tokio::spawn(async move {
                        let _ = handle_udp_burst_ws_connection(
                            stream,
                            cipher,
                            &master_key,
                            burst_size,
                            received_requests,
                        )
                        .await;
                    });
                }
            });

            Self {
                addr,
                accepted_connections,
                received_requests,
            }
        }

        fn url(&self) -> Url {
            Url::parse(&format!("ws://{}/udp", self.addr)).expect("valid burst server URL")
        }

        fn accepted_connections(&self) -> usize {
            self.accepted_connections.load(Ordering::SeqCst)
        }

        fn received_requests(&self) -> usize {
            self.received_requests.load(Ordering::SeqCst)
        }
    }

    async fn handle_udp_burst_ws_connection(
        stream: TcpStream,
        cipher: CipherKind,
        master_key: &[u8],
        burst_size: usize,
        received_requests: Arc<AtomicUsize>,
    ) -> Result<()> {
        let mut ws = accept_async(stream).await.context("accept websocket")?;
        while let Some(message) = ws.next().await {
            match message.context("read websocket message")? {
                Message::Binary(bytes) => {
                    received_requests.fetch_add(1, Ordering::SeqCst);
                    let payload =
                        decrypt_udp_packet(cipher, master_key, &bytes).context("decrypt UDP frame")?;
                    let (target, _) =
                        TargetAddr::from_wire_bytes(&payload).context("parse UDP target")?;
                    for index in 0..burst_size {
                        let mut response = target.to_wire_bytes().context("encode UDP target")?;
                        response.extend_from_slice(format!("reply-{index}").as_bytes());
                        let encrypted = encrypt_udp_packet(cipher, master_key, &response)
                            .context("encrypt UDP response")?;
                        ws.send(Message::Binary(encrypted.into()))
                            .await
                            .context("send UDP burst response")?;
                    }
                    ws.close(None).await.context("close websocket")?;
                    return Ok(());
                }
                Message::Ping(payload) => {
                    ws.send(Message::Pong(payload))
                        .await
                        .context("send websocket pong")?;
                }
                Message::Close(_) => return Ok(()),
                Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
        Ok(())
    }
}
