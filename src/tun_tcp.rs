use std::collections::{HashMap, VecDeque};
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle, Thread};
use std::time::{Duration, Instant};

use anyhow::{Context as AnyhowContext, Result, anyhow, bail};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::TunTcpConfig;
use crate::metrics;
use crate::transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use crate::tun::SharedTunWriter;
use crate::types::{TargetAddr, UplinkTransport};
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

const DEFAULT_TCP_SEND_BUFFER_SIZE: usize = 0x4000 * 4;
const DEFAULT_TCP_RECV_BUFFER_SIZE: usize = 0x4000 * 4;
const MIN_PENDING_LOCAL_HANDSHAKES: usize = 32;
const MAX_PENDING_LOCAL_HANDSHAKES: usize = 128;
const FLOW_CLOSE_REASON_FINISHED: &str = "finished";
const FLOW_CLOSE_REASON_CONNECT_FAILED: &str = "connect_failed";
const FLOW_CLOSE_REASON_IO_ERROR: &str = "io_error";
const FLOW_CLOSE_REASON_EVICTED: &str = "evicted";

#[derive(Clone)]
pub struct TunTcpEngine {
    inner: Arc<TunTcpEngineInner>,
}

struct TunTcpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: tokio::sync::Mutex<HashMap<TcpFlowKey, TcpFlowHandle>>,
    max_flows: usize,
    idle_timeout: Duration,
    tcp: TunTcpConfig,
    manager_socket_creation_tx: mpsc::UnboundedSender<TcpSocketCreation>,
    manager_notify: Arc<ManagerNotify>,
    manager_running: Arc<AtomicBool>,
    rx_queue: Arc<StdMutex<VecDeque<Vec<u8>>>>,
    manager_handle: StdMutex<Option<JoinHandle<()>>>,
}

impl Drop for TunTcpEngineInner {
    fn drop(&mut self) {
        self.manager_running.store(false, Ordering::Relaxed);
        self.manager_notify.notify();
        if let Some(handle) = self
            .manager_handle
            .lock()
            .expect("manager_handle poisoned")
            .take()
        {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    client: SocketAddr,
    remote: SocketAddr,
}

#[derive(Clone)]
struct TcpFlowHandle {
    uplink_name: Arc<StdMutex<Option<String>>>,
    created_at: Instant,
    last_activity_at: Arc<StdMutex<Instant>>,
    task_abort_handle: Arc<StdMutex<Option<tokio::task::AbortHandle>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    _buffers: TcpSocketBuffers,
    send_buffer: VecDeque<u8>,
    send_capacity: usize,
    send_waker: Option<Waker>,
    recv_buffer: VecDeque<u8>,
    recv_capacity: usize,
    recv_waker: Option<Waker>,
    established: bool,
    established_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
}

type SharedTcpConnectionControl = Arc<StdMutex<TcpSocketControl>>;

struct TcpSocketBuffers {
    recv_ptr: *mut u8,
    recv_len: usize,
    send_ptr: *mut u8,
    send_len: usize,
}

unsafe impl Send for TcpSocketBuffers {}

impl Drop for TcpSocketBuffers {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.recv_ptr,
                self.recv_len,
            )));
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
                self.send_ptr,
                self.send_len,
            )));
        }
    }
}

struct TcpSocketCreation {
    control: SharedTcpConnectionControl,
    socket: TcpSocket<'static>,
    socket_created_tx: oneshot::Sender<()>,
}

struct TcpConnection {
    control: SharedTcpConnectionControl,
    manager_notify: Arc<ManagerNotify>,
}

struct ManagerNotify {
    thread: Thread,
}

impl ManagerNotify {
    fn new(thread: Thread) -> Self {
        Self { thread }
    }

    fn notify(&self) {
        self.thread.unpark();
    }
}

struct VirtDevice {
    capabilities: DeviceCapabilities,
    rx_queue: Arc<StdMutex<VecDeque<Vec<u8>>>>,
    tx_packets_tx: mpsc::UnboundedSender<Vec<u8>>,
}

struct VirtRxToken {
    packet: Vec<u8>,
}

struct VirtTxToken {
    tx_packets_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl VirtDevice {
    fn recv_available(&self) -> bool {
        !self.rx_queue.lock().expect("rx_queue poisoned").is_empty()
    }
}

impl Device for VirtDevice {
    type RxToken<'a>
        = VirtRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.lock().expect("rx_queue poisoned").pop_front()?;
        Some((
            VirtRxToken { packet },
            VirtTxToken {
                tx_packets_tx: self.tx_packets_tx.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtTxToken {
            tx_packets_tx: self.tx_packets_tx.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

impl RxToken for VirtRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

impl TxToken for VirtTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        let _ = self.tx_packets_tx.send(packet);
        result
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut control = self.control.lock().expect("tcp control poisoned");
        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }
        self.manager_notify.notify();
    }
}

impl TcpConnection {
    async fn new(
        socket: TcpSocket<'static>,
        buffers: TcpSocketBuffers,
        socket_creation_tx: &mpsc::UnboundedSender<TcpSocketCreation>,
        manager_notify: Arc<ManagerNotify>,
        send_capacity: usize,
        recv_capacity: usize,
    ) -> Self {
        let control = Arc::new(StdMutex::new(TcpSocketControl {
            _buffers: buffers,
            send_buffer: VecDeque::with_capacity(send_capacity),
            send_capacity,
            send_waker: None,
            recv_buffer: VecDeque::with_capacity(recv_capacity),
            recv_capacity,
            recv_waker: None,
            established: false,
            established_waker: None,
            recv_state: TcpSocketState::Normal,
            send_state: TcpSocketState::Normal,
        }));
        let (socket_created_tx, socket_created_rx) = oneshot::channel();
        let _ = socket_creation_tx.send(TcpSocketCreation {
            control: Arc::clone(&control),
            socket,
            socket_created_tx,
        });
        let _ = socket_created_rx.await;
        Self {
            control,
            manager_notify,
        }
    }

    async fn wait_established(&self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut control = self.control.lock().expect("tcp control poisoned");
            if control.established {
                return Poll::Ready(Ok(()));
            }
            if matches!(control.recv_state, TcpSocketState::Closed)
                || matches!(control.send_state, TcpSocketState::Closed)
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "smoltcp connection closed before establishment",
                )));
            }
            control.established_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock().expect("tcp control poisoned");
        if control.recv_buffer.is_empty() {
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Poll::Ready(Ok(()));
            }
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone())
                && !old_waker.will_wake(cx.waker())
            {
                old_waker.wake();
            }
            return Poll::Pending;
        }

        let recv_buf =
            unsafe { mem::transmute::<&mut [mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut()) };
        let count = recv_buf.len().min(control.recv_buffer.len());
        for slot in recv_buf.iter_mut().take(count) {
            *slot = control.recv_buffer.pop_front().expect("recv_buffer length checked");
        }
        buf.advance(count);
        if count > 0 {
            self.manager_notify.notify();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpConnection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let mut control = self.control.lock().expect("tcp control poisoned");
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        let available = control.send_capacity.saturating_sub(control.send_buffer.len());
        if available == 0 {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone())
                && !old_waker.will_wake(cx.waker())
            {
                old_waker.wake();
            }
            return Poll::Pending;
        }

        let written = available.min(data.len());
        control.send_buffer.extend(data[..written].iter().copied());
        if written > 0 {
            self.manager_notify.notify();
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self.control.lock().expect("tcp control poisoned");
        if matches!(
            control.send_state,
            TcpSocketState::Closing | TcpSocketState::Closed
        ) {
            return Poll::Ready(Ok(()));
        }
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }
        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone())
            && !old_waker.will_wake(cx.waker())
        {
            old_waker.wake();
        }
        self.manager_notify.notify();
        Poll::Pending
    }
}

impl TunTcpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        uplinks: UplinkManager,
        max_flows: usize,
        idle_timeout: Duration,
        mtu: usize,
        tcp: TunTcpConfig,
    ) -> Self {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu;
        capabilities.checksum.ipv4 = Checksum::Tx;
        capabilities.checksum.tcp = Checksum::Tx;
        capabilities.checksum.udp = Checksum::Tx;
        capabilities.checksum.icmpv4 = Checksum::Tx;
        capabilities.checksum.icmpv6 = Checksum::Tx;

        let rx_queue = Arc::new(StdMutex::new(VecDeque::new()));
        let (tx_packets_tx, tx_packets_rx) = mpsc::unbounded_channel();
        let device = VirtDevice {
            capabilities,
            rx_queue: Arc::clone(&rx_queue),
            tx_packets_tx: tx_packets_tx.clone(),
        };

        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();

        let mut device_for_iface = device;
        let mut iface = Interface::new(
            iface_config,
            &mut device_for_iface,
            SmolInstant::from_millis(0),
        );
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .expect("default IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .expect("default IPv6 route");
        iface.set_any_ip(true);

        let (manager_socket_creation_tx, manager_socket_creation_rx) = mpsc::unbounded_channel();
        let manager_running = Arc::new(AtomicBool::new(true));
        let manager_handle = {
            let manager_running = Arc::clone(&manager_running);
            let manager_started_at = std::time::Instant::now();
            thread::Builder::new()
                .name("outline-tun-smoltcp".to_owned())
                .spawn(move || {
                    let mut socket_storage = std::iter::repeat_with(SocketStorage::default)
                        .take(max_flows.max(1))
                        .collect::<Vec<_>>();
                    let mut socket_set = SocketSet::new(socket_storage.as_mut_slice());
                    let mut sockets: HashMap<SocketHandle, SharedTcpConnectionControl> = HashMap::new();
                    let mut device = device_for_iface;
                    let mut iface = iface;
                    let mut socket_creation_rx = manager_socket_creation_rx;

                    while manager_running.load(Ordering::Relaxed) {
                        while let Ok(TcpSocketCreation {
                            control,
                            socket,
                            socket_created_tx,
                        }) = socket_creation_rx.try_recv()
                        {
                            let handle = socket_set.add(socket);
                            let _ = socket_created_tx.send(());
                            sockets.insert(handle, control);
                        }

                        let now = smol_now(manager_started_at);
                        let _ = iface.poll(now, &mut device, &mut socket_set);

                        let mut sockets_to_remove = Vec::new();
                        for (&socket_handle, control) in &sockets {
                            let socket = socket_set.get_mut::<TcpSocket<'_>>(socket_handle);
                            let mut control = control.lock().expect("tcp control poisoned");

                            if socket.state() == TcpState::Established && !control.established {
                                control.established = true;
                                if let Some(waker) = control.established_waker.take() {
                                    waker.wake();
                                }
                            }

                            if socket.state() == TcpState::Closed {
                                sockets_to_remove.push(socket_handle);
                                control.send_state = TcpSocketState::Closed;
                                control.recv_state = TcpSocketState::Closed;
                                if let Some(waker) = control.established_waker.take() {
                                    waker.wake();
                                }
                                if let Some(waker) = control.send_waker.take() {
                                    waker.wake();
                                }
                                if let Some(waker) = control.recv_waker.take() {
                                    waker.wake();
                                }
                                continue;
                            }

                            let mut wake_writer = false;

                            if matches!(control.send_state, TcpSocketState::Close)
                                && socket.send_queue() == 0
                                && control.send_buffer.is_empty()
                            {
                                socket.close();
                                control.send_state = TcpSocketState::Closing;
                                wake_writer = true;
                            }

                            let mut wake_reader = false;
                            while socket.can_recv() && control.recv_buffer.len() < control.recv_capacity {
                                let available = control.recv_capacity - control.recv_buffer.len();
                                let result = socket.recv(|buffer| {
                                    let count = available.min(buffer.len());
                                    (count, buffer[..count].to_vec())
                                });
                                match result {
                                    Ok(bytes) => {
                                        if bytes.is_empty() {
                                            break;
                                        }
                                        control.recv_buffer.extend(bytes);
                                        wake_reader = true;
                                    }
                                    Err(err) => {
                                        debug!(error = ?err, state = ?socket.state(), "smoltcp recv failed");
                                        socket.abort();
                                        control.recv_state = TcpSocketState::Closed;
                                        wake_reader = true;
                                        break;
                                    }
                                }
                            }

                            if matches!(control.recv_state, TcpSocketState::Normal)
                                && !socket.may_recv()
                                && !matches!(
                                    socket.state(),
                                    TcpState::Listen
                                        | TcpState::SynReceived
                                        | TcpState::Established
                                        | TcpState::FinWait1
                                        | TcpState::FinWait2
                                )
                            {
                                control.recv_state = TcpSocketState::Closed;
                                wake_reader = true;
                            }

                            if wake_reader && let Some(waker) = control.recv_waker.take() {
                                waker.wake();
                            }

                            while socket.can_send() && !control.send_buffer.is_empty() {
                                let queued: Vec<u8> = control.send_buffer.iter().copied().collect();
                                let result = socket.send(|buffer| {
                                    let count = buffer.len().min(queued.len());
                                    buffer[..count].copy_from_slice(&queued[..count]);
                                    (count, count)
                                });
                                match result {
                                    Ok(sent) => {
                                        for _ in 0..sent {
                                            let _ = control.send_buffer.pop_front();
                                        }
                                        wake_writer = true;
                                        if sent == 0 {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        debug!(error = ?err, state = ?socket.state(), "smoltcp send failed");
                                        socket.abort();
                                        control.send_state = TcpSocketState::Closed;
                                        wake_writer = true;
                                        break;
                                    }
                                }
                            }

                            if wake_writer && let Some(waker) = control.send_waker.take() {
                                waker.wake();
                            }
                        }

                        for socket_handle in sockets_to_remove {
                            sockets.remove(&socket_handle);
                            socket_set.remove(socket_handle);
                        }

                        if !device.recv_available() {
                            let next_duration = iface
                                .poll_delay(now, &socket_set)
                                .unwrap_or(SmolDuration::from_millis(5));
                            if next_duration != SmolDuration::ZERO {
                                thread::park_timeout(Duration::from(next_duration));
                            }
                        }
                    }
                })
                .expect("failed to spawn smoltcp manager thread")
        };

        let manager_notify = Arc::new(ManagerNotify::new(manager_handle.thread().clone()));
        let engine = Self {
            inner: Arc::new(TunTcpEngineInner {
                writer,
                uplinks,
                flows: tokio::sync::Mutex::new(HashMap::new()),
                max_flows,
                idle_timeout,
                tcp,
                manager_socket_creation_tx,
                manager_notify,
                manager_running,
                rx_queue,
                manager_handle: StdMutex::new(Some(manager_handle)),
            }),
        };
        engine.spawn_writer_task(tx_packets_rx);
        engine.spawn_cleanup_loop();
        engine
    }

    pub async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        let parsed = parse_syn_packet(packet)?;
        if let Some((key, remote_addr)) = parsed {
            self.ensure_flow(key, remote_addr).await?;
        }

        self.inner
            .rx_queue
            .lock()
            .expect("rx_queue poisoned")
            .push_back(packet.to_vec());
        self.inner.manager_notify.notify();
        Ok(())
    }

    fn spawn_writer_task(&self, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
        let writer = self.inner.writer.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let ip_family = packet
                    .first()
                    .map(|byte| match byte >> 4 {
                        4 => "ipv4",
                        6 => "ipv6",
                        _ => "unknown",
                    })
                    .unwrap_or("unknown");
                if let Err(error) = writer.write_packet(&packet).await {
                    metrics::record_tun_packet("upstream_to_tun", ip_family, "error");
                    warn!(error = %format!("{error:#}"), "failed to write smoltcp packet to TUN");
                } else {
                    metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_forwarded");
                }
            }
        });
    }

    fn spawn_cleanup_loop(&self) {
        let inner = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let Some(inner) = inner.upgrade() else {
                    break;
                };
                TunTcpEngine { inner }.cleanup_idle_flows().await;
            }
        });
    }

    async fn ensure_flow(&self, key: TcpFlowKey, remote_addr: SocketAddr) -> Result<()> {
        {
            let flows = self.inner.flows.lock().await;
            if flows.contains_key(&key) {
                return Ok(());
            }
            if flows.len() >= self.inner.max_flows {
                bail!("TUN TCP flow table limit reached");
            }
            let pending_local_handshake_limit =
                (self.inner.max_flows / 32).clamp(MIN_PENDING_LOCAL_HANDSHAKES, MAX_PENDING_LOCAL_HANDSHAKES);
            let pending_local_handshakes = flows
                .values()
                .filter(|handle| {
                    handle
                        .uplink_name
                        .lock()
                        .expect("uplink_name poisoned")
                        .is_none()
                })
                .count();
            if pending_local_handshakes >= pending_local_handshake_limit {
                warn!(
                    client = %key.client,
                    remote = %remote_addr,
                    pending_local_handshakes,
                    max_pending_local_handshakes = pending_local_handshake_limit,
                    "dropping new TUN TCP flow while too many local smoltcp handshakes are pending"
                );
                bail!("too many pending local smoltcp TCP handshakes");
            }
        }

        let send_capacity = self
            .inner
            .tcp
            .max_pending_server_bytes
            .clamp(DEFAULT_TCP_SEND_BUFFER_SIZE, 1 << 20);
        let recv_capacity = self
            .inner
            .tcp
            .max_pending_server_bytes
            .clamp(DEFAULT_TCP_RECV_BUFFER_SIZE, 1 << 20);

        let recv_storage = vec![0u8; recv_capacity].into_boxed_slice();
        let recv_len = recv_storage.len();
        let recv_ptr = Box::into_raw(recv_storage) as *mut u8;
        let recv_storage: &'static mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(recv_ptr, recv_len) };
        let send_storage = vec![0u8; send_capacity].into_boxed_slice();
        let send_len = send_storage.len();
        let send_ptr = Box::into_raw(send_storage) as *mut u8;
        let send_storage: &'static mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(send_ptr, send_len) };
        let mut socket = TcpSocket::new(
            TcpSocketBuffer::new(recv_storage),
            TcpSocketBuffer::new(send_storage),
        );
        socket.set_timeout(Some(SmolDuration::from_secs(
            self.inner.idle_timeout.as_secs().max(1),
        )));
        if let Err(error) = socket.listen(key.remote) {
            return Err(anyhow!("smoltcp listen error for {}: {:?}", key.remote, error));
        }

        let connection = TcpConnection::new(
            socket,
            TcpSocketBuffers {
                recv_ptr,
                recv_len,
                send_ptr,
                send_len,
            },
            &self.inner.manager_socket_creation_tx,
            Arc::clone(&self.inner.manager_notify),
            send_capacity,
            recv_capacity,
        )
        .await;

        let flow = TcpFlowHandle {
            uplink_name: Arc::new(StdMutex::new(None)),
            created_at: Instant::now(),
            last_activity_at: Arc::new(StdMutex::new(Instant::now())),
            task_abort_handle: Arc::new(StdMutex::new(None)),
        };
        self.inner.flows.lock().await.insert(key.clone(), flow.clone());
        metrics::add_tun_tcp_flows_active("pending", 1);
        metrics::record_tun_tcp_event("pending", "created");
        info!(
            client = %key.client,
            remote = %remote_addr,
            send_capacity,
            recv_capacity,
            max_flows = self.inner.max_flows,
            "TUN TCP flow created"
        );

        let engine = self.clone();
        let task_abort_handle = Arc::clone(&flow.task_abort_handle);
        let task = tokio::spawn(async move {
            let result = engine.bridge_flow(key.clone(), remote_addr, connection, flow.clone()).await;
            let close_reason = match result {
                Ok(()) => FLOW_CLOSE_REASON_FINISHED,
                Err(error) => {
                    warn!(
                        client = %key.client,
                        remote = %remote_addr,
                        error = %format!("{error:#}"),
                        "TUN TCP flow failed"
                    );
                    if format!("{error:#}").contains("all TCP uplinks failed") {
                        FLOW_CLOSE_REASON_CONNECT_FAILED
                    } else {
                        FLOW_CLOSE_REASON_IO_ERROR
                    }
                }
            };
            engine.close_flow(&key, close_reason, false).await;
        });
        *task_abort_handle
            .lock()
            .expect("task_abort_handle poisoned") = Some(task.abort_handle());

        Ok(())
    }

    async fn bridge_flow(
        &self,
        key: TcpFlowKey,
        remote_addr: SocketAddr,
        connection: TcpConnection,
        flow: TcpFlowHandle,
    ) -> Result<()> {
        let local_handshake_timeout = self.inner.tcp.handshake_timeout;
        debug!(
            client = %key.client,
            remote = %remote_addr,
            handshake_timeout_ms = local_handshake_timeout.as_millis(),
            "waiting for local smoltcp TCP handshake"
        );
        timeout(local_handshake_timeout, connection.wait_established())
            .await
            .context("timed out waiting for local smoltcp TCP handshake")?
            .context("local smoltcp TCP handshake failed")?;
        info!(
            client = %key.client,
            remote = %remote_addr,
            "local smoltcp TCP handshake established"
        );
        metrics::add_tun_tcp_async_connects_active(1);
        metrics::record_tun_tcp_async_connect("started");
        let connect_deadline = self.inner.tcp.connect_timeout + self.inner.tcp.handshake_timeout;
        debug!(
            client = %key.client,
            remote = %remote_addr,
            connect_deadline_ms = connect_deadline.as_millis(),
            "connecting TUN TCP uplink"
        );
        let ((candidate, mut upstream_writer, mut upstream_reader), uplink_name) = timeout(
            connect_deadline,
            async {
                let target = ip_to_target(remote_addr.ip(), remote_addr.port());
                let (candidate, writer, reader) =
                    select_tcp_candidate_and_connect(&self.inner.uplinks, &target).await?;
                Ok::<_, anyhow::Error>(((candidate.clone(), writer, reader), candidate.uplink.name.clone()))
            },
        )
        .await
        .context("timed out while connecting TUN TCP uplink")??;
        metrics::add_tun_tcp_async_connects_active(-1);
        metrics::record_tun_tcp_async_connect("success");
        metrics::add_tun_tcp_flows_active("pending", -1);
        metrics::add_tun_tcp_flows_active(&uplink_name, 1);
        metrics::record_tun_tcp_event(&uplink_name, "connected");
        info!(
            client = %key.client,
            remote = %remote_addr,
            uplink = %uplink_name,
            connect_timeout_ms = self.inner.tcp.connect_timeout.as_millis(),
            handshake_timeout_ms = self.inner.tcp.handshake_timeout.as_millis(),
            "TUN TCP uplink connected"
        );
        *flow.uplink_name.lock().expect("uplink_name poisoned") = Some(uplink_name.clone());
        let connected_at = Instant::now();
        *flow
            .last_activity_at
            .lock()
            .expect("last_activity_at poisoned") = connected_at;

        let (mut client_reader, mut client_writer) = tokio::io::split(connection);
        let uplinks = self.inner.uplinks.clone();
        let candidate_index = candidate.index;
        let is_direct_shadowsocks = candidate.uplink.transport == UplinkTransport::Shadowsocks;
        let uploaded_bytes_shared = Arc::new(AtomicUsize::new(0));
        let downloaded_bytes_shared = Arc::new(AtomicUsize::new(0));
        let uplink_for_upload = uplink_name.clone();
        let uplinks_for_upload = uplinks.clone();
        let activity_for_upload = Arc::clone(&flow.last_activity_at);
        let uploaded_bytes_for_upload = Arc::clone(&uploaded_bytes_shared);
        let client_for_upload = key.client;
        let remote_for_upload = remote_addr;
        let upload = async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut uploaded_bytes = 0usize;
            loop {
                let read = client_reader
                    .read(&mut buf)
                    .await
                    .context("failed reading from smoltcp TCP stream")?;
                if read == 0 {
                    if uploaded_bytes == 0 && is_direct_shadowsocks {
                        warn!(
                            client = %client_for_upload,
                            remote = %remote_for_upload,
                            uplink = %uplink_for_upload,
                            uploaded_bytes,
                            "client side reached EOF before any payload on direct Shadowsocks flow"
                        );
                    } else {
                        info!(
                            client = %client_for_upload,
                            remote = %remote_for_upload,
                            uplink = %uplink_for_upload,
                            uploaded_bytes,
                            "client side reached EOF, closing upstream TCP writer"
                        );
                    }
                    if let Err(error) = upstream_writer.close().await {
                        uplinks_for_upload
                            .report_runtime_failure(candidate_index, TransportKind::Tcp, &error)
                            .await;
                        return Err(error)
                            .context("failed closing upstream TCP writer after client EOF");
                    }
                    break;
                }
                *activity_for_upload
                    .lock()
                    .expect("last_activity_at poisoned") = Instant::now();
                metrics::add_bytes("tcp", "client_to_upstream", &uplink_for_upload, read);
                uploaded_bytes += read;
                uploaded_bytes_for_upload.store(uploaded_bytes, Ordering::Relaxed);
                if uploaded_bytes == read {
                    info!(
                        client = %client_for_upload,
                        remote = %remote_for_upload,
                        uplink = %uplink_for_upload,
                        first_chunk_bytes = read,
                        "first client TCP payload forwarded upstream"
                    );
                }
                if let Err(error) = upstream_writer.send_chunk(&buf[..read]).await {
                    uplinks_for_upload
                        .report_runtime_failure(candidate_index, TransportKind::Tcp, &error)
                        .await;
                    return Err(error).context("failed sending TCP payload upstream");
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        let uplink_for_download = uplink_name.clone();
        let uplinks_for_download = uplinks.clone();
        let activity_for_download = Arc::clone(&flow.last_activity_at);
        let downloaded_bytes_for_download = Arc::clone(&downloaded_bytes_shared);
        let half_close_timeout = self.inner.tcp.half_close_timeout;
        let client_for_download = key.client;
        let remote_for_download = remote_addr;
        let download = async move {
            let mut downloaded_bytes = 0usize;
            loop {
                let chunk = match upstream_reader.read_chunk().await {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        uplinks_for_download
                            .report_runtime_failure(candidate_index, TransportKind::Tcp, &error)
                            .await;
                        return Err(error).context("failed reading TCP payload from upstream");
                    }
                };
                if chunk.is_empty() {
                    if downloaded_bytes == 0 && is_direct_shadowsocks {
                        warn!(
                            client = %client_for_download,
                            remote = %remote_for_download,
                            uplink = %uplink_for_download,
                            downloaded_bytes,
                            half_close_timeout_ms = half_close_timeout.as_millis(),
                            "direct Shadowsocks upstream reached EOF before sending any payload"
                        );
                    } else {
                        info!(
                            client = %client_for_download,
                            remote = %remote_for_download,
                            uplink = %uplink_for_download,
                            downloaded_bytes,
                            half_close_timeout_ms = half_close_timeout.as_millis(),
                            "upstream side reached EOF, shutting down client TCP writer"
                        );
                    }
                    timeout(half_close_timeout, client_writer.shutdown())
                        .await
                        .context("timed out shutting down client TCP stream")?
                        .context("failed shutting down client TCP stream")?;
                    break;
                }
                *activity_for_download
                    .lock()
                    .expect("last_activity_at poisoned") = Instant::now();
                metrics::add_bytes("tcp", "upstream_to_client", &uplink_for_download, chunk.len());
                downloaded_bytes += chunk.len();
                downloaded_bytes_for_download.store(downloaded_bytes, Ordering::Relaxed);
                if downloaded_bytes == chunk.len() {
                    info!(
                        client = %client_for_download,
                        remote = %remote_for_download,
                        uplink = %uplink_for_download,
                        first_chunk_bytes = chunk.len(),
                        "first upstream TCP payload forwarded to client"
                    );
                }
                client_writer
                    .write_all(&chunk)
                    .await
                    .context("failed writing upstream TCP payload into smoltcp stream")?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let (upload_result, download_result) =
            if is_direct_shadowsocks {
                let first_byte_timeout = self.inner.tcp.connect_timeout;
                let transfer = async {
                    tokio::join!(upload, download)
                };
                tokio::pin!(transfer);
                tokio::select! {
                    results = &mut transfer => results,
                    _ = tokio::time::sleep(first_byte_timeout) => {
                        let uploaded_bytes = uploaded_bytes_shared.load(Ordering::Relaxed);
                        let downloaded_bytes = downloaded_bytes_shared.load(Ordering::Relaxed);
                        if uploaded_bytes == 0 && downloaded_bytes == 0 {
                            let error = anyhow!("no TUN TCP progress after uplink connect");
                            uplinks
                                .report_runtime_failure(candidate_index, TransportKind::Tcp, &error)
                                .await;
                            return Err(error).context("TUN TCP flow stalled before first payload");
                        }
                        if uploaded_bytes > 0 && downloaded_bytes == 0 {
                            let error = anyhow!("no upstream TCP response after client payload");
                            uplinks
                                .report_runtime_failure(candidate_index, TransportKind::Tcp, &error)
                                .await;
                            return Err(error)
                                .context("TUN TCP flow stalled waiting for first upstream payload");
                        }
                        (&mut transfer).await
                    }
                }
            } else {
                tokio::join!(upload, download)
            };
        upload_result?;
        download_result?;
        let uploaded_bytes = uploaded_bytes_shared.load(Ordering::Relaxed);
        let downloaded_bytes = downloaded_bytes_shared.load(Ordering::Relaxed);
        metrics::record_tun_tcp_event(&uplink_name, "closed");
        info!(
            client = %key.client,
            remote = %remote_addr,
            uplink = %uplink_name,
            transport = ?candidate.uplink.transport,
            uploaded_bytes,
            downloaded_bytes,
            lifetime_ms = flow.created_at.elapsed().as_millis(),
            "TUN TCP flow closed cleanly"
        );
        Ok(())
    }

    async fn cleanup_idle_flows(&self) {
        let now = Instant::now();
        let mut stale = Vec::new();
        {
            let flows = self.inner.flows.lock().await;
            for (key, handle) in flows.iter() {
                let last_activity_at = *handle
                    .last_activity_at
                    .lock()
                    .expect("last_activity_at poisoned");
                if now.duration_since(last_activity_at) > self.inner.idle_timeout * 2 {
                    stale.push(key.clone());
                }
            }
        }
        for key in stale {
            info!(
                client = %key.client,
                remote = %key.remote,
                idle_timeout_ms = self.inner.idle_timeout.as_millis(),
                "evicting idle TUN TCP flow"
            );
            self.close_flow(&key, FLOW_CLOSE_REASON_EVICTED, true)
                .await;
        }
    }

    async fn close_flow(&self, key: &TcpFlowKey, reason: &'static str, abort_task: bool) {
        let removed = self.inner.flows.lock().await.remove(key);
        let Some(handle) = removed else {
            return;
        };

        if abort_task
            && let Some(task_abort_handle) = handle
                .task_abort_handle
                .lock()
                .expect("task_abort_handle poisoned")
                .take()
        {
            task_abort_handle.abort();
        }

        let uplink_name = handle
            .uplink_name
            .lock()
            .expect("uplink_name poisoned")
            .clone()
            .unwrap_or_else(|| "pending".to_string());
        metrics::add_tun_tcp_flows_active(&uplink_name, -1);
        metrics::record_tun_tcp_flow_closed(
            &uplink_name,
            reason,
            Instant::now().saturating_duration_since(handle.created_at),
        );
        metrics::record_tun_tcp_event(&uplink_name, reason);
        info!(
            client = %key.client,
            remote = %key.remote,
            uplink = %uplink_name,
            reason,
            lifetime_ms = handle.created_at.elapsed().as_millis(),
            "TUN TCP flow closed"
        );
    }
}

fn parse_syn_packet(packet: &[u8]) -> Result<Option<(TcpFlowKey, SocketAddr)>> {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        bail!("empty TCP packet");
    };

    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).map_err(|err| anyhow!("invalid IPv4 packet: {err:?}"))?;
            let tcp = TcpPacket::new_checked(ip.payload()).map_err(|err| anyhow!("invalid TCP packet: {err:?}"))?;
            let client = SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port());
            let remote = SocketAddr::new(IpAddr::V4(ip.dst_addr()), tcp.dst_port());
            if tcp.syn() && !tcp.ack() {
                return Ok(Some((TcpFlowKey { client, remote }, remote)));
            }
            Ok(None)
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).map_err(|err| anyhow!("invalid IPv6 packet: {err:?}"))?;
            let tcp = TcpPacket::new_checked(ip.payload()).map_err(|err| anyhow!("invalid TCP packet: {err:?}"))?;
            let client = SocketAddr::new(IpAddr::V6(ip.src_addr()), tcp.src_port());
            let remote = SocketAddr::new(IpAddr::V6(ip.dst_addr()), tcp.dst_port());
            if tcp.syn() && !tcp.ack() {
                return Ok(Some((TcpFlowKey { client, remote }, remote)));
            }
            Ok(None)
        }
        _ => bail!("unsupported IP version {}", version),
    }
}

async fn select_tcp_candidate_and_connect(
    uplinks: &UplinkManager,
    target: &TargetAddr,
) -> Result<(UplinkCandidate, TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let mut last_error = None;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
    let mut failed_uplink: Option<String> = None;

    loop {
        let candidates = uplinks.tcp_candidates(target).await;
        if candidates.is_empty() {
            break;
        }

        let mut progressed = false;
        for candidate in candidates {
            if failed_uplink
                .as_ref()
                .is_some_and(|failed| failed == &candidate.uplink.name)
            {
                continue;
            }
            progressed = true;
            match connect_tcp_uplink(uplinks, &candidate, target).await {
                Ok((writer, reader)) => {
                    uplinks
                        .confirm_selected_uplink(TransportKind::Tcp, Some(target), candidate.index)
                        .await;
                    if let Some(from_uplink) = failed_uplink.take() {
                        metrics::record_failover("tcp", &from_uplink, &candidate.uplink.name);
                        info!(
                            from_uplink,
                            to_uplink = %candidate.uplink.name,
                            remote = %target,
                            "runtime TCP failover activated for TUN flow"
                        );
                    }
                    return Ok((candidate, writer, reader));
                }
                Err(error) => {
                    uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                        .await;
                    if failed_uplink.is_none() {
                        failed_uplink = Some(candidate.uplink.name.clone());
                    }
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                }
            }
        }
        if !strict_transport || !progressed {
            break;
        }
    }

    Err(anyhow!(
        "all TCP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no uplinks available".to_string())
    ))
}

async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "tun_tcp",
        )
        .await?;
        return do_tcp_ss_setup_socket(stream, &candidate.uplink, target).await;
    }

    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target).await {
            Ok(v) => return Ok(v),
            Err(error) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{error:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            }
        }
    }

    let ws = uplinks.connect_tcp_ws_fresh(candidate, "tun_tcp").await?;
    do_tcp_ss_setup(ws, &candidate.uplink, target).await
}

async fn do_tcp_ss_setup(
    ws_stream: crate::transport::AnyWsStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    use futures_util::StreamExt;

    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt().map(|salt| salt.to_vec());
    let reader =
        TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        remote = %target,
        transport = "websocket_shadowsocks",
        "sent Shadowsocks target address upstream for TUN TCP flow"
    );
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: tokio::net::TcpStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt().map(|salt| salt.to_vec()));
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        remote = %target,
        transport = "direct_shadowsocks",
        "sent Shadowsocks target address upstream for TUN TCP flow"
    );
    Ok((writer, reader))
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(addr) => TargetAddr::IpV4(addr, port),
        IpAddr::V6(addr) => TargetAddr::IpV6(addr, port),
    }
}

fn smol_now(started_at: std::time::Instant) -> SmolInstant {
    let elapsed = started_at.elapsed();
    let millis = elapsed.as_millis().min(i64::MAX as u128) as i64;
    SmolInstant::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::sync::atomic::AtomicBool;

    use crate::config::{
        LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TunTcpConfig,
        UplinkConfig, WsProbeConfig,
    };
    use crate::metrics;
    use crate::types::{CipherKind, UplinkTransport, WsTransportMode};

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    fn test_uplink_manager() -> UplinkManager {
        UplinkManager::new(
            vec![UplinkConfig {
                name: "test".to_string(),
                transport: UplinkTransport::Websocket,
                tcp_ws_url: None,
                tcp_ws_mode: WsTransportMode::Http1,
                udp_ws_url: None,
                udp_ws_mode: WsTransportMode::Http1,
                tcp_addr: None,
                udp_addr: None,
                cipher: CipherKind::Aes256Gcm,
                password: "password".to_string(),
                weight: 1.0,
                fwmark: None,
                ipv6_first: false,
            }],
            ProbeConfig {
                interval: Duration::from_secs(60),
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
                mode: LoadBalancingMode::ActivePassive,
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
        .expect("test uplink manager")
    }

    fn test_engine(idle_timeout: Duration) -> TunTcpEngine {
        let tun_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null for test TUN writer");
        let (manager_socket_creation_tx, _manager_socket_creation_rx) = mpsc::unbounded_channel();
        TunTcpEngine {
            inner: Arc::new(TunTcpEngineInner {
                writer: SharedTunWriter::new(tokio::fs::File::from_std(tun_file)),
                uplinks: test_uplink_manager(),
                flows: tokio::sync::Mutex::new(HashMap::new()),
                max_flows: 16,
                idle_timeout,
                tcp: TunTcpConfig {
                    connect_timeout: Duration::from_secs(1),
                    handshake_timeout: Duration::from_secs(1),
                    half_close_timeout: Duration::from_secs(1),
                    max_pending_server_bytes: DEFAULT_TCP_SEND_BUFFER_SIZE,
                },
                manager_socket_creation_tx,
                manager_notify: Arc::new(ManagerNotify::new(thread::current())),
                manager_running: Arc::new(AtomicBool::new(false)),
                rx_queue: Arc::new(StdMutex::new(VecDeque::new())),
                manager_handle: StdMutex::new(None),
            }),
        }
    }

    #[tokio::test]
    async fn cleanup_idle_flows_aborts_background_task() {
        metrics::init();

        let engine = test_engine(Duration::from_secs(1));
        let key = TcpFlowKey {
            client: "127.0.0.1:12345".parse().expect("client addr"),
            remote: "1.1.1.1:443".parse().expect("remote addr"),
        };
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_task = Arc::clone(&dropped);
        let (started_tx, started_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _drop_signal = DropSignal(dropped_for_task);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("background task started");
        let flow = TcpFlowHandle {
            uplink_name: Arc::new(StdMutex::new(Some("pending".to_string()))),
            created_at: Instant::now() - Duration::from_secs(5),
            last_activity_at: Arc::new(StdMutex::new(Instant::now() - Duration::from_secs(3))),
            task_abort_handle: Arc::new(StdMutex::new(Some(task.abort_handle()))),
        };
        engine.inner.flows.lock().await.insert(key, flow);
        drop(task);

        engine.cleanup_idle_flows().await;
        tokio::task::yield_now().await;

        assert!(
            dropped.load(Ordering::Relaxed),
            "idle TUN TCP cleanup must abort the background flow task"
        );
        assert!(
            engine.inner.flows.lock().await.is_empty(),
            "idle TUN TCP cleanup must remove the flow from the table"
        );
    }
}
