# 03 · 运行时与并发

## 1. 运行时选择

选 tokio，理由不是"最流行"，而是三条硬要求它都满足：

1. **需要 per-connection task**：每条连接独立取消，tokio 的 `spawn` + `AbortHandle` 是最省的表达。
2. **需要混合 IO 类型**：TCP、UDP、TUN 设备、Unix socket、命名管道、Windows 事件、信号。tokio 对前四者有原生支持，后两者用 `spawn_blocking` 或平台线程。
3. **需要和 QUIC 共存**：quinn 的 API 就是 tokio 的。

配置：

```rust
// crates/skyward-core/src/runtime.rs
pub fn build_runtime(worker_threads: Option<usize>) -> std::io::Result<tokio::runtime::Runtime> {
    let mut b = tokio::runtime::Builder::new_multi_thread();
    b.enable_all()
     .thread_name("skyward")
     .thread_keep_alive(std::time::Duration::from_secs(30));
    match worker_threads {
        Some(n) => b.worker_threads(n),
        // 移动端/低内存：1 个 worker 足够，省线程栈
        None if cfg!(feature = "low-memory") => b.worker_threads(1),
        None => b,
    }.build()
}
```

**不要**用 `#[tokio::main]`：FFI 场景下 runtime 由宿主创建，我们必须能把它传进去。

## 2. Go 并发原语的映射

| Go | Rust | 说明 |
| --- | --- | --- |
| `go f()` | `tokio::spawn(f())` | 需要 `'static + Send` |
| `chan T`（无缓冲） | `tokio::sync::mpsc::channel(1)` 或 `oneshot` | 优先 `oneshot` |
| `chan T`（有缓冲，非阻塞发送） | `mpsc::channel(n)` + `try_send` | UDP 路径必须 `try_send` |
| `chan struct{}` 关闭信号 | `tokio_util::sync::CancellationToken` | 比 `Notify` 更不易错 |
| `sync.Mutex` | `parking_lot::Mutex` | 不跨 await 持有 |
| `sync.RWMutex` | `parking_lot::RwLock` / `arc-swap` | 读多写少优先 `ArcSwap` |
| `sync.Map` | `dashmap::DashMap` / `ArcSwap<HashMap>` | 见下 |
| `sync.Once` | `std::sync::OnceLock` / `tokio::sync::OnceCell` | 异步初始化用后者 |
| `context.Context`（取消） | `CancellationToken` + 显式参数 | |
| `context.Context`（值） | 结构体字段 / `task_local!` | 不要滥用 `task_local` |
| `sync.WaitGroup` | `JoinSet` / `tokio::task::JoinSet` | |
| `atomic.Value` 存快照 | `arc_swap::ArcSwap<T>` | 核心热路径 |
| `errgroup.Group` | `futures::future::try_join_all` + `JoinSet` | |
| `select {}` | `tokio::select!` | |
| `time.AfterFunc` | `tokio::time::sleep` + `CancellationToken` | 需要注意 drop 即取消 |

**一个必须注意的差异**：Go 的 `chan` 在 sender 关闭后接收方会读到零值并结束循环；Rust 的 `mpsc::Receiver` `recv()` 返回 `None`。写迁移代码时，凡是 `for x := range ch` 都对应 `while let Some(x) = rx.recv().await`，不要用 `try_recv` 死循环。

## 3. TCP 连接的生命周期

```rust
// crates/skyward-core/src/tunnel/tcp.rs
pub async fn handle_tcp(tunnel: Arc<Tunnel>, mut conn: Box<dyn AsyncStream>, mut m: Metadata) {
    let snap = tunnel.snapshot.load_full();

    if !is_handle(&m, &snap) { return; }
    if !m.is_valid() { log::warn!(?m, "invalid metadata"); return; }

    pre_handle_metadata(&mut m, &snap).await;          // fake-ip 反查、hosts

    if snap.general.sniffing {
        if let Some(host) = sniff_tcp(&mut conn, &m, &snap).await {
            m.host = Some(host);
        }
    }

    let Some(proxy) = resolve_proxy(&m, &snap).await else { return };

    let mut cx = DialCtx::new(m.clone(), &snap);
    let upstream = match proxy.connect(cx).await {
        Ok(c) => c,
        Err(e) => { log::debug!(%e, "dial failed"); return; }
    };

    let tracker = tunnel.stats.track(&m, &upstream);
    let _ = relay::bidirectional(conn, upstream, tracker).await;
}
```

与 Go 的关键等价点：

- **判断顺序**：`isHandle → valid → preHandle → sniff → match → dial → relay`，顺序不能变，否则 fake-ip + sniff 的组合行为会漂移。
- **sniff 失败不致命**：Go 里 `preHandleFailed` 只有在 smoke 也没救回来时才放弃；Rust 版同样把"preHandle 失败"作为标志而非 `return`。
- **relay 的 half-close**：Go 的 `sing.go` 在单向拷贝结束后 `closeWrite` 而不是 `close`。Rust 用 `AsyncWrite::poll_shutdown`；对 `TcpStream` 这会发 FIN。

## 4. UDP 路径（最关键的一段）

Go 的设计：

```
HandleUDPPacket(packet)
  key = packet.Key()
  queueNo = hash(key) % len(queues)
  select { case queues[queueNo] <- pkt: default: pkt.Drop() }
```

每个 worker：

```
for pkt in queue:
   if let Some(sender) = nat.get(pkt.key()) { sender.send(pkt); continue }   // 稳态
   valid? -> preHandle -> (sniff) -> make_sender() -> nat.get_or_create(key, sender)
```

Rust 版：

```rust
// crates/skyward-core/src/tunnel/udp.rs
pub struct UdpDispatcher {
    queues: Vec<mpsc::Sender<UdpWork>>,      // 容量 256
    nat: NatTable,
}

impl UdpDispatcher {
    pub fn dispatch(&self, work: UdpWork) {
        let idx = hash_key(&work.key) as usize % self.queues.len();
        // 绝不 await：满即丢，QUIC 会把丢包当拥塞
        if self.queues[idx].try_send(work).is_err() {
            metrics::counter!("udp.queue.drop").increment(1);
        }
    }
}
```

会话对象：

```rust
pub struct UdpSession {
    sender: mpsc::Sender<Bytes>,             // 容量 128
    conn: Arc<dyn PacketConn>,
    tracker: Tracker,
    last_used: AtomicInstant,
    // 目标 NAT 映射：Go 的 packetSender.originToTarget
    mapping: Mutex<HashMap<IpAddr, IpAddr>>,
}
```

**必须保留的三个性质**：

1. 稳态不重新匹配规则（只查 NAT 表）。
2. 队列满丢包，不 backpressure。
3. 会话空闲超时（Go 默认 60s，`DefaultDropTime = 12 * 5s`）后回收；用 `tokio::time::timeout` 或惰性清理任务。

**UDP-over-TCP（UoT）** 是另一个通道：`SupportUOT()` 为真的出站（VMess/VLESS/SingMux）会把 UDP 塞进同一条 TCP 流。Rust 版把这条路径抽成 `PacketConn` 的两个实现：`DirectPacketConn`（真 UDP）与 `UotPacketConn`（帧化），NAT 表不区分。

## 5. 热重载

Go 版：`mux.Lock()` + `tunnel.OnSuspend()` → 逐模块替换 → `tunnel.OnRunning()`，期间读路径靠 `configMux.RLock()` 挡。

Rust 版用**双缓冲快照 + 版本号**：

```rust
impl Tunnel {
    pub async fn apply(&self, next: Arc<Snapshot>) -> Result<(), Error> {
        let old = self.snapshot.swap(next);
        // 旧快照交给一个延迟清理任务：等在飞的连接自然结束，
        // 而不是立刻 drop（drop 会关掉长连接池）。
        spawn_reap_old_snapshot(old);
        Ok(())
    }
}
```

细节：

- **哪些跟着快照走**：规则、出站表、provider 列表、DNS 配置、general（端口之外的通用项）。
- **哪些不跟**：NAT 表（UDP 会话必须跨重载存活，否则每个 QUIC 连接都会断）、统计计数、连接注册表。
- **端口变化**：`mixed-port` 等变化需要重建入站。这是 `ListenerManager` 的职责，不是 `Tunnel` 的。
- **失败回滚**：`config::build_snapshot` 全量构造成功后才 `swap`。构造失败时旧快照原样运行，返回错误给 API —— 这正是 Go 的 `ApplyConfig` 在 `Parse` 阶段失败时的行为。

## 6. 缓冲与内存

Go 版 `common/pool/alloc.go` 是 64B–64KB 的 11 级 `sync.Pool`。Rust 版不需要全局池，原因：

- `Bytes` / `BytesMut` 已经是引用计数的，relay 时可以直接切分。
- tokio 的 `BufReader` 有内部缓冲；我们自己只在协议编解码处用 `BytesMut`。

但有一件事必须做：**relay 的缓冲区不能每次分配**。

```rust
// crates/skyward-core/src/io/relay.rs
const BUF: usize = 32 * 1024;

pub async fn bidirectional<A, B>(a: A, b: B, tracker: Arc<Tracker>) -> std::io::Result<()>
where A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
      B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (a_r, a_w) = tokio::io::split(a);
    let (b_r, b_w) = tokio::io::split(b);

    let up   = copy_with_stats(a_r, b_w, tracker.clone(), Direction::Up);
    let down = copy_with_stats(b_r, a_w, tracker,       Direction::Down);

    // 任一方结束 -> 关闭对端写端，等另一方收尾
    let r = tokio::select! {
        x = up   => x,
        x = down => x,
    };
    r
}
```

关于 `splice(2)`：Go 版没有用 splice（`common/net/relay.go` 里的 splice 实现被整段注释掉了，用的是 sing 的 `bufio.Copy`）。Rust 版可以做，但必须**opt-in**：只有两端都是 `TcpStream` 且都在 Linux 上才走 `tokio::net::TcpStream` 的 `splice`（需要 `tokio-util` 或自写 `nix::splice`）。默认路径与 Go 一致，避免平台差异带来的行为分裂。

内存上限（对齐 Go 的 `with_low_memory` 思路）：

| 项 | 默认 | low-memory |
| --- | --- | --- |
| UDP 队列深度 | 256 | 64 |
| UDP worker 数 | max(4, cores) | 2 |
| 每会话发送队列 | 128 | 32 |
| relay 缓冲 | 32 KiB × 2 | 8 KiB × 2 |
| 嗅探预读上限 | 64 KiB | 16 KiB |
| DNS 缓存条目 | 4096 | 1024 |

## 7. 取消与超时

统一约定：

- **入站连接**：`CancellationToken` 由 listener 持有，连接 task 监听它；关闭入站即取消所有连接。
- **拨号**：`tokio::time::timeout(DEFAULT_TCP_TIMEOUT=5s, ...)` 包住 `connect`；DNS 另有自己的超时。Go 的 `DefaultDropTime = 12 * 5s` 用于 REJECT 的"假装成功然后丢弃"，Rust 版同样实现 `RejectDrop`（返回一个黑洞连接，60 秒后关）。
- **UDP 会话**：`last_used` 每包更新，清理任务每 10s 扫一遍，空闲 60s 回收。
- **健康检查**：per-provider 的 `CancellationToken`，provider 被替换时取消旧检查。
- **API WebSocket**：客户端断开即取消推送 task；不能让一个死掉的 dashboard 拖住统计任务。

## 8. 进程内可观测

- `tracing` 三层：库内用 `tracing::debug!`；FFI 层装一个 subscriber 把事件转成 Go 版同形的 `LogEvent { level, payload }`，供 `/logs` WebSocket 推送。
- 日志**必须先于 API 可用**，因为面板一连接就要历史/实时日志；Go 版用 `observable` 广播（无缓冲 channel + 订阅表），Rust 用 `tokio::sync::broadcast`（容量 1024，慢订阅者丢旧消息而不是阻塞——这与 Go 的 `logCh <- event` 阻塞行为不同，是**有意的改进**，但要写进兼容性说明）。
- 统计：`AtomicU64` 计数 + 每 1s 采样一次给 `/traffic`；连接表用 `DashMap<TrackerId, Arc<Tracker>>`。

## 9. 平台差异

| 平台 | 需要特别处理 |
| --- | --- |
| Android | FFI + JNI；`VpnService` 给出的 fd 直接包成 tokio fd；`find-process` 靠 UID（`/proc/net/*` 不可读时降级）；无 `SIGTERM`，靠显式 `shutdown()` |
| iOS | 只有 NetworkExtension 提供 `utun` fd；禁止 fork/exec；`find-process` 不可用（返回 `NotSupported`） |
| macOS | `utun` 命名规则（`utunN`）；进程查找用 `libproc`（`proc_pidpath`） |
| Windows | 命名管道（`external-controller-pipe`）、`WSAIoctl` 端口转发、进程查找用 `GetExtendedTcpTable` |
| Linux | `SO_MARK`、`SO_BINDTODEVICE`、`IP_TRANSPARENT`（tproxy）、`/proc/net` 进程查找、`netfilter` 队列 |

这些在 Go 版里散落在 `*_linux.go` / `*_windows.go` / `*_darwin.go`，Rust 版统一放 `skyward-core/src/sys/{linux,macos,windows,android}.rs`，用 `#[cfg]` 选择。

## 10. 一次 turn 里不要做的事

给后来接手的人留几条纪律，都是踩过坑的：

1. 不要在 `dispatch` 里 `await`（UDP 路径）。
2. 不要在持有 `parking_lot::Mutex` 时 `.await`（用 `tokio::sync::Mutex` 或改结构）。
3. 不要在 `Drop` 里做异步清理（用显式 `close()` + 任务）。
4. 不要让 `Arc<Snapshot>` 的生命周期超出"一次操作"：在 `handle_tcp` 里 `load_full()` 一次，之后全程用这同一个快照，**不要中途再 load** —— 否则规则与出站可能来自不同版本，Go 用 `configMux.RLock()` 保证了这点。
5. 不要在协议实现里用 `unwrap()` 解析网络数据；这是唯一的远程攻击面。
