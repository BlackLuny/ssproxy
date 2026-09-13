//! Reproduce russh's **inbound-window-stall / RC2 cross-channel HoL**.
//!
//! Canonical russh test: `russh/tests/test_inbound_window_stall.rs` with
//! `REPRO_BIDIR=1`, `REPRO_UPSTREAM_FREEZE_AT_SECS>0`, `REPRO_FREEZE_ONLY_CHAN=0`.
//!
//! Topology (one SSH session, many `direct-tcpip` channels):
//! - Every dest **floods downstream** (server → client) and **never reads**.
//! - Channel 0 is the **victim**: the client also floods **upstream**. The dest
//!   never drains, so the victim's inbound SSH window fills.
//! - Channels 1..N are **healthy** and **downstream-only** (client never sends).
//!
//! In russh the shared session loop parks on `reply() → chan.send().await` once
//! the victim's inbound mpsc fills, so healthy channels stop too. ssproxy is
//! sans-IO: a Pending dest write must not stop `process_in` / other dests.
//!
//! Gate: after warmup, a healthy channel that makes no progress for
//! `REPRO_STALL_SECS` is RC2 HoL — the test fails.
//!
//! Run:
//!   cargo test --release --test inbound_stall -- --nocapture
//!   REPRO_CHANNELS=64 REPRO_SECS=20 cargo test --release --test inbound_stall -- --nocapture

mod common;

use std::future::poll_fn;
use std::task::Poll;
use std::time::{Duration, Instant};

use ssproxy::config::{ClientConfig, ServerConfig};
use tokio::net::TcpStream;

use common::{spawn_flood_write_only, start_server, ClientPump};

fn env_u32(k: &str, d: u32) -> u32 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_window_stall_frozen_victim_does_not_wedge_healthy() {
    let window = env_u32("REPRO_WINDOW", 2048);
    let packet = env_u32("REPRO_PACKET", 2048);
    let num_channels = env_usize("REPRO_CHANNELS", 32);
    let duration = Duration::from_secs(env_u64("REPRO_SECS", 20));
    let stall_threshold = Duration::from_secs(env_u64("REPRO_STALL_SECS", 6));
    eprintln!(
        "repro cfg: window={window} packet={packet} channels={num_channels} \
         duration={}s stall_threshold={}s",
        duration.as_secs(),
        stall_threshold.as_secs()
    );

    let mut cfg = ServerConfig::test_config();
    cfg.window = window;
    cfg.max_packet = packet;
    cfg.max_channels = num_channels as u32 + 8;
    cfg.rekey_after_bytes = u64::MAX / 2;
    let ssh_addr = start_server(cfg).await;
    let dest = spawn_flood_write_only().await;
    tokio::time::sleep(Duration::from_millis(40)).await;

    let stream = TcpStream::connect(ssh_addr).await.unwrap();
    let mut ccfg = ClientConfig::new("proxy", "proxy");
    ccfg.window = window;
    ccfg.max_packet = packet;
    ccfg.write_buf_soft = 1024 * 1024;
    ccfg.write_buf_hard = 4 * 1024 * 1024;
    ccfg.rekey_after_bytes = u64::MAX / 2;
    let mut c = ClientPump::new(stream, ccfg);
    c.wait_handshake().await.unwrap();

    let host = dest.ip().to_string();
    let port = dest.port() as u32;
    let mut ids = Vec::with_capacity(num_channels);
    for _ in 0..num_channels {
        let id = c.conn.open_direct_tcpip(&host, port).unwrap();
        ids.push(id);
        c.wait_channel_up(id).await.unwrap();
    }
    let victim = ids[0];
    eprintln!("CLI opened {num_channels} channels; victim={victim}");

    let base = Instant::now();
    let mut last_progress_ms: Vec<u64> = vec![0; num_channels];
    let mut victim_down = 0u64;
    let mut victim_up = 0u64;
    let mut healthy_down = 0u64;
    let chunk = vec![0x5Au8; 4096];

    fn drain_ok(c: &mut ClientPump) -> Result<(), String> {
        while let Some(ev) = c.conn.pop_event() {
            if let ssproxy::Event::Disconnect { message, .. } = ev {
                return Err(message);
            }
        }
        Ok(())
    }

    // Give channels a moment to start flowing, then arm the stall clock.
    let warmup = Instant::now() + Duration::from_millis(500);
    let deadline = Instant::now() + duration;
    let mut armed = false;
    let mut last_log = Instant::now();
    let (mut last_v, mut last_h) = (0u64, 0u64);
    let mut stalled: Option<(usize, u64)> = None;

    while Instant::now() < deadline && stalled.is_none() {
        let slice = tokio::time::timeout(
            Duration::from_millis(250),
            poll_fn(|cx| -> Poll<Result<(), String>> {
                loop {
                    let io = match c.poll_io(cx) {
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(format!("ssh io: {e}")));
                        }
                        Poll::Ready(Ok(p)) => Some(p),
                        Poll::Pending => None,
                    };
                    if let Err(m) = drain_ok(&mut c) {
                        return Poll::Ready(Err(format!("disconnect: {m}")));
                    }

                    let mut progress = matches!(io, Some(true));

                    let allow = c.conn.outbound_allowance(victim);
                    if allow > 0 {
                        match c.conn.send_data(victim, &chunk[..allow.min(chunk.len())]) {
                            Ok(n) if n > 0 => {
                                victim_up += n as u64;
                                progress = true;
                            }
                            Ok(_) => {}
                            Err(e) => return Poll::Ready(Err(format!("victim send: {e}"))),
                        }
                    }

                    for (idx, &id) in ids.iter().enumerate() {
                        while let Some(d) = c.conn.peek_inbound(id) {
                            let take = d.len();
                            c.conn.consume_inbound(id, take);
                            if idx == 0 {
                                victim_down += take as u64;
                            } else {
                                healthy_down += take as u64;
                            }
                            last_progress_ms[idx] = base.elapsed().as_millis() as u64;
                            progress = true;
                        }
                    }

                    if !progress {
                        return Poll::Pending;
                    }
                }
            }),
        )
        .await;

        match slice {
            Ok(Err(e)) => panic!("session died during stall repro: {e}"),
            Ok(Ok(())) => {}
            Err(_) => {}
        }

        if !armed && Instant::now() >= warmup {
            let now = base.elapsed().as_millis() as u64;
            for t in last_progress_ms.iter_mut() {
                *t = now;
            }
            armed = true;
            eprintln!(
                "stall monitor armed: victim_down={victim_down} victim_up={victim_up} \
                 healthy_down={healthy_down}"
            );
        }

        if last_log.elapsed() >= Duration::from_secs(1) {
            last_log = Instant::now();
            let v_mbps = (victim_down - last_v) as f64 / 1_000_000.0;
            let h_mbps = (healthy_down - last_h) as f64 / 1_000_000.0;
            last_v = victim_down;
            last_h = healthy_down;
            let nowm = base.elapsed().as_millis() as u64;
            let mut worst = (usize::MAX, 0u64);
            if armed {
                for (i, p) in last_progress_ms.iter().enumerate() {
                    if i == 0 {
                        continue;
                    }
                    let idle = nowm.saturating_sub(*p);
                    if idle > worst.1 {
                        worst = (i, idle);
                    }
                }
            }
            eprintln!(
                "repro: healthy={h_mbps:.2} MB/s victim_down={v_mbps:.2} MB/s \
                 victim_up={} victim_down={victim_down} healthy_down={healthy_down}, \
                 worst HEALTHY idle: chan#{} {} ms",
                victim_up, worst.0, worst.1
            );
            if armed && worst.1 > stall_threshold.as_millis() as u64 {
                stalled = Some(worst);
                eprintln!(
                    "STALL: healthy downstream-only channel #{} made no progress for {} ms \
                     (healthy aggregate {h_mbps:.2} MB/s). A channel that sends NO upstream \
                     can only stall via the shared session loop being wedged by the victim's \
                     frozen upstream => cross-channel head-of-line blocking (RC2).",
                    worst.0, worst.1
                );
            }
        }
    }

    assert!(
        healthy_down > 1024 * 1024,
        "healthy channels transferred only {healthy_down} bytes; expected >1MiB downstream"
    );
    if let Some((ch, idle)) = stalled {
        panic!(
            "RC2 cross-channel HoL reproduced: healthy channel #{ch} idle {idle} ms \
             (victim_up={victim_up} victim_down={victim_down} healthy_down={healthy_down})"
        );
    }
}
