use std::collections::HashMap;
use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Session,
    DirectTcpIp,
}

/// Per-channel protocol state. Byte buffers here are the *protocol* queues:
/// `in_q` holds peer data not yet taken by the driver; `pending_out` holds
/// application data not yet sealed (blocked on window or rekey).
pub struct Channel {
    pub local_id: u32,
    pub remote_id: Option<u32>,
    pub kind: ChannelKind,
    /// Peer's receive window (how much we may still send).
    pub send_window: u32,
    /// Our receive window (how much the peer may still send).
    pub recv_window: u32,
    pub recv_max: u32,
    pub peer_max_packet: u32,
    pub local_max_packet: u32,
    /// Peer bytes not yet handed out (`take_inbound` / `inbound_front`).
    pub in_q: VecDeque<Bytes>,
    /// Bytes received from the peer that the application has not consumed
    /// yet — the credit ledger's `Q + P` (`in_q`, plus everything handed out
    /// but not yet reported back through `consume_credit`). Window credit is
    /// re-offered from this, so handing a chunk to the application does not
    /// by itself return any credit.
    pub unacked: usize,
    pub pending_out: VecDeque<Bytes>,
    pub pending_out_bytes: usize,
    pub open_confirmed: bool,
    pub got_eof: bool,
    pub sent_eof: bool,
    pub wire_eof: bool,
    pub got_close: bool,
    pub sent_close: bool,
    pub wire_close: bool,
    pub host: Option<String>,
    pub port: u16,
    /// Queued in the table's dirty list.
    pub dirty: bool,
}

impl Channel {
    pub fn new(
        kind: ChannelKind,
        recv_window: u32,
        local_max_packet: u32,
        send_window: u32,
        peer_max_packet: u32,
    ) -> Self {
        Self {
            local_id: 0,
            remote_id: None,
            kind,
            send_window,
            recv_window,
            recv_max: recv_window,
            peer_max_packet,
            local_max_packet,
            in_q: VecDeque::new(),
            unacked: 0,
            pending_out: VecDeque::new(),
            pending_out_bytes: 0,
            open_confirmed: false,
            got_eof: false,
            sent_eof: false,
            wire_eof: false,
            got_close: false,
            sent_close: false,
            wire_close: false,
            host: None,
            port: 0,
            dirty: false,
        }
    }

    /// Window-adjust step: credit is offered back in units of this many
    /// bytes (1/16 of the window). Small enough that a peer parked on a full
    /// window resumes early; coarse enough that adjusts stay rare.
    pub fn credit_step(&self) -> usize {
        (self.recv_max / 16) as usize
    }

    /// Window-adjust increment to advertise, or 0 if not worth it yet.
    ///
    /// Credit is restored to `recv_max - unacked`: everything the peer sent
    /// that the application has consumed. That is replenishment, not growth —
    /// `recv_max` is fixed when the channel opens — so it must not be gated on
    /// any session-level allowance. Throttling it here (an earlier
    /// `min(recv_window + budget_room)` did exactly that) wedges the channel:
    /// once the window hits zero with an exhausted allowance, no adjust is ever
    /// produced again and the peer waits forever.
    pub fn window_adjust(&self) -> u32 {
        let used = self.unacked.min(u32::MAX as usize) as u32;
        let target = self.recv_max.saturating_sub(used);
        if target <= self.recv_window {
            return 0;
        }
        let add = target - self.recv_window;
        // Advertise in small steps. This is not about bandwidth (an adjust is
        // ~30 bytes) but about *when* the peer may send again: a peer that
        // parks on a read once its own buffer fills wakes on the first adjust,
        // so a coarse step leaves it idle while we drain a whole quarter
        // window. Measured with such a peer, 64 KiB steps (1/16 of the default
        // 1 MiB window) nearly double single-stream throughput versus 256 KiB
        // steps; going finer than 1/16 buys nothing further.
        let step = self.recv_max / 16;
        if add >= step || self.recv_window < step {
            add
        } else {
            0
        }
    }

    /// May the application still hand us new data for this channel?
    pub fn can_send(&self) -> bool {
        self.can_write() && !self.sent_eof && !self.sent_close
    }

    /// May bytes still go on the wire? True even after EOF/CLOSE were *marked*:
    /// those only stop new application data, and the peer has not seen the
    /// marker yet, so anything already buffered must still be flushed ahead of
    /// it (RFC 4254 §5.3 — data precedes the close).
    pub fn can_write(&self) -> bool {
        self.open_confirmed && self.remote_id.is_some()
    }
}

/// Channel table keyed by local id, with a dirty list so the driver only
/// revisits channels that have protocol-side work.
///
/// Ids are handed out monotonically and never reused while the process runs
/// (wrap-around at 2^32 skips live ids). A freed slot that were reused right
/// away could be confused with its predecessor by a driver that still holds
/// the old channel's application state: a CLOSE and a fresh OPEN can land in
/// one read, before the driver has looked at either.
pub struct ChannelTable {
    map: HashMap<u32, Channel>,
    next_id: u32,
    dirty: VecDeque<u32>,
    max_channels: u32,
}

impl ChannelTable {
    pub fn new(max_channels: u32) -> Self {
        Self {
            map: HashMap::new(),
            next_id: 0,
            dirty: VecDeque::new(),
            max_channels,
        }
    }

    pub fn active(&self) -> u32 {
        self.map.len() as u32
    }

    pub fn is_full(&self) -> bool {
        self.active() >= self.max_channels
    }

    pub fn alloc(&mut self, mut ch: Channel) -> Option<u32> {
        if self.is_full() {
            return None;
        }
        let mut id = self.next_id;
        while self.map.contains_key(&id) {
            id = id.wrapping_add(1);
        }
        self.next_id = id.wrapping_add(1);
        ch.local_id = id;
        self.map.insert(id, ch);
        self.mark(id);
        Some(id)
    }

    pub fn get(&self, id: u32) -> Option<&Channel> {
        self.map.get(&id)
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Channel> {
        self.map.get_mut(&id)
    }

    pub fn free(&mut self, id: u32) {
        self.map.remove(&id);
    }

    pub fn mark(&mut self, id: u32) {
        if let Some(ch) = self.map.get_mut(&id) {
            if !ch.dirty {
                ch.dirty = true;
                self.dirty.push_back(id);
            }
        }
    }

    /// Pop the next channel needing attention.
    pub fn next_dirty(&mut self) -> Option<u32> {
        while let Some(id) = self.dirty.pop_front() {
            if let Some(ch) = self.map.get_mut(&id) {
                ch.dirty = false;
                return Some(id);
            }
        }
        None
    }

    pub fn ids(&self) -> Vec<u32> {
        self.map.keys().copied().collect()
    }
}
