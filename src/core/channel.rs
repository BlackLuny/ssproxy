use std::collections::VecDeque;

use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Session,
    DirectTcpIp,
}

/// Per-channel protocol state. Byte buffers here are the *protocol* queues:
/// `in_q` holds peer data not yet handed to the application; `pending_out`
/// holds application data not yet sealed (blocked on window or rekey).
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
    pub in_q: VecDeque<Bytes>,
    pub in_q_bytes: usize,
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
            in_q_bytes: 0,
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
        }
    }

    /// Window-adjust increment to advertise, or 0 if not worth it yet.
    /// `budget_room` caps how much the window may grow this session-wide.
    pub fn window_adjust(&self, budget_room: u32) -> u32 {
        let used = self.in_q_bytes as u32;
        let target = self.recv_max.saturating_sub(used).min(self.recv_window + budget_room);
        if target <= self.recv_window {
            return 0;
        }
        let add = target - self.recv_window;
        // Only bother once we've drained a quarter (avoid a WINDOW_ADJUST storm).
        if add >= self.recv_max / 4 || self.recv_window < self.recv_max / 4 {
            add
        } else {
            0
        }
    }

    pub fn can_send(&self) -> bool {
        self.open_confirmed && !self.sent_eof && !self.sent_close && self.remote_id.is_some()
    }
}

/// Slotted channel table with a free-list and a dirty set so the driver only
/// revisits channels that have pending work.
pub struct ChannelTable {
    slots: Vec<Option<Channel>>,
    free: Vec<u32>,
    dirty: VecDeque<u32>,
    dirty_set: Vec<bool>,
    max_channels: u32,
    active: u32,
}

impl ChannelTable {
    pub fn new(max_channels: u32) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            dirty: VecDeque::new(),
            dirty_set: Vec::new(),
            max_channels,
            active: 0,
        }
    }

    pub fn active(&self) -> u32 {
        self.active
    }

    pub fn is_full(&self) -> bool {
        self.active >= self.max_channels
    }

    pub fn alloc(&mut self, mut ch: Channel) -> Option<u32> {
        if self.is_full() {
            return None;
        }
        let id = if let Some(id) = self.free.pop() {
            id
        } else {
            let id = self.slots.len() as u32;
            self.slots.push(None);
            self.dirty_set.push(false);
            id
        };
        ch.local_id = id;
        self.slots[id as usize] = Some(ch);
        self.active += 1;
        self.mark(id);
        Some(id)
    }

    pub fn get(&self, id: u32) -> Option<&Channel> {
        self.slots.get(id as usize).and_then(|c| c.as_ref())
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut Channel> {
        self.slots.get_mut(id as usize).and_then(|c| c.as_mut())
    }

    pub fn by_remote(&self, remote: u32) -> Option<u32> {
        self.slots.iter().flatten().find_map(|c| {
            (c.remote_id == Some(remote)).then_some(c.local_id)
        })
    }

    pub fn free(&mut self, id: u32) {
        if let Some(slot) = self.slots.get_mut(id as usize) {
            if slot.take().is_some() {
                self.free.push(id);
                self.active -= 1;
            }
        }
    }

    pub fn mark(&mut self, id: u32) {
        if let Some(d) = self.dirty_set.get_mut(id as usize) {
            if !*d {
                *d = true;
                self.dirty.push_back(id);
            }
        }
    }

    /// Pop the next channel needing attention.
    pub fn next_dirty(&mut self) -> Option<u32> {
        while let Some(id) = self.dirty.pop_front() {
            if let Some(d) = self.dirty_set.get_mut(id as usize) {
                *d = false;
            }
            if self.get(id).is_some() {
                return Some(id);
            }
        }
        None
    }

    pub fn ids(&self) -> Vec<u32> {
        self.slots.iter().flatten().map(|c| c.local_id).collect()
    }
}
