use std::collections::VecDeque;

use bytes::Bytes;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelKind {
    Session,
    DirectTcpIp,
}

pub struct Channel {
    pub local_id: u32,
    pub remote_id: Option<u32>,
    pub kind: ChannelKind,
    pub send_window: u32,
    pub recv_window: u32,
    pub recv_max: u32,
    pub max_remote_packet: u32,
    pub max_local_packet: u32,
    pub in_q: VecDeque<Bytes>,
    pub in_q_bytes: usize,
    pub pending_out: VecDeque<Bytes>,
    pub pending_out_bytes: usize,
    pub got_eof: bool,
    pub sent_eof: bool,
    pub wire_eof: bool,
    pub got_close: bool,
    pub sent_close: bool,
    pub wire_close: bool,
    pub open_confirmed: bool,
    pub host: Option<String>,
    pub port: u32,
}

impl Channel {
    pub fn new(
        local_id: u32,
        kind: ChannelKind,
        window: u32,
        max_packet: u32,
        send_window: u32,
        max_remote_packet: u32,
    ) -> Self {
        Self {
            local_id,
            remote_id: None,
            kind,
            send_window,
            recv_window: window,
            recv_max: window,
            max_remote_packet,
            max_local_packet: max_packet,
            in_q: VecDeque::new(),
            in_q_bytes: 0,
            pending_out: VecDeque::new(),
            pending_out_bytes: 0,
            got_eof: false,
            sent_eof: false,
            wire_eof: false,
            got_close: false,
            sent_close: false,
            wire_close: false,
            open_confirmed: false,
            host: None,
            port: 0,
        }
    }

    pub fn push_in(&mut self, data: Bytes) -> Result<()> {
        let n = data.len() as u32;
        if n > self.recv_window {
            return Err(Error::protocol("channel window exceeded"));
        }
        self.recv_window -= n;
        self.in_q_bytes += data.len();
        self.in_q.push_back(data);
        Ok(())
    }

    pub fn pop_in(&mut self) -> Option<Bytes> {
        let b = self.in_q.pop_front()?;
        self.in_q_bytes = self.in_q_bytes.saturating_sub(b.len());
        Some(b)
    }

    pub fn window_adjust_amount(&self) -> u32 {
        let used = self.in_q_bytes as u32;
        let allowed = self.recv_max.saturating_sub(used);
        if allowed <= self.recv_window {
            return 0;
        }
        let add = allowed - self.recv_window;
        if add >= self.recv_max / 8 || self.recv_window < self.recv_max / 4 {
            add
        } else {
            0
        }
    }

    pub fn outbound_allowance(&self) -> usize {
        if !self.open_confirmed || self.sent_eof || self.sent_close {
            return 0;
        }
        let w = self.send_window as usize;
        let p = self.max_remote_packet as usize;
        w.min(p)
    }

    pub fn fully_dead(&self) -> bool {
        self.got_close && self.sent_close
    }
}

pub struct ChannelTable {
    slots: Vec<Option<Channel>>,
    free: Vec<u32>,
    pub max_channels: u32,
}

impl ChannelTable {
    pub fn new(max_channels: u32) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            max_channels,
        }
    }

    pub fn alloc(&mut self, ch: Channel) -> Result<u32> {
        let id = if let Some(id) = self.free.pop() {
            id
        } else {
            if self.slots.len() as u32 >= self.max_channels {
                return Err(Error::protocol("too many channels"));
            }
            let id = self.slots.len() as u32;
            self.slots.push(None);
            id
        };
        let mut ch = ch;
        ch.local_id = id;
        self.slots[id as usize] = Some(ch);
        Ok(id)
    }

    pub fn get(&self, id: u32) -> Result<&Channel> {
        self.slots
            .get(id as usize)
            .and_then(|c| c.as_ref())
            .ok_or(Error::protocol("no such channel"))
    }

    pub fn get_mut(&mut self, id: u32) -> Result<&mut Channel> {
        self.slots
            .get_mut(id as usize)
            .and_then(|c| c.as_mut())
            .ok_or(Error::protocol("no such channel"))
    }

    pub fn by_remote(&self, remote: u32) -> Option<u32> {
        self.slots.iter().find_map(|s| {
            s.as_ref().and_then(|c| {
                if c.remote_id == Some(remote) {
                    Some(c.local_id)
                } else {
                    None
                }
            })
        })
    }

    pub fn free(&mut self, id: u32) {
        if let Some(slot) = self.slots.get_mut(id as usize) {
            if slot.take().is_some() {
                self.free.push(id);
            }
        }
    }

    pub fn iter_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref().map(|c| c.local_id))
    }

    pub fn len_active(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}
