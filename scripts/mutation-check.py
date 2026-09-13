import sys, subprocess, os, shutil
# Mutation check for tests/regression.rs: apply one mutation per gate to a
# scratch copy of the crate and require the matching test to go RED. A gate
# that stays green under its mutation is not load-bearing.
# usage: python3 scripts/mutation-check.py [M1 M2 ...]   (run from the crate root)
import tempfile
ROOT=os.getcwd(); M=tempfile.mkdtemp(prefix="ssproxy-mut-")
for f in ("Cargo.toml","Cargo.lock"): shutil.copy(os.path.join(ROOT,f), M)
for d in ("src","examples","tests"): shutil.copytree(os.path.join(ROOT,d), os.path.join(M,d))
only=set(sys.argv[1:])
def patch(path, old, new):
    p=os.path.join(M,path); s=open(p).read(); assert s.count(old)==1, (path, old[:50]); open(p,'w').write(s.replace(old,new))
def restore():
    for d in ("src","tests"):
        shutil.rmtree(os.path.join(M,d)); shutil.copytree(os.path.join(ROOT,d), os.path.join(M,d))
muts = {
 "M1 no compaction → out_retained": ("out_retained_capacity_bounded_under_short_writes", lambda: patch("src/core/conn.rs","        self.compact_out(total);\n        let start = self.out.len();","        let start = self.out.len();")),
 "M2 EOF on closed → large_tail": ("server_channel_stream_close_preserves_large_tail", lambda: patch("src/stream.rs","            if s.to_app_eof {\n                return Poll::Ready(Ok(())); // EOF, after every queued byte","            if s.to_app_eof || s.closed {\n                return Poll::Ready(Ok(()));")),
 "M3 no termination guard → eof_wakes": ("transport_eof_wakes_channel_readers_and_writers", lambda: patch("src/driver.rs","        for sh in self.map.values() {\n            sh.lock().terminate(self.clean);\n        }","        let _ = self.clean;")),
 "M4 no FIFO gate → rekey_fifo": ("rekey_pending_precedes_fresh_data", lambda: (patch("src/core/conn.rs","        if !ch.pending_out.is_empty() {\n            // Bytes parked earlier (rekey / zero window) go first: one FIFO\n            // per channel, nothing overtakes it. `flush_pending` drains it.\n            return 0;\n        }\n",""), patch("src/core/conn.rs","ch.can_send() && !self.kex_blocks_app && ch.pending_out.is_empty(),","ch.can_send() && !self.kex_blocks_app,"))),
 "M5 no flush → buffered_transport": ("buffered_transport_flush_progress", lambda: patch("src/driver.rs","        let want_flush = !want_write && need_flush;","        let want_flush = false && need_flush;")),
 "M6 no rekey timers → timers": ("rekey_interval_and_each_kex_deadline_fire", lambda: patch("src/driver.rs","                Event::KexStarted => kex_dl.arm(Instant::now(), Some(base.kex_timeout)),\n                Event::KexDone => {\n                    kex_dl.disarm();\n                    rekey_dl.arm(Instant::now(), base.rekey_interval);\n                }","                Event::KexStarted => {}\n                Event::KexDone => kex_dl.disarm(),")),
 "M7 no window floor → admission": ("window_budget_admission_is_explicit", lambda: patch("src/core/conn.rs","        ((per_channel as u64).min(room) as u32).max(floor)","        let _ = floor;\n        (per_channel as u64).min(room) as u32")),
 "M8 no backlog retry → revisited": ("backlog_blocked_channels_are_revisited", lambda: patch("src/driver.rs","        if backlog_blocked && !s.out_blocked {\n            s.out_blocked = true;\n            chans.out_blocked.push(id);\n        }","        let _ = backlog_blocked;")),
}
for name,(test,apply) in muts.items():
    if only and name.split()[0] not in only: continue
    restore(); apply()
    r=subprocess.run(["cargo","test","--release","--test","regression",test,"--","--test-threads=1"],cwd=M,capture_output=True,text=True,env={**os.environ,"CARGO_TARGET_DIR":M+"/target"},timeout=600)
    out=r.stdout+r.stderr
    if "error[" in out or "error: could not compile" in out:
        print(f"{name}: BUILD ERROR"); print(out[-1500:]); continue
    failed = "test result: FAILED" in out or "FAILED" in out
    print(f"{name}: {'RED (test caught it)' if failed else 'GREEN — NOT LOAD-BEARING'}")
shutil.rmtree(M)
