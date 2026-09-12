# ssproxy

High-performance SSH TCP-proxy daemon written in Rust. It masquerades as a modern OpenSSH server, accepts **password auth only**, and proxies `direct-tcpip` (and SOCKS via `ssh -D`) to target hosts.

The protocol core is a rustls-style sans-IO state machine: bytes in, bytes out, **no `.await`**. Tokio is only the adapter (`Future::poll` for the TCP session).

## Features

- OpenSSH interop: `ssh -W`, `ssh -D` + SOCKS
- Ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`
- KEX: `curve25519-sha256` (+ `@libssh.org`), strict-kex (Terrapin), `ext-info`
- Host key: `ssh-ed25519`
- Channel multiplexing, window flow control, small max-packet to reduce HOL
- Server-initiated rekey; FIFO write queue so control packets cannot overtake sealed `CHANNEL_DATA`

Not a full SSH server: no real shell, SFTP, or pubkey auth.

## Run

```bash
cargo run --release --bin ssproxyd -- --listen 127.0.0.1:2222 --user proxy:proxy
```

Defaults if `--user` is omitted: `proxy:proxy`. Host key is created at `ssproxy_host_ed25519` (+ `.pub`).

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -p 2222 -W example.com:443 proxy@127.0.0.1

ssh -N -D 1080 -p 2222 proxy@127.0.0.1
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

```text
ssproxyd --help
  -l, --listen       Listen address (default 0.0.0.0:2222)
  -u, --user         name:password (repeatable)
      --host-key     Ed25519 seed file
      --ident        Banner / masquerade (default SSH-2.0-OpenSSH_9.6)
      --window       Channel window bytes (default 2MiB)
      --max-packet   Max SSH packet (default 32KiB)
```

## Tests

```bash
cargo test
cargo test --test openssh -- --test-threads=1
```

Interop tests need `ssh` and `curl`.

## License

Apache-2.0 OR MIT
