# coqui-net-acl

An ordered, first-match access control list over source networks, for any listener, with or
without TLS. Rules are read top to bottom, the first match wins, and a default action (deny
unless set) applies when none does. It can be evaluated before the first byte is read and again
after a handshake with the verified peer fingerprint.

The crate is not published to crates.io; depend on it by git revision:

```toml
coqui-net-acl = { git = "https://github.com/Boriken-Dev/coqui-net-acl", rev = "<commit>" }
```

The API reference is under [Rust API](https://boriken-dev.github.io/coqui-net-acl/rust/index.html).
The source, the API header (`AGENTS.md`) and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-net-acl).
