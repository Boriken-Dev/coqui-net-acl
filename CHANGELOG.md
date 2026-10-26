# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coqui-net-acl`: an ordered access control list for network listeners. `Acl` holds `Rule`s
  (action, source, destination, port, peer fingerprint, log hint) read top to bottom, then a
  default (`Deny` unless set). `decide` answers at accept time and defers a rule that names a
  fingerprint; `decide_peer` finishes the decision after the handshake; `permits_bind` is
  advisory; `weakened` reports a `permit` default.
- `IpNet` and `PortRange` with `FromStr`/`Display`; an IPv4-mapped IPv6 address is the IPv4
  address it maps. `Display` on `Acl` prints a router-style listing.
- The `serde` feature: a TOML-friendly text form (`default`, `[[rule]]`) that refuses unknown
  keys. A default build has no dependencies and no `unsafe` code.
- Not published to crates.io; depend on it by git revision:
  `coqui-net-acl = { git = "https://github.com/Boriken-Dev/coqui-net-acl", rev = "<commit>" }`.
