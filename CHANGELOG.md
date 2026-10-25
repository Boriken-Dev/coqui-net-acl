# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `coqui-net-acl` moved out of the `coqui-access` repository into this one, with its history.
  The crate and its API are unchanged. Depend on this repository instead of
  [Boriken-Dev/coqui-access](https://github.com/Boriken-Dev/coqui-access):
  `coqui-net-acl = { git = "https://github.com/Boriken-Dev/coqui-net-acl", rev = "<commit>" }`.
  The crate is still not published to crates.io.
