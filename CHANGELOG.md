# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- A certificate without DNS subject alternative names is now matched against the host by its subject common name, as OpenSSL and libpq do. Self-signed certificates made with only a common name, such as those in PostgreSQL's documentation, are accepted. A certificate that has DNS names is still matched against those only.

## [0.2.0] - 2026-11-14

This release adds an optional engine based on AWS-LC's libssl. Build with `-Dimpl=libssl` to use it with the same ztls API. It supports TLS 1.0 through 1.3 as both client and server, including CBC suites and RSA key exchange. The native engine remains the default and is faster; the libssl engine provides broader compatibility and requires a C++ runtime.

- `config.Client` and `config.Server` now require `io`. The libssl engine uses it to wait for its connection lock without blocking a thread. With this engine, reads, writes and handshakes can return `Canceled`.
- `now` is optional. When omitted, certificate verification reads the current time through `io`.
- Added `min_version` and `max_version` to the client and server options. These and `cipher_suites` can be left as null to use the engine's defaults. The native engine rejects unsupported cipher suites and version ranges.
- `verify_schemes` and `signing_schemes` are now optional and use the engine's defaults. Added the TLS 1.2 schemes `ecdsa_sha1` and `rsa_pkcs1_sha1`: libssl enables them by default, while the native engine requires them to be explicitly listed. `config.known_signature_schemes` lists all supported schemes.
- Added `Connection.keyUpdatesSent` and `Connection.keyUpdatesReceived` to count KeyUpdate messages.
- Removed the `tls12` build option. The native TLS 1.2 client is now always included.
- On x86_64 Windows, `asm` now defaults to false, so builds no longer need NASM. Use `-Dasm=true` to enable AWS-LC's assembly.
- Invalid configurations are rejected before the handshake starts, including group lists with no usable key exchange group and native server configurations with no TLS 1.3 cipher suite.
- Fixed the native client advertising secp521r1 for key exchange, which it does not implement. TLS 1.2 connections can still use P-521 certificates when secp521r1 is listed.
- The native engine now accepts empty handshake records after the handshake. It also handles `close_notify` or transport EOF during a post-handshake message as a clean shutdown, unless `strict_close_notify` requires a truncation error. NewSessionTicket messages larger than the greater of 16 KiB and `max_handshake_message_len` are rejected with `illegal_parameter`.
- Fixed KeyUpdate handling in the native engine. If a peer's update request is pending when `requestKeyUpdate` is called, both updates are sent as required by RFC 8446 §4.6.3. A transport failure during `requestKeyUpdate` no longer discards the pending request.

Interoperability tests, API tests and tlsfuzzer now run against both engines. BoGo and TLS-Anvil continue to test the native engine.

## [0.1.0] - 2026-11-11

The first release. ztls is a TLS library for Zig on AWS-LC's libcrypto, for clients and servers on `std.Io` readers and writers, with independent read and write directions for one task reading while another writes.

- TLS 1.3 client and server, and a TLS 1.2 client for servers that have nothing newer (ECDHE with AES-GCM or ChaCha20-Poly1305 and the extended master secret). The `tls12` build option leaves the TLS 1.2 client out.
- AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; X25519MLKEM768, X25519, P-256 and P-384 key exchange, with HelloRetryRequest on both sides.
- ECDSA, RSA-PSS and Ed25519 signatures; certificate verification by AWS-LC's X.509 code against a trust store built from PEM or DER, from files, or from the system's roots.
- Server name indication, with the server's certificate picked by name or by a callback, ALPN, and client certificates, requested or required.
- KeyUpdate in both directions and close_notify. Writers have `requestKeyUpdate` and `close`.
- A cleartext reader and writer that are ordinary `std.Io.Reader` and `std.Io.Writer`, plus an in-place writer that encrypts inside the transport buffer. A transport failure, such as a cancelled read or write, does not end the connection: the operation may be retried, and a `defer` under cancel protection can still close cleanly.
- Session resumption, 0-RTT, a TLS 1.2 server, CBC suites and RSA key exchange are left out.

Tested with BoGo, tlsfuzzer and TLS-Anvil, against OpenSSL and Go's `crypto/tls`, and with a survey of real servers: the Chrome UX Report's top 10,000 sites and 5,000 more drawn at random from its list.
