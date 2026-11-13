# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- The `tls12` build option is gone; the TLS 1.2 client is always built in.
- `config.Client` and `config.Server` take an `io`, which the libssl engine waits with; there, reads, writes and handshakes may fail with `Canceled`.
- `now` is optional in `config.Client` and `config.Server`; by default the real clock is read through `io` when a certificate is checked.
- `config.Client` and `config.Server` take `min_version` and `max_version`, and `cipher_suites` is optional; null leaves each to the engine. The libssl engine now speaks whatever AWS-LC does: TLS 1.0 to 1.3 on both sides, with AWS-LC's suites, CBC and RSA key exchange among them. The native engine refuses a suite it does not implement, and a range without a version it speaks.
- `verify_schemes` and `signing_schemes` are optional too, and TLS 1.2's SHA-1 schemes, `ecdsa_sha1` and `rsa_pkcs1_sha1`, are supported. The libssl engine takes them by default, the native one when they are listed. `config.known_signature_schemes` lists every scheme ztls implements.

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
