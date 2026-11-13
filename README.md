# ztls

A TLS library for Zig, built on [AWS-LC](https://github.com/aws/aws-lc).
It works on top of any `std.Io.Reader` and `std.Io.Writer`, and gives you a
cleartext reader and writer in return. It has a client and a server.

There are two engines with the same API, and you pick one at build time.
The native engine implements the TLS protocol in Zig and uses AWS-LC's
libcrypto for cryptography and certificate verification. The libssl engine
wraps AWS-LC's libssl.

Requires Zig 0.16 or 0.17. AWS-LC is built by the Zig build system.

## The native engine

ztls was written for servers and clients on [zio](https://github.com/lalinsky/zio),
such as [Dusty](https://github.com/lalinsky/dusty). There, fibers move
between threads, and one task often reads a connection while another writes
to it.

libssl does not fit this well. It wants to call the transport itself, and a
fiber must not block inside C code. A wrapper has to feed libssl through
memory buffers, which copies every byte. Both directions also share one
libssl object, so the reading and writing tasks need a lock.

The native engine avoids all of this. Reading and writing are independent.
Records are decrypted directly into the reader's buffer, and can be
encrypted in place in the transport's buffer. C code never waits for I/O.
It also doesn't need a C++ runtime.

## The libssl engine

Build with `-Dimpl=libssl`, or pass `.impl = .libssl` to the dependency.
This engine wraps libssl, AWS-LC's TLS implementation, which it shares with
BoringSSL. It is a fallback for compatibility, and for when you prefer code
with more real-world use.

## Features

- TLS 1.3 client and server ([RFC 9846](https://www.rfc-editor.org/rfc/rfc9846)).
- TLS 1.2 client: ECDHE with AES-GCM or ChaCha20-Poly1305, extended master
  secret, no renegotiation. Build with `-Dtls12=false` to leave it out.
  Older versions are not supported.
- AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
- X25519MLKEM768, X25519, P-256 and P-384 key exchange, with
  HelloRetryRequest.
- ECDSA (P-256, P-384, P-521), RSA-PSS and Ed25519 signatures.
- Server name indication. A server can choose its certificate by name.
- ALPN.
- Client certificates.
- Certificate verification with AWS-LC, against roots from PEM, DER, files
  or the system store.
- KeyUpdate and close_notify.

## Using it

```sh
zig fetch --save "git+https://github.com/lalinsky/ztls#v0.1.0"
```

```zig
const ztls = b.dependency("ztls", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("ztls", ztls.module("ztls"));
```

A server:

```zig
var pair = try ztls.CertKeyPair.fromFilePath(gpa, io, .cwd(), "chain.pem", "key.pem");
defer pair.deinit(gpa);

// The transport's reader and writer. Their buffers must fit a whole record.
var input_buffer: [ztls.input_buffer_len]u8 = undefined;
var output_buffer: [ztls.output_buffer_len]u8 = undefined;
var input = stream.reader(io, &input_buffer);
var output = stream.writer(io, &output_buffer);

var conn = try ztls.server(&input.interface, &output.interface, .{
    .gpa = gpa,
    .auth = &pair,
    .alpn_protocols = &.{ "h2", "http/1.1" },
    .now = std.Io.Clock.real.now(io),
});
defer conn.deinit(); // after both tasks are done

var read_buffer: [16 * 1024]u8 = undefined;
var write_buffer: [16 * 1024]u8 = undefined;
var reader = conn.reader(&read_buffer);
var writer = conn.writer(&write_buffer);

while (try reader.interface.takeDelimiter('\n')) |line| {
    try writer.interface.print("echo: {s}\n", .{line});
    try writer.interface.flush();
}
try writer.close(); // sends close_notify
```

A client:

```zig
var trust = try ztls.TrustStore.init();
defer trust.deinit();
try trust.addSystemBundle(gpa, io); // or addPem(gpa, ca_pem)

var conn = try ztls.client(&input.interface, &output.interface, .{
    .gpa = gpa,
    .host = "example.com", // sent as SNI, and checked against the certificate
    .root_ca = &trust,
    .now = std.Io.Clock.real.now(io),
});
```

After the handshake, `conn.alpn_protocol` holds the protocol agreed through
ALPN.

### Reading and writing

One task can read while another writes. The read side never writes to the
transport. If reading fails, the alert is sent by the next write. A
KeyUpdate requested by the peer is answered the same way.

The transport buffers must be at least `input_buffer_len` and
`output_buffer_len` bytes. The `Connection` must not move after you create
a reader or writer.

The reader and writer buffers belong to the application. The reader's
buffer decides how far ahead you can peek, for example to see a whole HTTP
header. A record carries at most 16 KiB, so a writer buffer larger than
that doesn't help.

With the native engine, `conn.writerInPlace()` avoids one copy. It writes
your data directly into the transport buffer, where the record is
encrypted. This has a few rules. Don't replace the writer's buffer. Close
with `writer.close()`, not `conn.close()`. The transport writer must not
touch its unused capacity while it sends, which is true of std's and zio's
socket writers.

The handshake needs about 64 KiB of stack. `gpa` is used only during the
handshake, unless you set `keep_peer_certificates`. Then the peer's
certificates are kept in `conn.peer_certificates`, and `gpa` must stay
valid until `conn.deinit()`.

### Errors

`std.Io.Reader` and `std.Io.Writer` only return `ReadFailed` and
`WriteFailed`. The ztls reader and writer have an `err` field with the
real cause. It can be an alert from the peer (`TlsAlert...`), a record
error (`TlsBadRecordMac`, `TlsConnectionTruncated`, ...), a rejected
certificate (`CertificateIssuerNotFound`, `CertificateExpired`, ...), or
`ReadFailed` or `WriteFailed` from the transport.

A transport error doesn't end the connection. You can retry a read. After a
failed write, the data that was already encrypted is sent with the next
flush. If a write is cancelled, you can still call `close` from a `defer`
with cancellation blocked. Flush first if you want to keep what is still in
the writer's buffer.

If the transport ends between records without close_notify, the reader
sees a normal end of stream. Set `strict_close_notify` to treat it as an
error.

### Certificates

`CertKeyPair` loads a PEM certificate chain (leaf first) and a PEM private
key, from files or memory. `TrustStore` loads trusted certificates from
PEM or DER files, directories, or the system store. `now` is the time used
to check certificates. A server can have several certificates, and picks
one by the client's server name and signature algorithms, or with a
`select_certificate` callback.

## Testing

- Unit tests.
- Client-server tests over loopback, for both engines.
- Interoperability tests with OpenSSL's `s_server` and `s_client` and with
  Go's `crypto/tls`, as client and server, for both engines.

The native engine is also tested with:

- [BoGo](https://boringssl.googlesource.com/boringssl/+/HEAD/ssl/test/),
  BoringSSL's test runner, as client and server. Tests for unsupported
  features, such as session resumption or 0-RTT, are disabled in
  `tests/bogo/config.json`.
- [tlsfuzzer](https://github.com/tlsfuzzer/tlsfuzzer)'s TLS 1.3 scripts, as
  server. Skipped scripts are listed in `tests/tlsfuzzer/run.sh`.
- [TLS-Anvil](https://github.com/tls-attacker/TLS-Anvil), as server.
- `tools/survey/run.sh`, which connects to sites from the
  [Chrome UX Report](https://github.com/zakird/crux-top-lists) top million
  over TLS 1.3 and 1.2, and compares the result with OpenSSL. We ran it on
  the top 10,000 sites and on a random 5,000. About 10% of the servers that
  answered only support TLS 1.2, which is why the client supports it too.
  ztls connects to about 99% of the servers that answered. The rest need
  CBC cipher suites or RSA key exchange, which ztls doesn't support.

## Development

```sh
zig build test                                      # 0.17, or ~/.zvm/0.16.0/zig
zig build test -Dimpl=libssl
zig build test -fwine -Dtarget=x86_64-windows-gnu   # networking tests skip under wine
zig build test -fqemu -Dtarget=aarch64-linux-musl
```

The OpenSSL and Go tests run if OpenSSL 1.1.1 or newer and Go are on the
PATH. `tests/bogo/run.sh` runs BoGo and needs Go. `tests/tlsfuzzer/run.sh`
runs tlsfuzzer and needs Python 3. Format with Zig 0.16's `zig fmt`,
because 0.17's renames builtins that 0.16 doesn't accept.

`-Dasm=false` builds AWS-LC's portable C code instead of its assembly. It
builds faster the first time, and on x86_64 Windows it doesn't need NASM.

`vendor/aws-lc` builds AWS-LC. After an upgrade, run `gen_sources.py`
there to regenerate the file lists from upstream's CMake build.

## License

ztls is [MIT](LICENSE). The test keys and the example handshake in
`src/testdata` come from [tls.zig](https://github.com/ianic/tls.zig), also
MIT, so its author is named in the license too.

AWS-LC is compiled into every binary that uses ztls. Its code is under
Apache-2.0 or ISC. Parts that come from BoringSSL are ISC, and parts that
come from OpenSSL are Apache-2.0 with the original SSLeay notice. See
[its LICENSE](https://github.com/aws/aws-lc/blob/main/LICENSE) for
details. A binary you ship must include those notices as well as ztls's.
