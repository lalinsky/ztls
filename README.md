# ztls

A TLS library for Zig, built on [AWS-LC](https://github.com/aws/aws-lc)'s
libcrypto. It runs over any `std.Io.Reader` and `std.Io.Writer` and hands
back a cleartext reader and writer of the same kind, on both the client and
the server side.

It was written for servers and clients on [zio](https://github.com/lalinsky/zio),
such as [Dusty](https://github.com/lalinsky/dusty), where fibers move between
threads and a connection is read by one task and written by another. AWS-LC
does the cryptography and the X.509 work, and the protocol itself is written
in Zig.

Requires Zig 0.16 or 0.17. AWS-LC is built by the Zig build system.

## Features

- TLS 1.3 client and server per [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846).
- A TLS 1.2 client, for servers that have nothing newer: ECDHE with
  AES-GCM or ChaCha20-Poly1305 and the extended master secret, and no
  renegotiation. Older versions are refused. The `tls12` build option,
  set to false, leaves it out.
- AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
- X25519MLKEM768, X25519, P-256 and P-384 key exchange, with
  HelloRetryRequest on both sides.
- ECDSA (P-256, P-384, P-521), RSA-PSS and Ed25519 signatures.
- Server name indication, with the server's certificate picked by name.
- ALPN.
- Client certificates, requested or required.
- Certificate verification by AWS-LC's X.509 code, against a trust store
  built from PEM or DER, from files, or from the system's roots.
- KeyUpdate in both directions and close_notify.

## Using it

```sh
zig fetch --save "git+https://github.com/lalinsky/ztls"
```

```zig
const ztls = b.dependency("ztls", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("ztls", ztls.module("ztls"));
```

A server:

```zig
var pair = try ztls.CertKeyPair.fromFilePath(gpa, io, .cwd(), "chain.pem", "key.pem");
defer pair.deinit(gpa);

// The transport's reader and writer, with buffers for whole records.
var input_buffer: [ztls.input_buffer_len]u8 = undefined;
var output_buffer: [ztls.output_buffer_len]u8 = undefined;
var input = stream.reader(io, &input_buffer);
var output = stream.writer(io, &output_buffer);

var conn = try ztls.server(&input.interface, &output.interface, .{
    .allocator = gpa,
    .auth = &pair,
    .alpn_protocols = &.{ "h2", "http/1.1" },
    .now = std.Io.Clock.real.now(io),
});
defer conn.deinit(); // after both tasks are done

var read_buffer: [16 * 1024]u8 = undefined;
var reader = conn.reader(&read_buffer);
var writer = conn.writer();           // encrypts inside the transport buffer

while (try reader.interface.takeDelimiter('\n')) |line| {
    try writer.interface.print("echo: {s}\n", .{line});
    try writer.interface.flush();
}
try conn.close(); // close_notify
```

A client:

```zig
var trust = try ztls.TrustStore.init();
defer trust.deinit();
try trust.addSystemBundle(gpa, io); // or addPem(gpa, ca_pem)

var conn = try ztls.client(&input.interface, &output.interface, .{
    .allocator = gpa,
    .host = "example.com", // SNI and the name the certificate must carry
    .root_ca = &trust,
    .now = std.Io.Clock.real.now(io),
});
```

`conn.alpn_protocol` is the protocol ALPN agreed on.

### Reading and writing

After the handshake the two directions are independent: one task may read
while another writes, with no lock between them. The read side never writes
to the transport. An alert for a failure found while reading, or a KeyUpdate
the peer asked for, goes out with the next written record.

The transport buffers must hold a whole record: `input_buffer_len` for the
reader and `output_buffer_len` for the writer. The buffer given to `reader`
is an ordinary `std.Io.Reader` buffer owned by the application.
The writer has no buffer of its own and seals records inside the transport
buffer. The `Connection` must not move once readers or writers
exist.

The handshake keeps about 16 KiB on the stack of the task that runs it, plus
AWS-LC's ML-KEM working memory, so give that task at least 64 KiB of stack.
The peer's handshake messages are reassembled through the `allocator` in the
options, up to `max_handshake_message_len`.

### Errors

`std.Io.Reader` and `std.Io.Writer` only report `ReadFailed` and
`WriteFailed`. The `err` field of the ztls reader or writer has the cause:
an alert the peer sent (`TlsAlert...`), a record layer error
(`TlsBadRecordMac`, `TlsConnectionTruncated`, ...), a rejected peer
certificate under std's names (`CertificateIssuerNotFound`,
`CertificateExpired`, ...), or `ReadFailed` or `WriteFailed` when the
transport itself failed. A transport `ReadFailed`, such as a cancelled read,
does not end the connection and the read may be retried.

A transport that ends between records without close_notify is a clean end
of stream; the `strict_close_notify` option makes it an error.

### Certificates and trust

`CertKeyPair` takes a PEM chain, leaf first, and a PEM private key, from
files or from memory. `TrustStore` takes certificates from PEM or DER, from
files or directories, or from the system's root store; every certificate in
it is a trust anchor. `now` is the time certificates are checked against.
A server may hold several certificates, chosen by the
client's server name and signature algorithms, or by a `select_certificate`
callback.

## Development

```sh
zig build test                                      # 0.17, or ~/.zvm/0.16.0/zig
zig build test -fwine -Dtarget=x86_64-windows-gnu   # networking tests skip under wine
zig build test -fqemu -Dtarget=aarch64-linux-musl
```

The tests include client-server tests over a loopback socket and interoperability
with `openssl s_server` and `s_client` when OpenSSL 1.1.1 or newer is on the
PATH. `tests/bogo/run.sh` runs BoringSSL's test runner against the library;
it needs Go. Format with Zig 0.16's `zig fmt`: 0.17's rewrites builtins
that 0.16 does not accept.

`vendor/aws-lc` builds libcrypto; `gen_sources.py` there regenerates the
file lists from upstream's CMake build after an upgrade. AWS-LC's headers
reach Zig through translate-c from `src/c.h`.

## License

ztls is [MIT](LICENSE). The test keys and the example handshake in
`src/testdata` come from [tls.zig](https://github.com/ianic/tls.zig), also
MIT, which is why its author is named in the licence too.

AWS-LC is compiled into every binary that links ztls. Its code is
Apache-2.0 or ISC, with BoringSSL-derived parts under ISC and
OpenSSL-derived parts under Apache-2.0 and the original SSLeay notice;
[its LICENSE](https://github.com/aws/aws-lc/blob/main/LICENSE) has the
details. A shipped binary carries those notices along with ztls's.
