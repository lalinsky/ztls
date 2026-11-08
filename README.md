# ztls

A TLS 1.3 library for Zig, built on [AWS-LC](https://github.com/aws/aws-lc)'s
libcrypto. It speaks TLS 1.3 only, on both the client and the server side,
over any `std.Io.Reader` and `std.Io.Writer`, and hands back a cleartext
reader and writer of the same kind.

It exists for servers and clients on [zio](https://github.com/lalinsky/zio),
such as [Dusty](https://github.com/lalinsky/dusty), where fibers may move
between threads and a connection is read by one task and written by another.
Everything cryptographic, X.509 included, is AWS-LC's; the protocol is Zig.

Requires Zig 0.16 or 0.17. AWS-LC is built by the Zig build system, with no
CMake, Perl or Go.

## What it does

- TLS 1.3 client and server (RFC 8446), with no TLS 1.2.
- AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305.
- X25519MLKEM768, X25519, P-256 and P-384 key exchange, with
  HelloRetryRequest on both sides.
- ECDSA (P-256, P-384, P-521), RSA-PSS and Ed25519 signatures.
- Server name indication, with the server's certificate picked by name;
  ALPN; client certificates, requested or required.
- Certificate verification through AWS-LC's X.509 code, against a trust
  store the application builds from PEM or DER bytes. ztls never reads a
  file itself.
- KeyUpdate in both directions; close_notify; precise errors.

Not yet: session resumption, 0-RTT, post-handshake client authentication.
A peer that only speaks TLS 1.2 gets a protocol_version alert.

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
var pair = try ztls.CertKeyPair.fromSlice(gpa, chain_pem, key_pem);
defer pair.deinit();

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
defer conn.deinit(); // after both tasks are done; sends nothing

var reader = conn.reader(&read_buffer); // a plain reader buffer, yours
var writer = conn.inPlaceWriter();      // writes land where they are sealed

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
_ = try trust.addSystemBundle(gpa, io); // or addPem(gpa, ca_pem)

var conn = try ztls.client(&input.interface, &output.interface, .{
    .allocator = gpa,
    .host = "example.com", // SNI and the name the certificate must carry
    .root_ca = &trust,
    .now = std.Io.Clock.real.now(io),
});
```

`conn.alpn_protocol` is what ALPN agreed on, pointing into your own list.

### Reading and writing

After the handshake the two directions are independent: one task may read
through `reader` while another writes through `writer` or `inPlaceWriter`,
with no lock between them. The read side never writes to the transport. An
alert for a failure found while reading, or a KeyUpdate the peer asked for,
goes out with the write side's next record.

The transport reader's buffer must hold a whole record
(`input_buffer_len`), the writer's a whole sealed record
(`output_buffer_len`). The buffer given to `reader` is an ordinary
`std.Io.Reader` buffer that the application owns and may swap at any time;
records are decrypted straight into it when it has room, otherwise in place
in the transport buffer and handed out in pieces. `inPlaceWriter` has no
buffer of its own: what is written goes into the next record's plaintext
inside the transport buffer and is sealed there.

The `Connection` must not move once readers or writers exist.

The handshake keeps its working buffers on the stack of the task that runs
it (its own are around 16 KiB; AWS-LC's ML-KEM adds its own on top) and
reassembles the peer's messages through the `allocator` in the options, up
to `max_handshake_message_len` (64 KiB by default) for the certificate
chain. Budget 64 KiB of stack for a task that runs handshakes.

### Errors

`std.Io.Reader` and `std.Io.Writer` can only report `ReadFailed` and
`WriteFailed`. The `err` field of the reader or writer says what happened:
an alert the peer sent (`TlsAlert...`), something the record layer found
(`TlsBadRecordMac`, `TlsConnectionTruncated`, ...), or `ReadFailed` or
`WriteFailed` when the transport itself failed and its own error says why.
A transport `ReadFailed`, such as a cancelled read, does not end the
connection; the read may be retried.

A transport that ends between records without close_notify is a clean end
of stream, as with tls.zig; `strict_close_notify` makes it a truncation.

### Certificates and trust

`CertKeyPair.fromSlice` takes a PEM chain (leaf first) and a PEM private
key (PKCS#8, SEC 1 or PKCS#1). `TrustStore.addPem` and `addDer` take
certificates; any certificate in the store is a trust anchor, an
intermediate included. `addSystemBundle` loads the roots the system
trusts through your `std.Io`; `addPemFile`, `addPemDir` and `addBundle`
(for a `std.crypto.Certificate.Bundle`) are the pieces it is made of.

A server can hold several certificates: `certificates` are tried for the
client's server name and the signature algorithms it accepts, and
`select_certificate` lets the application decide first.

## Development

```sh
zig build test                                      # 0.17, or ~/.zvm/0.16.0/zig
zig build test -fwine -Dtarget=x86_64-windows-gnu   # networking tests skip under wine
zig build test -fqemu -Dtarget=aarch64-linux-musl
```

The tests include self-talk over a loopback socket and interoperability
with `openssl s_server` and `s_client` when OpenSSL 1.1.1 or newer is on the
PATH. Format with Zig 0.16's `zig fmt`: 0.17's rewrites builtins that 0.16
does not accept.

`vendor/aws-lc` builds libcrypto; `gen_sources.py` there regenerates the
file lists from upstream's CMake build after an upgrade. AWS-LC's headers
reach Zig through translate-c from `src/c.h`.
