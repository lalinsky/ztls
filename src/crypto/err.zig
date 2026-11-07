//! AWS-LC's error queue. It is thread-local, so it must be read right after
//! the failing call, before anything that could move the fiber to another
//! thread. Every wrapper in this directory does that and leaves the queue
//! empty.

const std = @import("std");
const c = @import("c");

pub const Error = error{CryptoFailed};

/// The first error AWS-LC queued on this thread (the root cause; later
/// entries wrap it), or 0 if none. Clears the queue.
pub fn take() u32 {
    const code = c.ERR_peek_error();
    c.ERR_clear_error();
    return code;
}

/// Logs every queued error at debug level, clears the queue and returns the
/// generic failure. Used where the cause is a bug or an exhausted resource
/// rather than something the caller can act on.
pub fn fail() Error {
    if (std.log.logEnabled(.debug, .ztls)) {
        var buf: [256]u8 = undefined;
        while (true) {
            const code = c.ERR_get_error();
            if (code == 0) break;
            std.log.scoped(.ztls).debug("AWS-LC: {s}", .{describe(code, &buf)});
        }
    }
    c.ERR_clear_error();
    return error.CryptoFailed;
}

/// A description of `code` for logs.
pub fn describe(code: u32, buf: []u8) []const u8 {
    _ = c.ERR_error_string_n(code, buf.ptr, buf.len);
    return std.mem.sliceTo(buf, 0);
}

test "the queue is empty after take" {
    _ = take();
    try std.testing.expectEqual(0, take());
}
