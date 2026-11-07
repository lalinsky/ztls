//! Access to AWS-LC's libcrypto. The declarations come from AWS-LC's headers
//! through the build's translate-c step (`src/c.h`).

const std = @import("std");
pub const c = @import("c");

test "translated headers match the linked library" {
    try std.testing.expectEqual(@as(u64, c.AWSLC_API_VERSION), @as(u64, c.awslc_api_version_num()));
}

test "EVP_AEAD_CTX layout comes from the header" {
    // The struct we used to mirror by hand; now it is whatever aead.h says.
    var ctx: c.EVP_AEAD_CTX = undefined;
    const key: [16]u8 = @splat(0x11);
    try std.testing.expectEqual(1, c.EVP_AEAD_CTX_init(&ctx, c.EVP_aead_aes_128_gcm(), &key, key.len, c.EVP_AEAD_DEFAULT_TAG_LENGTH, null));
    defer c.EVP_AEAD_CTX_cleanup(&ctx);

    const nonce: [12]u8 = @splat(0);
    var buf: [32]u8 = @splat(0x42);
    var tag: [16]u8 = undefined;
    var tag_len: usize = 0;
    try std.testing.expectEqual(1, c.EVP_AEAD_CTX_seal_scatter(&ctx, &buf, &tag, &tag_len, tag.len, &nonce, nonce.len, &buf, buf.len, null, 0, null, 0));
    try std.testing.expectEqual(16, tag_len);
    try std.testing.expectEqual(1, c.EVP_AEAD_CTX_open_gather(&ctx, &buf, &nonce, nonce.len, &buf, buf.len, &tag, tag.len, null, 0));
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x42)), &buf);
}
