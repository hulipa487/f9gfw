const std = @import("std");

/// ChaCha20-Poly1305 AEAD cipher
pub const Cipher = struct {
    key: [32]u8,
    nonce_counter: std.atomic.Value(u64),

    const NonceSize = 12;
    const KeySize = 32;
    const TagSize = 16;
    const Overhead = NonceSize + TagSize;

    /// Initialize cipher with a 32-byte key
    pub fn init(key: [32]u8) Cipher {
        return .{
            .key = key,
            .nonce_counter = std.atomic.Value(u64).init(0),
        };
    }

    /// Derive a 32-byte key from a password string
    /// Simple key derivation using SHA-256
    /// For production, consider using HKDF or Argon2
    pub fn deriveKey(password: []const u8) [32]u8 {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(password, &hash, .{});
        return hash;
    }

    /// Get next nonce (incrementing counter + random prefix)
    fn nextNonce(self: *Cipher, nonce: *[NonceSize]u8) void {
        const counter = self.nonce_counter.fetchAdd(1, .monotonic);
        // Use first 4 bytes as random-ish prefix (could be random)
        // and last 8 bytes as counter
        nonce[0..4].* = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
        std.mem.writeInt(u64, nonce[4..12], counter, .little);
    }

    /// Encrypt plaintext, returns ciphertext with nonce prepended
    /// Output format: [nonce(12)][ciphertext][tag(16)]
    pub fn encrypt(self: *Cipher, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        const output_len = NonceSize + plaintext.len + TagSize;
        const output = try allocator.alloc(u8, output_len);
        errdefer allocator.free(output);

        var nonce: [NonceSize]u8 = undefined;
        self.nextNonce(&nonce);

        // Copy nonce to output
        @memcpy(output[0..NonceSize], &nonce);

        // Encrypt with ChaCha20-Poly1305
        const ciphertext = output[NonceSize..];
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
            ciphertext[0 .. ciphertext.len - TagSize],
            ciphertext[ciphertext.len - TagSize ..][0..TagSize],
            plaintext,
            &[_]u8{},
            nonce,
            self.key,
        );

        return output;
    }

    /// Decrypt ciphertext (with nonce prepended), returns plaintext
    pub fn decrypt(self: *Cipher, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len < NonceSize + TagSize) {
            return error.CiphertextTooShort;
        }

        const nonce = ciphertext[0..NonceSize];
        const encrypted_data = ciphertext[NonceSize..];
        const tag = encrypted_data[encrypted_data.len - TagSize ..][0..TagSize];
        const actual_ciphertext = encrypted_data[0 .. encrypted_data.len - TagSize];

        const plaintext = try allocator.alloc(u8, actual_ciphertext.len);
        errdefer allocator.free(plaintext);

        std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            plaintext,
            actual_ciphertext,
            tag.*,
            &[_]u8{},
            nonce[0..NonceSize].*,
            self.key,
        ) catch {
            allocator.free(plaintext);
            return error.DecryptionFailed;
        };

        return plaintext;
    }
};

test "Cipher encrypt/decrypt roundtrip" {
    const key = [_]u8{1} ** 32;
    var cipher = Cipher.init(key);

    const plaintext = "Hello, World!";

    const gpa = std.testing.allocator;
    const ciphertext = try cipher.encrypt(gpa, plaintext);
    defer gpa.free(ciphertext);

    const decrypted = try cipher.decrypt(gpa, ciphertext);
    defer gpa.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "Cipher key derivation" {
    const key = Cipher.deriveKey("test_password");
    _ = key;
}

test "Cipher multiple encrypts produce different ciphertexts" {
    const key = [_]u8{1} ** 32;
    var cipher = Cipher.init(key);

    const plaintext = "Same message";

    const gpa = std.testing.allocator;
    const ct1 = try cipher.encrypt(gpa, plaintext);
    defer gpa.free(ct1);
    const ct2 = try cipher.encrypt(gpa, plaintext);
    defer gpa.free(ct2);

    // Nonces should differ, so ciphertexts should differ
    try std.testing.expect(!std.mem.eql(u8, ct1, ct2));
}
