import Foundation
import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Binary on-disk format for the encrypted vault.
///
/// Layout (all multi-byte fields little-endian):
/// ```
/// 0..4    magic         = "PSCF"
/// 4       version       = 0x01
/// 5       suite         = 0x01 (ChaCha20-Poly1305, 256-bit key)
/// 6..8    flags (u16)
/// 8..20   nonce         (12 bytes, random per write)
/// 20..52  index_hash    SHA-256(index.json) at write time, or 32 zero bytes
/// 52..N   ciphertext || 16-byte Poly1305 tag
/// ```
///
/// The AAD fed to ChaCha20-Poly1305 is bytes 0..52 verbatim, so tampering
/// with any header field (including the index hash) causes decryption to
/// fail with an auth error.
enum VaultFile {
    static let magic: [UInt8] = [0x50, 0x53, 0x43, 0x46]  // "PSCF"
    static let currentVersion: UInt8 = 0x01
    static let suiteChaChaPoly: UInt8 = 0x01
    static let headerSize = 52

    struct Header: Equatable, Sendable {
        var version: UInt8 = currentVersion
        var suite: UInt8 = suiteChaChaPoly
        var flags: UInt16 = 0
        var nonce: Data              // 12 bytes
        var indexHash: Data          // 32 bytes (zeros if no companion index)
    }

    /// Encode and encrypt the plaintext with `key`, producing a full vault blob.
    /// `nonce` is normally random; the parameter exists so tests can inject
    /// a known value.
    static func seal(
        plaintext: Data,
        key: SymmetricKey,
        indexHash: Data,
        nonce: Data? = nil
    ) throws(SecretStoreError) -> Data {
        guard indexHash.count == 32 else {
            throw .vaultCorrupt("indexHash must be 32 bytes (got \(indexHash.count))")
        }
        let nonceBytes: Data
        if let nonce {
            guard nonce.count == 12 else {
                throw .vaultCorrupt("nonce must be 12 bytes (got \(nonce.count))")
            }
            nonceBytes = nonce
        } else {
            var bytes = [UInt8](repeating: 0, count: 12)
            for i in 0..<12 {
                bytes[i] = UInt8.random(in: 0...255)
            }
            nonceBytes = Data(bytes)
        }

        let header = Header(nonce: nonceBytes, indexHash: indexHash)
        let headerBytes = encodeHeader(header)

        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.seal(
                plaintext,
                using: key,
                nonce: try ChaChaPoly.Nonce(data: nonceBytes),
                authenticating: headerBytes
            )
        } catch {
            throw .storeFailed("encryption failed: \(error)")
        }

        // SealedBox.combined = nonce + ciphertext + tag. We already wrote the
        // nonce into the header, so strip that prefix and store ciphertext+tag.
        let ctAndTag = sealed.ciphertext + sealed.tag
        return headerBytes + ctAndTag
    }

    /// Decrypt a vault blob with `key`. Also returns the header so callers
    /// can compare `indexHash` against the companion index file.
    static func open(
        blob: Data,
        key: SymmetricKey
    ) throws(SecretStoreError) -> (plaintext: Data, header: Header) {
        guard blob.count >= headerSize + 16 else {
            throw .vaultCorrupt("file too short (\(blob.count) bytes)")
        }
        let headerBytes = blob.prefix(headerSize)
        let header = try decodeHeader(Data(headerBytes))

        guard header.version == currentVersion else {
            throw .vaultVersionUnsupported(found: Int(header.version))
        }
        guard header.suite == suiteChaChaPoly else {
            throw .vaultCorrupt("unknown cipher suite \(header.suite)")
        }

        let ctAndTag = blob.suffix(from: headerSize)
        guard ctAndTag.count >= 16 else {
            throw .vaultCorrupt("ciphertext too short")
        }
        let tag = ctAndTag.suffix(16)
        let ciphertext = ctAndTag.dropLast(16)

        let sealedBox: ChaChaPoly.SealedBox
        do {
            sealedBox = try ChaChaPoly.SealedBox(
                nonce: try ChaChaPoly.Nonce(data: header.nonce),
                ciphertext: ciphertext,
                tag: tag
            )
        } catch {
            throw .vaultCorrupt("malformed sealed box: \(error)")
        }

        let plaintext: Data
        do {
            plaintext = try ChaChaPoly.open(
                sealedBox,
                using: key,
                authenticating: Data(headerBytes)
            )
        } catch {
            throw .authFailed("vault decryption failed (wrong key or tampered file)")
        }

        return (plaintext, header)
    }

    static func encodeHeader(_ h: Header) -> Data {
        var out = Data(capacity: headerSize)
        out.append(contentsOf: magic)
        out.append(h.version)
        out.append(h.suite)
        out.append(UInt8(h.flags & 0xFF))
        out.append(UInt8((h.flags >> 8) & 0xFF))
        out.append(h.nonce)
        out.append(h.indexHash)
        return out
    }

    static func decodeHeader(_ data: Data) throws(SecretStoreError) -> Header {
        guard data.count >= headerSize else {
            throw .vaultCorrupt("header too short")
        }
        let bytes = Array(data.prefix(headerSize))
        guard Array(bytes[0..<4]) == magic else {
            throw .vaultCorrupt("bad magic")
        }
        let version = bytes[4]
        let suite = bytes[5]
        let flags = UInt16(bytes[6]) | (UInt16(bytes[7]) << 8)
        let nonce = Data(bytes[8..<20])
        let indexHash = Data(bytes[20..<52])
        return Header(version: version, suite: suite, flags: flags, nonce: nonce, indexHash: indexHash)
    }

    /// Atomically write `blob` to `url`: write to a `.tmp` sibling, fsync,
    /// rename, then fsync the directory. Any crash before the final rename
    /// leaves the existing file untouched.
    static func atomicWrite(blob: Data, to url: URL) throws(SecretStoreError) {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(url.lastPathComponent + ".tmp")

        do {
            try FileManager.default.createDirectory(
                at: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .atomicWriteFailed("creating \(dir.path): \(error.localizedDescription)")
        }

        guard FileManager.default.createFile(
            atPath: tmp.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        ) else {
            throw .atomicWriteFailed("creating temp file")
        }

        do {
            let handle = try FileHandle(forWritingTo: tmp)
            defer { try? handle.close() }
            try handle.write(contentsOf: blob)
            try handle.synchronize()
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw .atomicWriteFailed("writing \(tmp.path): \(error.localizedDescription)")
        }

        // `rename(2)` atomically replaces `url` if it exists, or creates it if
        // not. FileManager.replaceItemAt requires the destination to exist on
        // Linux, so we drop down to POSIX here.
        let renameResult = tmp.path.withCString { src in
            url.path.withCString { dst in
                rename(src, dst)
            }
        }
        if renameResult != 0 {
            let err = String(cString: strerror(errno))
            try? FileManager.default.removeItem(at: tmp)
            throw .atomicWriteFailed("renaming to \(url.path): \(err)")
        }

        // fsync the containing directory so the rename is durable.
        #if canImport(Darwin)
        let dfd = dir.path.withCString { Darwin.open($0, O_RDONLY) }
        #else
        let dfd = dir.path.withCString { Glibc.open($0, O_RDONLY | O_DIRECTORY) }
        #endif
        if dfd >= 0 {
            _ = fsync(dfd)
            #if canImport(Darwin)
            _ = Darwin.close(dfd)
            #else
            _ = Glibc.close(dfd)
            #endif
        }
    }
}
