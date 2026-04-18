#if os(Linux)
import Foundation
import CArgon2

/// Minimal Swift wrapper over `libargon2`. We use Argon2id with raw (not
/// encoded) output so the result is a fixed-length key we can feed into HKDF.
enum Argon2 {
    struct Params: Sendable, Equatable {
        var memoryKiB: UInt32
        var iterations: UInt32
        var parallelism: UInt32
        var hashLen: UInt32 = 32
    }

    /// Argon2id hashing. `pwd` and `salt` are passed through as-is. Writes the
    /// result into `out` (a caller-owned buffer; typically the inner storage
    /// of a `SecretBytes`).
    static func hash(
        password pwd: Data,
        salt: Data,
        params: Params,
        out: UnsafeMutableRawBufferPointer
    ) throws(SecretStoreError) {
        guard out.count == Int(params.hashLen) else {
            throw .configInvalid("Argon2 output buffer is \(out.count) bytes but hashLen=\(params.hashLen)")
        }
        let rc = pwd.withUnsafeBytes { pwdPtr in
            salt.withUnsafeBytes { saltPtr in
                argon2id_hash_raw(
                    params.iterations,
                    params.memoryKiB,
                    params.parallelism,
                    pwdPtr.baseAddress,
                    pwd.count,
                    saltPtr.baseAddress,
                    salt.count,
                    out.baseAddress,
                    Int(params.hashLen)
                )
            }
        }
        guard rc == ARGON2_OK.rawValue else {
            let msg = String(cString: argon2_error_message(rc))
            throw .configInvalid("Argon2id failed: \(msg) (code \(rc))")
        }
    }

    /// Convenience: allocate a fresh `SecretBytes` and fill it via `hash`.
    static func hash(password pwd: Data, salt: Data, params: Params) throws(SecretStoreError) -> SecretBytes {
        var out = SecretBytes(count: Int(params.hashLen))
        try out.withMutableBytes { buf throws(SecretStoreError) in
            try Self.hash(password: pwd, salt: salt, params: params, out: buf)
        }
        return out
    }
}
#endif
