import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Noncopyable buffer for secret material. The `~Copyable` constraint prevents
/// silent duplication of keys across the program — every use is an explicit
/// `consume` or borrow via `withBytes`.
///
/// On Linux the buffer is `mlock`'d against swap and zeroed in `deinit` (and
/// after a `consume`). On macOS this is a best-effort wrapper; the OS already
/// encrypts swap for signed apps.
///
/// Memory-locking can fail with `ENOMEM` when `RLIMIT_MEMLOCK` is low. We log
/// a warning and keep going rather than aborting — the macOS Keychain has no
/// memory-locking either, so this is a defense-in-depth measure, not a
/// correctness requirement.
struct SecretBytes: ~Copyable {
    private var storage: UnsafeMutableRawBufferPointer
    private let didLock: Bool

    init(count: Int) {
        precondition(count > 0, "SecretBytes size must be positive")
        let raw = UnsafeMutableRawBufferPointer.allocate(byteCount: count, alignment: 1)
        raw.initializeMemory(as: UInt8.self, repeating: 0)
        self.storage = raw

        #if canImport(Glibc) || canImport(Darwin)
        let locked = mlock(raw.baseAddress, count) == 0
        if !locked {
            let err = String(cString: strerror(errno))
            FileHandle.standardError.write(
                Data("pscht: warning: mlock(\(count)) failed: \(err)\n".utf8)
            )
        }
        self.didLock = locked
        #else
        self.didLock = false
        #endif
    }

    var count: Int { storage.count }

    /// Borrow the bytes immutably for the duration of `body`.
    borrowing func withBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(UnsafeRawBufferPointer(storage))
    }

    /// Borrow the bytes mutably for the duration of `body`.
    mutating func withMutableBytes<R: ~Copyable, E: Error>(
        _ body: (UnsafeMutableRawBufferPointer) throws(E) -> R
    ) throws(E) -> R {
        try body(storage)
    }

    deinit {
        // `memset_s` / `explicit_bzero` aren't universally available.
        // The pointer chase after the loop is a best-effort compiler barrier
        // that stops an aggressive optimizer from eliding the zeroing when
        // the buffer is about to be freed.
        if let base = storage.baseAddress {
            let p = base.assumingMemoryBound(to: UInt8.self)
            for i in 0..<storage.count {
                (p + i).pointee = 0
            }
            _ = withUnsafePointer(to: p) { $0 }
        }
        #if canImport(Glibc) || canImport(Darwin)
        if didLock, let base = storage.baseAddress {
            _ = munlock(base, storage.count)
        }
        #endif
        storage.deallocate()
    }
}

/// Utility: fill `count` bytes with fresh random data from the system CSPRNG.
/// Separate from `SecretBytes` so callers can generate ephemeral random
/// material (salts, nonces) without involving the noncopyable wrapper.
func secureRandomBytes(count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    for i in 0..<count {
        bytes[i] = UInt8.random(in: 0...255)
    }
    return Data(bytes)
}
