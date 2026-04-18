import Foundation

/// Simple time-instrumentation collector. Each call to `measure` records a
/// labelled duration; `report` prints them to stderr in `--timings` mode.
///
/// Single-threaded CLI, so no locking. `@unchecked Sendable` is pragmatic,
/// not principled — enable with care if this ever becomes multi-actor.
final class Timings: @unchecked Sendable {
    private var spans: [(label: String, duration: Duration)] = []
    private var enabled: Bool = false
    private let programStart = ContinuousClock.now

    static let shared = Timings()

    func enable() { enabled = true }

    /// Measure an async block.
    static func measure<T>(
        _ label: String,
        _ body: () async throws -> T
    ) async rethrows -> T {
        let start = ContinuousClock.now
        let result = try await body()
        shared.record(label, ContinuousClock.now - start)
        return result
    }

    /// Measure a sync block.
    static func measureSync<T>(
        _ label: String,
        _ body: () throws -> T
    ) rethrows -> T {
        let start = ContinuousClock.now
        let result = try body()
        shared.record(label, ContinuousClock.now - start)
        return result
    }

    /// Record a duration directly (for cases where the caller already has
    /// start/end timestamps).
    func record(_ label: String, _ duration: Duration) {
        guard enabled else { return }
        spans.append((label, duration))
    }

    /// Emit the breakdown to stderr. No-op when `--timings` wasn't passed.
    /// Idempotent so that commands can call it explicitly (e.g. `run` prints
    /// before `exec`ing the child) without the `defer` path double-reporting.
    private var reported: Bool = false
    func report() {
        guard enabled, !reported else { return }
        reported = true
        let sinceProgramStart = ContinuousClock.now - programStart
        var out = "pscht: timings (ms):\n"
        let measured = spans.reduce(Duration.zero) { $0 + $1.duration }
        for (label, duration) in spans {
            out += "  \(Self.format(duration))  \(label)\n"
        }
        out += "  \(Self.format(sinceProgramStart - measured))  (unmeasured / startup)\n"
        out += "  \(Self.format(sinceProgramStart))  total\n"
        FileHandle.standardError.write(Data(out.utf8))
    }

    /// Format a Duration as right-aligned ms with one decimal (`"   123.4"`).
    private static func format(_ d: Duration) -> String {
        let (s, attos) = d.components
        let ms = Double(s) * 1_000.0 + Double(attos) / 1_000_000_000_000_000.0
        return String(format: "%8.1fms", ms)
    }
}
