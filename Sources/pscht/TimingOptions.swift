import ArgumentParser

/// `--timings` flag shared by every subcommand. Drops a per-phase breakdown
/// to stderr when enabled. Useful for diagnosing PIN/Argon2/TPM latency.
struct TimingOptions: ParsableArguments {
    @Flag(name: .long, help: "Print a per-phase timing breakdown to stderr")
    var timings: Bool = false

    /// Call once at the top of a command's `run()`.
    func apply() {
        if timings {
            Timings.shared.enable()
        }
    }
}
