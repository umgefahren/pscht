import ArgumentParser

struct BiometricOptions: ParsableArguments {
    @Flag(name: .long, help: "Skip biometric authentication")
    var noBio: Bool = false

    func authenticateIfNeeded(reason: String) throws {
        guard !noBio else { return }
        _ = try Keychain.authenticate(reason: reason)
    }
}
