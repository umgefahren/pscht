import ArgumentParser

struct BiometricOptions: ParsableArguments {
    @Flag(name: .long, help: "Store secret without biometric protection")
    var noBio: Bool = false
}
