package release

// SigningKeyFingerprint is the release-signing key this build trusts. It is
// injected at build time with -ldflags and is deliberately empty by default.
//
// Empty means "trust nothing": a build that was not given a fingerprint refuses
// to install a binary from a store rather than accepting any signature it can
// verify. The value must never be read from the store — that is the whole point
// of R5.4.1. If the verification key travelled with the artifacts it verifies,
// anyone who obtained the recovery passphrase or compromised one machine could
// sign a malicious binary that every future bootstrap would accept.
var SigningKeyFingerprint = ""

// Trusted reports whether this build can verify a release signature at all.
func Trusted() bool { return SigningKeyFingerprint != "" }
