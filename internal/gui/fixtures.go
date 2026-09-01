package gui

import "time"

// Fixture data for the pass-1 prototype (spec 002, pass 1 acceptance criteria).
//
// Everything here is visibly invented. No value in this file is credential
// shaped: there is no passphrase, no key material, and no armored block, not
// even a fake one, because a fake one is indistinguishable from a real one in a
// grep and in a reviewer's memory. The fingerprints below are the string
// EXAMPLE repeated, which no real key can produce.
//
// This file is deleted in pass 3, when internal/core supplies these shapes from
// a real store.

const fixtureStoreDir = "/home/example/Sync/secrets.angou"

func fixtureSession() Session {
	return Session{
		StoreDir: fixtureStoreDir,
		Route:    UnlockLocalKey,
		Agent:    AgentState{Running: true, Remaining: 7*time.Minute + 12*time.Second, Socket: "$XDG_RUNTIME_DIR/angou.sock"},
	}
}

func ago(d time.Duration) time.Time { return time.Now().Add(-d) }

func fixtureEntries() []StoreEntry {
	return []StoreEntry{
		{"ssh/id_ed25519", "a3f1c2/0e7b91d4", 464, true, ago(31 * 24 * time.Hour), "~/.ssh/id_ed25519"},
		{"ssh/id_ed25519.pub", "a3f1c2/5c20aa83", 102, true, ago(31 * 24 * time.Hour), "~/.ssh/id_ed25519.pub"},
		{"aws/credentials", "9b04de/1f8e6072", 288, true, ago(6 * 24 * time.Hour), "~/.aws/credentials"},
		{"gnupg/secring.gpg", "9b04de/77c1b005", 24118, false, ago(90 * 24 * time.Hour), "~/.gnupg/secring.gpg"},
		{"kube/config", "41ca77/b3920fe1", 5390, true, ago(2 * 24 * time.Hour), "~/.kube/config"},
		{"notes/recovery-plan.md", "41ca77/2d55c48a", 1804, true, ago(14 * time.Hour), ""},
		{"vpn/work.ovpn", "0d3e15/9a6740bb", 7622, true, ago(58 * 24 * time.Hour), "~/vpn/work.ovpn"},
		{"db/prod.pgpass", "0d3e15/ce13d720", 196, true, ago(3 * time.Hour), "~/.pgpass"},
	}
}

func fixtureCandidates() []ScanCandidate {
	return []ScanCandidate{
		{"~/.ssh/id_rsa", "OpenSSH private key header", 1876, true, false},
		{"~/.ssh/id_ecdsa", "OpenSSH private key header", 513, true, false},
		{"~/.ssh/known_hosts", "name matches ssh/known_hosts", 12043, false, false},
		{"~/.aws/credentials", "name matches aws/credentials", 288, false, true},
		{"~/.docker/config.json", "contains a base64 auth field", 421, true, false},
		{"~/.netrc", "name matches netrc", 164, true, false},
		{"~/.config/gcloud/application_default_credentials.json", "name matches *credentials*.json", 2380, true, false},
		{"~/projects/api/.env", "name matches .env", 892, true, false},
		{"~/projects/api/.env.example", "name matches .env, contents look like placeholders", 340, false, false},
		{"~/certs/wildcard.pem", "PEM private key header", 3272, true, false},
		{"~/certs/wildcard.crt", "PEM certificate, no private key", 2104, false, false},
	}
}

// The two fingerprints below are not hex: they spell EXAMPLE. A real OpenPGP
// fingerprint cannot contain the letters X, M, or L.
const (
	fixtureIdentityKey   = "EXAMPLE EXAMPLE EXAMPLE EXAMPLE EXAMPLE1"
	fixtureSupersededKey = "EXAMPLE EXAMPLE EXAMPLE EXAMPLE EXAMPLE2"
)

func fixtureDoctor() []DoctorGroup {
	return []DoctorGroup{
		{"Store", []DoctorRow{
			{"directory", fixtureStoreDir, StatusInfo, ""},
			{"format", "ANGOU1", StatusInfo, ""},
			{"blobs", "8", StatusInfo, ""},
			{"index", "present, consistent with the blobs", StatusGood, ""},
			{"identity key", fixtureIdentityKey, StatusInfo, ""},
		}},
		{"This machine", []DoctorRow{
			{"local key", "present", StatusGood, "This machine opens the store without the recovery passphrase."},
			{"keyring backend", "KWallet (Secret Service)", StatusGood, ""},
			{"keyring entry", "present", StatusGood, ""},
			{"agent", "running, 7m12s remaining", StatusGood, ""},
		}},
		{"Key bundles", []DoctorRow{
			{"current bundle", fixtureIdentityKey, StatusGood, ""},
			{"superseded bundle", fixtureSupersededKey, StatusWarn,
				"A superseded bundle is still in the store. Until it is pruned, the key you rotated away from can still open the blobs it wrote. Run Prune, then assert the old key is dead."},
		}},
		{"Bootstrap namespace", []DoctorRow{
			{"bootstrap.sh", "present, digest matches the recorded value", StatusGood,
				"This is drift detection after the fact, not a guarantee about the first run."},
			{"binaries", "6 across 4 platforms", StatusInfo, ""},
			{"signing key", "not configured in this build", StatusBad,
				"This build refuses to install a binary from the store: with no pinned fingerprint it would trust any signature it could verify."},
		}},
	}
}

func fixtureReleases() []ReleaseEntry {
	return []ReleaseEntry{
		{"linux/amd64", "0.1.4", 7032994, true},
		{"linux/amd64", "0.1.3", 7018220, true},
		{"linux/arm64", "0.1.4", 6744118, true},
		{"darwin/amd64", "0.1.4", 7210448, true},
		{"darwin/arm64", "0.1.4", 6980112, true},
		{"darwin/arm64", "0.1.3", 6961884, false},
	}
}
