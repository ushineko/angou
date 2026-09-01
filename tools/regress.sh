#!/usr/bin/env bash
# Diff the CLI's observable output against a previous commit's, on a throwaway store.
#
# This is the check that guards the internal/core extraction (spec 002 pass 2). The
# refactor's whole claim is that behaviour is unchanged, and the e2e suite is not
# sufficient evidence for it: the suite asserts the properties someone thought to
# assert, and the first slice of the extraction reordered two --verbose lines while
# every test stayed green. Comparing against the binary that existed before the change
# asserts everything, including the parts nobody wrote a test for.
#
# What it does: builds angou at a baseline commit and at the working tree, runs the same
# read-only commands against the same store under a throwaway HOME, and diffs stdout,
# stderr and exit codes.
#
# Deliberately NOT hermetic about the session bus. `make e2e` unsets it so a test can
# never touch the developer's real wallet, which also means the keyring-gated output --
# the bootstrap suggestion, the keyring lines in doctor -- never appears there. This
# script keeps the bus so those paths are compared. It still redirects HOME and the
# XDG directories, so it reads the developer's wallet but writes no store of theirs.
set -euo pipefail

BASE="${1:-HEAD}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    cat <<'USAGE'
usage: tools/regress.sh [<baseline-commit>]

  <baseline-commit>   what to compare against; defaults to HEAD, which is what you want
                      when the change is still in the working tree

Run it when moving an operation into internal/core, before committing:

  tools/regress.sh                 # working tree vs HEAD
  tools/regress.sh b826f73         # working tree vs a named commit

A clean run prints "no differences". Any difference is a behaviour change: either fix
it, or -- if it is intended -- say so in the commit message, because "the refactor
changed nothing" is the claim this script exists to keep honest.
USAGE
}

[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && { usage; exit 0; }

command -v git >/dev/null || { echo "git is not installed" >&2; exit 1; }
git -C "$REPO_DIR" rev-parse --verify --quiet "$BASE" >/dev/null || {
    echo "not a commit: $BASE" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'git -C "$REPO_DIR" worktree remove --force "$WORK/baseline" 2>/dev/null || true;
      git -C "$REPO_DIR" worktree prune 2>/dev/null || true;
      rm -rf "$WORK"' EXIT

echo "baseline: $(git -C "$REPO_DIR" rev-parse --short "$BASE")  ($(git -C "$REPO_DIR" log -1 --format=%s "$BASE"))"
echo "building ..."
git -C "$REPO_DIR" worktree add -q --detach "$WORK/baseline" "$BASE"
( cd "$WORK/baseline" && CGO_ENABLED=0 go build -trimpath -o "$WORK/angou-base" ./cmd/angou )
( cd "$REPO_DIR"      && CGO_ENABLED=0 go build -trimpath -o "$WORK/angou-head" ./cmd/angou )

# A throwaway home, so nothing here can reach the developer's own store or config.
export HOME="$WORK/home"
export XDG_RUNTIME_DIR="$WORK/home/run"
export XDG_DATA_HOME="$WORK/home/data"
export XDG_CONFIG_HOME="$WORK/home/cfg"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME"

# Per-run passphrase from a CSPRNG. No credential-shaped constant is committed, not
# even a fake one.
head -c 32 /dev/urandom | base64 | tr -d '\n' > "$WORK/pw"

STORE="$WORK/store"
angou() { local bin="$1"; shift; exec 9<"$WORK/pw"; "$bin" --passphrase-fd 9 "$@"; local rc=$?; exec 9<&-; return $rc; }

echo "seeding a store with the baseline binary ..."
angou "$WORK/angou-base" init --no-bootstrap --store "$STORE" >/dev/null 2>&1
printf 'contents of a test file\n' > "$WORK/secret.txt"
angou "$WORK/angou-base" enc "$WORK/secret.txt" --as secret.txt --store "$STORE" >/dev/null 2>&1

# Read-only commands only. This compares behaviour; it must not be the thing that
# mutates the store between the two runs, or the second binary sees a different one.
CASES=(
    "ls"
    "ls --raw"
    "ls --names"
    "ls --no-color"
    "doctor"
    "dec secret.txt --stdout"
    "get secret.txt --dest DEST"
    "verify-bootstrap"
    "--version"
    "--help"
    "enc --help"
    "-v ls"
    "-v doctor"
    "-v dec secret.txt --stdout"
)

differences=0
for case in "${CASES[@]}"; do
    for side in base head; do
        dest="$WORK/dest-$side"; mkdir -p "$dest"
        # shellcheck disable=SC2086  # the case is a deliberate word list
        args=${case//DEST/$dest}
        # shellcheck disable=SC2086
        angou "$WORK/angou-$side" $args --store "$STORE" \
            >"$WORK/$side.out" 2>"$WORK/$side.err" && echo 0 >"$WORK/$side.rc" || echo $? >"$WORK/$side.rc"
        # The store path and the throwaway home appear in output and differ per run only
        # if something is wrong, but the dest directory legitimately differs by side.
        sed -i "s#$dest#DEST#g" "$WORK/$side.out" "$WORK/$side.err"
    done

    if ! diff -q "$WORK/base.out" "$WORK/head.out" >/dev/null ||
       ! diff -q "$WORK/base.err" "$WORK/head.err" >/dev/null ||
       ! diff -q "$WORK/base.rc"  "$WORK/head.rc"  >/dev/null; then
        differences=$((differences + 1))
        echo
        echo "DIFFERS: angou $case"
        diff -u --label "baseline stdout" --label "working tree stdout" "$WORK/base.out" "$WORK/head.out" || true
        diff -u --label "baseline stderr" --label "working tree stderr" "$WORK/base.err" "$WORK/head.err" || true
        diff -u --label "baseline exit"   --label "working tree exit"   "$WORK/base.rc"  "$WORK/head.rc"  || true
    else
        printf '  same: angou %s\n' "$case"
    fi
done

echo
if [ "$differences" -eq 0 ]; then
    echo "no differences across ${#CASES[@]} invocations."
else
    echo "$differences of ${#CASES[@]} invocations differ." >&2
    exit 1
fi
