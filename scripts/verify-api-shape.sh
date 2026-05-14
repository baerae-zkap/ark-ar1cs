#!/usr/bin/env bash
# verify-api-shape.sh — phase-aware API-shape probes.
#
# Verifies that the *new* import paths and `prove` signature targeted by
# the feature-boundary migration (Commits 3 and 4 of
# docs/feature-boundary-tdd-plan.md) are in the expected state at the
# given commit phase.
#
# Probes:
#   B-import-1..4 — `synthesize_full_assignment` / `WitnessError` reachable
#                   via both `ark_ar1cs::*` (root) and `ark_ar1cs::witness::*`.
#   C-shape-1     — `prove(&ProvingKey<E>, &ArcsFile<F>, &[F], &mut R)` fn
#                   coercion succeeds.
#   C-shape-2     — `prove(&ArzkeyFile<E>, &[F], &mut R)` (legacy 3-arg sig)
#                   no longer compiles.
#   C-shape-3     — `prove(.., .., .., .., &[u8; 32])` 5-arg coercion fails
#                   (no manifest/expected-hash arg in any phase).
#
# Usage:
#   scripts/verify-api-shape.sh [commit2|commit3|commit4|commit5|commit6|commit7|final]
#
# Exit 0  = every probe matches this phase's expectation.
# Exit 1  = at least one probe diverged.
#
# Cost characteristics and env overrides match verify-removal-boundary.sh.

set -euo pipefail
PHASE="${1:-final}"

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -n "${ARK_AR1CS_PROBE_TMPDIR:-}" ]]; then
    mkdir -p "$ARK_AR1CS_PROBE_TMPDIR"
    TMP_ROOT="$ARK_AR1CS_PROBE_TMPDIR"
    OWN_TMP=0
else
    TMP_ROOT="$(mktemp -d -t ark-ar1cs-probe.XXXXXX)"
    OWN_TMP=1
fi

export CARGO_TARGET_DIR="$TMP_ROOT/shared-target"

cleanup() {
    if [[ "$OWN_TMP" -eq 1 ]]; then
        rm -rf "$TMP_ROOT"
    fi
}
trap cleanup EXIT

run_probe() {
    local name="$1"; local expected="$2"; local body="$3"; local extra_deps="${4:-}"
    local crate_dir="$TMP_ROOT/$name"
    mkdir -p "$crate_dir/src"

    local pkg_name="${name//_/-}"

    {
        # Empty [workspace] table — keeps the probe crate from being
        # absorbed into the parent workspace when TMP_ROOT lives inside
        # the repo tree (the case when ARK_AR1CS_PROBE_TMPDIR is set to
        # an in-tree directory like ".probe-target/").
        echo '[workspace]'
        echo ''
        echo '[package]'
        echo "name = \"$pkg_name\""
        echo 'version = "0.0.0"'
        echo 'edition = "2021"'
        echo 'publish = false'
        echo ''
        echo '[lib]'
        echo 'path = "src/lib.rs"'
        echo ''
        echo '[dependencies]'
        echo "ark-ar1cs = { path = \"$WORKSPACE_ROOT/crates/ark-ar1cs\" }"
        if [[ -n "$extra_deps" ]]; then
            printf '%s\n' "$extra_deps"
        fi
    } > "$crate_dir/Cargo.toml"

    {
        echo '#![allow(dead_code, unused_imports, unused_variables)]'
        echo "$body"
    } > "$crate_dir/src/lib.rs"

    local stderr_log="$crate_dir/cargo-check.stderr"
    local outcome
    if (cd "$crate_dir" && cargo check --quiet 2>"$stderr_log"); then
        outcome="compiles"
    else
        outcome="compile-fails"
    fi

    if [[ "$outcome" == "$expected" ]]; then
        printf 'OK   [%s] %s: %s (expected)\n' "$PHASE" "$name" "$outcome"
        return 0
    fi

    printf 'FAIL [%s] %s: %s (expected %s)\n' "$PHASE" "$name" "$outcome" "$expected"
    echo "----- cargo check stderr -----"
    cat "$stderr_log"
    echo "------------------------------"
    return 1
}

# Arkworks deps block reused by every C-shape probe.
ARKWORKS_DEPS='ark-bn254 = "0.6"
ark-groth16 = "0.6"
ark-std = "0.6"'

# Per-phase expectations.
case "$PHASE" in
    commit2)
        b_import_expect="compile-fails"     # helper not yet moved to core
        c_shape_1_expect="compile-fails"    # current `prove` takes &ArzkeyFile
        c_shape_2_expect="compiles"         # legacy 3-arg sig still present
        ;;
    commit3)
        b_import_expect="compiles"          # helper relocated to core
        c_shape_1_expect="compile-fails"    # `prove` sig still legacy
        c_shape_2_expect="compiles"
        ;;
    commit4|commit5|commit6|commit7|final)
        b_import_expect="compiles"
        c_shape_1_expect="compiles"         # new 4-arg sig in place
        c_shape_2_expect="compile-fails"    # legacy 3-arg sig removed
        ;;
    *)
        echo "FAIL: unknown phase '$PHASE'" >&2
        echo "Usage: $0 [commit2|commit3|commit4|commit5|commit6|commit7|final]" >&2
        exit 2
        ;;
esac

# C-shape-3 — 5-arg coercion must fail in every phase (boundary already met).
c_shape_3_expect="compile-fails"

set +e
fail=0

# B-import-1: root-level synthesize_full_assignment
run_probe probe_synthesize_full_assignment_root_import "$b_import_expect" \
    'use ark_ar1cs::synthesize_full_assignment;' \
    || ((fail++))

# B-import-2: root-level WitnessError
run_probe probe_witness_error_root_import "$b_import_expect" \
    'use ark_ar1cs::WitnessError;' \
    || ((fail++))

# B-import-3: ark_ar1cs::witness::synthesize_full_assignment
run_probe probe_synthesize_full_assignment_witness_module_import "$b_import_expect" \
    'use ark_ar1cs::witness::synthesize_full_assignment;' \
    || ((fail++))

# B-import-4: ark_ar1cs::witness::WitnessError
run_probe probe_witness_error_witness_module_import "$b_import_expect" \
    'use ark_ar1cs::witness::WitnessError;' \
    || ((fail++))

# C-shape-1: new 4-arg prove fn-pointer coercion compiles.
run_probe probe_prove_new_signature "$c_shape_1_expect" \
    'use ark_ar1cs::prove;
use ark_ar1cs::format::ArcsFile;
use ark_groth16::ProvingKey;
use ark_bn254::{Bn254, Fr};
use ark_std::rand::rngs::StdRng;
fn _coerce() {
    let _: fn(&ProvingKey<Bn254>, &ArcsFile<Fr>, &[Fr], &mut StdRng) -> _ = prove;
}' \
    "$ARKWORKS_DEPS" \
    || ((fail++))

# C-shape-2: legacy 3-arg prove call site no longer compiles after Commit 4.
run_probe probe_prove_legacy_arzkey_signature "$c_shape_2_expect" \
    'use ark_ar1cs::prove;
use ark_ar1cs::arzkey::ArzkeyFile;
use ark_bn254::{Bn254, Fr};
use ark_std::rand::rngs::StdRng;
fn _legacy(arzkey: &ArzkeyFile<Bn254>, full: &[Fr], rng: &mut StdRng) {
    let _ = prove(arzkey, full, rng);
}' \
    "$ARKWORKS_DEPS" \
    || ((fail++))

# C-shape-3: 5-arg coercion (with a hash/manifest tail) must fail in all phases.
run_probe probe_prove_no_manifest_arg "$c_shape_3_expect" \
    'use ark_ar1cs::prove;
use ark_ar1cs::format::ArcsFile;
use ark_groth16::ProvingKey;
use ark_bn254::{Bn254, Fr};
use ark_std::rand::rngs::StdRng;
fn _coerce() {
    let _: fn(&ProvingKey<Bn254>, &ArcsFile<Fr>, &[Fr], &mut StdRng, &[u8; 32]) -> _ = prove;
}' \
    "$ARKWORKS_DEPS" \
    || ((fail++))

set -e

echo ""
if (( fail > 0 )); then
    echo "FAIL: $fail probe(s) diverged from expected outcome at phase=$PHASE"
    exit 1
fi
echo "OK: phase=$PHASE — all probes match expected outcome"
exit 0
