#!/usr/bin/env bash
# verify-removal-boundary.sh — phase-aware removal-boundary probes.
#
# Verifies that the public API removals targeted by the feature-boundary
# migration (Commits 5–7 of docs/feature-boundary-tdd-plan.md) are in the
# expected state at the given commit phase.
#
# Usage:
#   scripts/verify-removal-boundary.sh [commit2|commit5|commit6|commit7|final]
#
# Exit 0  = every probe's outcome matches this phase's expectation.
# Exit 1  = at least one probe diverged (early green, regression, or
#           unrelated build failure).
#
# Cost: ~30–60 s per phase after the first run (arkworks dep graph cached
# via a shared CARGO_TARGET_DIR). First cold-cache run: ~5–10 min. NOT for
# the inner dev loop — run once per commit and attach the output to the
# PR description.
#
# Env overrides:
#   ARK_AR1CS_PROBE_TMPDIR  — base dir for temporary probe crates and the
#                             shared CARGO_TARGET_DIR. Defaults to a fresh
#                             `mktemp -d` (tmpfs on Linux — use the override
#                             when /tmp is small).

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

# Single CARGO_TARGET_DIR shared by every probe so the arkworks dep graph
# is built exactly once. Without this, 6+ probes each rebuild from scratch
# and the script takes hours.
export CARGO_TARGET_DIR="$TMP_ROOT/shared-target"

cleanup() {
    if [[ "$OWN_TMP" -eq 1 ]]; then
        rm -rf "$TMP_ROOT"
    fi
}
trap cleanup EXIT

# run_probe — build a minimal probe crate and run `cargo check`. Verify
# the resulting outcome matches the expected state for this phase.
#
# Args:
#   $1 name      — snake_case identifier (Cargo package gets hyphenated)
#   $2 expected  — "compiles" | "compile-fails"
#   $3 body      — Rust source for src/lib.rs (single import / fn coercion / match)
#   $4 extra     — optional extra [dependencies] block (verbatim). Special-cased:
#                  if it mentions `ark-ar1cs-build` without a path/version spec,
#                  the script supplies the workspace path dep.
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
        # If the caller asked for ark-ar1cs-build by bare name, supply the
        # path dep automatically (otherwise the bare name fails to resolve).
        if [[ "$extra_deps" == *"ark-ar1cs-build"* && "$extra_deps" != *"= { path"* && "$extra_deps" != *"= { version"* ]]; then
            echo "ark-ar1cs-build = { path = \"$WORKSPACE_ROOT/crates/ark-ar1cs-build\" }"
            extra_deps=""
        fi
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

# count_workspace_members — read [workspace] members entries from the root
# Cargo.toml. Returns the count via stdout.
count_workspace_members() {
    awk '
        /^\[workspace\]/ { in_ws = 1; next }
        /^\[/             { in_ws = 0 }
        in_ws && /^[[:space:]]*"crates\// { count++ }
        END { print count + 0 }
    ' "$WORKSPACE_ROOT/Cargo.toml"
}

# Build expectations for each phase.
case "$PHASE" in
    commit2|commit3|commit4)
        # Pre-removal. D1–D6 importers still compile. D7 fast-prove
        # feature still builds. D8 wasm-witness crate still builds.
        # Workspace member count still 4.
        d_compile_expect="compiles"
        fast_prove_expect="pass"
        wasm_witness_expect="pass"
        members_expect="4"
        ;;
    commit5)
        # .arzkey + verify + from_setup_output + ArtifactMismatch*  removed.
        # fast-prove + wasm-witness still present.
        d_compile_expect="compile-fails"
        fast_prove_expect="pass"
        wasm_witness_expect="pass"
        members_expect="4"
        ;;
    commit6)
        # fast-prove cargo feature removed; wasm-witness still here.
        d_compile_expect="compile-fails"
        fast_prove_expect="fail"
        wasm_witness_expect="pass"
        members_expect="4"
        ;;
    commit7|final)
        # wasm-witness crate removed. Workspace down to two members.
        d_compile_expect="compile-fails"
        fast_prove_expect="fail"
        wasm_witness_expect="fail"
        members_expect="2"
        ;;
    *)
        echo "FAIL: unknown phase '$PHASE'" >&2
        echo "Usage: $0 [commit2|commit3|commit4|commit5|commit6|commit7|final]" >&2
        exit 2
        ;;
esac

set +e
fail=0

# D1: `ark_ar1cs::arzkey::ArzkeyFile`
run_probe probe_arzkeyfile_import "$d_compile_expect" \
    'use ark_ar1cs::arzkey::ArzkeyFile;' \
    || ((fail++))

# D2: `ark_ar1cs::verify`
run_probe probe_verify_import "$d_compile_expect" \
    'use ark_ar1cs::verify;' \
    || ((fail++))

# D3: `ark_ar1cs_build::from_setup_output`
run_probe probe_from_setup_output_import "$d_compile_expect" \
    'use ark_ar1cs_build::from_setup_output;' \
    "ark-ar1cs-build" \
    || ((fail++))

# D4: `ark_ar1cs::ArtifactMismatchReason`
run_probe probe_artifact_mismatch_reason "$d_compile_expect" \
    'use ark_ar1cs::ArtifactMismatchReason;' \
    || ((fail++))

# D5: `ProverError::ArtifactMismatch { .. }` match arm.
run_probe probe_artifact_mismatch_match "$d_compile_expect" \
    'fn _p(e: ark_ar1cs::ProverError) { match e { ark_ar1cs::ProverError::ArtifactMismatch { .. } => (), _ => () } }' \
    || ((fail++))

# D6: `ProverError::CorruptArtifact` match arm.
run_probe probe_corrupt_artifact_match "$d_compile_expect" \
    'fn _p(e: ark_ar1cs::ProverError) { match e { ark_ar1cs::ProverError::CorruptArtifact => (), _ => () } }' \
    || ((fail++))

# D7: `cargo build -p ark-ar1cs --features fast-prove` exit code.
fast_prove_log="$TMP_ROOT/fast-prove.log"
if (cd "$WORKSPACE_ROOT" && cargo build -p ark-ar1cs --features fast-prove --quiet 2>"$fast_prove_log"); then
    fast_prove_outcome="pass"
else
    fast_prove_outcome="fail"
fi
if [[ "$fast_prove_outcome" == "$fast_prove_expect" ]]; then
    printf 'OK   [%s] cargo build --features fast-prove: %s (expected)\n' "$PHASE" "$fast_prove_outcome"
else
    printf 'FAIL [%s] cargo build --features fast-prove: %s (expected %s)\n' \
        "$PHASE" "$fast_prove_outcome" "$fast_prove_expect"
    echo "----- cargo build stderr -----"
    cat "$fast_prove_log"
    echo "------------------------------"
    ((fail++))
fi

# D8: `cargo build -p ark-ar1cs-wasm-witness` exit code.
wasm_witness_log="$TMP_ROOT/wasm-witness.log"
if (cd "$WORKSPACE_ROOT" && cargo build -p ark-ar1cs-wasm-witness --quiet 2>"$wasm_witness_log"); then
    wasm_witness_outcome="pass"
else
    wasm_witness_outcome="fail"
fi
if [[ "$wasm_witness_outcome" == "$wasm_witness_expect" ]]; then
    printf 'OK   [%s] cargo build -p ark-ar1cs-wasm-witness: %s (expected)\n' "$PHASE" "$wasm_witness_outcome"
else
    printf 'FAIL [%s] cargo build -p ark-ar1cs-wasm-witness: %s (expected %s)\n' \
        "$PHASE" "$wasm_witness_outcome" "$wasm_witness_expect"
    echo "----- cargo build stderr -----"
    cat "$wasm_witness_log"
    echo "------------------------------"
    ((fail++))
fi

# D9 / E1: workspace [workspace] members count.
members_actual="$(count_workspace_members)"
if [[ "$members_actual" == "$members_expect" ]]; then
    printf 'OK   [%s] workspace members = %s (expected)\n' "$PHASE" "$members_actual"
else
    printf 'FAIL [%s] workspace members = %s (expected %s)\n' \
        "$PHASE" "$members_actual" "$members_expect"
    ((fail++))
fi

set -e

echo ""
if (( fail > 0 )); then
    echo "FAIL: $fail probe(s) diverged from expected outcome at phase=$PHASE"
    exit 1
fi
echo "OK: phase=$PHASE — all probes match expected outcome"
exit 0
