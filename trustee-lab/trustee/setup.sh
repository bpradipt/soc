#!/bin/sh
# Fetch Trustee and kbs-types at pinned releases, add the "litexdice" TEE type, build the KBS.
#
#   trustee/setup.sh         KBS with only the litexdice verifier: needs no TDX, SGX or TPM libraries
#   trustee/setup.sh --all   KBS with every verifier, as Trustee ships it (needs Intel DCAP and tpm2-tss)
#
# The result is build/trustee-src/kbs (or $TRUSTEE_SRC/kbs), which trustee_soc.py starts.
set -eu

TRUSTEE_TAG=v0.22.0
KBS_TYPES_TAG=v0.18.0
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${TRUSTEE_SRC:-$HERE/../build/trustee-src}

mkdir -p "$SRC"
cd "$SRC"
[ -d trustee ] || git clone -q --depth 1 -b "$TRUSTEE_TAG" https://github.com/confidential-containers/trustee
[ -d kbs-types ] || git clone -q --depth 1 -b "$KBS_TYPES_TAG" https://github.com/virtee/kbs-types

if [ ! -d trustee/deps/verifier/src/litexdice ]; then
    git -C kbs-types apply "$HERE/kbs-types.patch"         # 1. the new Tee::LitexDice variant
    git -C trustee apply "$HERE/trustee.patch"             # 2. dispatch, features, default policy
    cp -r "$HERE/litexdice" trustee/deps/verifier/src/     # 3. the verifier itself
    if [ "${1:-}" != --all ]; then
        git -C trustee apply "$HERE/kbs-litexdice-only.patch"
    fi
fi

cd trustee
cargo build -p kbs --bin kbs --no-default-features --features coco-as-builtin
cp "${CARGO_TARGET_DIR:-target}/debug/kbs" "$SRC/kbs"
echo "Built $SRC/kbs"
