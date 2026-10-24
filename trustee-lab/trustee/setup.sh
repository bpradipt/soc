#!/bin/sh
# Fetch Trustee and kbs-types at pinned releases, add the "litexdice" TEE type, build the KBS.
# The KBS gets only the litexdice verifier, so the build needs no TDX, SGX or TPM libraries.
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
    git -C trustee apply "$HERE/kbs-litexdice-only.patch"  # 4. build KBS with only this verifier
fi

cd trustee
cargo build -p kbs --bin kbs --no-default-features --features coco-as-builtin
cp "${CARGO_TARGET_DIR:-target}/debug/kbs" "$SRC/kbs"
echo "Built $SRC/kbs"
