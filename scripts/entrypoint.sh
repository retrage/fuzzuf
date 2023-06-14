#!/usr/bin/env bash

set -eux

FUZZUF_ROOT_DIR="/src/fuzzuf"
FUZZUF_BUILD_DIR="$FUZZUF_ROOT_DIR/build"
FUZZUF_PATH="$FUZZUF_BUILD_DIR/fuzzuf"
PUT_DIR="$FUZZUF_ROOT_DIR/docs/resources/exifutil"
PUT_PATH="$PUT_DIR/afl-exifutil"
PUT_SEED_PATH="$PUT_DIR/fuzz_input/jpeg.jpg"

TMP_DIR="$(mktemp -d /tmp/tmp.XXXXXXXXXX)"
IN_DIR="$TMP_DIR/in"
OUT_DIR="$TMP_DIR/out"

mkdir -p "$IN_DIR"
cp "$PUT_SEED_PATH" "$IN_DIR"

"$FUZZUF_PATH" \
  "$FUZZUF_FUZZER" \
  --in_dir="$IN_DIR" \
  --out_dir="$OUT_DIR" \
  -- \
    "$PUT_PATH" \
    -f \
    @@ \
   >& /dev/null
