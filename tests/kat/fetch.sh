#!/usr/bin/env bash
# Fetch the ML-KEM-768 test vectors into tests/kat/vectors (gitignored).
# Every source is pinned to a commit; bump deliberately and re-run the
# suite when you do. Idempotent. Needs curl and python3.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
V="$DIR/vectors"
mkdir -p "$V"

# PQShield reference KATs (1000 vectors per set, with implicit-rejection ct_n/ss_n).
# https://github.com/post-quantum-cryptography/KAT
KAT_REF="f238e347b1323344208eb316df9993c923334817"   # main 2026-09-15

# NIST ACVP demo vectors for FIPS 203 (keyGen, encapDecap incl. key checks).
# https://github.com/usnistgov/ACVP-Server
ACVP_REF="975de31eb83d87039ec88934fdc47d8c312b892d"  # master 2026-09-15

# C2SP/CCTV negative vectors as shipped in the upstream LibFormalPQC test
# suite (unlucky rejection sampling; 780 encapsulation keys with an
# unreduced coefficient). https://github.com/awslabs/LibFormalPQC
LFP_REF="1a392899f4f1a03b41a6241637cd102370a87ca6"

get() {  # get <url> <dest>
    if [ -f "$2" ]; then return 0; fi
    echo "fetching $(basename "$2")"
    curl -sSfL -o "$2.tmp" "$1" && mv "$2.tmp" "$2"
}

get "https://raw.githubusercontent.com/post-quantum-cryptography/KAT/$KAT_REF/MLKEM/kat_MLKEM_768.rsp" \
    "$V/kat_MLKEM_768.rsp"
get "https://raw.githubusercontent.com/post-quantum-cryptography/KAT/$KAT_REF/MLKEM/kat_MLKEM_1024.rsp" \
    "$V/kat_MLKEM_1024.rsp"
get "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$ACVP_REF/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json" \
    "$V/acvp_keygen.json"
get "https://raw.githubusercontent.com/usnistgov/ACVP-Server/$ACVP_REF/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json" \
    "$V/acvp_encapdecap.json"
get "https://raw.githubusercontent.com/awslabs/LibFormalPQC/$LFP_REF/MLKEM/spark_ada/tests/unlucky.rsp" \
    "$V/cctv_unlucky.rsp"
get "https://raw.githubusercontent.com/awslabs/LibFormalPQC/$LFP_REF/MLKEM/spark_ada/tests/invalid_ek.txt" \
    "$V/cctv_invalid_ek.txt"

python3 "$DIR/acvp_to_txt.py" "$V"
