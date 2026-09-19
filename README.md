# SPARKMLKEM

SPARK/Ada implementation of ML-KEM (FIPS 203) for the SPARKTLS stack.

## Origin and credit

**This crate is derived from the ML-KEM implementation in
[LibFormalPQC](https://github.com/awslabs/LibFormalPQC) (formerly LibMLKEM),
written by Rod Chapman and the AWS Labs team at Amazon Web Services.** The
algorithm structure, the `Zq` field arithmetic with its division-free
design, the type design that makes the parameter bounds part of the types,
and the SPARK proofs of functional correctness and absence of run-time
errors are their work. We started from their code because it is the best
formally verified ML-KEM we know of, and we would not have a verified
post-quantum key exchange without it.

Their code is published under the Apache License 2.0, and so is this crate.
`NOTICE` carries their copyright, `CHANGES_FROM_UPSTREAM.md` lists exactly
what we changed and why, and every modified source file says so under its
copyright header. If you use this crate, please credit them as well.

## What this crate adds

The SPARKTLS project needs ML-KEM-768 for the X25519MLKEM768 TLS 1.3 key
exchange. On top of the upstream code this crate adds:

- the package made generic over the parameter set (upstream's own TODO),
  with ML-KEM-768 and ML-KEM-1024 instantiated and both tested (done);
- proof under GNATprove 16 with COLIBRI in the prover set (done);
- constant-time evidence: ctgrind and dudect harnesses with planted-leak
  controls (done);
- NIST ACVP known-answer tests in addition to the upstream vectors (done);
- the SPARKTLS crate conventions: Alire-managed libkeccak, `ci/` lanes,
  a Nix flake, hosted CI (done);
- sanitisation of every secret intermediate (FIPS 203 section 3.3), by
  rewriting the secret-bearing paths in procedural style: functions
  return only public values, every secret has a name and is zeroed
  before its scope ends, hash contexts are re-initialised after use
  (done);
- a lemma-free field reduction, so the crate has no `pragma Assume`
  (done).

`CHANGES_FROM_UPSTREAM.md` lists every departure from the upstream text.

## Layout

`MLKEM` (src/mlkem.ads) is the parameter-independent core, Rod's code:
the field, the NTT, sampling and encoding. `MLKEM.Generic_KEM` is a
generic child over k, eta, du and dv holding K-PKE and the ML-KEM API.
`MLKEM.ML_KEM_768` and `MLKEM.ML_KEM_1024` are its instances; both run
the known-answer suite. Callers use an instance:

```ada
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
...
MLKEM_KeyGen (D, Z, Key);
MLKEM_Encaps (Key.EK, M, Shared, Ciphertext);
MLKEM_Decaps (Ciphertext, Key.DK, Shared2);
```

The API is procedural on purpose: key material never travels through
a function result, so nothing secret is left in an anonymous temporary.
Callers own the sanitisation of the objects they declare (`Sanitize`
is exported for byte sequences).

## Build

```shell
alr build
```

Checked debug build:

```shell
SPARKMLKEM_BUILD_MODE=debug SPARKMLKEM_RUNTIME_CHECKS=enabled \
SPARKMLKEM_CONTRACTS=enabled alr build
```

Proof:

```shell
ci/proof.sh
```

## Performance

Reference-implementation speed, `tests/bench` (median rdtsc cycles, one
x86-64 core, optimize build, 2026-09-18):

| | KeyGen | Encaps | Decaps |
|---|---|---|---|
| ML-KEM-768 | 86k | 106k | 133k |
| ML-KEM-1024 | 132k | 155k | 189k |

Pure SPARK, no SIMD or assembly: the 2026-09-18 pass (inlinable field
operators, byte-wise encoders, block-wise XOF reads; see
`CHANGES_FROM_UPSTREAM.md`) took ML-KEM-768 from 224k/224k/280k to the
figures above. The Keccak permutation and the NTT are where the
remaining time goes; an AVX2 tier would be the next step and is not a
priority until the TLS stack is at its verification goals.

## License

Apache License 2.0. See `LICENSE`, `NOTICE` and `THIRD-PARTY`.
