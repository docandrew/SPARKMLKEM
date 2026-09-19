# SPARKMLKEM CI

`ci/check.sh` is the local wrapper for the hosted CI lane. Hosted CI runs
the same wrapper inside the Nix environment:

```shell
nix develop --command bash ci/check.sh
```

It builds the library and runs the known-answer suite (`ci/kat.sh`):
the PQShield reference vectors, the NIST ACVP FIPS 203 vectors, and the
C2SP/CCTV negatives. `tests/kat/fetch.sh` downloads the vectors, each
pinned to a commit; bump a pin deliberately and re-run the suite.

Proof runs as its own job:

```shell
nix develop --command bash ci/proof.sh
```

It scopes GNATprove to the crate's source units and fails on any unproved
check in them. libkeccak units are pulled in through semantic dependencies
and classified separately.

Timing lanes:

```shell
nix develop --command bash ci/timing.sh ctgrind
nix develop --command bash ci/timing.sh dudect
```

`ctgrind` runs in hosted CI. It taints the secret inputs (seeds, the
message, the secret half of the decapsulation key) under Valgrind
memcheck and fails on any branch or memory access that depends on them.
The canary harness must fail. `ct_keygen` is pinned to an exact site
count: the seed `d` yields `rho`, and the A-matrix rejection sampling
branches on SHAKE128(rho) output by design; `rho` is public (it is in
the encapsulation key) but Valgrind cannot know that. The count is
enforced in both directions.

`dudect` is statistical and machine-sensitive, so it is a manual lane.
Its canary plants a secret-dependent delay on a real decapsulation and
must be flagged; the real harnesses compare key generation across seeds,
encapsulation across messages, decapsulation across keys, and
decapsulation of a valid versus a tampered ciphertext (the implicit
rejection path).
