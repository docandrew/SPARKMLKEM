# Changes from upstream LibFormalPQC

Upstream: https://github.com/awslabs/LibFormalPQC, directory `MLKEM/spark_ada`,
commit 1a39289 (imported 2026-09-15). Author of the upstream code: Rod Chapman,
Amazon Web Services, with contributions from the AWS Labs team.

Every file that departs from the upstream text carries a line under its
copyright header naming the change, as the Apache License 2.0 section 4(b)
requires. This file is the running summary.

## Layout (2026-09-15 restructure)

Upstream is one package, `MLKEM`, with the parameter set (k, eta, du,
dv) fixed as constants and a TODO to make it generic. The crate keeps
every upstream subprogram but splits the package by what it depends on:

| Unit | Content | Origin |
|---|---|---|
| `src/mlkem.ads` / `.adb` | the parameter-independent core: `Zq`, polynomials, NTT, NTT_Inv, MultiplyNTTs, XOF_Then_SampleNTT, the d = 1 and 12-bit encoders, G/H/J, Byte_Seq_Equal, BitsToBytes/BytesToBits; plus the two generics `Generic_Compression` (d, UD) and `Generic_CBD` (eta) | upstream text, moved; the two generics fold upstream's per-width and per-eta copies into one text each |
| `src/mlkem-generic_kem.ads` / `.adb` | generic child over K, Eta_1, Eta_2, DU, DV, UDU, UDV: key and ciphertext types, vector and matrix operators, K-PKE, the section 7 checks, the ML-KEM API | upstream text with the constants as formals; the sequential K_PKE_KeyGen subunit is a plain function here |
| `src/mlkem-compressed_widths.ads` | the modular types U4, U5, U10, U11 (a modulus must be static, so a generic cannot form them) | new |
| `src/mlkem-ml_kem_768.ads`, `src/mlkem-ml_kem_1024.ads` | the instances | new |
| `src/zq_multiply_proof.txt`, `sparkmlkem.adc` (was `mlkem.adc`) | unchanged | upstream |

Consumers name an instance: `MLKEM.ML_KEM_768.MLKEM_KeyGen` and so on.
The instance also publishes `Parameter_K`, `Parameter_DU`, `Parameter_DV`.

## Not imported

- `mlkem-k_pke_keygen_par.adb`, `par.adc`: the tasking key-generation variant
  (and, with it, the subunit mechanism that selected it).
- `mlkem-debug.*`, `mlkem-tests.*`: development aids.
- The libkeccak git submodule: replaced by the Alire crate `libkeccak ^3.0.0`,
  the same library from the same author.
- The HQC crate, the `experimental/` directory and the ML-DSA model.

## Modified

### `src/mlkem.adb` and `src/mlkem-generic_kem.adb`

- **Generic over the parameter set (2026-09-15).** See Layout above. The
  moved subprograms are the upstream text; the mechanical edits are the
  conversions the formals require (`Byte (K)` where upstream used the
  named number `K` as a byte; `I32 (D)` in index arithmetic of the
  compression generic; `C : constant U64 := U64 (UD'Modulus)` where
  upstream had a named number). K_Range is a subtype of I32 rather than a
  new integer type, because a new type's bounds must be static.
- **Field multiplication without the assumed lemma (2026-09-17).**
  Upstream's `Zq."*"` computed the Barrett quotient and then relied on
  `pragma Assume` of Lemma 1 (q is prime, so the product of two non-zero
  residues is not a multiple of q; proved in Lean 4 and HOL Light in
  `zq_multiply_proof.txt`) to conclude the quotient is exact. The
  quotient is exact or one too small, so the remainder is in 0 .. 2q-1;
  one masked subtraction of q (the idiom the upstream `"+"` already uses)
  finishes the reduction, and GNATprove proves the postcondition from the
  arithmetic alone. Cost: one compare and one subtract per field multiply.
  The crate now contains no `pragma Assume`. `zq_multiply_proof.txt` is
  kept as documentation of the upstream argument.
- **Procedural style and sanitisation (2026-09-15, FIPS 203 section
  3.3).** Upstream computed in functional style (`S_Hat := NTT (S)`,
  `KR := G (M_Tick & H)`, key material returned from functions) and
  sanitised nothing; its README says so. Every subprogram whose result
  or operands can be secret is now a procedure with an out parameter,
  so the value has a name and its owner sanitises it before return:
  NTT, NTT_Inv, MultiplyNTTs, the polynomial add/subtract, the CBD
  sampler and its PRF, the d-bit and 12-bit encoders and decoders, the
  hashes G, H and J, and the vector, K-PKE and ML-KEM layers. Functions
  remain only where every value is public: XOF_Then_SampleNTT and
  Transpose (the matrix A), the scalar Compress/Decompress, and the
  Boolean checks. `Sanitize` (SPARKNaCl's idiom: a No_Inline procedure
  writing zeros followed by `pragma Inspection_Point`) is provided for
  byte and bit sequences, polynomials and vectors, and every secret
  local is sanitised: in key generation the seed hash and sigma, s, e,
  their NTT images and A*s; in encryption the PRF block, y, e1, e2,
  y_hat, A^T y before and after the inverse NTT, u, the decoded and
  decompressed message and every partial of v; in decryption s_hat,
  s^T u, w and its bits; in the KEM the shared-secret candidates, the
  re-encryption randomness, the recovered message, z, dk_pke and the
  re-encrypted ciphertext. Inside the core, the bit expansions of the
  encoders and decoders are sanitised, the loop scalar of BytesToBits is
  cleared, and every hash context is re-initialised after use (libkeccak's
  `Init` zeroes the sponge state and the block buffer) under an inspection
  point. G and J take two inputs and the PRF two updates, so no secret
  is ever concatenated into a temporary; the decapsulation key is
  assembled by slice assignments. The public API changed accordingly:
  `MLKEM_KeyGen (D, Z, Key)` and `MLKEM_Decaps (C, DK, Key)` are
  procedures. What this does not reach: the compiler's own temporaries
  for `&` on public data, and registers.
- **Byte-wise encoders and decoders (2026-09-18).** Upstream's
  ByteEncode12 / ByteDecode12 and the d-bit ByteEncode / ByteDecode went
  through the standard's bit arrays (a 3072-element array of bits for
  one polynomial, then BitsToBytes), which was a quarter of the
  instructions of key generation. The 12-bit pair packs two
  coefficients into three bytes directly; the d-bit generic runs a bit
  accumulator (at most 7 pending bits between coefficients, whole bytes
  drained from the bottom), with loop invariants that tie the byte
  index to the bits consumed so every index is proved in range. Same
  bytes as the bit-array form (least significant bit first); the KAT
  suite (19132 records across both parameter sets) is the functional
  check. The `Coef_Bits_Value` ghost function and the element-wise
  invariant of the 2026-09-15 pass went with the bit array they
  described. BitsToBytes / BytesToBits remain for the d = 1 encoders.
- **Zq operators inlinable (2026-09-18).** Upstream marked `Zq."+"`,
  `"-"`, `"*"` and `ModQ` `No_Inline`; every NTT butterfly was three
  calls. They are `Inline` now. Proof is unaffected (the project proves
  with `--no-inlining`, and the operators have contracts, so GNATprove
  analyses them once either way); the constant-time lanes (ctgrind on
  the compiled code, dudect) are the check that the compiler kept the
  masked corrections branch-free once inlined.
- **XOF_Then_SampleNTT reads whole blocks (2026-09-18).** Upstream asked
  SHAKE128 for three bytes per candidate pair. The function now extracts
  one rate block (168 bytes) per call and walks it in three-byte groups;
  the sampling decisions are algorithm 7's, the bytes left in the last
  block are discarded with the context, so the polynomial is the one the
  three-bytes-at-a-time reading of the same stream produces. Both
  candidates now check `J2 < 256` since the block may run past the last
  sample.

- **XOF_Then_SampleNTT termination justification (2026-09-15).** Upstream
  put a `Loop_Variant (Increases => J2)` on the rejection-sampling loop,
  disabled it at run time, and justified the "loop variant might fail"
  check as a False_Positive. GNATprove 16 ignores a disabled variant and
  instead reports the loop as possibly non-terminating, so the old
  justification attached to nothing. The variant and its policy pragma
  are removed and the same justification (termination with overwhelming
  probability; FIPS 203 algorithm 7 has no bound) is attached to the
  check the tool now emits. Same loop; decided with the project owner
  on 2026-09-15 rather than bounding the block count.

  (An earlier pass the same day also rewrote the NTT and NTT_Inv loop
  control to avoid `2**I`; that was reverted once COLIBRI was added to
  the prover set, which proves the upstream loops as written.)

### `sparkmlkem.gpr` (was `mlkem.gpr`)

- COLIBRI added to the prover set (`z3,cvc5,altergo,colibri`); it is the
  solver that closes the power-of-two invariants under GNATprove 16.
- Proof step budget 200000 instead of 25000 (MultiplyNTTs needs more than 100000 on a fresh run), no wall-clock timeout,
  per-prover memory capped at 2000 MB.

## Verification status

- Build: clean with upstream's `-gnatwae` warning set under GNAT 16.1.
- KAT: 19132 checks pass across both parameter sets (PQShield 1000
  vectors each with implicit rejection, NIST ACVP keyGen / encap / decap
  / key checks for 768 and 1024, CCTV negatives).
- ctgrind: encapsulation and both decapsulation harnesses clean; key
  generation reports exactly the two rejection-sampling `candidate < q`
  tests on the public seed rho (three until 2026-09-18, when the
  three-bytes-per-Extract loop compiled one test as a fused compare; the
  block-wise sampler compiles to one site per test).
- dudect: canary flagged, four real harnesses below the t = 4.5
  threshold.
- Proof under GNATprove 16 (`z3,cvc5,altergo,colibri`, level default,
  200000 steps): the two instances ML_KEM_768 and ML_KEM_1024 discharge
  every check, 20604 in total (6823 flow, 13702 proof, 79 justified).
  The 79 justifications are the rejection-sampling loop termination in
  XOF_Then_SampleNTT (FIPS 203 algorithm 7 has no block bound), repeated
  per instantiation. No `pragma Assume` anywhere.
