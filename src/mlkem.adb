--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0
--
--  Modified for SPARKMLKEM (SPARKTLS project), 2026-09-15. Changes from
--  the upstream LibFormalPQC sources are listed in CHANGES_FROM_UPSTREAM.md.
--  This unit is the parameter-set-independent core of the upstream MLKEM
--  package: the field, polynomials, the NTT, sampling, the fixed-width
--  encoders and the hash functions, as upstream wrote them. Everything
--  that depends on k, eta or the compression widths lives in the generic
--  child MLKEM.Generic_KEM. The two families upstream wrote out once per
--  parameter value (Compress/Decompress/ByteEncode/ByteDecode for d;
--  SamplePolyCBD and PRF for eta) are the generics Generic_Compression
--  and Generic_CBD here.
--    * Zq."*": a masked correction step after the Barrett quotient
--      replaces the upstream pragma Assume of a primality lemma; the
--      function is proved with no assumption (same result, constant time).
--
--  Style rule of this crate (FIPS 203 section 3.3, destruction of
--  intermediate values): a function returns only a public value. Every
--  operation whose result or operands are secret is a procedure with an
--  out parameter, so the value has a name and its owner sanitises it;
--  secret temporaries inside the core are sanitised before return; hash
--  contexts are re-initialised after use (libkeccak's Init clears the
--  state and the block buffer); no secret is passed through "&".

with SHA3;  use SHA3;
with SHAKE; use SHAKE;

package body MLKEM
  with SPARK_Mode => On
is
   --==============================================================================
   --  Notation, Naming and Operators
   --==============================================================================
   --
   --  This section lays out a few notational conventions for readers
   --  that might not be familiar with Ada or SPARK, and notes a few
   --  important differences between the notation used in FIPS 203 and
   --  that appearing here.
   --
   --  Assignment and Equality
   --  -----------------------
   --
   --  As in Pascal, SPARK uses ":=" for assignment and "=" for equality.
   --  The latter is predefined for most types, and always returns the predefined
   --  Boolean type. The "not equals" operator is denoted "/="
   --
   --  Concatenation
   --  -------------
   --
   --  FIPS 203 uses "||" for concatenation of sequences and/or arrays.
   --  In SPARK, all one-dimensional arrays have a predefined concatentation
   --  index operator, denoted "&".
   --
   --  Ranges and Array Slices
   --  -----------------------
   --
   --  Ranges of integers in SPARK (denoted "X .. Y") are _inclusive_
   --  at both ends. Similarly a "slice" of an array object, denoted
   --  A (X .. Y), is all the elements of A from the X'th to the Y'th
   --  element inclusive.
   --
   --  Naming
   --  ------
   --
   --  Where FIPS 203 uses accented characters such as the UNICODE code-point
   --  "Latin Capital A with Circumflex", this code uses a suffix on a simple
   --  name (e.g. "A_Hat" in this case) and sticks to the simple Latin_1 subset
   --  of the character set. Other than that, the code maintains the names of all
   --  types and variables from FIPS 203.
   --==============================================================================



   --  GNATProve generates false-alarms for the gnatwa.t warning ("suspicious contracts")
   --  when instantiating generics owing to a defect in the compiler front-end in
   --  GNAT versions up to and including 13.1.0. This problem will be corrected in GNAT Pro 25.0
   --  (See AdaCore TN CS0037963)
   pragma Warnings (GNATprove, Off, "postcondition does not mention function result");
   pragma Warnings (GNATprove, Off, "conjunct in postcondition does not check the outcome");

   --=======================================
   --  Local constants and types
   --=======================================

   package body Zq
     with SPARK_Mode => On
   is
      C      : constant := 2**37;
      Magic  : constant := C / Q;

      function "+" (Left, Right : in T) return T
      is
         R      : I32;
         Reduce : I32;
      begin
         --  At -O0 and -Og, GCC typically generates a branch for a
         --  predefined modular "+" operator, so we code
         --  explicitly here for constant time

         R := I32 (Left) + I32 (Right);
         pragma Assert (R >= 0 and R <= 2 * I32 (T'Last));

         Reduce := Boolean'Pos (R >= Q);

         R := R - (Reduce * Q);

         --  Prove that we can safely convert the answer back to type T...
         pragma Assert (R >= 0 and R < Q);
         --  ... and that the answer is correct
         pragma Assert (R = (I32 (Left) + I32 (Right)) mod Q);

         return T (R);
      end "+";

      function "-" (Left, Right : in T) return T
      is
         R      : I32;
         Reduce : I32;
      begin
         R := I32 (Left) - I32 (Right);
         pragma Assert (R > -Q and R < Q); --  R in -3228 .. 3228

         --  If R is negative, then we need to add Q, else add 0
         Reduce := Boolean'Pos (R < 0);
         R := R + (Reduce * Q);

         --  Prove that we can safely convert the answer back to type T...
         pragma Assert (R >= 0 and R < Q);
         --  ... and that the answer is correct
         pragma Assert (R = (I32 (Left) - I32 (Right)) mod Q);

         return T (R);
      end "-";

      function "*" (Left, Right : in T) return T
      is
         R2         : I64;
         R, R1, R3  : I32;
         Reduce     : I32;
      begin
         --  We know that Left and Right and both < Q, so 16x16->32-bit multiplication
         --  is sufficient
         R1 := I32 (Left) * I32 (Right);

         --  Switch to 64-bit multiplication now
         R2 := I64 (R1) * Magic;

         --  Shift right by 37 places, and switch back to 32-bit from here on
         R3 := I32 (R2 / C);

         --  Magic = floor (C / Q) is rounded down, so R3 is either R1 / Q or
         --  one less (the latter exactly when Q divides R1). The remainder
         --  below is therefore in 0 .. 2Q - 1, and one masked subtraction
         --  of Q completes the reduction in constant time.
         --
         --  Upstream excluded the "one less" case with a lemma (Q prime, so
         --  no product of two non-zero residues is a multiple of Q), proved
         --  in Lean4 and HOL-Light (zq_multiply_proof.txt) and assumed here.
         --  The correction step needs no lemma and no assumption.
         R := R1 - R3 * Q;
         pragma Assert (R >= 0 and R < 2 * Q);

         Reduce := Boolean'Pos (R >= Q);
         R := R - (Reduce * Q);

         --  Prove that we can safely convert the answer back to type T...
         pragma Assert (R >= 0 and R < Q);
         --  ... and that the answer is correct
         pragma Assert (R = R1 mod Q);

         return T (R);
      end "*";

      function ModQ (X : in U16_12Bits) return T
      is
      begin
         --  X is in range 0 .. 4095, so a constant-time
         --  conditional subtract of Q suffices.
         return T (X - (Q * Boolean'Pos (X >= Q)));
      end ModQ;

      function Div2 (Right : in T) return T
      is
      begin
         --  Note that Interfaces.Shift_Right for U16 is intrinsic,
         --  so should generate exactly one instruction on most ISAs.
         return T (Shift_Right (U16 (Right), 1));
      end Div2;

   end Zq;

   --  Make everything in Zq directly visible from here on
   use Zq;

   subtype NTT_Len_Bit_Index is Natural range 0 .. 6;
   subtype NTT_Len_Power     is Natural range 1 .. 7;
   --  A power of 2 between 2 and 128. Used in NTT and NTT_Inv
   subtype Len_T is Index_256 range 2 .. 128
      with Dynamic_Predicate => (for some I in NTT_Len_Power => Len_T = 2**I);

   --  A power of 2 between 1 and 64. Used in NTT and NTT_Inv
   subtype Count_T is Index_256 range 1 .. 64
      with Dynamic_Predicate => (for some I in NTT_Len_Bit_Index => Count_T = 2**I);

   --  Barrett reduction constants used by Compress
   Q_C : constant := 43;
   Q_M : constant := 2_642_262_849; --  round (2**Q_C / Q);

   --=======================================
   --  Sanitisation
   --=======================================

   procedure Sanitize (R : out Byte_Seq) is
   begin
      R := (others => 0);
      pragma Inspection_Point (R); --  See RM H3.2 (9)
   end Sanitize;

   procedure Sanitize (R : out Bit_Seq) is
   begin
      R := (others => 0);
      pragma Inspection_Point (R);
   end Sanitize;

   procedure Sanitize (R : out Poly_Zq) is
   begin
      R := (others => 0);
      pragma Inspection_Point (R);
   end Sanitize;

   procedure Sanitize (R : out NTT_Poly_Zq) is
   begin
      R := (others => 0);
      pragma Inspection_Point (R);
   end Sanitize;

   --=======================================
   --  Polynomial operators
   --=======================================

   procedure Add (Left, Right : in NTT_Poly_Zq; R : out NTT_Poly_Zq) is
   begin
      for I in R'Range loop
         R (I) := Left (I) + Right (I); --  implicitly mod q
      end loop;
   end Add;

   procedure Add_To (R : in out NTT_Poly_Zq; X : in NTT_Poly_Zq) is
   begin
      for I in R'Range loop
         R (I) := R (I) + X (I); --  implicitly mod q
      end loop;
   end Add_To;

   procedure Add (Left, Right : in Poly_Zq; R : out Poly_Zq) is
   begin
      for I in R'Range loop
         R (I) := Left (I) + Right (I); --  implicitly mod q
      end loop;
   end Add;

   procedure Sub (Left, Right : in Poly_Zq; R : out Poly_Zq) is
   begin
      for I in R'Range loop
         R (I) := Left (I) - Right (I); --  implicitly mod q
      end loop;
   end Sub;

   --=======================================
   --  Hash functions
   --=======================================

   procedure G (A, B : in Byte_Seq; R : out Bytes_64)
   is
      Ctx : SHA3_512.Context;
      D   : SHA3_512.Digest_Type;
   begin
      --  Scrub statements below: to flow analysis they are dead stores,
      --  which is the point; the context is set by Final/Extract and then
      --  re-initialised rather than read.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      SHA3_512.Init (Ctx);
      SHA3_512.Update (Ctx, SHA3_512.Byte_Array (A));
      SHA3_512.Update (Ctx, SHA3_512.Byte_Array (B));
      SHA3_512.Final (Ctx, D);
      R := Bytes_64 (D);
      --  The context absorbed the input and the digest buffer held the
      --  output; both may be secret.
      SHA3_512.Init (Ctx);
      pragma Inspection_Point (Ctx);
      D := (others => 0);
      pragma Inspection_Point (D);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end G;

   procedure H (C : in Byte_Seq; R : out Bytes_32)
   is
      Ctx : SHA3_256.Context;
      D   : SHA3_256.Digest_Type;
   begin
      --  Scrub statements below: to flow analysis they are dead stores,
      --  which is the point; the context is set by Final/Extract and then
      --  re-initialised rather than read.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      SHA3_256.Init (Ctx);
      SHA3_256.Update (Ctx, SHA3_256.Byte_Array (C));
      SHA3_256.Final (Ctx, D);
      R := Bytes_32 (D);
      SHA3_256.Init (Ctx);
      pragma Inspection_Point (Ctx);
      D := (others => 0);
      pragma Inspection_Point (D);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end H;

   procedure J (A, B : in Byte_Seq; R : out Bytes_32)
   is
      Ctx : SHAKE256.Context;
   begin
      --  Scrub statements below: to flow analysis they are dead stores,
      --  which is the point; the context is set by Final/Extract and then
      --  re-initialised rather than read.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      SHAKE256.Init (Ctx);
      SHAKE256.Update (Ctx, SHAKE256.Byte_Array (A));
      SHAKE256.Update (Ctx, SHAKE256.Byte_Array (B));
      SHAKE256.Extract (Ctx, SHAKE256.Byte_Array (R));
      SHAKE256.Init (Ctx);
      pragma Inspection_Point (Ctx);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end J;

   --=======================================
   --  BitsToBytes and BytesToBits
   --=======================================

   procedure Generic_BitsToBytes (B : in Some_Bits; R : out Some_Bytes)
   is
   begin
      R := Some_Bytes'(others => 0); --  calls _memset()
      for I in B'Range loop
         R (Bytes_Index (I / 8)) := R (Bytes_Index (I / 8)) +
                                    B (I) * (2 ** Natural (I mod 8));
      end loop;
   end Generic_BitsToBytes;

   procedure Generic_BytesToBits (B : in Some_Bytes; R : out Some_Bits)
   is
      This_Byte : Byte;
   begin
      R := (others => 0); --  calls _memset()
      for I in B'Range loop
         This_Byte := B (I);
         for J in Index_8 loop
            R (8 * Bits_Index (I) + Bits_Index (J)) := This_Byte mod 2;
            This_Byte := This_Byte / 2;
         end loop;
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      This_Byte := 0;
      pragma Inspection_Point (This_Byte);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Generic_BytesToBits;

   --=======================================
   --  d = 1 compression and encoding
   --=======================================

   function Compress1 (X : in Zq.T) return U8_Bit
   is
      T : U64;
   begin
      T := U64 (X) * 4 + Q;

      --  Division by (Q * 2) is first achieved by dividing by 2
      T := T / 2;
      --  Then multiplication by Q_M and a shift right by Q_C places
      T := T * Q_M;
      T := Shift_Right (T, Q_C);

      --  T might be in 0 .. 2 here, so a final reduction mod 2 is required
      T := T mod 2;
      return U8_Bit (T);
   end Compress1;

   procedure Compress1 (X : in Poly_Zq; R : out Bits_256)
   is
   begin
      for I in X'Range loop
         R (I) := Compress1 (X (I));
      end loop;
   end Compress1;

   function Decompress1 (Y : in U8_Bit) return Zq.T
   is
      subtype RT is I32 range 0 .. 1665;
      T : RT;
   begin
      --  Round (Q / 2) = 1665
      --  0 -> 0
      --  1 -> 1665
      --  but implement in constant-time
      T := RT (Y) * 1665;
      return Zq.T (T);
   end Decompress1;

   --  Decompress a vector of Zq_Bit values
   procedure Decompress1 (Y : in Poly_Zq_Bit; R : out Poly_Zq)
   is
   begin
      for I in R'Range loop
         R (I) := Decompress1 (U8_Bit (Y (I)));
      end loop;
   end Decompress1;

   --  256 1-bit digits is 256 bits, which is 32 bytes
   procedure ByteEncode1 (F : in Bits_256; R : out Bytes_32)
   is
      procedure BitsToBytes is new Generic_BitsToBytes
        (Index_256, Bits_256, Index_32, Bytes_32);
   begin
      BitsToBytes (F, R);
   end ByteEncode1;

   procedure ByteDecode1 (B : in Bytes_32; F : out Poly_Zq_Bit)
   is
      procedure BytesToBits is new Generic_BytesToBits
        (Index_32, Bytes_32, Index_256, Bits_256);
      Bits : Bits_256;
   begin
      BytesToBits (B, Bits);
      --  F carries the Zq_Bit predicate, so it must exist as a whole
      --  (all zeros satisfy it) before its elements are assigned.
      F := (others => 0); --  calls _memset()
      for I in F'Range loop
         F (I) := Zq_Bit (Bits (I));
         pragma Loop_Invariant (for all K in 0 .. I => F (K) in Zq_Bit);
      end loop;
      pragma Assert (F in Poly_Zq_Bit);
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (Bits);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end ByteDecode1;

   -------------------------------------------------------
   --  Compression and Decompression for a width d
   --  (upstream CompressDU/DV, DecompressDU/DV,
   --  ByteEncodeDU/DV, ByteDecodeDU/DV, one text)
   -------------------------------------------------------

   package body Generic_Compression is

      function Compress (X : in Zq.T) return UD
      is
         C : constant U64 := U64 (UD'Modulus);
         T : U64;
      begin
         --  Add Q to the top-line, so that subsequent truncating division
         --  by 2Q is effectively "round to nearest"
         --    round-to-nearest(CX / Q) =
         --    floor((CX + 0.5Q)/Q) =
         --    floor((2CX + Q)/2Q)
         T := U64 (X) * 2 * C + Q;

         --  Division by (Q * 2) is first achieved by dividing by 2
         T := T / 2;

         --  Then multiplication by Q_M and a shift right by Q_C places
         T := T * Q_M;
         T := Shift_Right (T, Q_C);

         --  To return a value in UD, an explicit reduction is
         --  required here. This is missing in FIPS-203 Eq 4.5
         T := T mod C;
         return UD (T);
      end Compress;

      procedure Compress (V : in Poly_Zq; R : out Poly_UD)
      is
      begin
         for I in V'Range loop
            R (I) := Compress (V (I));
         end loop;
      end Compress;

      function Decompress (Y : in UD) return Zq.T
      is
         C      : constant I32 := I32 (UD'Modulus);
         Half_C : constant I32 := C / 2;
         subtype Int_T is I32 range 0 .. (Q * I32 (UD'Last) + Half_C);
         T : Int_T;
      begin
         T := Q * I32 (Y) + Half_C;
         T := T / C;
         pragma Assert (T >= 0);
         pragma Assert (T < Q);
         return Zq.T (T);
      end Decompress;

      procedure Decompress (Y : in Poly_UD; R : out Poly_Zq)
      is
      begin
         for I in R'Range loop
            R (I) := Decompress (Y (I));
         end loop;
      end Decompress;

      procedure ByteEncode (F : in Poly_UD; R : out Bytes_UD)
      is
         --  Bit accumulator, least significant bit first as in
         --  BitsToBytes: Fill pending bits sit at the bottom of Acc,
         --  each coefficient adds its D bits above them and whole
         --  bytes drain from the bottom. Fill is at most 7 between
         --  coefficients, so Acc never holds more than 7 + D bits.
         --  Out_Idx * 8 + Fill counts the bits consumed so far.
         Acc     : U32 := 0;
         Fill    : Natural := 0;
         Out_Idx : I32 := 0;
         DI      : constant I32 := I32 (D);
      begin
         R := (others => 0); --  calls _memset()
         for I in F'Range loop
            pragma Loop_Invariant (Fill <= 7);
            pragma Loop_Invariant (Out_Idx * 8 + I32 (Fill) = I * DI);
            Acc  := Acc or Shift_Left (U32 (F (I)), Fill);
            Fill := Fill + D;
            while Fill >= 8 loop
               pragma Loop_Invariant (Fill <= 7 + D);
               pragma Loop_Invariant
                 (Out_Idx * 8 + I32 (Fill) = (I + 1) * DI);
               R (Out_Idx) := Byte (Acc and 16#FF#);
               Acc     := Shift_Right (Acc, 8);
               Fill    := Fill - 8;
               Out_Idx := Out_Idx + 1;
            end loop;
         end loop;
         --  The (secret) bits still in the accumulator
         --  Scrub: to flow analysis these are dead stores, which is the point.
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "unused assignment");
         pragma Warnings (GNATprove, Off, "*not used after the call");
         Acc := 0;
         pragma Inspection_Point (Acc);
         pragma Warnings (GNATprove, On, "*not used after the call");
         pragma Warnings (GNATprove, On, "unused assignment");
         pragma Warnings (GNATprove, On, "statement has no effect");
      end ByteEncode;

      procedure ByteDecode (B : in Bytes_UD; F : out Poly_UD)
      is
         --  Inverse of ByteEncode: bytes enter the accumulator above
         --  the Fill pending bits, D bits leave from the bottom per
         --  coefficient. In_Idx * 8 counts the bits read so far.
         Acc    : U32 := 0;
         Fill   : Natural := 0;
         In_Idx : I32 := 0;
         DI     : constant I32 := I32 (D);
         Mask   : constant U32 := 2 ** D - 1;
      begin
         for I in F'Range loop
            pragma Loop_Invariant (Fill <= 7);
            pragma Loop_Invariant (In_Idx * 8 = I * DI + I32 (Fill));
            while Fill < D loop
               pragma Loop_Invariant (Fill < D);
               pragma Loop_Invariant (In_Idx * 8 = I * DI + I32 (Fill));
               Acc    := Acc or Shift_Left (U32 (B (In_Idx)), Fill);
               Fill   := Fill + 8;
               In_Idx := In_Idx + 1;
            end loop;
            F (I) := UD (Acc and Mask);
            Acc   := Shift_Right (Acc, D);
            Fill  := Fill - D;
         end loop;
         --  Scrub: to flow analysis these are dead stores, which is the point.
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "unused assignment");
         pragma Warnings (GNATprove, Off, "*not used after the call");
         Acc := 0;
         pragma Inspection_Point (Acc);
         pragma Warnings (GNATprove, On, "*not used after the call");
         pragma Warnings (GNATprove, On, "unused assignment");
         pragma Warnings (GNATprove, On, "statement has no effect");
      end ByteDecode;

   end Generic_Compression;

   --=======================================
   --  12-bit encoding
   --=======================================

   procedure ByteEncode12 (F : in NTT_Poly_Zq; R : out Bytes_384)
   is
      --  Two 12-bit coefficients fill three bytes, least significant
      --  bit first exactly as BitsToBytes lays them out: byte 0 is the
      --  low 8 bits of the first coefficient, byte 1 its high 4 bits
      --  under the low 4 bits of the second, byte 2 the high 8 bits of
      --  the second. Same bytes as the bit-array form of the standard,
      --  without expanding 3072 bits one at a time.
      A, B : U16;
   begin
      --  Every byte is written below; the aggregate is for flow analysis,
      --  which does not follow the 3 * I indexing.
      R := (others => 0); --  calls _memset()
      for I in Index_128 loop
         A := U16 (F (2 * I));
         B := U16 (F (2 * I + 1));
         R (3 * I)     := Byte (A and 16#FF#);
         R (3 * I + 1) := Byte (Shift_Right (A, 8) or
                                Shift_Left (B and 16#0F#, 4));
         R (3 * I + 2) := Byte (Shift_Right (B, 4));
      end loop;
      --  The (secret) coefficients held in scalars
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      A := 0;
      B := 0;
      pragma Inspection_Point (A);
      pragma Inspection_Point (B);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end ByteEncode12;

   procedure ByteDecode12 (B : in Bytes_384; F : out NTT_Poly_Zq)
   is
      --  Inverse of the three-bytes-per-pair layout in ByteEncode12.
      --  Each 12-bit value is at most 4095 and goes through ModQ as in
      --  the bit-array form.
      B0, B1, B2 : U16;
   begin
      --  Every coefficient is written below; the aggregate is for flow
      --  analysis, which does not follow the 2 * I indexing.
      F := (others => 0); --  calls _memset()
      for I in Index_128 loop
         B0 := U16 (B (3 * I));
         B1 := U16 (B (3 * I + 1));
         B2 := U16 (B (3 * I + 2));
         F (2 * I)     := ModQ (B0 or Shift_Left (B1 and 16#0F#, 8));
         F (2 * I + 1) := ModQ (Shift_Right (B1, 4) or Shift_Left (B2, 4));
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      B0 := 0;
      B1 := 0;
      B2 := 0;
      pragma Inspection_Point (B0);
      pragma Inspection_Point (B1);
      pragma Inspection_Point (B2);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end ByteDecode12;

   ----------------------------------
   --  NTT, NTT_Inv and Sampling
   ----------------------------------

   Max_Zeta  : constant := 3289;
   subtype Zeta_Entry is Zq.T range 0 .. Max_Zeta;
   type Zeta_Exp_Table_Type is array (SU7) of Zeta_Entry;

   Max_Gamma : constant := 3312;
   subtype Gamma_Entry is Zq.T range 0 .. Max_Gamma;
   type Gamma_Table_Type is array (Index_128) of Gamma_Entry;

   --  This table generated by MLKEM.Tests.Gen_Zeta_Exp_Table procedure
   Zeta_ExpC : constant Zeta_Exp_Table_Type :=
     (0 => 1,
      1 => 1729,
      2 => 2580,
      3 => 3289,
      4 => 2642,
      5 => 630,
      6 => 1897,
      7 => 848,
      8 => 1062,
      9 => 1919,
      10 => 193,
      11 => 797,
      12 => 2786,
      13 => 3260,
      14 => 569,
      15 => 1746,
      16 => 296,
      17 => 2447,
      18 => 1339,
      19 => 1476,
      20 => 3046,
      21 => 56,
      22 => 2240,
      23 => 1333,
      24 => 1426,
      25 => 2094,
      26 => 535,
      27 => 2882,
      28 => 2393,
      29 => 2879,
      30 => 1974,
      31 => 821,
      32 => 289,
      33 => 331,
      34 => 3253,
      35 => 1756,
      36 => 1197,
      37 => 2304,
      38 => 2277,
      39 => 2055,
      40 => 650,
      41 => 1977,
      42 => 2513,
      43 => 632,
      44 => 2865,
      45 => 33,
      46 => 1320,
      47 => 1915,
      48 => 2319,
      49 => 1435,
      50 => 807,
      51 => 452,
      52 => 1438,
      53 => 2868,
      54 => 1534,
      55 => 2402,
      56 => 2647,
      57 => 2617,
      58 => 1481,
      59 => 648,
      60 => 2474,
      61 => 3110,
      62 => 1227,
      63 => 910,
      64 => 17,
      65 => 2761,
      66 => 583,
      67 => 2649,
      68 => 1637,
      69 => 723,
      70 => 2288,
      71 => 1100,
      72 => 1409,
      73 => 2662,
      74 => 3281,
      75 => 233,
      76 => 756,
      77 => 2156,
      78 => 3015,
      79 => 3050,
      80 => 1703,
      81 => 1651,
      82 => 2789,
      83 => 1789,
      84 => 1847,
      85 => 952,
      86 => 1461,
      87 => 2687,
      88 => 939,
      89 => 2308,
      90 => 2437,
      91 => 2388,
      92 => 733,
      93 => 2337,
      94 => 268,
      95 => 641,
      96 => 1584,
      97 => 2298,
      98 => 2037,
      99 => 3220,
      100 => 375,
      101 => 2549,
      102 => 2090,
      103 => 1645,
      104 => 1063,
      105 => 319,
      106 => 2773,
      107 => 757,
      108 => 2099,
      109 => 561,
      110 => 2466,
      111 => 2594,
      112 => 2804,
      113 => 1092,
      114 => 403,
      115 => 1026,
      116 => 1143,
      117 => 2150,
      118 => 2775,
      119 => 886,
      120 => 1722,
      121 => 1212,
      122 => 1874,
      123 => 1029,
      124 => 2110,
      125 => 2935,
      126 => 885,
      127 => 2154);

   --  This table generated by MLKEM.Tests.Gen_Gamma_Table procedure
   Gamma_Table : constant Gamma_Table_Type :=
     (0 => 17,
      1 => 3312,
      2 => 2761,
      3 => 568,
      4 => 583,
      5 => 2746,
      6 => 2649,
      7 => 680,
      8 => 1637,
      9 => 1692,
      10 => 723,
      11 => 2606,
      12 => 2288,
      13 => 1041,
      14 => 1100,
      15 => 2229,
      16 => 1409,
      17 => 1920,
      18 => 2662,
      19 => 667,
      20 => 3281,
      21 => 48,
      22 => 233,
      23 => 3096,
      24 => 756,
      25 => 2573,
      26 => 2156,
      27 => 1173,
      28 => 3015,
      29 => 314,
      30 => 3050,
      31 => 279,
      32 => 1703,
      33 => 1626,
      34 => 1651,
      35 => 1678,
      36 => 2789,
      37 => 540,
      38 => 1789,
      39 => 1540,
      40 => 1847,
      41 => 1482,
      42 => 952,
      43 => 2377,
      44 => 1461,
      45 => 1868,
      46 => 2687,
      47 => 642,
      48 => 939,
      49 => 2390,
      50 => 2308,
      51 => 1021,
      52 => 2437,
      53 => 892,
      54 => 2388,
      55 => 941,
      56 => 733,
      57 => 2596,
      58 => 2337,
      59 => 992,
      60 => 268,
      61 => 3061,
      62 => 641,
      63 => 2688,
      64 => 1584,
      65 => 1745,
      66 => 2298,
      67 => 1031,
      68 => 2037,
      69 => 1292,
      70 => 3220,
      71 => 109,
      72 => 375,
      73 => 2954,
      74 => 2549,
      75 => 780,
      76 => 2090,
      77 => 1239,
      78 => 1645,
      79 => 1684,
      80 => 1063,
      81 => 2266,
      82 => 319,
      83 => 3010,
      84 => 2773,
      85 => 556,
      86 => 757,
      87 => 2572,
      88 => 2099,
      89 => 1230,
      90 => 561,
      91 => 2768,
      92 => 2466,
      93 => 863,
      94 => 2594,
      95 => 735,
      96 => 2804,
      97 => 525,
      98 => 1092,
      99 => 2237,
      100 => 403,
      101 => 2926,
      102 => 1026,
      103 => 2303,
      104 => 1143,
      105 => 2186,
      106 => 2150,
      107 => 1179,
      108 => 2775,
      109 => 554,
      110 => 886,
      111 => 2443,
      112 => 1722,
      113 => 1607,
      114 => 1212,
      115 => 2117,
      116 => 1874,
      117 => 1455,
      118 => 1029,
      119 => 2300,
      120 => 2110,
      121 => 1219,
      122 => 2935,
      123 => 394,
      124 => 885,
      125 => 2444,
      126 => 2154,
      127 => 1175);



   --  Algorithm 7 - SampleNTT and XOF
   --  For this implementation, we combine XOF and SampleNTT
   --  into a single function. This avoids the need for XOF
   --  to return an unbounded sequence of bytes and/or some
   --  sort of lazy evaluation of an infinite sequence.

   function XOF_Then_SampleNTT (B : in Bytes_34) return NTT_Poly_Zq
   is
      --  One SHAKE128 rate block: 168 bytes, 56 three-byte groups
      subtype Index_168 is I32 range 0 .. 167;
      subtype Bytes_168 is Byte_Seq (Index_168);

      Ctx : SHAKE128.Context;
      J2  : Natural := 0;
      A   : NTT_Poly_Zq := (others => 0); --  calls _memset()
      Blk : Bytes_168;
   begin
      --  Initialize and feed input data into the XOF function
      --  which is actually SHAKE128
      SHAKE128.Init (Ctx);
      SHAKE128.Update (Ctx, SHAKE128.Byte_Array (B));

      while J2 < 256 loop
         --  The XOF output is taken one rate block at a time and the
         --  block is walked in three-byte groups, each giving the two
         --  candidates of algorithm 7. Bytes left over when the 256th
         --  sample lands are discarded with the context, so the result
         --  is the one the standard's three-bytes-per-step reading of
         --  the same stream produces.
         SHAKE128.Extract (Ctx, SHAKE128.Byte_Array (Blk));
         for T in I32 range 0 .. 55 loop
            pragma Loop_Invariant (J2 <= 256);
            declare
               D1 : constant U16 :=
                 U16 (Blk (3 * T)) + (256 * (U16 (Blk (3 * T + 1)) mod 16));
               D2 : constant U16 :=
                 U16 (Blk (3 * T + 1)) / 16 + (16 * U16 (Blk (3 * T + 2)));
            begin
               if D1 < Q and J2 < 256 then
                  A (Index_256 (J2)) := Zq.T (D1);
                  J2 := J2 + 1;
               end if;
               if D2 < Q and J2 < 256 then
                  A (Index_256 (J2)) := Zq.T (D2);
                  J2 := J2 + 1;
               end if;
            end;
         end loop;
      end loop;
      --  Termination of the rejection-sampling loop is probabilistic, as
      --  in FIPS 203 algorithm 7, which imposes no bound: each 3-byte XOF
      --  block yields two candidates, each accepted with probability
      --  3329/4096, so 256 samples need about 158 blocks and the chance
      --  of needing more than 1000 is below 2**-500. GNATprove 16 reports
      --  the loop as possibly non-terminating (it has no variant: J2 does
      --  not advance on a rejected candidate); upstream justified the same
      --  fact on the loop variant check of earlier tool versions.
      pragma Annotate (GNATprove,
                       False_Positive,
                       "loop might be nonterminating",
                       "FIPS 203 algorithm 7 rejection sampling terminates "
                       & "with overwhelming probability; no bound in the standard");
      return A;
   end XOF_Then_SampleNTT;

   procedure NTT (F : in Poly_Zq; F_Hat : out NTT_Poly_Zq)
   is
      subtype K_T is Byte range 1 .. 128;
      K     : K_T;
      Len   : Len_T;
      Count : Count_T;

      procedure NTT_Inner (Zeta  : in     Zq.T;
                           Start : in     Index_256)
        with No_Inline,
             Global => (In_Out => F_Hat,
                        Input  => Len),
             Pre    => Start <= 252 and
                       Start + 2 * Len <= 256
      is
         T : Zq.T;
      begin
         for J in Index_256 range Start .. Start + (Len - 1) loop
            T               := Zeta * F_Hat (J + Len);
            F_Hat (J + Len) := F_Hat (J) - T;
            F_Hat (J)       := F_Hat (J) + T;
         end loop;
      end NTT_Inner;

   begin
      F_Hat := NTT_Poly_Zq (F); --  calls _memcpy()
      K     := 1;

      for I in NTT_Len_Bit_Index loop
         --  When I = 0, Len = 128, Count = 1
         --       I = 1, Len =  64, Count = 2
         --       ...
         --       I = 6, Len =   2, Count = 64
         Len   := 2**(7 - I);
         Count := 2**I;
         for J in I32 range 0 .. Count - 1 loop
            pragma Loop_Invariant (Count * Len = 128);
            pragma Loop_Invariant (J * 2 * Len <= 252);
            pragma Loop_Invariant (I32 (K) = 2**I + J);
            NTT_Inner (Zeta  => Zeta_ExpC (K),
                       Start => J * 2 * Len);
            K := K + 1;
         end loop;

         --  When the inner loop terminates, K has been
         --  incremented Count times, therefore...
         pragma Assert (I32 (K) = 2**I + Count);
         --  But we know that Count = 2**I, so...
         pragma Assert (I32 (K) = 2 * 2**I);
         pragma Assert (I32 (K) = 2**(I + 1));
         pragma Loop_Invariant (2**(I + 1) <= 128);
         pragma Loop_Invariant (I32 (K) = 2**(I + 1));
      end loop;
      pragma Assert (K = 128);
   end NTT;

   procedure NTT_Inv (F : in NTT_Poly_Zq; F_Hat : out Poly_Zq)
   is
      subtype K_T is Byte range 0 .. 127;
      K     : K_T;
      Len   : Len_T;
      Count : Count_T;

      procedure NTT_Inv_Inner (Zeta  : in     Zq.T;
                               Start : in     Index_256)
        with No_Inline,
             Global => (In_Out => F_Hat,
                        Input => Len),
             Pre    => Start <= 252 and
                       Start + 2 * Len <= 256
      is
         T : Zq.T;
      begin
         for J in Index_256 range Start .. Start + (Len - 1) loop
            T := F_Hat (J);
            F_Hat (J) := T + F_Hat (J + Len);
            F_Hat (J + Len) := Zeta * (F_Hat (J + Len) - T);
         end loop;
      end NTT_Inv_Inner;
   begin
      F_Hat := Poly_Zq (F); --  calls _memcpy()
      K     := 127;

      --  note "reverse" loop here for NTT_Inv
      for I in reverse NTT_Len_Bit_Index loop
         --  When I = 6, Len =   2, Count = 64
         --       I = 5, Len =   4, Count = 32
         --       ...
         --       I = 0, Len = 128, Count = 1
         Len   := 2**(7 - I);
         Count := 2**I;
         for J in I32 range 0 .. Count - 1 loop
            pragma Loop_Invariant (Count * Len = 128);
            --  A bit of spoon-feeding the prover here to help it work
            --  out that J * 2 * Len <= 252
            pragma Loop_Invariant (J <= Count - 1);
            pragma Loop_Invariant (J * 2 <= (Count - 1) * 2);
            pragma Loop_Invariant (J * 2 * Len <= (Count - 1) * 2 * Len);
            pragma Loop_Invariant (J * 2 * Len <= Count * 2 * Len - 2 * Len);
            pragma Loop_Invariant (J * 2 * Len <= 2**I * 2 * 2**(7 - I) - 2 * 2**(7 - I));
            pragma Loop_Invariant (J * 2 * Len <= 256 - 2 * 2**(7 - I));
            pragma Loop_Invariant (J * 2 * Len <= 256 - 2**(8 - I));
            pragma Loop_Invariant (J * 2 * Len <= 252);

            pragma Loop_Invariant (I32 (K) = 2**I + Count - J - 1);

            NTT_Inv_Inner (Zeta  => Zeta_ExpC (K),
                           Start => J * 2 * Len);
            K := K - 1;
         end loop;

         --  When the inner loop terminates, K has been
         --  decremented Count times, therefore
         --  K = 2**I + Count - Count - 1, which simplifies to
         pragma Loop_Invariant (I32 (K) = 2**I - 1);
      end loop;

      --  Substitute I = 0 into the outer loop invariant to get
      pragma Assert (K = 0);
      --  Multiply by 128**-1 mod q (= 3303), in place.
      for I in F_Hat'Range loop
         F_Hat (I) := F_Hat (I) * 3303; --  implicitly mod q
      end loop;
   end NTT_Inv;

   procedure MultiplyNTTs (F, G : in NTT_Poly_Zq; H : out NTT_Poly_Zq)
   is
   begin
      for I in Index_128 loop
         declare
            A0    : constant Zq.T := F (2 * I);
            A1    : constant Zq.T := F (2 * I + 1);
            B0    : constant Zq.T := G (2 * I);
            B1    : constant Zq.T := G (2 * I + 1);
            Gamma : constant Zq.T := Gamma_Table (I);
            B1G   : constant Zq.T := B1 * Gamma;
         begin
            H (2 * I)     := (A0 * B0) + (A1 * B1G);
            H (2 * I + 1) := (A0 * B1) + (A1 * B0);
         end;
         pragma Loop_Invariant
           (for all K in Index_256 range 0 .. I * 2 + 1 => H (K)'Initialized);
      end loop;
   end MultiplyNTTs;

   function Byte_Seq_Equal (X, Y : in Byte_Seq) return Boolean
   is
      D : Boolean := True;
      I : N32 := X'First;
   begin
      --  Explicit loop statement here to avoid dead branch that
      --  a "for" loop generates when X'Length = 0
      loop
         D := D and (X (I) = Y (I));
         pragma Loop_Invariant
           (I >= X'First and I <= X'Last and
            (D = (for all J in N32 range X'First .. I => X (J) = Y (J))));
         pragma Loop_Variant (Increases => I);
         exit when I = X'Last;
         I := I + 1;
      end loop;
      return D;
   end Byte_Seq_Equal;

   -------------------------------------------------------
   --  PRF and SamplePolyCBD for a given eta (upstream
   --  PRF_Eta_1/2 and SamplePolyCBD_Eta_1/2, one text)
   -------------------------------------------------------

   package body Generic_CBD is

      procedure PRF (S : in     Bytes_32;
                     B : in     Byte;
                     R :    out PRF_Bytes)
      is
         C : SHAKE256.Context;
      begin
         --  Scrub statements below: dead stores to flow analysis, which is
         --  the point; the context is set by Extract and then re-initialised.
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "unused assignment");
         pragma Warnings (GNATprove, Off, "*not used after the call");
         SHAKE256.Init (C);
         SHAKE256.Update (C, SHAKE256.Byte_Array (S));
         SHAKE256.Update (C, SHAKE256.Byte_Array'(0 => B));
         SHAKE256.Extract (C, SHAKE256.Byte_Array (R));
         SHAKE256.Init (C);
         pragma Inspection_Point (C);
         pragma Warnings (GNATprove, On, "*not used after the call");
         pragma Warnings (GNATprove, On, "unused assignment");
         pragma Warnings (GNATprove, On, "statement has no effect");
      end PRF;

      --  Algorithm 8 - SamplePolyCBD
      procedure SamplePolyCBD (B : in PRF_Bytes; F : out Poly_Zq)
      is
         EtaI : constant I32 := I32 (Eta);
         subtype Index_PRF_Bits is I32 range 0 .. 8 * 64 * EtaI - 1;
         subtype PRF_Bits is Bit_Seq (Index_PRF_Bits);

         procedure BytesToBits is new Generic_BytesToBits
           (Index_PRF_Bytes, PRF_Bytes,
            Index_PRF_Bits, PRF_Bits);

         SB : PRF_Bits;

         subtype Bit_Sum is Natural range 0 .. Eta;

         function Sum_X (I : in Index_256) return Bit_Sum
           with No_Inline,
                Global => SB
         is
            R : Bit_Sum := 0;
         begin
            for J in Index_PRF_Bytes range 0 .. EtaI - 1 loop
               pragma Loop_Invariant (R >= 0);
               pragma Loop_Invariant (R <= Natural (J));
               R := R + Natural (SB (2 * I * EtaI + J));
            end loop;
            return R;
         end Sum_X;

         function Sum_Y (I : in Index_256) return Bit_Sum
           with No_Inline,
                Global => SB
         is
            R : Bit_Sum := 0;
         begin
            for J in Index_PRF_Bytes range 0 .. EtaI - 1 loop
               pragma Loop_Invariant (R >= 0);
               pragma Loop_Invariant (R <= Natural (J));
               R := R + Natural (SB (2 * I * EtaI + EtaI + J));
            end loop;
            return R;
         end Sum_Y;

      begin
         BytesToBits (B, SB);
         for I in Index_256 loop
            declare
               X : constant Bit_Sum := Sum_X (I);
               Y : constant Bit_Sum := Sum_Y (I);
            begin
               --  This "-" _is_ modulo Q
               F (I) := Zq.T (X) - Zq.T (Y); --  implicitly mod Q
            end;
         end loop;
         --  Scrub: to flow analysis these are dead stores, which is the point.
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "unused assignment");
         pragma Warnings (GNATprove, Off, "*not used after the call");
         Sanitize (SB);
         pragma Warnings (GNATprove, On, "*not used after the call");
         pragma Warnings (GNATprove, On, "unused assignment");
         pragma Warnings (GNATprove, On, "statement has no effect");
      end SamplePolyCBD;

   end Generic_CBD;

end MLKEM;
