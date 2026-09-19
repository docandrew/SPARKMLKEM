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
--
--  Style rule of this crate (FIPS 203 section 3.3, destruction of
--  intermediate values): a function returns only a public value. Every
--  operation whose result or operands are secret is a procedure with an
--  out parameter, so the value has a name and its owner sanitises it;
--  secret temporaries inside the core are sanitised before return; hash
--  contexts are re-initialised after use (libkeccak's Init clears the
--  state and the block buffer); no secret is passed through "&".

with Interfaces; use Interfaces;
package MLKEM
  with SPARK_Mode => On
is
   --==============================================
   --  Constants common to all parameter sets
   --  from FIPS 203 section 8
   --==============================================
   Q      : constant := 3329;
   N      : constant := 256;

   subtype Byte is Unsigned_8;
   subtype I32  is Integer_32;
   subtype N32  is I32 range 0 .. I32'Last;

   --  Unconstrained (aka "Size Polymorphic") array of bytes
   type Byte_Seq is array (N32 range <>) of Byte;

   subtype Index_32  is I32 range 0 .. 31;
   subtype Bytes_32  is Byte_Seq (Index_32);

   subtype Index_64  is I32 range 0 .. 63;
   subtype Bytes_64  is Byte_Seq (Index_64);

   --  Overwrite R with zeros in a way the optimiser cannot remove
   --  (SPARKNaCl's idiom: a No_Inline procedure and an inspection point).
   procedure Sanitize (R : out Byte_Seq)
     with No_Inline,
          Global => null,
          Post   => (for all I in R'Range => R (I) = 0);

private
   subtype U16 is Unsigned_16;
   subtype U32 is Unsigned_32;
   subtype U64 is Unsigned_64;
   subtype I64 is Integer_64;

   subtype SU7 is Byte range 0 .. 127;

   subtype Index_128 is I32 range 0 .. 127;

   --  We wrap type Zq.T in its own package so we can precisely control
   --  which operators ("+", "-", "*" etc) are available for it, and how
   --  they are implemented.
   --
   --  This package is declared here, so it is visible to the public
   --  child package MLKEM.Tests
   package Zq
     with SPARK_Mode => On
   is
      --  In theory, Zq could fit in 12 bits, but force compiler
      --  to represent in 16 bits for natural convenience and efficiency
      type T is mod Q
        with Object_Size => 16;

      subtype Zq_Bit is T range 0 .. 1;

      --  OVERRIDE the opertors that we wish to allow for T, but
      --  to allow for implementations which are specific to a particular
      --  CPU and/or constant-time at all optimization levels.
      function "+" (Left, Right : in T) return T
         with Inline,
              Global => null,
              Post => "+"'Result = T ((I32 (Left) + I32 (Right)) mod Q);

      function "-" (Left, Right : in T) return T
         with Inline,
              Global => null,
              Post => "-"'Result = T ((I32 (Left) - I32 (Right)) mod Q);

      function "*" (Left, Right : in T) return T
         with Inline,
              Global => null,
              Post => "*"'Result = T ((I64 (Left) * I64 (Right)) mod Q);

      --  Divide "Right" by 2
      function Div2 (Right : in T) return T
         with Inline_Always,
              Global => null;

      --  Returns X mod Q, but implemented in constant time.
      subtype U16_12Bits is U16 range 0 .. 4095;
      function ModQ (X : in U16_12Bits) return T
         with Inline,
              Global => null,
              Post   => ModQ'Result = T (X mod Q);

      --  Forbid all other predefined operators on T
      function "+"   (Right : in T) return T is abstract;
      function "-"   (Right : in T) return T is abstract;
      function "abs" (Right : in T) return T is abstract;
      function "/"   (Left, Right : in T) return T is abstract;
      function "mod" (Left, Right : in T) return T is abstract;
      function "rem" (Left, Right : in T) return T is abstract;
      function "**"  (Left : in T; Right : in Natural) return T is abstract;

      --  Stop the compiler warning about unreferenced entities
      pragma Unreferenced ("+");
      pragma Unreferenced ("-");
      pragma Unreferenced ("abs");
      pragma Unreferenced ("/");
      pragma Unreferenced ("mod");
      pragma Unreferenced ("rem");
   end Zq;

   subtype U8_Bit is Unsigned_8 range 0 .. 1;

   subtype Index_256 is I32 range 0 .. 255;
   type Poly_Zq is array (Index_256) of Zq.T;

   --  Polynomials in the NTT domain are structurally identical to the
   --  above, but should never be mixed up with them, so we declare
   --  an explicitly derived named types for them here.
   type NTT_Poly_Zq is new Poly_Zq;

   subtype Index_3    is I32 range 0 .. 2;
   subtype Index_8    is I32 range 0 .. 7;
   subtype Index_12   is I32 range 0 .. 11;
   subtype Index_34   is I32 range 0 .. 33;
   subtype Index_384  is I32 range 0 .. 383;
   subtype Index_3072 is I32 range 0 .. 3071;

   subtype Bytes_3   is Byte_Seq (Index_3);
   subtype Bytes_34  is Byte_Seq (Index_34);
   subtype Bytes_384 is Byte_Seq (Index_384);

   --  Array of bits, bit each bit stored as a Byte, so
   --  ineffecient in terms of space
   type Bit_Seq is array (N32 range <>) of U8_Bit;

   subtype Bits_12   is Bit_Seq (Index_12);
   subtype Bits_256  is Bit_Seq (Index_256);
   subtype Bits_3072 is Bit_Seq (Index_3072);

   subtype Poly_Zq_Bit is Poly_Zq
     with Dynamic_Predicate =>
            (for all I in Poly_Zq_Bit'Range => Poly_Zq_Bit (I) in Zq.Zq_Bit);

   Null_NTT_Poly_Zq : constant NTT_Poly_Zq := (others => 0);

   procedure Sanitize (R : out Bit_Seq)
     with No_Inline,
          Global => null,
          Post   => (for all I in R'Range => R (I) = 0);

   procedure Sanitize (R : out Poly_Zq)
     with No_Inline,
          Global => null,
          Post   => (for all I in R'Range => Zq."=" (R (I), 0));

   procedure Sanitize (R : out NTT_Poly_Zq)
     with No_Inline,
          Global => null,
          Post   => (for all I in R'Range => Zq."=" (R (I), 0));

   -----------------------------------------
   --  Basic mathematical operators on
   --  polynomials
   -----------------------------------------

   procedure Add (Left, Right : in NTT_Poly_Zq; R : out NTT_Poly_Zq)
     with No_Inline, Global => null;

   --  R := R + X, for accumulations
   procedure Add_To (R : in out NTT_Poly_Zq; X : in NTT_Poly_Zq)
     with No_Inline, Global => null;

   procedure Add (Left, Right : in Poly_Zq; R : out Poly_Zq)
     with No_Inline, Global => null;

   procedure Sub (Left, Right : in Poly_Zq; R : out Poly_Zq)
     with No_Inline, Global => null;

   ----------------------------------
   --  Hash functions, built on SHA3
   --  See FIPS 203 4.1
   ----------------------------------

   --  G (A || B) returns a (32 bytes) followed by b (32 bytes)
   --  concatenated into 64 bytes. Two inputs so that callers never
   --  concatenate a secret.
   procedure G (A, B : in Byte_Seq; R : out Bytes_64)
     with No_Inline,
          Global => null,
          Pre    => A'First = 0 and B'First = 0 and
                    A'Last <= I32 (Natural'Last - 1) and
                    B'Last <= I32 (Natural'Last - 1);

   procedure H (C : in Byte_Seq; R : out Bytes_32)
     with No_Inline,
          Global => null,
          Pre    => C'First = 0 and
                    C'Last <= I32 (Natural'Last - 1);

   --  J (A || B)
   procedure J (A, B : in Byte_Seq; R : out Bytes_32)
     with No_Inline,
          Global => null,
          Pre    => A'First = 0 and B'First = 0 and
                    A'Last <= I32 (Natural'Last - 1) and
                    B'Last <= I32 (Natural'Last - 1);

   ----------------------------------
   --  BitsToBytes and BytesToBits
   --  See FIPS 203 4.2.1
   ----------------------------------

   --  Algorithm 3
   --  BitsToBytes is generic here over its parameter and result types
   --  so that each instantiation of it has definite/constrained types.
   --  This avoids the need for unconstrained parameters and return types,
   --  and this avoids the need for secondary stack and/or heap usage
   --  at run-time.
   generic
      type Bits_Index is range <>;
      type Some_Bits is array (Bits_Index) of U8_Bit;
      type Bytes_Index is range <>;
      type Some_Bytes is array (Bytes_Index) of Byte;
   procedure Generic_BitsToBytes (B : in Some_Bits; R : out Some_Bytes)
     with No_Inline,
          Global => null,
          Pre    => B'First = 0 and
                    B'Length >= 8 and   --  at least 1 byte's worth
                    B'Length mod 8 = 0 and --  an exact multiple of 8 bits
                    R'First = 0 and
                    R'Length * 8 = B'Length;

   --  Algorithm 4
   --  Similarly, BytesToBits is generic to avoid unconstrained types
   generic
      type Bytes_Index is range <>;
      type Some_Bytes is array (Bytes_Index) of Byte;
      type Bits_Index is range <>;
      type Some_Bits is array (Bits_Index) of U8_Bit;
   procedure Generic_BytesToBits (B : in Some_Bytes; R : out Some_Bits)
     with No_Inline,
          Global => null,
          Pre    => B'First = 0 and
                    U32 (B'Length) <= U32 (I32'Last / 8) and
                    R'First = 0 and
                    R'Length = 8 * B'Length;

   -------------------------------------------------------
   --  Compression, decompression, byte encoding and
   --  decoding for d = 1 (FIPS 203 4.2.1, algorithms 5
   --  and 6, equations 4.7 and 4.8)
   -------------------------------------------------------

   function Compress1 (X : in Zq.T) return U8_Bit
     with No_Inline, Global => null;

   procedure Compress1 (X : in Poly_Zq; R : out Bits_256)
     with No_Inline, Global => null;

   function Decompress1 (Y : in U8_Bit) return Zq.T
     with No_Inline, Global => null;

   --  Decompress a vector of Zq_Bit values
   procedure Decompress1 (Y : in Poly_Zq_Bit; R : out Poly_Zq)
     with No_Inline, Global => null;

   --  256 1-bit digits is 256 bits, which is 32 bytes
   procedure ByteEncode1 (F : in Bits_256; R : out Bytes_32)
     with No_Inline, Global => null;

   procedure ByteDecode1 (B : in Bytes_32; F : out Poly_Zq_Bit)
     with No_Inline, Global => null;

   -------------------------------------------------------
   --  The same four operations for a compression width d
   --  in 2 .. 11 (the ciphertext widths du and dv of the
   --  three parameter sets). UD is the modular type of a
   --  d-bit value, mod 2**d, stored in 16 bits. Upstream
   --  wrote this family once per width; it is one generic
   --  here, instantiated per parameter set.
   -------------------------------------------------------

   generic
      D : in Positive;
      type UD is mod <>;
   package Generic_Compression is
      subtype Index_Bits_UD is I32 range 0 .. I32 (N * D) - 1;
      subtype Bits_UD is Bit_Seq (Index_Bits_UD);
      subtype Index_Bytes_UD is I32 range 0 .. I32 (N * D) / 8 - 1;
      subtype Bytes_UD is Byte_Seq (Index_Bytes_UD);
      type Poly_UD is array (Index_256) of UD;

      function Compress (X : in Zq.T) return UD
        with No_Inline, Global => null;

      procedure Compress (V : in Poly_Zq; R : out Poly_UD)
        with No_Inline, Global => null;

      function Decompress (Y : in UD) return Zq.T
        with No_Inline, Global => null;

      procedure Decompress (Y : in Poly_UD; R : out Poly_Zq)
        with No_Inline, Global => null;

      procedure ByteEncode (F : in Poly_UD; R : out Bytes_UD)
        with No_Inline, Global => null;

      procedure ByteDecode (B : in Bytes_UD; F : out Poly_UD)
        with No_Inline, Global => null;
   end Generic_Compression;

   -------------------------------------------------------
   --  12-bit encoding of a polynomial in the NTT domain
   -------------------------------------------------------

   procedure ByteEncode12 (F : in NTT_Poly_Zq; R : out Bytes_384)
     with No_Inline, Global => null;

   procedure ByteDecode12 (B : in Bytes_384; F : out NTT_Poly_Zq)
     with No_Inline, Global => null;

   -------------------------------------------------------
   --  Sampling (FIPS 203 4.2.2)
   -------------------------------------------------------

   --  Algorithm 7 - SampleNTT and XOF combined. A function: its input
   --  (rho, published in the encapsulation key) and output (the matrix
   --  A) are public.
   function XOF_Then_SampleNTT (B : in Bytes_34) return NTT_Poly_Zq
     with No_Inline, Global => null;

   --  Algorithm 8 - SamplePolyCBD with its PRF (FIPS 203 4.1), for a
   --  given eta. Upstream wrote this once per eta; it is one generic
   --  here, instantiated per parameter set.
   generic
      Eta : in Positive;
   package Generic_CBD is
      subtype Index_PRF_Bytes is I32 range 0 .. I32 (64 * Eta) - 1;
      subtype PRF_Bytes is Byte_Seq (Index_PRF_Bytes);

      procedure PRF (S : in     Bytes_32;
                     B : in     Byte;
                     R :    out PRF_Bytes)
        with No_Inline, Global => null;

      procedure SamplePolyCBD (B : in PRF_Bytes; F : out Poly_Zq)
        with No_Inline, Global => null;
   end Generic_CBD;

   -------------------------------------------------------
   --  NTT (FIPS 203 4.3)
   -------------------------------------------------------

   --  Algorithm 9
   procedure NTT (F : in Poly_Zq; F_Hat : out NTT_Poly_Zq)
     with No_Inline, Global => null;

   --  Algorithm 10
   procedure NTT_Inv (F : in NTT_Poly_Zq; F_Hat : out Poly_Zq)
     with No_Inline, Global => null;

   --  Algorithms 11 and 12
   --  BaseCaseMultiply is inlined here in MultiplyNTTs
   procedure MultiplyNTTs (F, G : in NTT_Poly_Zq; H : out NTT_Poly_Zq)
     with No_Inline,
          Global => null,
          Relaxed_Initialization => H,
          Post => H'Initialized;

   -------------------------------------------------------
   --  Constant time equality test for unconstrained
   --  Byte_Seq's, where bounds match exactly.
   -------------------------------------------------------

   function Byte_Seq_Equal (X, Y : in Byte_Seq) return Boolean
     with No_Inline,
          Global => null,
          Pre    => X'First = Y'First and
                    X'Last  = Y'Last and
                    X'Length >= 1 and
                    Y'Length >= 1 and
                    X'Length = Y'Length,
          Post   => Byte_Seq_Equal'Result =
                      (for all I in X'Range => X (I) = Y (I));

end MLKEM;
