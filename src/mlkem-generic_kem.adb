--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0
--
--  Modified for SPARKMLKEM (SPARKTLS project), 2026-09-15: see the spec
--  and CHANGES_FROM_UPSTREAM.md. The algorithms are the upstream text with
--  k, eta and the widths as generic formals, rewritten in procedural
--  style: every secret intermediate is a named object sanitised before
--  the subprogram returns, hashes take their inputs in pieces so no
--  secret is concatenated, and only public values are returned from
--  functions. The per-width and per-eta operations are the instances
--  Comp_U, Comp_V, CBD_1 and CBD_2 of the core generics; the sequential
--  K_PKE_KeyGen subunit is a plain procedure here (the tasking variant
--  was not imported).

package body MLKEM.Generic_KEM
  with SPARK_Mode => On
is
   package CBD_1  is new Generic_CBD (Eta_1);
   package CBD_2  is new Generic_CBD (Eta_2);
   package Comp_U is new Generic_Compression (Positive (DU), UDU);
   package Comp_V is new Generic_Compression (Positive (DV), UDV);

   --=======================================
   --  Local constants and types
   --=======================================

   subtype K_Range is I32 range 0 .. K - 1;

   type Poly_Zq_Vector     is array (K_Range) of Poly_Zq;
   type NTT_Poly_Zq_Vector is array (K_Range) of NTT_Poly_Zq;
   type NTT_Poly_Matrix    is array (K_Range) of NTT_Poly_Zq_Vector;
   type Poly_UDU_Vector    is array (K_Range) of Comp_U.Poly_UD;

   subtype Index_Poly_UDU_Bytes is I32 range 0 .. ((N * DU * K) / 8 - 1);
   subtype Poly_UDU_Bytes is Byte_Seq (Index_Poly_UDU_Bytes);

   subtype Index_Poly_Zq_Vector_Bytes is I32 range 0 .. (384 * K - 1);
   subtype Poly_Zq_Vector_Bytes is Byte_Seq (Index_Poly_Zq_Vector_Bytes);

   ------------------
   --  PKE Keys
   ------------------

   subtype PKE_Decryption_Key_Index is I32 range 0 .. (384 * K - 1);
   subtype PKE_Decryption_Key is Byte_Seq (PKE_Decryption_Key_Index);

   subtype PKE_Encryption_Key is MLKEM_Encapsulation_Key;

   --=======================================
   --  Sanitisation of vectors
   --=======================================

   procedure Sanitize (R : out Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      R := (others => (others => 0));
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      pragma Inspection_Point (R);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Sanitize;

   procedure Sanitize (R : out NTT_Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      R := (others => (others => 0));
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      pragma Inspection_Point (R);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Sanitize;

   --=======================================
   --  Vector and matrix operators
   --=======================================

   procedure Add (Left, Right : in NTT_Poly_Zq_Vector; R : out NTT_Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in R'Range loop
         Add (Left (I), Right (I), R (I));
      end loop;
   end Add;

   procedure Add (Left, Right : in Poly_Zq_Vector; R : out Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in R'Range loop
         Add (Left (I), Right (I), R (I));
      end loop;
   end Add;

   procedure CompressDU (V : in Poly_Zq_Vector; R : out Poly_UDU_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in V'Range loop
         Comp_U.Compress (V (I), R (I));
      end loop;
   end CompressDU;

   --  Applies DecompressDU to all elements of V
   procedure DecompressDU (V : in Poly_UDU_Vector; R : out Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in K_Range loop
         Comp_U.Decompress (V (I), R (I));
      end loop;
   end DecompressDU;

   procedure ByteEncodeDU (F : in Poly_UDU_Vector; R : out Poly_UDU_Bytes)
     with No_Inline,
          Global => null,
          Relaxed_Initialization => R,
          Post => R'Initialized
   is
      C : constant I32 := (N * DU) / 8;
   begin
      for I in K_Range loop
         Comp_U.ByteEncode (F (I), R (I32 (I) * C .. (I32 (I) + 1) * C - 1));
         pragma Loop_Invariant (R (0 .. (I32 (I) + 1) * C - 1)'Initialized);
      end loop;
      --  Substitute K for I + 1 in the loop invariant to get...
      pragma Assert (R (0 .. (K * C - 1))'Initialized);
      --  ...and therefore...
      pragma Assert (R'Initialized);
   end ByteEncodeDU;

   procedure ByteDecodeDU (B : in Poly_UDU_Bytes; R : out Poly_UDU_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in K_Range loop
         Comp_U.ByteDecode (B (I32 (I) * 32 * DU .. (I32 (I) + 1) * 32 * DU - 1),
                            R (I));
      end loop;
   end ByteDecodeDU;

   --  Applies ByteEncode12 to all elements of V
   procedure ByteEncode12 (V : in NTT_Poly_Zq_Vector; R : out Poly_Zq_Vector_Bytes)
     with No_Inline,
          Global => null,
          Relaxed_Initialization => R,
          Post => R'Initialized
   is
   begin
      for I in K_Range loop
         ByteEncode12 (V (I), R (I32 (I) * 384 .. I32 (I) * 384 + 383));
         pragma Loop_Invariant (R (0 .. I32 (I) * 384 + 383)'Initialized);
      end loop;
      pragma Assert (R'Initialized);
   end ByteEncode12;

   procedure ByteDecode12 (B : in Poly_Zq_Vector_Bytes; R : out NTT_Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in K_Range loop
         ByteDecode12 (B (384 * I32 (I) .. 384 * I32 (I) + 383), R (I));
      end loop;
   end ByteDecode12;

   --  Applies NTT to all elements of V
   procedure NTT (V : in Poly_Zq_Vector; R : out NTT_Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in R'Range loop
         NTT (V (I), R (I));
      end loop;
   end NTT;

   --  Applies NTT_Inv to all elements of V
   procedure NTT_Inv (V : in NTT_Poly_Zq_Vector; R : out Poly_Zq_Vector)
     with No_Inline, Global => null
   is
   begin
      for I in R'Range loop
         NTT_Inv (V (I), R (I));
      end loop;
   end NTT_Inv;

   --  FIPS 203 2.4.7 defines a "dot product" operator between
   --  matrices and vectors of Poly_Zq: R := Left * Right
   procedure Matrix_Vector_Mul (Left  : in     NTT_Poly_Matrix;
                                Right : in     NTT_Poly_Zq_Vector;
                                R     :    out NTT_Poly_Zq_Vector)
     with No_Inline,
          Global => null,
          Relaxed_Initialization => R,
          Post => R'Initialized
   is
      T : NTT_Poly_Zq;
   begin
      for I in K_Range loop
         --  Unroll the first iteration of the inner loop to avoid
         --  need to pre-initialize R with all 0 values
         MultiplyNTTs (Left (I) (0), Right (0), R (I));
         pragma Loop_Invariant (for all P in K_Range range 0 .. I => R (P)'Initialized);
         for J in K_Range range 1 .. K_Range'Last loop
            pragma Loop_Invariant (for all P in K_Range range 0 .. I => R (P)'Initialized);
            MultiplyNTTs (Left (I) (J), Right (J), T);
            Add_To (R (I), T);
         end loop;
      end loop;
      --  The partial products may involve a secret operand
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (T);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Matrix_Vector_Mul;

   --  Dot product of K-length vectors of NTT_Poly_Zq.
   --  third equation
   procedure Dot (Left, Right : in NTT_Poly_Zq_Vector; R : out NTT_Poly_Zq)
     with No_Inline, Global => null
   is
      T : NTT_Poly_Zq;
   begin
      --  Unroll the first iteration of the loop to avoid
      --  need to pre-initialize R with all 0 values
      MultiplyNTTs (Left (0), Right (0), R);
      for J in K_Range range 1 .. K_Range'Last loop
         MultiplyNTTs (Left (J), Right (J), T);
         Add_To (R, T);
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (T);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Dot;

   -------------------------------------
   --  K-PKE KeyGen, Encrypt and Decrypt
   -------------------------------------

   --  A function: the matrix A is public.
   function Transpose (X : in NTT_Poly_Matrix) return NTT_Poly_Matrix
     with No_Inline
   is
      T : NTT_Poly_Matrix := (others => (others => Null_NTT_Poly_Zq)); --  calls _memset()
   begin
      for I in K_Range loop
         for J in K_Range loop
            T (J) (I) := X (I) (J); --  calls _memcpy()
         end loop;
      end loop;
      return T;
   end Transpose;

   --  Generating the A_Hat matrix is common to K_PKE_KeyGen and
   --  K_PKE_Encrypt, so is factored out here
   procedure Generate_A_Hat_Matrix (Rho   : in     Bytes_32;
                                    A_Hat :    out NTT_Poly_Matrix)
     with Relaxed_Initialization => A_Hat,
          Post => A_Hat'Initialized
   is
   begin
      --  In order to avoid a double-initialization of A_Hat, we prove
      --  safe initialization of A_Hat by proof here, rather than using
      --  the PDG flow-analysis engine.  Therefore, A_Hat is marked
      --  with the "Relaxed_Initialization" aspect, and loop
      --  invariants are used to track initialization of each slice
      --  and element of A_Hat.
      for I in K_Range loop
         for J in K_Range loop
            A_Hat (I) (J) := XOF_Then_SampleNTT (Rho & Byte (J) & Byte (I));
            --  The first I-1 slices of R are fully initialized and
            --  the first J elements of slice I are initialized
            pragma Loop_Invariant (A_Hat (K_Range'First .. I - 1)'Initialized and
                                   A_Hat (I) (K_Range'First .. J)'Initialized);
         end loop;
         --  The first I slices of A_Hat are fully initialized
         pragma Loop_Invariant (A_Hat (K_Range'First .. I)'Initialized);
      end loop;
      --  All slices of R are now initialized...
      pragma Assert (A_Hat (K_Range'First .. K_Range'Last)'Initialized);
      --  ...and therefore
      pragma Assert (A_Hat'Initialized);
   end Generate_A_Hat_Matrix;

   --  Generating a Poly_Zq_Vector with Eta_1 is common to K_PKE_KeyGen and
   --  K_PKE_Encrypt, so is factored out here
   procedure Generate_Poly_Zq_Vector_With_Eta_1
      (Sigma     : in     Bytes_32;
       Initial_N : in     Byte;
       V         :    out Poly_Zq_Vector)
     with Pre => Initial_N = 0 or Initial_N = Byte (K)
   is
      N   : Byte := Initial_N;
      Buf : CBD_1.PRF_Bytes;
   begin
      for I in K_Range loop
         pragma Loop_Invariant (N = Initial_N + Byte (I));
         CBD_1.PRF (Sigma, N, Buf);
         CBD_1.SamplePolyCBD (Buf, V (I));
         N := N + 1;
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (Buf);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Generate_Poly_Zq_Vector_With_Eta_1;

   --  Generating a Poly_Zq_Vector with Eta_2 is common to K_PKE_KeyGen and
   --  K_PKE_Encrypt, so is factored out here
   procedure Generate_Poly_Zq_Vector_With_Eta_2
      (Sigma     : in     Bytes_32;
       V         :    out Poly_Zq_Vector)
   is
      N   : Byte := Byte (K);
      Buf : CBD_2.PRF_Bytes;
   begin
      for I in K_Range loop
         pragma Loop_Invariant (N = Byte (K) + Byte (I));
         CBD_2.PRF (Sigma, N, Buf);
         CBD_2.SamplePolyCBD (Buf, V (I));
         N := N + 1;
      end loop;
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (Buf);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end Generate_Poly_Zq_Vector_With_Eta_2;

   --  Algorithm 13, FIPS 203 5.1
   --  (upstream: the sequential subunit mlkem-k_pke_keygen.adb)
   procedure K_PKE_KeyGen (Random_D : in     Bytes_32;
                           EK       :    out PKE_Encryption_Key;
                           DK       :    out PKE_Decryption_Key)
     with No_Inline, Global => null
   is
      D_Hash  : Bytes_64;
      Rho     : Bytes_32;
      Sigma   : Bytes_32;
      A_Hat   : NTT_Poly_Matrix;
      S       : Poly_Zq_Vector;
      E       : Poly_Zq_Vector;
      S_Hat   : NTT_Poly_Zq_Vector;
      E_Hat   : NTT_Poly_Zq_Vector;
      AS_Hat  : NTT_Poly_Zq_Vector;
      T_Hat   : NTT_Poly_Zq_Vector;
      T_Bytes : Poly_Zq_Vector_Bytes;
   begin
      G (Random_D, Byte_Seq'(0 => Byte (K)), D_Hash);
      Rho   := D_Hash (0 .. 31);
      Sigma := D_Hash (32 .. 63);

      Generate_A_Hat_Matrix (Rho, A_Hat);
      Generate_Poly_Zq_Vector_With_Eta_1 (Sigma, 0, S);
      Generate_Poly_Zq_Vector_With_Eta_1 (Sigma, Byte (K), E);

      NTT (S, S_Hat);
      NTT (E, E_Hat);
      Matrix_Vector_Mul (A_Hat, S_Hat, AS_Hat);
      Add (AS_Hat, E_Hat, T_Hat);

      ByteEncode12 (T_Hat, T_Bytes);
      EK := T_Bytes & Rho; --  public: calls _memcpy()
      ByteEncode12 (S_Hat, DK);

      --  Secrets: the seed hash (sigma), the noise vectors and their
      --  NTT images, and the product A*s.
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (D_Hash);
      Sanitize (Sigma);
      Sanitize (S);
      Sanitize (E);
      Sanitize (S_Hat);
      Sanitize (E_Hat);
      Sanitize (AS_Hat);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end K_PKE_KeyGen;

   --  Algorithm 14, FIPS 203 5.2
   procedure K_PKE_Encrypt (EK_PKE   : in     PKE_Encryption_Key;
                            M        : in     Bytes_32;
                            Random_R : in     Bytes_32;
                            C        :    out Ciphertext)
     with No_Inline, Global => null
   is
      A_Hat  : NTT_Poly_Matrix;
      A_T    : NTT_Poly_Matrix;
      T_Hat  : NTT_Poly_Zq_Vector;
      Rho    : Bytes_32;
      Y      : Poly_Zq_Vector;
      E1     : Poly_Zq_Vector;
      E2     : Poly_Zq;
      Buf2   : CBD_2.PRF_Bytes;
      Y_Hat  : NTT_Poly_Zq_Vector;
      AY_Hat : NTT_Poly_Zq_Vector;
      AY     : Poly_Zq_Vector;
      U      : Poly_Zq_Vector;
      M_Bits : Poly_Zq_Bit;
      Mu     : Poly_Zq;
      TY_Hat : NTT_Poly_Zq;
      TY     : Poly_Zq;
      V0     : Poly_Zq;
      V      : Poly_Zq;
      U_C    : Poly_UDU_Vector;
      V_C    : Comp_V.Poly_UD;
      C1     : Poly_UDU_Bytes;
      C2     : Comp_V.Bytes_UD;
   begin
      ByteDecode12 (EK_PKE (0 .. 384 * K - 1), T_Hat);
      Rho := EK_PKE (384 * K .. EK_PKE'Last); --  Should be exactly 32 bytes

      Generate_A_Hat_Matrix (Rho, A_Hat);
      Generate_Poly_Zq_Vector_With_Eta_1 (Random_R, 0, Y);
      Generate_Poly_Zq_Vector_With_Eta_2 (Random_R, E1);
      CBD_2.PRF (Random_R, Byte (K * 2), Buf2);
      CBD_2.SamplePolyCBD (Buf2, E2);

      NTT (Y, Y_Hat);
      A_T := Transpose (A_Hat);
      Matrix_Vector_Mul (A_T, Y_Hat, AY_Hat);
      NTT_Inv (AY_Hat, AY);
      Add (AY, E1, U);

      ByteDecode1 (M, M_Bits);
      Decompress1 (M_Bits, Mu);
      Dot (T_Hat, Y_Hat, TY_Hat);
      NTT_Inv (TY_Hat, TY);
      Add (TY, E2, V0);
      Add (V0, Mu, V);

      CompressDU (U, U_C);
      ByteEncodeDU (U_C, C1);
      Comp_V.Compress (V, V_C);
      Comp_V.ByteEncode (V_C, C2);
      C := C1 & C2; --  public: calls _memcpy()

      --  Secrets: everything derived from r and m before compression.
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (Buf2);
      Sanitize (Y);
      Sanitize (E1);
      Sanitize (E2);
      Sanitize (Y_Hat);
      Sanitize (AY_Hat);
      Sanitize (AY);
      Sanitize (U);
      Sanitize (M_Bits);
      Sanitize (Mu);
      Sanitize (TY_Hat);
      Sanitize (TY);
      Sanitize (V0);
      Sanitize (V);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end K_PKE_Encrypt;

   --  Algorithm 15, FIPS 203 5.3
   procedure K_PKE_Decrypt (DK_PKE : in     PKE_Decryption_Key;
                            C      : in     Ciphertext;
                            M      :    out Bytes_32)
     with No_Inline, Global => null
   is
      U_C    : Poly_UDU_Vector;
      V_C    : Comp_V.Poly_UD;
      U_Tick : Poly_Zq_Vector;
      U_Hat  : NTT_Poly_Zq_Vector;
      V_Tick : Poly_Zq;
      S_Hat  : NTT_Poly_Zq_Vector;
      SU_Hat : NTT_Poly_Zq;
      SU     : Poly_Zq;
      W      : Poly_Zq;
      W_Bits : Bits_256;
   begin
      --  c1 and c2 are public
      ByteDecodeDU (C (0 .. 32 * DU * K - 1), U_C);
      DecompressDU (U_C, U_Tick);
      Comp_V.ByteDecode (C (32 * DU * K .. 32 * (DU * K + DV) - 1), V_C);
      Comp_V.Decompress (V_C, V_Tick);
      NTT (U_Tick, U_Hat);

      --  from here on, secret
      ByteDecode12 (DK_PKE, S_Hat);
      Dot (S_Hat, U_Hat, SU_Hat);
      NTT_Inv (SU_Hat, SU);
      Sub (V_Tick, SU, W);
      Compress1 (W, W_Bits);
      ByteEncode1 (W_Bits, M);

      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (S_Hat);
      Sanitize (SU_Hat);
      Sanitize (SU);
      Sanitize (W);
      Sanitize (W_Bits);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end K_PKE_Decrypt;

   --=======================================
   --  Exported subprogram bodies
   --=======================================

   --  FIPS 203 section 7.2
   function EK_Valid_For_Encaps (EK_Bar : in MLKEM_Encapsulation_Key)
     return Boolean
   is
      Key_To_Check : constant Poly_Zq_Vector_Bytes := EK_Bar (0 .. 384 * K - 1);
      Decoded      : NTT_Poly_Zq_Vector;
      Reencoded    : Poly_Zq_Vector_Bytes;
   begin
      --  FIPS 203 7.2 - Encapsulation key check
      --    1. Type check. Check on the length of EK is a static type-check in SPARK, so
      --       nothing to do here.
      --    2. Modulus check - check that Decode/Encode is idempotent:
      ByteDecode12 (Key_To_Check, Decoded);
      ByteEncode12 (Decoded, Reencoded);
      return Byte_Seq_Equal (Key_To_Check, Reencoded);
   end EK_Valid_For_Encaps;

   --  FIPS 203 section 7.3 - Decapsulation key and Ciphertext check
   function DK_Valid_For_Decaps (DK_Bar : in MLKEM_Decapsulation_Key)
     return Boolean
   is
      subtype Hash_Data_Index is I32 range 0 .. 384 * K + 31;
      subtype Hash_Data is Byte_Seq (Hash_Data_Index);
      HD : constant Hash_Data := Hash_Data (DK_Bar (384 * K .. 768 * K + 31));
      Test, Reference_Hash : Bytes_32;
   begin
      --  FIPS 203 7.3 - Decapsulation key check
      --    1. Ciphertext type check. This is a static type-check in SPARK,
      --       so nothing to do here.
      --    2. Decapsulation key type check. This is a static type-check in
      --       SPARK, so nothing to do here.
      --    3. Hash check, as follows:
      H (HD, Test);
      Reference_Hash := Bytes_32 (DK_Bar (768 * K + 32 .. 768 * K + 63));
      return Byte_Seq_Equal (Test, Reference_Hash);
   end DK_Valid_For_Decaps;

   --  FIPS 203 section 7.1
   function Key_Pair_Is_Consistent_With_Seed
      (Key_Pair : in MLKEM_Key;
       Random_D : in Bytes_32;
       Random_Z : in Bytes_32) return Boolean
   is
      Regenerated_Key : MLKEM_Key;
      Same            : Boolean;
   begin
      MLKEM_KeyGen (Random_D, Random_Z, Regenerated_Key);
      Same := Byte_Seq_Equal (Key_Pair.EK, Regenerated_Key.EK) and
              Byte_Seq_Equal (Key_Pair.DK, Regenerated_Key.DK);
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (Regenerated_Key.DK);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
      return Same;
   end Key_Pair_Is_Consistent_With_Seed;

   --  FIPS 203 section 7.1 "Key pair check (without seed)"
   function Key_Pair_Check_Without_Seed
      (Key_Pair : in MLKEM_Key;
       Random_M : in Bytes_32) return Boolean
   is
      Key      : Bytes_32;
      Key_Tick : Bytes_32;
      C        : Ciphertext;
      Same     : Boolean;
   begin
      --  We can only call MLKEM_Encaps and MLKEM_Decaps if
      --  we know that DK and EK really are valid first.
      if (DK_Valid_For_Decaps (Key_Pair.DK) and
          EK_Valid_For_Encaps (Key_Pair.EK)) then
         --  Now we can do the Pair-wise consistency check. Section 7.1 (4)
         MLKEM_Encaps (Key_Pair.EK, Random_M, Key, C);
         MLKEM_Decaps (C, Key_Pair.DK, Key_Tick);
         Same := Byte_Seq_Equal (Key, Key_Tick);
         --  Scrub: to flow analysis these are dead stores, which is the point.
         pragma Warnings (GNATprove, Off, "statement has no effect");
         pragma Warnings (GNATprove, Off, "unused assignment");
         pragma Warnings (GNATprove, Off, "*not used after the call");
         Sanitize (Key);
         Sanitize (Key_Tick);
         pragma Warnings (GNATprove, On, "*not used after the call");
         pragma Warnings (GNATprove, On, "unused assignment");
         pragma Warnings (GNATprove, On, "statement has no effect");
         return Same;
      else
         return False;
      end if;
   end Key_Pair_Check_Without_Seed;

   --  FIPS 203 section 7.1 "Key pair check (with seed)"
   function Key_Pair_Check_With_Seed
      (Key_Pair : in MLKEM_Key;
       Random_D : in Bytes_32;
       Random_Z : in Bytes_32;
       Random_M : in Bytes_32) return Boolean
   is
   begin
      return (Key_Pair_Is_Consistent_With_Seed (Key_Pair, Random_D, Random_Z) and
              Key_Pair_Check_Without_Seed (Key_Pair, Random_M));
   end Key_Pair_Check_With_Seed;

   -- This is also ML-KEM.KeyGen_internal from FIPS 203 Algorithm 16
   procedure MLKEM_KeyGen (Random_D : in     Bytes_32;
                           Random_Z : in     Bytes_32;
                           Key      :    out MLKEM_Key)
   is
      EK_PKE : PKE_Encryption_Key;
      DK_PKE : PKE_Decryption_Key;
      HEK    : Bytes_32;
      DK     : MLKEM_Decapsulation_Key;
   begin
      K_PKE_KeyGen (Random_D, EK_PKE, DK_PKE);
      H (EK_PKE, HEK);
      --  dk = dk_pke || ek || H(ek) || z, assembled by slices (no "&"
      --  temporary holding the secret key)
      DK (0 .. 384 * K - 1)                 := DK_PKE;
      DK (384 * K .. 768 * K + 31)          := EK_PKE;
      DK (768 * K + 32 .. 768 * K + 63)     := HEK;
      DK (768 * K + 64 .. 768 * K + 95)     := Random_Z;
      Key := MLKEM_Key'(EK => EK_PKE, DK => DK);
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (DK_PKE);
      Sanitize (DK);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end MLKEM_KeyGen;

   -- This is also ML-KEM.Encaps_internal from FIPS 203 Algorithm 17
   procedure MLKEM_Encaps (EK       : in     MLKEM_Encapsulation_Key;
                           Random_M : in     Bytes_32;
                           Key      :    out Bytes_32;
                           C        :    out Ciphertext)
   is
      HEK : Bytes_32;
      KR  : Bytes_64;
      R   : Bytes_32;
   begin
      H (EK, HEK);
      G (Random_M, HEK, KR);
      Key := KR (0 .. 31);
      R   := KR (32 .. 63);
      K_PKE_Encrypt (EK, Random_M, R, C);
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (KR);
      Sanitize (R);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end MLKEM_Encaps;

   -- This is also ML-KEM.Decaps_internal from FIPS 203 Algorithm 18
   procedure MLKEM_Decaps (C   : in     Ciphertext;
                           DK  : in     MLKEM_Decapsulation_Key;
                           Key :    out Bytes_32)
   is
      DK_PKE : PKE_Decryption_Key;
      EK_PKE : PKE_Encryption_Key;
      HK     : Bytes_32;
      Z      : Bytes_32;
      M_Tick : Bytes_32;
      K_Bar  : Bytes_32;
      KR     : Bytes_64;
      R_Tick : Bytes_32;
      C_Tick : Ciphertext;

      --  Constant time conditional swap of Key and K_Bar.
      --  For illustration, this procedure is proven correct
      --  with the following Contract_Cases postcondition.
      procedure CSwap (Swap : in Boolean)
        with Global => (In_Out => (Key, K_Bar)),
             No_Inline,
             Contract_Cases =>
               (Swap     => (K_Bar = Key'Old and Key = K_Bar'Old),
                not Swap => (K_Bar = K_Bar'Old  and Key = Key'Old));

      procedure CSwap (Swap : in Boolean)
      is
         -- Conditional swap from Hacker's Delight 2-19
         T : Byte;
         M : constant Byte := 16#FF# * Boolean'Pos (Swap);
      begin
         for I in Index_32 loop
            T := M and (K_Bar (I) xor Key (I));
            K_Bar (I) := K_Bar (I) xor T;
            Key (I) := Key (I) xor T;
            pragma Loop_Invariant
              (if Swap then
                 (for all J in Index_32 range 0 .. I =>
                      (K_Bar (J) = Key'Loop_Entry (J) and
                       Key (J) = K_Bar'Loop_Entry (J)))
               else
                 (for all J in Index_32 range 0 .. I =>
                      (K_Bar (J) = K_Bar'Loop_Entry (J) and
                       Key (J) = Key'Loop_Entry (J)))
              );
         end loop;
      end CSwap;

   begin
      DK_PKE := PKE_Decryption_Key (DK (0 .. 384 * K - 1)); --  calls _memcpy()
      EK_PKE := PKE_Encryption_Key (DK (384 * K .. 768 * K + 32 - 1)); --  calls _memcpy()
      HK     := Bytes_32 (DK (768 * K + 32 .. 768 * K + 64 - 1));
      Z      := Bytes_32 (DK (768 * K + 64 .. 768 * K + 96 - 1));

      K_PKE_Decrypt (DK_PKE, C, M_Tick);

      G (M_Tick, HK, KR);

      J (Z, C, K_Bar);

      R_Tick := KR (32 .. 63);
      K_PKE_Encrypt (EK_PKE, M_Tick, R_Tick, C_Tick);

      Key := KR (0 .. 31);

      --  if C /= C_Tick then swap K_Bar into Key.
      --  This fulfills the FIPS-203 spec for implicit rejection
      --  but does so in constant time.
      CSwap (not Byte_Seq_Equal (C, C_Tick));

      --  Secrets: the private key parts, the recovered message, both
      --  candidate keys and the re-encryption randomness; the
      --  re-encrypted ciphertext is a function of the recovered message.
      --  Scrub: to flow analysis these are dead stores, which is the point.
      pragma Warnings (GNATprove, Off, "statement has no effect");
      pragma Warnings (GNATprove, Off, "unused assignment");
      pragma Warnings (GNATprove, Off, "*not used after the call");
      Sanitize (DK_PKE);
      Sanitize (Z);
      Sanitize (M_Tick);
      Sanitize (KR);
      Sanitize (R_Tick);
      Sanitize (K_Bar);
      Sanitize (C_Tick);
      pragma Warnings (GNATprove, On, "*not used after the call");
      pragma Warnings (GNATprove, On, "unused assignment");
      pragma Warnings (GNATprove, On, "statement has no effect");
   end MLKEM_Decaps;

end MLKEM.Generic_KEM;
