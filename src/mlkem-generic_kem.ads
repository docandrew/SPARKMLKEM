--  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
--  SPDX-License-Identifier: Apache-2.0
--
--  Modified for SPARKMLKEM (SPARKTLS project), 2026-09-15. Changes from
--  the upstream LibFormalPQC sources are listed in CHANGES_FROM_UPSTREAM.md.
--  This generic child holds everything in the upstream MLKEM package that
--  depends on the parameter set (FIPS 203 section 8): the key and
--  ciphertext types, K-PKE (algorithms 13 to 15), the input checks of
--  section 7 and the ML-KEM API (algorithms 16 to 18). Upstream fixed
--  k, eta and the widths as constants and carried a TODO to make the
--  package generic; this is that generic. MLKEM.ML_KEM_768 and
--  MLKEM.ML_KEM_1024 are its instances. The secret-bearing subprograms
--  are procedures that sanitise their intermediates (FIPS 203 section
--  3.3); see the style rule in mlkem.ads.

generic
   K     : in I32;       --  2, 3 or 4
   Eta_1 : in Positive;  --  3 for ML-KEM-512, else 2
   Eta_2 : in Positive;  --  2
   DU    : in I32;       --  10, or 11 for ML-KEM-1024
   DV    : in I32;       --  4, or 5 for ML-KEM-1024
   type UDU is mod <>;   --  mod 2**DU, 16-bit object
   type UDV is mod <>;   --  mod 2**DV, 16-bit object
package MLKEM.Generic_KEM
  with SPARK_Mode => On
is
   ----------------------------------------------------------------------
   --  Parameter set validation
   ----------------------------------------------------------------------

   --  FIPS 203 section 8 requires that implementations shall confirm
   --  that only valid sets of parameters are chosen.  This can be
   --  encoded as an assertion, thus:
   pragma Assert
      --  ML-KEM-512
      ((K = 2 and Eta_1 = 3 and Eta_2 = 2 and DU = 10 and DV = 4) or
       --  ML-KEM-768
       (K = 3 and Eta_1 = 2 and Eta_2 = 2 and DU = 10 and DV = 4) or
       --  ML-KEM-1024
       (K = 4 and Eta_1 = 2 and Eta_2 = 2 and DU = 11 and DV = 5));

   --  The compressed-coefficient types must match the widths.
   pragma Assert (UDU'Modulus = 2**Natural (DU) and
                  UDV'Modulus = 2**Natural (DV));

   --  The parameters of this instance, for callers (test fixtures, the
   --  TLS key-share layout).
   Parameter_K  : constant I32 := K;
   Parameter_DU : constant I32 := DU;
   Parameter_DV : constant I32 := DV;

   --  Ciphertext is 1088 bytes for K = 3, DU = 10, DV = 4
   subtype Ciphertext_Index is I32 range 0 .. 32 * (DU * K + DV) - 1;
   subtype Ciphertext is Byte_Seq (Ciphertext_Index);

   --  1184 bytes for K = 3
   subtype MLKEM_Encapsulation_Key_Index is I32 range 0 .. (384 * K + 32 - 1);
   subtype MLKEM_Encapsulation_Key is Byte_Seq (MLKEM_Encapsulation_Key_Index);

   --  2400 bytes for K = 3
   subtype MLKEM_Decapsulation_Key_Index is I32 range 0 .. (768 * K + 96 - 1);
   subtype MLKEM_Decapsulation_Key is Byte_Seq (MLKEM_Decapsulation_Key_Index);

   type MLKEM_Key is record
      EK : MLKEM_Encapsulation_Key;
      DK : MLKEM_Decapsulation_Key;
   end record;

   --==============================================
   --  Exported subprograms. These subprograms
   --  form the main user-facing API for MLKEM
   --==============================================

   --  Input Validation Functions

   --  FIPS 203 section 7.2 - Encapsulation key check
   function EK_Valid_For_Encaps (EK_Bar : in MLKEM_Encapsulation_Key)
      return Boolean
     with Global => null;

   --  FIPS 203 section 7.3 - Decapsulation key check
   --  NOTE: The "Ciphertext type check" specified in 7.1 (1) is a wholly
   --  static type-check in SPARK, so does not require a dynamic check here.
   function DK_Valid_For_Decaps (DK_Bar : in MLKEM_Decapsulation_Key)
     return Boolean
     with Global => null;

   --  FIPS 203 section 7.1 "Key pair check (without seed)"
   function Key_Pair_Check_Without_Seed
      (Key_Pair : in MLKEM_Key;
       Random_M : in Bytes_32) return Boolean
     with Global => null;

   --  FIPS 203 section 7.1 "Key pair check (with seed)"
   function Key_Pair_Check_With_Seed
      (Key_Pair : in MLKEM_Key;
       Random_D : in Bytes_32;
       Random_Z : in Bytes_32;
       Random_M : in Bytes_32) return Boolean
     with Global => null;

   --  Main MLKEM API. Key generation and decapsulation are procedures
   --  with out parameters (upstream returned the key material from
   --  functions): every secret has a name and is sanitised before return.

   --  Algorithm 19
   procedure MLKEM_KeyGen (Random_D : in     Bytes_32;
                           Random_Z : in     Bytes_32;
                           Key      :    out MLKEM_Key)
     with Global => null;

   --  Algorithm 20
   procedure MLKEM_Encaps (EK       : in     MLKEM_Encapsulation_Key;
                           Random_M : in     Bytes_32;
                           Key      :    out Bytes_32;
                           C        :    out Ciphertext)
     with Global => null,
                     --  Precondition from FIPS 203
          Pre    => EK'Length = 384 * K + 32 and
                    EK_Valid_For_Encaps (EK);

   --  Algorithm 21
   procedure MLKEM_Decaps (C   : in     Ciphertext;
                           DK  : in     MLKEM_Decapsulation_Key;
                           Key :    out Bytes_32)
     with Global => null,
                     --  Precondition from FIPS 203
          Pre    => C'Length = 32 * (DU * K + DV) and
                    DK'Length = 768 * K + 96 and
                    DK_Valid_For_Decaps (DK);

end MLKEM.Generic_KEM;
