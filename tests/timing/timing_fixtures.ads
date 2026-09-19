--  Shared fixtures for the timing harnesses: two ML-KEM-768 key pairs
--  from fixed seeds, a ciphertext for each, and mask-select helpers so
--  a harness can pick a class's secret as DATA (never a branch on the
--  class). The seeds are arbitrary constants; nothing here is random.

with Interfaces; use Interfaces;
with MLKEM;      use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;

package Timing_Fixtures is

   --  Byte layout of a decapsulation key (FIPS 203 algorithm 16):
   --    dk_pke (384 * K)  ||  ek (384 * K + 32)  ||  H(ek) (32)  ||  z (32)
   --  Only dk_pke and z are secret; ek and H(ek) are the public key.
   DK_PKE_Last : constant I32 := 384 * Parameter_K - 1;
   DK_Z_First  : constant I32 := 768 * Parameter_K + 64;

   Seed_D0 : constant Bytes_32 := (others => 16#11#);
   Seed_Z0 : constant Bytes_32 := (others => 16#22#);
   Seed_D1 : constant Bytes_32 := (others => 16#33#);
   Seed_Z1 : constant Bytes_32 := (others => 16#44#);
   Msg_0   : constant Bytes_32 := (others => 16#55#);
   Msg_1   : constant Bytes_32 := (others => 16#66#);

   --  Functional wrappers for harness setup code (the library API is
   --  procedural; test fixtures may hold key material by value).
   function Key_Pair (D, Z : Bytes_32) return MLKEM_Key;
   function Decaps (C : Ciphertext; DK : MLKEM_Decapsulation_Key) return Bytes_32
     with Pre => DK_Valid_For_Decaps (DK);

   --  Select B when Second, A otherwise, with a byte mask: one
   --  instruction stream for both classes.
   procedure Select_Bytes
     (A, B   : in     Byte_Seq;
      Second : in     Boolean;
      Result :    out Byte_Seq)
     with Pre => A'First = B'First and A'Last = B'Last
                 and Result'First = A'First and Result'Last = A'Last;

end Timing_Fixtures;
