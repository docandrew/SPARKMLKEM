--  dudect: decapsulation timing across two key pairs, each with its
--  own valid ciphertext. Both keys share d (so rho, A and the public
--  rejection-sampling trip count are identical) and differ in z; the
--  ciphertexts differ because they encapsulate different messages.
--  Expectation: |t| < 4.5.

with MLKEM;           use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Timing_Fixtures; use Timing_Fixtures;
with Dudect_Helpers;

procedure Dudect_Decaps_Keys is
   K0 : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   K1 : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z1);
   SS0, SS1 : Bytes_32;
   C0, C1   : Ciphertext;
   Cur_DK   : MLKEM_Decapsulation_Key;
   Cur_C    : Ciphertext;
   Out_SS   : Bytes_32;

   procedure Prep (Second : Boolean) is
   begin
      Select_Bytes (K0.DK, K1.DK, Second, Cur_DK);
      Select_Bytes (C0, C1, Second, Cur_C);
   end Prep;

   procedure Decaps is
   begin
      Out_SS := Decaps (Cur_C, Cur_DK);
   end Decaps;
begin
   MLKEM_Encaps (K0.EK, Msg_0, SS0, C0);
   MLKEM_Encaps (K1.EK, Msg_1, SS1, C1);
   Dudect_Helpers.Time_Test
     (Name    => "MLKEM_Decaps (key0/ct0 vs key1/ct1, same rho)",
      Prepare => Prep'Access,
      Subject => Decaps'Access,
      N       => 10_000);
end Dudect_Decaps_Keys;
