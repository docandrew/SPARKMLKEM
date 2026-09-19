--  dudect: encapsulation timing across two message classes on one
--  public key. m is the encapsulator's secret; everything derived from
--  it (K, r, the noise polynomials, the ciphertext) must take the same
--  time. Expectation: |t| < 4.5.

with MLKEM;           use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Timing_Fixtures; use Timing_Fixtures;
with Dudect_Helpers;

procedure Dudect_Encaps is
   Key   : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   Cur_M : Bytes_32;
   SS    : Bytes_32;
   C     : Ciphertext;

   procedure Prep (Second : Boolean) is
   begin
      Select_Bytes (Msg_0, Msg_1, Second, Cur_M);
   end Prep;

   procedure Encaps is
   begin
      MLKEM_Encaps (Key.EK, Cur_M, SS, C);
   end Encaps;
begin
   Dudect_Helpers.Time_Test
     (Name    => "MLKEM_Encaps (fixed ek, m0 vs m1)",
      Prepare => Prep'Access,
      Subject => Encaps'Access,
      N       => 10_000);
end Dudect_Encaps;
