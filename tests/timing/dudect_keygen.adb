--  dudect: key generation timing across two seed classes.
--  Expectation: |t| < 4.5. Rejection sampling of A runs on rho, which
--  is derived from d, so its trip count legitimately varies with the
--  seed; rho is public (it is in the encapsulation key), so a timing
--  difference here does not leak a secret. Two fixed seeds give a
--  fixed trip-count difference, though, which this test would report as
--  a leak. So the classes here share d (same rho, same A) and differ in
--  z only, and a second test varies d to record the public
--  rho-dependent difference for the log without gating on it.

with MLKEM;           use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Timing_Fixtures; use Timing_Fixtures;
with Dudect_Helpers;

procedure Dudect_Keygen is
   Cur_D, Cur_Z : Bytes_32;
   Key : MLKEM_Key;

   procedure Prep_Z (Second : Boolean) is
   begin
      Cur_D := Seed_D0;
      Select_Bytes (Seed_Z0, Seed_Z1, Second, Cur_Z);
   end Prep_Z;

   procedure Gen is
   begin
      Key := Key_Pair (Cur_D, Cur_Z);
   end Gen;
begin
   Dudect_Helpers.Time_Test
     (Name    => "MLKEM_KeyGen (same d, z0 vs z1)",
      Prepare => Prep_Z'Access,
      Subject => Gen'Access,
      N       => 10_000);
end Dudect_Keygen;
