--  Known-answer and validation tests for SPARKMLKEM, both parameter
--  sets. Vector sources (fetched by fetch.sh, pinned by commit):
--    * PQShield reference KATs, 1000 vectors per set including the
--      implicit rejection pair (ct_n, ss_n);
--    * NIST ACVP FIPS 203 demo vectors per set: keyGen, encapsulation,
--      decapsulation (with modified ciphertexts), and the encapsulation
--      and decapsulation key checks of FIPS 203 section 7;
--    * C2SP/CCTV negatives for ML-KEM-768 as shipped by upstream
--      LibFormalPQC: the "unlucky" rejection-sampling vector and 780
--      encapsulation keys with an unreduced coefficient.
--  The corrupt-key checks follow upstream tvalidation.adb.

with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Command_Line;
with MLKEM.ML_KEM_768;
with MLKEM.ML_KEM_1024;
with KAT_Runner;

procedure KAT_Tests is
   procedure Run_768  is new KAT_Runner (MLKEM.ML_KEM_768,  "768",  Has_CCTV => True);
   procedure Run_1024 is new KAT_Runner (MLKEM.ML_KEM_1024, "1024", Has_CCTV => False);
   Pass : Natural := 0;
   Fail : Natural := 0;
begin
   Put_Line ("=== SPARKMLKEM known-answer tests ===");
   Run_768 (Pass, Fail);
   Run_1024 (Pass, Fail);
   Put_Line ("=== KAT:" & Pass'Image & " passed," & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end KAT_Tests;
