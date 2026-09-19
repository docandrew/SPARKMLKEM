--  dudect: decapsulation timing, valid ciphertext vs a tampered one on
--  the same key. The tampered ciphertext takes the implicit-rejection
--  path (K = J(z || c)); if that path costs a different amount of time
--  than acceptance, an attacker learns whether a chosen ciphertext
--  decrypts to the honest message, which is the classic KEM
--  side-channel. Expectation: |t| < 4.5.

with Interfaces;      use Interfaces;
with MLKEM;           use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Timing_Fixtures; use Timing_Fixtures;
with Dudect_Helpers;

procedure Dudect_Decaps_Reject is
   Key   : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   SS    : Bytes_32;
   C_OK  : Ciphertext;
   C_Bad : Ciphertext;
   Cur_C : Ciphertext;
   Out_SS : Bytes_32;

   procedure Prep (Second : Boolean) is
   begin
      Select_Bytes (C_OK, C_Bad, Second, Cur_C);
   end Prep;

   procedure Decaps is
   begin
      Out_SS := Decaps (Cur_C, Key.DK);
   end Decaps;
begin
   MLKEM_Encaps (Key.EK, Msg_0, SS, C_OK);
   C_Bad := C_OK;
   C_Bad (17) := C_Bad (17) xor 16#80#;
   Dudect_Helpers.Time_Test
     (Name    => "MLKEM_Decaps (valid ct vs tampered ct, implicit rejection)",
      Prepare => Prep'Access,
      Subject => Decaps'Access,
      N       => 10_000);
end Dudect_Decaps_Reject;
