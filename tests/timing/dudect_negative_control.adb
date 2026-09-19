--  dudect canary: a PLANTED secret-dependent delay on top of a real
--  decapsulation. The lane requires this harness to report
--  "TIMING DEPENDS ON SECRET INPUT"; if it ever reads "ok", the
--  statistics or the measurement loop have lost their teeth and every
--  other dudect verdict is meaningless.
--
--  Same shape as dudect_decaps_keys (Prepare/Subject form, masked
--  select, shared buffers) so the canary exercises exactly the path the
--  real harnesses rely on. The subject does a genuine Decaps and then
--  spends Leak extra dependent iterations (~2-3 cycles each) only when
--  the secret's low bit is set. Override Leak on the command line to
--  probe the detection floor (0 must read "ok").

with Interfaces;      use Interfaces;
with Ada.Command_Line;
with MLKEM;           use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Timing_Fixtures; use Timing_Fixtures;
with Dudect_Helpers;

procedure Dudect_Negative_Control is
   K0 : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   K1 : constant MLKEM_Key := Key_Pair (Seed_D1, Seed_Z1);
   SS0, SS1 : Bytes_32;
   C0, C1   : Ciphertext;

   Leak : Natural := 16;

   --  Shared buffers written by Prepare, read by Subject.
   Cur_DK : MLKEM_Decapsulation_Key;
   Cur_C  : Ciphertext;
   Secret : Byte := 0;
   Out_SS : Bytes_32;

   Acc : Unsigned_64 := 0 with Volatile;

   procedure Prep (Second : Boolean) is
   begin
      Select_Bytes (K0.DK, K1.DK, Second, Cur_DK);
      Select_Bytes (C0, C1, Second, Cur_C);
      Secret := Byte (Boolean'Pos (Second));
   end Prep;

   procedure Decaps_Then_Leak is
      Extra : constant Natural := Natural (Secret and 1) * Leak;
      A     : Unsigned_64 := Acc;
   begin
      Out_SS := Decaps (Cur_C, Cur_DK);
      for I in 1 .. Extra loop
         A := A * 3 + Unsigned_64 (I);
      end loop;
      Acc := A + Unsigned_64 (Out_SS (0));
   end Decaps_Then_Leak;
begin
   MLKEM_Encaps (K0.EK, Msg_0, SS0, C0);
   MLKEM_Encaps (K1.EK, Msg_1, SS1, C1);
   if Ada.Command_Line.Argument_Count >= 1 then
      Leak := Natural'Value (Ada.Command_Line.Argument (1));
   end if;
   Dudect_Helpers.Time_Test
     (Name      =>
        "CANARY: Decaps + planted" & Leak'Image
        & "-iteration secret-dependent delay (must be flagged)",
      Prepare   => Prep'Access,
      Subject   => Decaps_Then_Leak'Access,
      N         => 10_000);
end Dudect_Negative_Control;
