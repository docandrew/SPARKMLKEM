--  ctgrind: ML-KEM-768 encapsulation with the message secret.
--
--  The encapsulation key is public. The 32-byte message m is the
--  encapsulator's secret randomness: K and r derive from it, and the
--  CBD sampling of the r, e1, e2 noise and the compression of the
--  ciphertext must not branch on it. Rejection sampling here runs on
--  rho from the public key, which is defined, so this harness must be
--  clean.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with MLKEM;       use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Ctgrind;
with Timing_Fixtures; use Timing_Fixtures;

procedure Ct_Encaps is
   Key : constant MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   M   : Bytes_32 := Msg_0;
   SS  : Bytes_32;
   C   : Ciphertext;
begin
   Ctgrind.Make_Undefined (M'Address, Interfaces.C.size_t (M'Length));

   MLKEM_Encaps (Key.EK, M, SS, C);

   Ctgrind.Make_Defined (SS'Address, Interfaces.C.size_t (SS'Length));
   Ctgrind.Make_Defined (C'Address, Interfaces.C.size_t (C'Length));
   Ctgrind.Use_Output (SS'Address, Interfaces.C.size_t (SS'Length));
   Ctgrind.Use_Output (C'Address, Interfaces.C.size_t (C'Length));
   Put_Line ("ct_encaps: MLKEM_Encaps completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Encaps;
