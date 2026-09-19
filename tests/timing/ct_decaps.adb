--  ctgrind: ML-KEM-768 decapsulation with the secret parts of the key
--  tainted, valid ciphertext.
--
--  The decapsulation key is dk_pke || ek || H(ek) || z. Only dk_pke and
--  z are secret; ek and H(ek) are the public key and stay defined, so
--  the A-matrix rejection sampling (on rho inside ek) is not reported
--  and every reported site is a real secret dependency: the decryption
--  m' = Decompress(v) - s^T u, the re-encryption from r' = G(m' || h),
--  the ciphertext comparison and the implicit-rejection select.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Interfaces.C;
with MLKEM;       use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Ctgrind;
with Timing_Fixtures; use Timing_Fixtures;

procedure Ct_Decaps is
   Key : MLKEM_Key := Key_Pair (Seed_D0, Seed_Z0);
   SS  : Bytes_32;
   C   : Ciphertext;
   Out_SS : Bytes_32;
begin
   MLKEM_Encaps (Key.EK, Msg_0, SS, C);

   Ctgrind.Make_Undefined
     (Key.DK (0)'Address, Interfaces.C.size_t (DK_PKE_Last + 1));
   Ctgrind.Make_Undefined
     (Key.DK (DK_Z_First)'Address, Interfaces.C.size_t (32));

   Out_SS := Decaps (C, Key.DK);

   Ctgrind.Make_Defined (Out_SS'Address, Interfaces.C.size_t (Out_SS'Length));
   Ctgrind.Use_Output (Out_SS'Address, Interfaces.C.size_t (Out_SS'Length));
   Put_Line ("ct_decaps: MLKEM_Decaps completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Decaps;
