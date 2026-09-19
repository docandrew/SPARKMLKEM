--  ctgrind: ML-KEM-768 key generation with both seeds secret.
--
--  KeyGen derives rho (the public A-matrix seed, published inside the
--  encapsulation key) and sigma (secret) from d. Rejection sampling of
--  the A matrix branches on SHAKE128(rho) output: that is data-dependent
--  by design and public by design, but Valgrind cannot know rho is
--  public once d is tainted, so it reports those sites. The lane
--  therefore classifies this harness by an exact site count rather than
--  requiring zero; a change in the count is a regression to triage, not
--  to renumber. Everything else in KeyGen (CBD sampling of s and e, the
--  NTT, encoding) must be free of tainted branches.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with MLKEM;       use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Ctgrind;
with Timing_Fixtures; use Timing_Fixtures;

procedure Ct_Keygen is
   D   : Bytes_32 := Seed_D0;
   Z   : Bytes_32 := Seed_Z0;
   Key : MLKEM_Key;
begin
   Ctgrind.Make_Undefined (D'Address, Interfaces.C.size_t (D'Length));
   Ctgrind.Make_Undefined (Z'Address, Interfaces.C.size_t (Z'Length));

   Key := Key_Pair (D, Z);

   Ctgrind.Make_Defined (Key'Address, Interfaces.C.size_t (Key'Size / 8));
   Ctgrind.Use_Output (Key'Address, Interfaces.C.size_t (Key'Size / 8));
   Put_Line ("ct_keygen: MLKEM_KeyGen completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Keygen;
