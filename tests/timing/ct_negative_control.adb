--  Negative control / harness self-test for the ctgrind lane.
--
--  Deliberately branches and indexes on a byte marked undefined.
--  Valgrind memcheck MUST report "use of uninitialised value"; if it
--  does not, the harness plumbing is broken and every other ctgrind
--  verdict is meaningless. Same canary as the sibling crates.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces;
with Interfaces.C;
with MLKEM;       use MLKEM;
with MLKEM.ML_KEM_768; use MLKEM.ML_KEM_768;
with Ctgrind;

procedure Ct_Negative_Control is
   Key  : Bytes_32 := (others => 16#42#);
   Sink : Natural  := 0;

   Lookup_Table : constant array (0 .. 255) of Natural := (others => 7);

   procedure Leaky (K : Bytes_32; Sink : in out Natural) is
      Idx : constant Natural := Natural (K (0));
   begin
      if Interfaces.">" (K (0), 127) then
         Sink := Sink + 1;
      else
         Sink := Sink + 2;
      end if;
      Sink := Sink + Lookup_Table (Idx);
   end Leaky;
begin
   Ctgrind.Make_Undefined (Key'Address, Interfaces.C.size_t (Key'Length));
   Leaky (Key, Sink);
   Ctgrind.Make_Defined (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));
   Ctgrind.Use_Output (Sink'Address, Interfaces.C.size_t (Sink'Size / 8));
   Put_Line ("ct_negative_control: ran leaky function (sink=" & Sink'Image & ")");
   Put_Line ("  EXPECTED: 'use of uninitialised value' error from valgrind.");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_Negative_Control;
