--  Cycle counts (rdtsc) and wall time for KeyGen, Encaps and Decaps of
--  each instantiated parameter set: median and minimum over N runs on
--  fixed seeds. The library build is the crate's default (optimize).

with Ada.Text_IO;         use Ada.Text_IO;
with Ada.Real_Time;       use Ada.Real_Time;
with Interfaces;          use Interfaces;
with System.Machine_Code; use System.Machine_Code;
with MLKEM;               use MLKEM;
with MLKEM.Generic_KEM;
with MLKEM.ML_KEM_768;
with MLKEM.ML_KEM_1024;

procedure MLKEM_Bench is

   function Rdtsc return Unsigned_64 is
      Lo, Hi : Unsigned_32;
   begin
      Asm ("rdtsc",
           Outputs => (Unsigned_32'Asm_Output ("=a", Lo), Unsigned_32'Asm_Output ("=d", Hi)),
           Volatile => True);
      return Unsigned_64 (Hi) * 2**32 or Unsigned_64 (Lo);
   end Rdtsc;

   N : constant := 2000;
   type Samples is array (1 .. N) of Unsigned_64;

   procedure Sort (S : in out Samples) is
      T : Unsigned_64;
   begin
      for I in S'Range loop
         for J in reverse I + 1 .. S'Last loop
            if S (J) < S (J - 1) then
               T := S (J); S (J) := S (J - 1); S (J - 1) := T;
            end if;
         end loop;
      end loop;
   end Sort;

   procedure Report (Name : String; S : in out Samples; Secs : Duration) is
   begin
      Sort (S);
      Put_Line ("  " & Name
                & ": median" & S (N / 2)'Image & " cycles, min" & S (1)'Image
                & " cycles, " & Integer (Duration (N) / Secs)'Image & " ops/s");
   end Report;

   generic
      with package KEM is new MLKEM.Generic_KEM (<>);
      Name : String;
   procedure Bench_Set;

   procedure Bench_Set is
      use KEM;
      D  : constant Bytes_32 := (others => 16#11#);
      Z  : constant Bytes_32 := (others => 16#22#);
      M  : constant Bytes_32 := (others => 16#33#);
      Key : MLKEM_Key;
      SS, SS2 : Bytes_32;
      C  : Ciphertext;
      S_Gen, S_Enc, S_Dec : Samples;
      T0, T1 : Unsigned_64;
      W0, W1 : Time;
      Gen_Secs, Enc_Secs, Dec_Secs : Duration;
      Acc : Unsigned_8 := 0;
   begin
      Put_Line (Name & " (N =" & N'Image & ")");
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         MLKEM_KeyGen (D, Z, Key);
         T1 := Rdtsc;
         S_Gen (I) := T1 - T0;
         Acc := Acc xor Key.EK (0);
      end loop;
      W1 := Clock; Gen_Secs := To_Duration (W1 - W0);
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         MLKEM_Encaps (Key.EK, M, SS, C);
         T1 := Rdtsc;
         S_Enc (I) := T1 - T0;
         Acc := Acc xor SS (0);
      end loop;
      W1 := Clock; Enc_Secs := To_Duration (W1 - W0);
      W0 := Clock;
      for I in 1 .. N loop
         T0 := Rdtsc;
         MLKEM_Decaps (C, Key.DK, SS2);
         T1 := Rdtsc;
         S_Dec (I) := T1 - T0;
         Acc := Acc xor SS2 (0);
      end loop;
      W1 := Clock; Dec_Secs := To_Duration (W1 - W0);
      Report ("KeyGen", S_Gen, Gen_Secs);
      Report ("Encaps", S_Enc, Enc_Secs);
      Report ("Decaps", S_Dec, Dec_Secs);
      Put_Line ("  (shared secrets agree: " & Boolean'Image (SS = SS2) & ", sink" & Acc'Image & ")");
   end Bench_Set;

   procedure B768  is new Bench_Set (MLKEM.ML_KEM_768,  "ML-KEM-768");
   procedure B1024 is new Bench_Set (MLKEM.ML_KEM_1024, "ML-KEM-1024");
begin
   B768;
   B1024;
end MLKEM_Bench;
