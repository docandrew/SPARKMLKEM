--  Body of the generic known-answer harness; see kat_runner.ads. The
--  hex reader follows tkats.adb from AWS LibFormalPQC (Rod Chapman,
--  Apache-2.0); the harness counts, prints failures and reports.

with Ada.Text_IO;      use Ada.Text_IO;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Interfaces;       use Interfaces;
with MLKEM;            use MLKEM;

procedure KAT_Runner (Pass, Fail : in out Natural) is
   use KEM;

   --  Functional wrappers: the library API is procedural.
   function Key_Pair (D, Z : Bytes_32) return MLKEM_Key is
      Key : MLKEM_Key;
   begin
      MLKEM_KeyGen (D, Z, Key);
      return Key;
   end Key_Pair;

   function Decaps (C : Ciphertext; DK : MLKEM_Decapsulation_Key) return Bytes_32 is
      SS : Bytes_32;
   begin
      MLKEM_Decaps (C, DK, SS);
      return SS;
   end Decaps;

   procedure Check (Name : String; Ok : Boolean) is
   begin
      if Ok then
         Pass := Pass + 1;
      else
         Fail := Fail + 1;
         Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   ----------------------------------------------------------------
   --  Hex and "key = value" file reading
   ----------------------------------------------------------------

   function Hex_To_Bytes (S : String) return Byte_Seq
     with Pre => S'Length mod 2 = 0
   is
      function Nibble (C : Character) return Byte is
        (case C is
           when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
           when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
           when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
           when others     => raise Constraint_Error with "bad hex");
      R : Byte_Seq (0 .. N32 (S'Length / 2) - 1) := (others => 0);
      J : Positive := S'First;
   begin
      for I in R'Range loop
         R (I) := Nibble (S (J)) * 16 + Nibble (S (J + 1));
         J := J + 2;
      end loop;
      return R;
   end Hex_To_Bytes;

   --  One "key = value" line; Key is empty at end of file or on a blank
   --  line.
   procedure Next_Field (F : File_Type; Key, Value : out Ada.Strings.Unbounded.Unbounded_String);

   package US renames Ada.Strings.Unbounded;
   use type US.Unbounded_String;

   procedure Next_Field (F : File_Type; Key, Value : out US.Unbounded_String) is
   begin
      Key   := US.Null_Unbounded_String;
      Value := US.Null_Unbounded_String;
      if End_Of_File (F) then
         return;
      end if;
      declare
         L : constant String := Get_Line (F);
         P : constant Natural := Ada.Strings.Fixed.Index (L, " = ");
      begin
         if P = 0 then
            return;
         end if;
         Key   := US.To_Unbounded_String (L (L'First .. P - 1));
         Value := US.To_Unbounded_String (L (P + 3 .. L'Last));
      end;
   end Next_Field;

   function Vec (Name : String) return String is ("vectors/" & Name);

   ----------------------------------------------------------------
   --  PQShield / CCTV ".rsp" records: count z d msg seed pk sk [ct_n ss_n] ct ss
   ----------------------------------------------------------------

   procedure Run_RSP (File : String; With_Reject : Boolean) is
      F     : File_Type;
      K, V  : US.Unbounded_String;
      Z, D, M, SS, SS_N : Bytes_32 := (others => 0);
      PK    : MLKEM_Encapsulation_Key := (others => 0);
      SK    : MLKEM_Decapsulation_Key := (others => 0);
      CT, CT_N : Ciphertext := (others => 0);
      Count : Natural := 0;
      Done  : Natural := 0;
      Have_Reject : Boolean := False;

      procedure Run_One is
         Key : constant MLKEM_Key := Key_Pair (D, Z);
         C   : Ciphertext;
         S1  : Bytes_32;
         Tag : constant String := File & " #" & Count'Image;
      begin
         Done := Done + 1;
         Check (Tag & " ek", Key.EK = PK);
         Check (Tag & " dk", Key.DK = SK);
         Check (Tag & " ek valid", EK_Valid_For_Encaps (Key.EK));
         Check (Tag & " dk valid", DK_Valid_For_Decaps (Key.DK));
         Check (Tag & " pair check (seed)", Key_Pair_Check_With_Seed (Key, D, Z, M));
         if EK_Valid_For_Encaps (Key.EK) and DK_Valid_For_Decaps (Key.DK) then
            MLKEM_Encaps (Key.EK, M, S1, C);
            Check (Tag & " ct", C = CT);
            Check (Tag & " ss", S1 = SS);
            Check (Tag & " decaps", Decaps (C, Key.DK) = SS);
            if With_Reject and Have_Reject then
               Check (Tag & " implicit rejection", Decaps (CT_N, Key.DK) = SS_N);
            end if;
         end if;
      end Run_One;
   begin
      Open (F, In_File, Vec (File));
      loop
         Next_Field (F, K, V);
         exit when End_Of_File (F) and US.Length (K) = 0;
         declare
            KS : constant String := US.To_String (K);
            VS : constant String := US.To_String (V);
         begin
            if KS = "count" then
               Count := Natural'Value (VS);
               Have_Reject := False;
            elsif KS = "z" then Z := Hex_To_Bytes (VS);
            elsif KS = "d" then D := Hex_To_Bytes (VS);
            elsif KS = "msg" then M := Hex_To_Bytes (VS);
            elsif KS = "pk" then PK := Hex_To_Bytes (VS);
            elsif KS = "sk" then SK := Hex_To_Bytes (VS);
            elsif KS = "ct_n" then CT_N := Hex_To_Bytes (VS); Have_Reject := True;
            elsif KS = "ss_n" then SS_N := Hex_To_Bytes (VS);
            elsif KS = "ct" then CT := Hex_To_Bytes (VS);
            elsif KS = "ss" then
               SS := Hex_To_Bytes (VS);
               Run_One;   --  "ss" closes a record
            end if;
         end;
      end loop;
      Close (F);
      Put_Line ("  " & File & ": " & Done'Image & " records");
   end Run_RSP;

   ----------------------------------------------------------------
   --  CCTV invalid encapsulation keys: one hex key per line, all must
   --  fail the FIPS 203 section 7.2 check.
   ----------------------------------------------------------------

   procedure Run_Invalid_EK (File : String) is
      F : File_Type;
      N : Natural := 0;
   begin
      Open (F, In_File, Vec (File));
      while not End_Of_File (F) loop
         declare
            L : constant String := Get_Line (F);
         begin
            if L'Length = 2 * MLKEM_Encapsulation_Key'Length then
               N := N + 1;
               declare
                  EK : constant MLKEM_Encapsulation_Key := Hex_To_Bytes (L);
               begin
                  Check (File & " #" & N'Image & " rejected", not EK_Valid_For_Encaps (EK));
               end;
            end if;
         end;
      end loop;
      Close (F);
      Put_Line ("  " & File & ": " & N'Image & " keys");
   end Run_Invalid_EK;

   ----------------------------------------------------------------
   --  ACVP flattened files (acvp_to_txt.py): blank line ends a record
   ----------------------------------------------------------------

   type ACVP_Kind is (Key_Gen, Encap, Decap, EK_Check, DK_Check);

   procedure Run_ACVP (File : String; Kind : ACVP_Kind) is
      F     : File_Type;
      Kf, V : US.Unbounded_String;
      Z, D, M, SS : Bytes_32 := (others => 0);
      EK    : MLKEM_Encapsulation_Key := (others => 0);
      DK    : MLKEM_Decapsulation_Key := (others => 0);
      CT    : Ciphertext := (others => 0);
      Tc    : Natural := 0;
      Passed : Boolean := False;
      Reason : US.Unbounded_String;
      N     : Natural := 0;

      procedure Run_One is
         Tag : constant String := File & " tc" & Tc'Image;
      begin
         N := N + 1;
         case Kind is
            when Key_Gen =>
               declare
                  Key : constant MLKEM_Key := Key_Pair (D, Z);
               begin
                  Check (Tag & " ek", Key.EK = EK);
                  Check (Tag & " dk", Key.DK = DK);
               end;
            when Encap =>
               Check (Tag & " ek valid", EK_Valid_For_Encaps (EK));
               if EK_Valid_For_Encaps (EK) then
                  declare
                     C  : Ciphertext;
                     S1 : Bytes_32;
                  begin
                     MLKEM_Encaps (EK, M, S1, C);
                     Check (Tag & " c", C = CT);
                     Check (Tag & " k", S1 = SS);
                  end;
               end if;
            when Decap =>
               Check (Tag & " dk valid", DK_Valid_For_Decaps (DK));
               if DK_Valid_For_Decaps (DK) then
                  Check (Tag & " k (" & US.To_String (Reason) & ")",
                         Decaps (CT, DK) = SS);
               end if;
            when EK_Check =>
               Check (Tag & " ek check (" & US.To_String (Reason) & ")",
                      EK_Valid_For_Encaps (EK) = Passed);
            when DK_Check =>
               Check (Tag & " dk check (" & US.To_String (Reason) & ")",
                      DK_Valid_For_Decaps (DK) = Passed);
         end case;
      end Run_One;

      In_Record : Boolean := False;
   begin
      Open (F, In_File, Vec (File));
      loop
         Next_Field (F, Kf, V);
         if US.Length (Kf) = 0 then
            if In_Record then
               Run_One;
               In_Record := False;
            end if;
            exit when End_Of_File (F);
         else
            In_Record := True;
            declare
               KS : constant String := US.To_String (Kf);
               VS : constant String := US.To_String (V);
            begin
               if KS = "tcId" then Tc := Natural'Value (VS);
               elsif KS = "z" then Z := Hex_To_Bytes (VS);
               elsif KS = "d" then D := Hex_To_Bytes (VS);
               elsif KS = "m" then M := Hex_To_Bytes (VS);
               elsif KS = "ek" then EK := Hex_To_Bytes (VS);
               elsif KS = "dk" then DK := Hex_To_Bytes (VS);
               elsif KS = "c" then CT := Hex_To_Bytes (VS);
               elsif KS = "k" then SS := Hex_To_Bytes (VS);
               elsif KS = "testPassed" then Passed := VS = "true";
               elsif KS = "reason" then Reason := V;
               end if;
            end;
         end if;
      end loop;
      Close (F);
      Put_Line ("  " & File & ": " & N'Image & " cases");
   end Run_ACVP;

   ----------------------------------------------------------------
   --  Corrupt-key checks (after upstream tvalidation.adb)
   ----------------------------------------------------------------

   procedure Run_Validation is
      D : constant Bytes_32 := (others => 16#01#);
      Z : constant Bytes_32 := (others => 16#02#);
      M : constant Bytes_32 := (others => 16#03#);
      D2 : constant Bytes_32 := (others => 16#04#);
      Key : constant MLKEM_Key := Key_Pair (D, Z);
      Bad : MLKEM_Key := Key;
   begin
      Check ("validation: good pair (no seed)", Key_Pair_Check_Without_Seed (Key, M));
      Check ("validation: good pair (seed)", Key_Pair_Check_With_Seed (Key, D, Z, M));
      Bad.EK (100) := Bad.EK (100) xor 16#FF#;
      Check ("validation: corrupt ek rejected", not Key_Pair_Check_Without_Seed (Bad, M));
      Bad := Key;
      Bad.DK (100) := Bad.DK (100) xor 16#FF#;
      Check ("validation: corrupt dk rejected", not Key_Pair_Check_Without_Seed (Bad, M));
      Check ("validation: wrong seed rejected", not Key_Pair_Check_With_Seed (Key, D2, Z, M));
      Check ("validation: ek valid", EK_Valid_For_Encaps (Key.EK));
      Check ("validation: dk valid", DK_Valid_For_Decaps (Key.DK));
   end Run_Validation;

begin
   if not Ada.Directories.Exists (Vec ("kat_MLKEM_" & Set & ".rsp")) then
      Put_Line ("vectors missing: run tests/kat/fetch.sh first");
      Fail := Fail + 1;
      return;
   end if;

   Put_Line ("--- ML-KEM-" & Set & " ---");
   Run_RSP ("kat_MLKEM_" & Set & ".rsp", With_Reject => True);
   if Has_CCTV then
      Run_RSP ("cctv_unlucky.rsp", With_Reject => False);
      Run_Invalid_EK ("cctv_invalid_ek.txt");
   end if;
   Run_ACVP ("acvp_keygen_" & Set & ".txt", Key_Gen);
   Run_ACVP ("acvp_encap_" & Set & ".txt", Encap);
   Run_ACVP ("acvp_decap_" & Set & ".txt", Decap);
   Run_ACVP ("acvp_ekcheck_" & Set & ".txt", EK_Check);
   Run_ACVP ("acvp_dkcheck_" & Set & ".txt", DK_Check);
   Run_Validation;
end KAT_Runner;
