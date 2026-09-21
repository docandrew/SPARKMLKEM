--  Stack-residue scan for ML-KEM-768 key generation, encapsulation and
--  decapsulation.
--
--  Method: a deep frame paints the stack below the harness with a marker;
--  the primitive then runs at the same depth, so its frames overwrite the
--  painted region; after it returns the region is read back and searched
--  for 8-byte fragments of the secrets that went in (the seeds d and z,
--  the decryption key dk_pke, the encapsulation coins m, the shared
--  secret). Source-level sanitisation zeroes named temporaries; this
--  finds what it cannot reach: register spills, function return
--  temporaries, compiler-made copies.
--
--  Harness hygiene: every secret and every output buffer lives in the
--  main frame, above the region; the case bodies only call the primitive;
--  the scan reads the region without copying anything into it and skips
--  the top Skip bytes, where its own small frame sits. Needles are
--  random so that no window matches by accident. Run natively, not under
--  valgrind (memcheck marks popped stack inaccessible). Exit status 1 if
--  any primitive leaves a fragment, or if the negative control does not
--  find all of its planted windows (then the scanner itself is broken and
--  a zero would mean nothing). ci/residue.sh runs it as a gate.
--
--  The same scanner core, with the classical primitives, lives in
--  sparktlscrypto/tests/residue.
with Ada.Text_IO;                use Ada.Text_IO;
with Ada.Command_Line;
with System;
with System.Storage_Elements;    use System.Storage_Elements;
with Interfaces;                 use Interfaces;
with MLKEM;                      use MLKEM;
with MLKEM.ML_KEM_768;           use MLKEM.ML_KEM_768;

procedure Residue_Scan is
   Scan_Bytes : constant := 262_144;   --  256 KB below the harness
   Skip       : constant := 512;       --  the scan's own frame
   Window     : constant := 8;         --  one 64-bit word: catches lone spills
   Paint_Byte : constant Byte := 16#A5#;
   Total_Hits : Natural := 0;   --  primitives only, the control excluded
   Ctl_Found  : Natural := 0;
   Ctl_Want   : Natural := 0;
   Sink       : Byte := 0;

   type Needle_Ref is access constant Byte_Seq;
   type Needle_Set is array (Positive range <>) of Needle_Ref;
   type Needle_Result is record
      Windows, Found : Natural := 0;
      Lo, Hi         : Natural := 0;   --  offsets below the marker
   end record;
   type Result_Set is array (1 .. 8) of Needle_Result;

   --  Deterministic pseudo-random bytes for the needles
   Seed : Unsigned_64 := 16#9E37_79B9_7F4A_7C15#;
   function Rand (Len : N32) return Byte_Seq is
      R : Byte_Seq (0 .. Len - 1);
   begin
      for I in R'Range loop
         Seed := Seed xor Shift_Left (Seed, 13);
         Seed := Seed xor Shift_Right (Seed, 7);
         Seed := Seed xor Shift_Left (Seed, 17);
         R (I) := Byte (Seed and 255);
      end loop;
      return R;
   end Rand;

   procedure Paint is
      Buf : Byte_Seq (0 .. Scan_Bytes - 1) := (others => Paint_Byte);
      pragma Volatile (Buf);
   begin
      Sink := Sink xor Buf (Scan_Bytes - 1);
   end Paint;

   --  Read the region below Marker and search it in place.
   procedure Scan
     (Marker  : System.Address;
      Needles : Needle_Set;
      Res     : out Result_Set;
      Touched : out Natural)
   is
      Base   : constant System.Address :=
        To_Address (To_Integer (Marker) - Skip - Scan_Bytes);
      Region : Byte_Seq (0 .. Scan_Bytes - 1) with Import, Address => Base;
   begin
      Res := (others => <>);
      Touched := 0;
      for I in Region'Range loop
         if Region (I) /= Paint_Byte then
            Touched := Touched + 1;
         end if;
      end loop;
      for N in Needles'Range loop
         for S in Needles (N).all'First .. Needles (N).all'Last - Window + 1 loop
            Res (N).Windows := Res (N).Windows + 1;
            for I in Region'First .. Region'Last - Window + 1 loop
               if Region (I .. I + Window - 1) = Needles (N).all (S .. S + Window - 1) then
                  declare
                     Off : constant Natural := Natural (Scan_Bytes - 1 - I) + Skip;
                  begin
                     if Res (N).Found = 0 then
                        Res (N).Lo := Off; Res (N).Hi := Off;
                     else
                        Res (N).Lo := Natural'Min (Res (N).Lo, Off);
                        Res (N).Hi := Natural'Max (Res (N).Hi, Off);
                     end if;
                     Res (N).Found := Res (N).Found + 1;
                  end;
                  exit;
               end if;
            end loop;
         end loop;
      end loop;
   end Scan;

   --  Run the case below a spacer frame, so that the scan's own frame
   --  (which follows at the same depth as this one) lands on the spacer
   --  and not on the primitive's frames.
   procedure Deep (Op : access procedure) is
      Spacer : Byte_Seq (0 .. 4095) := (others => 0);
      pragma Volatile (Spacer);
   begin
      Op.all;
      Sink := Sink xor Spacer (0);
   end Deep;

   --  Paint, run the case below the spacer, then scan from here.
   procedure Run (Name : String; Op : access procedure; Needles : Needle_Set; Names : String;
                  Is_Control : Boolean := False) is
      Marker  : Byte := 0;
      pragma Volatile (Marker);
      Res     : Result_Set;
      Touched : Natural;
      Hits    : Natural := 0;
   begin
      Paint;
      Deep (Op);
      Scan (Marker'Address, Needles, Res, Touched);
      for N in Needles'Range loop
         Hits := Hits + Res (N).Found;
      end loop;
      Put_Line (Name & ": stack used" & Touched'Image & " B, residue fragments:" & Hits'Image & "   [" & Names & "]");
      for N in Needles'Range loop
         if Res (N).Found > 0 then
            Put_Line ("    needle" & N'Image & ":" & Res (N).Found'Image & " of" & Res (N).Windows'Image
                      & " windows found," & Res (N).Lo'Image & " .." & Res (N).Hi'Image & " bytes below the harness frame");
         end if;
      end loop;
      if Is_Control then
         Ctl_Found := Hits;
         Ctl_Want  := Res (1).Windows;
      else
         Total_Hits := Total_Hits + Hits;
      end if;
   end Run;

   ---------------------------------------------------------------------
   --  Secrets: the seeds d and z, the coins m, and what the primitives
   --  derive from them (dk_pke, the shared secret). All computed here,
   --  before any paint, from the same seeds the cases use.
   ---------------------------------------------------------------------
   D : constant Bytes_32 := Bytes_32 (Rand (32));
   Z : constant Bytes_32 := Bytes_32 (Rand (32));
   M : constant Bytes_32 := Bytes_32 (Rand (32));
   --  Needles are unconstrained views of the same bytes
   D_N : aliased constant Byte_Seq := Byte_Seq (D);
   Z_N : aliased constant Byte_Seq := Byte_Seq (Z);
   M_N : aliased constant Byte_Seq := Byte_Seq (M);

   function Keypair return MLKEM_Key is
      K : MLKEM_Key;
   begin
      MLKEM_KeyGen (D, Z, K);
      return K;
   end Keypair;
   Key  : constant MLKEM_Key := Keypair;
   Key2 : MLKEM_Key;                                  --  keygen case output
   --  dk_pke is the first 384 * 3 bytes of dk; z the last 32.
   DK_PKE : aliased constant Byte_Seq := Key.DK (0 .. 1151);

   function Encaps_SS return Byte_Seq is
      SS : Bytes_32;
      C  : Ciphertext;
   begin
      MLKEM_Encaps (Key.EK, M, SS, C);
      return Byte_Seq (SS);
   end Encaps_SS;
   SS   : aliased constant Byte_Seq := Encaps_SS;     --  the shared secret both sides derive
   CT   : Ciphertext;                                 --  encaps case output, decaps case input
   SS_E : Bytes_32;                                   --  encaps case output
   SS_D : Bytes_32;                                   --  decaps case output

   --  Negative control: a routine that copies the secret into a local and
   --  returns without sanitising. The scanner must see this one.
   Ctl_Secret : aliased constant Byte_Seq := Rand (32);
   procedure Case_Control is
      Local : Byte_Seq (0 .. 31) := Ctl_Secret;
      pragma Volatile (Local);
   begin
      Sink := Sink xor Local (5);
   end Case_Control;

   --  Case bodies: nothing but the call. No type conversions here: a
   --  conversion inside a case body would make a temporary copy in that
   --  frame, which the scan would then find.
   procedure Case_KeyGen is
   begin
      MLKEM_KeyGen (D, Z, Key2);
   end Case_KeyGen;
   procedure Case_Encaps is
   begin
      MLKEM_Encaps (Key.EK, M, SS_E, CT);
   end Case_Encaps;
   procedure Case_Decaps is
   begin
      MLKEM_Decaps (CT, Key.DK, SS_D);
   end Case_Decaps;
begin
   Put_Line ("=== stack residue scan (ML-KEM-768):" & Integer'Image (Scan_Bytes / 1024)
             & " KB region, 8-byte fragments, random needles ===");
   Run ("negative control  ", Case_Control'Access, (1 => Ctl_Secret'Access), "1=leaked copy; MUST be found",
        Is_Control => True);
   Run ("ML-KEM-768 keygen ", Case_KeyGen'Access, (D_N'Access, Z_N'Access, DK_PKE'Access), "1=d 2=z 3=dk_pke");
   Run ("ML-KEM-768 encaps ", Case_Encaps'Access, (M_N'Access, SS'Access), "1=m (coins) 2=shared secret");
   Run ("ML-KEM-768 decaps ", Case_Decaps'Access, (DK_PKE'Access, Z_N'Access, M_N'Access, SS'Access),
        "1=dk_pke 2=z 3=m' 4=shared secret");
   Put_Line ("=== residue fragments in the primitives:" & Total_Hits'Image
             & "; control found" & Ctl_Found'Image & " of" & Ctl_Want'Image
             & "  (decaps agrees:" & Boolean'Image (SS_D = SS_E and then Byte_Seq (SS_E) = SS)
             & ", sink" & Sink'Image & ")");
   if Ctl_Found /= Ctl_Want or Ctl_Want = 0 then
      Put_Line ("=== residue scan: FAIL (the control did not light up; the scanner is not seeing the stack)");
      Ada.Command_Line.Set_Exit_Status (1);
   elsif Total_Hits > 0 then
      Put_Line ("=== residue scan: FAIL");
      Ada.Command_Line.Set_Exit_Status (1);
   else
      Put_Line ("=== residue scan: PASS");
      Ada.Command_Line.Set_Exit_Status (0);
   end if;
end Residue_Scan;
