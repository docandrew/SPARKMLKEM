with Interfaces; use Interfaces;

package body Timing_Fixtures is

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

   procedure Select_Bytes
     (A, B   : in     Byte_Seq;
      Second : in     Boolean;
      Result :    out Byte_Seq)
   is
      Mask : constant Byte := Byte (Boolean'Pos (Second)) * Byte'Last;
   begin
      for I in Result'Range loop
         Result (I) := (A (I) and not Mask) or (B (I) and Mask);
      end loop;
   end Select_Bytes;

end Timing_Fixtures;
