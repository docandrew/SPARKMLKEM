--  Copyright (c) 2026 Jon Andrew (SPARKTLS project).
--  SPDX-License-Identifier: Apache-2.0
--
--  The modular types of compressed coefficients for the ciphertext widths
--  of the three parameter sets (FIPS 203 section 8: du = 10 or 11, dv = 4
--  or 5). A modular type's modulus must be static, which a generic formal
--  cannot be, so the instances name these types explicitly.

package MLKEM.Compressed_Widths
  with SPARK_Mode => On
is
   type U4  is mod 2**4  with Object_Size => 16;
   type U5  is mod 2**5  with Object_Size => 16;
   type U10 is mod 2**10 with Object_Size => 16;
   type U11 is mod 2**11 with Object_Size => 16;
end MLKEM.Compressed_Widths;
