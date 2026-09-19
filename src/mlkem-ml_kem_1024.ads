with MLKEM.Generic_KEM;
--  Copyright (c) 2026 Jon Andrew (SPARKTLS project).
--  SPDX-License-Identifier: Apache-2.0
--
--  ML-KEM-1024 (FIPS 203 section 8): the CNSA 2.0 parameter set, kept
--  instantiated and tested so the generic stays honest.

with MLKEM.Compressed_Widths;
package MLKEM.ML_KEM_1024 is new MLKEM.Generic_KEM
  (K     => 4,
   Eta_1 => 2,
   Eta_2 => 2,
   DU    => 11,
   DV    => 5,
   UDU   => MLKEM.Compressed_Widths.U11,
   UDV   => MLKEM.Compressed_Widths.U5);
