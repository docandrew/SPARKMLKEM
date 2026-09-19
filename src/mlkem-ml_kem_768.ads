with MLKEM.Generic_KEM;
--  Copyright (c) 2026 Jon Andrew (SPARKTLS project).
--  SPDX-License-Identifier: Apache-2.0
--
--  ML-KEM-768 (FIPS 203 section 8): the instance used by the TLS 1.3
--  X25519MLKEM768 key exchange.

with MLKEM.Compressed_Widths;
package MLKEM.ML_KEM_768 is new MLKEM.Generic_KEM
  (K     => 3,
   Eta_1 => 2,
   Eta_2 => 2,
   DU    => 10,
   DV    => 4,
   UDU   => MLKEM.Compressed_Widths.U10,
   UDV   => MLKEM.Compressed_Widths.U4);
