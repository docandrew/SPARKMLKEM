--  Known-answer and validation tests for one ML-KEM parameter set. The
--  instance under test is a formal package, so the same harness runs
--  ML-KEM-768 and ML-KEM-1024 (see kat_tests.adb). Vector files carry
--  the set as a suffix; the CCTV negatives exist for 768 only.

with MLKEM.Generic_KEM;

generic
   with package KEM is new MLKEM.Generic_KEM (<>);
   Set      : String;    --  "768" or "1024"
   Has_CCTV : Boolean;
procedure KAT_Runner (Pass, Fail : in out Natural);
