REQ-001:
sum_array(void) creates a local array of exactly ten int elements containing
0, 1, 2, 3, 4, 5, 6, 7, 8, 9 in order. It visits indices 0 through 9 and returns
their sum, which must equal 45. The function takes no arguments and requires no
precondition (P is true, expressed as 1). This is an unconditional postcondition
under P: Q1 is result == 45, with no caller-specific guard.

This requirement concerns this fixed, internally initialized array, not an
arbitrary array passed by a caller. Do not add assumptions to hide implementation
errors or replace the expected sum with a value inferred from faulty code.
