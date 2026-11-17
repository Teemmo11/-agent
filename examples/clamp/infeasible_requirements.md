REQ-001:
This is an intentionally infeasible verification regression, not a useful production contract.
For clamp(int x, int low, int high), use exactly the contradictory precondition:
x > 0 && x < 0.
Q1 requires result >= low. Q2 requires result <= high. Both clauses are unguarded.
Do not repair or weaken this intentionally contradictory precondition. Expected verification
classification is VACUOUS after a separate feasibility check, not non-vacuous HOLDS.
