REQ-001:
For limit_speed, limit may be any value from 0 through 100 inclusive. The
request may be any signed char. A negative request returns 0. A request
above limit returns limit. Any other request is returned unchanged.

REQ-002:
For target_speed, limit may be any value from 0 through 100 inclusive. The
request may be any signed char. A nonpositive request returns 0. For a
positive request below 20, the result is 20 when limit is at least 20,
and limit otherwise. For a request of at least 20, return the request
when it does not exceed limit, and return limit otherwise.

REQ-003:
For fan_command, limit may be any value from 0 through 100 inclusive, and
mode must be 0, 1 or 2. The request may be any signed char in all three
modes. Mode 0 always returns 0. Mode 1 applies the target_speed behavior
specified in REQ-002 to the original request. Mode 2 returns limit
regardless of the original request. In every mode, the result is within
the inclusive range from 0 to limit.

REQ-004:
At a mode 1 call, fan_command relies on target_speed handling the original
request under the original limit. At a mode 2 call, it passes limit as
both arguments and relies on target_speed returning that limit, including
when the limit is 0 or below 20. When target_speed raises a request to 20,
it relies on limit_speed capping that raised request. For requests of at
least 20 it relies on limit_speed either preserving the original request
or capping it at limit. These callsite obligations do not narrow the
permitted inputs of the called functions.
