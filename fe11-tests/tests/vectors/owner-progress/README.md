# Digest ownership and progression

These cases use the SHA256 answer for `abc` from FIPS 180-4. Three one-byte
updates establish an active operation. Completed cases retain the published
answer across explicit session close. Session and both Advanced pacing policies
are covered. Every cooperative poll checks the next native function and all
call counters; explicit close must make only C_CloseSession.

The output-capacity case supplies zero storage, checks required length 32,
then explicitly replaces storage and resumes Final. It does not interpret an
empty output as a successful digest or automatically replay the input.
