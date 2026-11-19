# Digest ownership and observable quotas

These cases distinguish session quota accounting from the private byte budget.
A rejected preparation and a refused native capture must leave the public
ModuleResourceStatus unchanged; the original owner must still produce SHA256
for `abc`. Dropping a ticket must retain the active operation in its session:
a second Init is refused without native dispatch until the explicit close.
Closing settles exactly one of the two owned sessions.

The public status has no byte-balance field. These assertions do not prove an
internal byte-budget baseline, nor do they infer a successful native capture.
All native failures and cleanup results retain their original diagnostics.
