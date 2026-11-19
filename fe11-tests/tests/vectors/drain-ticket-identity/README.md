# Ticket identity under explicit drainage

Real synchronous SHA-256 tickets are foreign to the receiver or already
consumed before the drain begins. Token cases retain one exact TokenContext
for both sessions and the drain permit. Cleanup uses the same drain authority
and requires completed closures; ordinary operations are not resumed during
the drain. Published digest bytes remain readable after cleanup.
