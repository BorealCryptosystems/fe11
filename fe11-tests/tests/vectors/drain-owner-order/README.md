# Drain order across native owners

Three sessions hold an idle owner, a completed SHA-256 result, and an active
cooperative digest. Each permutation closes those owners under a module drain.
Finalization refuses locally while a usable session remains, without native
close or finalization. The active digest completes through the drain permit;
accounting follows each explicit close. Both exact digest results remain readable
after finalization. Every failed path still attempts owned cleanup.
