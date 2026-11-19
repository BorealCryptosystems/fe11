# Cooperative zero output capacity

This case explicitly selects Cooperative pacing before starting a SHA256 stream
with zero output storage. It observes required length32, explicitly supplies
that capacity, and completes without replaying the three input fragments.
