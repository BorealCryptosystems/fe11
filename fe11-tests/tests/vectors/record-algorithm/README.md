# Record algorithm consistency

Each fixture preserves a complete, structurally valid saved SHA-256 frame and
changes one byte in its profile, mechanism, result width or message hash.
The exact typed incompatibility is required; truncation is not an alternative
oracle. Native counters and the retained positive frame remain unchanged.
Synthetic state bytes are only parsed, never authenticated or restored.
